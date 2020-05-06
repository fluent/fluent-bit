/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "test.h"
#include "rdkafka.h"

/**
 * @brief Admin API integration tests.
 */


static int32_t *avail_brokers;
static size_t avail_broker_cnt;




static void do_test_CreateTopics (const char *what,
                                  rd_kafka_t *rk, rd_kafka_queue_t *useq,
                                  int op_timeout, rd_bool_t validate_only) {
        rd_kafka_queue_t *q = useq ? useq : rd_kafka_queue_new(rk);
#define MY_NEW_TOPICS_CNT 6
        char *topics[MY_NEW_TOPICS_CNT];
        rd_kafka_NewTopic_t *new_topics[MY_NEW_TOPICS_CNT];
        rd_kafka_AdminOptions_t *options = NULL;
        rd_kafka_resp_err_t exp_topicerr[MY_NEW_TOPICS_CNT] = {0};
        rd_kafka_resp_err_t exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        /* Expected topics in metadata */
        rd_kafka_metadata_topic_t exp_mdtopics[MY_NEW_TOPICS_CNT] = {{0}};
        int exp_mdtopic_cnt = 0;
        /* Not expected topics in metadata */
        rd_kafka_metadata_topic_t exp_not_mdtopics[MY_NEW_TOPICS_CNT] = {{0}};
        int exp_not_mdtopic_cnt = 0;
        int i;
        char errstr[512];
        const char *errstr2;
        rd_kafka_resp_err_t err;
        test_timing_t timing;
        rd_kafka_event_t *rkev;
        const rd_kafka_CreateTopics_result_t *res;
        const rd_kafka_topic_result_t **restopics;
        size_t restopic_cnt;
        int metadata_tmout ;
        int num_replicas = (int)avail_broker_cnt;
        int32_t *replicas;

        /* Set up replicas */
        replicas = rd_alloca(sizeof(*replicas) * num_replicas);
        for (i = 0 ; i < num_replicas ; i++)
                replicas[i] = avail_brokers[i];

        TEST_SAY(_C_MAG "[ %s CreateTopics with %s, "
                 "op_timeout %d, validate_only %d ]\n",
                 rd_kafka_name(rk), what, op_timeout, validate_only);

        /**
         * Construct NewTopic array with different properties for
         * different partitions.
         */
        for (i = 0 ; i < MY_NEW_TOPICS_CNT ; i++) {
                char *topic = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
                int num_parts = i * 7 + 1;
                int set_config = (i & 1);
                int add_invalid_config = (i == 1);
                int set_replicas = !(i % 3);
                rd_kafka_resp_err_t this_exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;

                topics[i] = topic;
                new_topics[i] = rd_kafka_NewTopic_new(topic,
                                                      num_parts,
                                                      set_replicas ? -1 :
                                                      num_replicas,
                                                      NULL, 0);

                if (set_config) {
                        /*
                         * Add various configuration properties
                         */
                        err = rd_kafka_NewTopic_set_config(
                                new_topics[i], "compression.type", "lz4");
                        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

                        err = rd_kafka_NewTopic_set_config(
                                new_topics[i], "delete.retention.ms", "900");
                        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
                }

                if (add_invalid_config) {
                        /* Add invalid config property */
                        err = rd_kafka_NewTopic_set_config(
                                new_topics[i],
                                "dummy.doesntexist",
                                "broker is verifying this");
                        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
                        this_exp_err = RD_KAFKA_RESP_ERR_INVALID_CONFIG;
                }

                TEST_SAY("Expected result for topic #%d: %s "
                         "(set_config=%d, add_invalid_config=%d, "
                         "set_replicas=%d)\n",
                         i, rd_kafka_err2name(this_exp_err),
                         set_config, add_invalid_config, set_replicas);

                if (set_replicas) {
                        int32_t p;

                        /*
                         * Set valid replica assignments
                         */
                        for (p = 0 ; p < num_parts ; p++) {
                                err = rd_kafka_NewTopic_set_replica_assignment(
                                        new_topics[i], p,
                                        replicas, num_replicas,
                                        errstr, sizeof(errstr));
                                TEST_ASSERT(!err, "%s", errstr);
                        }
                }

                if (this_exp_err || validate_only) {
                        exp_topicerr[i] = this_exp_err;
                        exp_not_mdtopics[exp_not_mdtopic_cnt++].topic = topic;

                } else {
                        exp_mdtopics[exp_mdtopic_cnt].topic = topic;
                        exp_mdtopics[exp_mdtopic_cnt].partition_cnt =
                                num_parts;
                        exp_mdtopic_cnt++;
                }
        }

        if (op_timeout != -1 || validate_only) {
                options = rd_kafka_AdminOptions_new(
                        rk, RD_KAFKA_ADMIN_OP_CREATETOPICS);

                if (op_timeout != -1) {
                        err = rd_kafka_AdminOptions_set_operation_timeout(
                                options, op_timeout, errstr, sizeof(errstr));
                        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
                }

                if (validate_only) {
                        err = rd_kafka_AdminOptions_set_validate_only(
                                options, validate_only, errstr, sizeof(errstr));
                        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
                }
        }

        TIMING_START(&timing, "CreateTopics");
        TEST_SAY("Call CreateTopics\n");
        rd_kafka_CreateTopics(rk, new_topics, MY_NEW_TOPICS_CNT,
                                    options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /* Poll result queue for CreateTopics result.
         * Print but otherwise ignore other event types
         * (typically generic Error events). */
        TIMING_START(&timing, "CreateTopics.queue_poll");
        do {
                rkev = rd_kafka_queue_poll(q, tmout_multip(20*1000));
                TEST_SAY("CreateTopics: got %s in %.3fms\n",
                         rd_kafka_event_name(rkev),
                         TIMING_DURATION(&timing) / 1000.0f);
                if (rd_kafka_event_error(rkev))
                        TEST_SAY("%s: %s\n",
                                 rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));
        } while (rd_kafka_event_type(rkev) !=
                 RD_KAFKA_EVENT_CREATETOPICS_RESULT);

        /* Convert event to proper result */
        res = rd_kafka_event_CreateTopics_result(rkev);
        TEST_ASSERT(res, "expected CreateTopics_result, not %s",
                    rd_kafka_event_name(rkev));

        /* Expecting error */
        err = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(err == exp_err,
                    "expected CreateTopics to return %s, not %s (%s)",
                    rd_kafka_err2str(exp_err),
                    rd_kafka_err2str(err),
                    err ? errstr2 : "n/a");

        TEST_SAY("CreateTopics: returned %s (%s)\n",
                 rd_kafka_err2str(err), err ? errstr2 : "n/a");

        /* Extract topics */
        restopics = rd_kafka_CreateTopics_result_topics(res, &restopic_cnt);


        /* Scan topics for proper fields and expected failures. */
        for (i = 0 ; i < (int)restopic_cnt ; i++) {
                const rd_kafka_topic_result_t *terr = restopics[i];

                /* Verify that topic order matches our request. */
                if (strcmp(rd_kafka_topic_result_name(terr), topics[i]))
                        TEST_FAIL_LATER("Topic result order mismatch at #%d: "
                                        "expected %s, got %s",
                                        i, topics[i],
                                        rd_kafka_topic_result_name(terr));

                TEST_SAY("CreateTopics result: #%d: %s: %s: %s\n",
                         i,
                         rd_kafka_topic_result_name(terr),
                         rd_kafka_err2name(rd_kafka_topic_result_error(terr)),
                         rd_kafka_topic_result_error_string(terr));
                if (rd_kafka_topic_result_error(terr) != exp_topicerr[i])
                        TEST_FAIL_LATER(
                                "Expected %s, not %d: %s",
                                rd_kafka_err2name(exp_topicerr[i]),
                                rd_kafka_topic_result_error(terr),
                                rd_kafka_err2name(rd_kafka_topic_result_error(
                                                          terr)));
        }

        /**
         * Verify that the expecteded topics are created and the non-expected
         * are not. Allow it some time to propagate.
         */
        if (validate_only) {
                /* No topics should have been created, give it some time
                 * before checking. */
                rd_sleep(2);
                metadata_tmout = 5 * 1000;
        } else {
                if (op_timeout > 0)
                        metadata_tmout = op_timeout + 1000;
                else
                        metadata_tmout = 10 * 1000;
        }

        test_wait_metadata_update(rk,
                                  exp_mdtopics,
                                  exp_mdtopic_cnt,
                                  exp_not_mdtopics,
                                  exp_not_mdtopic_cnt,
                                  metadata_tmout);

        rd_kafka_event_destroy(rkev);

        for (i = 0 ; i < MY_NEW_TOPICS_CNT ; i++) {
                rd_kafka_NewTopic_destroy(new_topics[i]);
                rd_free(topics[i]);
        }

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

#undef MY_NEW_TOPICS_CNT
}




/**
 * @brief Test deletion of topics
 *
 *
 */
static void do_test_DeleteTopics (const char *what,
                                  rd_kafka_t *rk, rd_kafka_queue_t *useq,
                                  int op_timeout) {
        rd_kafka_queue_t *q = useq ? useq : rd_kafka_queue_new(rk);
        const int skip_topic_cnt = 2;
#define MY_DEL_TOPICS_CNT 9
        char *topics[MY_DEL_TOPICS_CNT];
        rd_kafka_DeleteTopic_t *del_topics[MY_DEL_TOPICS_CNT];
        rd_kafka_AdminOptions_t *options = NULL;
        rd_kafka_resp_err_t exp_topicerr[MY_DEL_TOPICS_CNT] = {0};
        rd_kafka_resp_err_t exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        /* Expected topics in metadata */
        rd_kafka_metadata_topic_t exp_mdtopics[MY_DEL_TOPICS_CNT] = {{0}};
        int exp_mdtopic_cnt = 0;
        /* Not expected topics in metadata */
        rd_kafka_metadata_topic_t exp_not_mdtopics[MY_DEL_TOPICS_CNT] = {{0}};
        int exp_not_mdtopic_cnt = 0;
        int i;
        char errstr[512];
        const char *errstr2;
        rd_kafka_resp_err_t err;
        test_timing_t timing;
        rd_kafka_event_t *rkev;
        const rd_kafka_DeleteTopics_result_t *res;
        const rd_kafka_topic_result_t **restopics;
        size_t restopic_cnt;
        int metadata_tmout;

        TEST_SAY(_C_MAG "[ %s DeleteTopics with %s, op_timeout %d ]\n",
                 rd_kafka_name(rk), what, op_timeout);

        /**
         * Construct DeleteTopic array
         */
        for (i = 0 ; i < MY_DEL_TOPICS_CNT ; i++) {
                char *topic = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
                int notexist_topic = i >= MY_DEL_TOPICS_CNT - skip_topic_cnt;

                topics[i] = topic;

                del_topics[i] = rd_kafka_DeleteTopic_new(topic);

                if (notexist_topic)
                        exp_topicerr[i] =
                                RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
                else {
                        exp_topicerr[i] =
                                RD_KAFKA_RESP_ERR_NO_ERROR;

                        exp_mdtopics[exp_mdtopic_cnt++].topic = topic;
                }

                exp_not_mdtopics[exp_not_mdtopic_cnt++].topic = topic;
        }

        if (op_timeout != -1) {
                options = rd_kafka_AdminOptions_new(
                        rk, RD_KAFKA_ADMIN_OP_ANY);

                err = rd_kafka_AdminOptions_set_operation_timeout(
                        options, op_timeout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        }


        /* Create the topics first, minus the skip count. */
        test_CreateTopics_simple(rk, NULL, topics,
                                 MY_DEL_TOPICS_CNT-skip_topic_cnt,
                                 2/*num_partitions*/,
                                 NULL);

        /* Verify that topics are reported by metadata */
        test_wait_metadata_update(rk,
                                  exp_mdtopics, exp_mdtopic_cnt,
                                  NULL, 0,
                                  15*1000);

        TIMING_START(&timing, "DeleteTopics");
        TEST_SAY("Call DeleteTopics\n");
        rd_kafka_DeleteTopics(rk, del_topics, MY_DEL_TOPICS_CNT,
                                    options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /* Poll result queue for DeleteTopics result.
         * Print but otherwise ignore other event types
         * (typically generic Error events). */
        TIMING_START(&timing, "DeleteTopics.queue_poll");
        while (1) {
                rkev = rd_kafka_queue_poll(q, tmout_multip(20*1000));
                TEST_SAY("DeleteTopics: got %s in %.3fms\n",
                         rd_kafka_event_name(rkev),
                         TIMING_DURATION(&timing) / 1000.0f);
                if (rd_kafka_event_error(rkev))
                        TEST_SAY("%s: %s\n",
                                 rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));

                if (rd_kafka_event_type(rkev) ==
                    RD_KAFKA_EVENT_DELETETOPICS_RESULT)
                        break;

                rd_kafka_event_destroy(rkev);
        }

        /* Convert event to proper result */
        res = rd_kafka_event_DeleteTopics_result(rkev);
        TEST_ASSERT(res, "expected DeleteTopics_result, not %s",
                    rd_kafka_event_name(rkev));

        /* Expecting error */
        err = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(err == exp_err,
                    "expected DeleteTopics to return %s, not %s (%s)",
                    rd_kafka_err2str(exp_err),
                    rd_kafka_err2str(err),
                    err ? errstr2 : "n/a");

        TEST_SAY("DeleteTopics: returned %s (%s)\n",
                 rd_kafka_err2str(err), err ? errstr2 : "n/a");

        /* Extract topics */
        restopics = rd_kafka_DeleteTopics_result_topics(res, &restopic_cnt);


        /* Scan topics for proper fields and expected failures. */
        for (i = 0 ; i < (int)restopic_cnt ; i++) {
                const rd_kafka_topic_result_t *terr = restopics[i];

                /* Verify that topic order matches our request. */
                if (strcmp(rd_kafka_topic_result_name(terr), topics[i]))
                        TEST_FAIL_LATER("Topic result order mismatch at #%d: "
                                        "expected %s, got %s",
                                        i, topics[i],
                                        rd_kafka_topic_result_name(terr));

                TEST_SAY("DeleteTopics result: #%d: %s: %s: %s\n",
                         i,
                         rd_kafka_topic_result_name(terr),
                         rd_kafka_err2name(rd_kafka_topic_result_error(terr)),
                         rd_kafka_topic_result_error_string(terr));
                if (rd_kafka_topic_result_error(terr) != exp_topicerr[i])
                        TEST_FAIL_LATER(
                                "Expected %s, not %d: %s",
                                rd_kafka_err2name(exp_topicerr[i]),
                                rd_kafka_topic_result_error(terr),
                                rd_kafka_err2name(rd_kafka_topic_result_error(
                                                          terr)));
        }

        /**
         * Verify that the expected topics are deleted and the non-expected
         * are not. Allow it some time to propagate.
         */
        if (op_timeout > 0)
                metadata_tmout = op_timeout + 1000;
        else
                metadata_tmout = 10 * 1000;

        test_wait_metadata_update(rk,
                                  NULL, 0,
                                  exp_not_mdtopics,
                                  exp_not_mdtopic_cnt,
                                  metadata_tmout);

        rd_kafka_event_destroy(rkev);

        for (i = 0 ; i < MY_DEL_TOPICS_CNT ; i++) {
                rd_kafka_DeleteTopic_destroy(del_topics[i]);
                rd_free(topics[i]);
        }

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

#undef MY_DEL_TOPICS_CNT
}



/**
 * @brief Test creation of partitions
 *
 *
 */
static void do_test_CreatePartitions (const char *what,
                                      rd_kafka_t *rk, rd_kafka_queue_t *useq,
                                      int op_timeout) {
        rd_kafka_queue_t *q = useq ? useq : rd_kafka_queue_new(rk);
#define MY_CRP_TOPICS_CNT 9
        char *topics[MY_CRP_TOPICS_CNT];
        rd_kafka_NewTopic_t *new_topics[MY_CRP_TOPICS_CNT];
        rd_kafka_NewPartitions_t *crp_topics[MY_CRP_TOPICS_CNT];
        rd_kafka_AdminOptions_t *options = NULL;
        /* Expected topics in metadata */
        rd_kafka_metadata_topic_t exp_mdtopics[MY_CRP_TOPICS_CNT] = {{0}};
        rd_kafka_metadata_partition_t exp_mdparts[2] = {{0}};
        int exp_mdtopic_cnt = 0;
        int i;
        char errstr[512];
        rd_kafka_resp_err_t err;
        test_timing_t timing;
        int metadata_tmout;
        int num_replicas = (int)avail_broker_cnt;

        TEST_SAY(_C_MAG "[ %s CreatePartitions with %s, op_timeout %d ]\n",
                 rd_kafka_name(rk), what, op_timeout);

        /* Set up two expected partitions with different replication sets
         * so they can be matched by the metadata checker later.
         * Even partitions use exp_mdparts[0] while odd partitions
         * use exp_mdparts[1]. */

        /* Set valid replica assignments (even, and odd (reverse) ) */
        exp_mdparts[0].replicas = rd_alloca(sizeof(*exp_mdparts[0].replicas) *
                                            num_replicas);
        exp_mdparts[1].replicas = rd_alloca(sizeof(*exp_mdparts[1].replicas) *
                                            num_replicas);
        exp_mdparts[0].replica_cnt = num_replicas;
        exp_mdparts[1].replica_cnt = num_replicas;
        for (i = 0 ; i < num_replicas ; i++) {
                exp_mdparts[0].replicas[i] = avail_brokers[i];
                exp_mdparts[1].replicas[i] = avail_brokers[num_replicas-i-1];
        }

        /**
         * Construct CreatePartitions array
         */
        for (i = 0 ; i < MY_CRP_TOPICS_CNT ; i++) {
                char *topic = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
                int initial_part_cnt = 1 + (i * 2);
                int new_part_cnt = 1 + (i / 2);
                int final_part_cnt = initial_part_cnt + new_part_cnt;
                int set_replicas = !(i % 2);
                int pi;

                topics[i] = topic;

                /* Topic to create with initial partition count */
                new_topics[i] = rd_kafka_NewTopic_new(topic, initial_part_cnt,
                                                      set_replicas ?
                                                      -1 : num_replicas,
                                                      NULL, 0);

                /* .. and later add more partitions to */
                crp_topics[i] = rd_kafka_NewPartitions_new(topic,
                                                           final_part_cnt,
                                                           errstr,
                                                           sizeof(errstr));

                if (set_replicas) {
                        exp_mdtopics[exp_mdtopic_cnt].partitions =
                                rd_alloca(final_part_cnt *
                                          sizeof(*exp_mdtopics[exp_mdtopic_cnt].
                                                 partitions));

                        for (pi = 0 ; pi < final_part_cnt ; pi++) {
                                const rd_kafka_metadata_partition_t *exp_mdp =
                                        &exp_mdparts[pi & 1];

                                exp_mdtopics[exp_mdtopic_cnt].
                                        partitions[pi] = *exp_mdp; /* copy */

                                exp_mdtopics[exp_mdtopic_cnt].
                                        partitions[pi].id = pi;

                                if (pi < initial_part_cnt) {
                                        /* Set replica assignment
                                         * for initial partitions */
                                        err = rd_kafka_NewTopic_set_replica_assignment(
                                                new_topics[i], pi,
                                                exp_mdp->replicas,
                                                (size_t)exp_mdp->replica_cnt,
                                                errstr, sizeof(errstr));
                                        TEST_ASSERT(!err, "NewTopic_set_replica_assignment: %s",
                                                errstr);
                                } else {
                                        /* Set replica assignment for new
                                         * partitions */
                                        err = rd_kafka_NewPartitions_set_replica_assignment(
                                                crp_topics[i],
                                                pi - initial_part_cnt,
                                                exp_mdp->replicas,
                                                (size_t)exp_mdp->replica_cnt,
                                                errstr, sizeof(errstr));
                                        TEST_ASSERT(!err, "NewPartitions_set_replica_assignment: %s",
                                                errstr);
                                }

                        }
                }

                TEST_SAY(_C_YEL "Topic %s with %d initial partitions will grow "
                         "by %d to %d total partitions with%s replicas set\n",
                         topics[i],
                         initial_part_cnt, new_part_cnt, final_part_cnt,
                         set_replicas ? "" : "out");

                exp_mdtopics[exp_mdtopic_cnt].topic = topic;
                exp_mdtopics[exp_mdtopic_cnt].partition_cnt = final_part_cnt;

                exp_mdtopic_cnt++;
        }

        if (op_timeout != -1) {
                options = rd_kafka_AdminOptions_new(
                        rk, RD_KAFKA_ADMIN_OP_ANY);

                err = rd_kafka_AdminOptions_set_operation_timeout(
                        options, op_timeout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        }

        /*
         * Create topics with initial partition count
         */
        TIMING_START(&timing, "CreateTopics");
        TEST_SAY("Creating topics with initial partition counts\n");
        rd_kafka_CreateTopics(rk, new_topics, MY_CRP_TOPICS_CNT,
                                    options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        err = test_wait_topic_admin_result(q,
                                           RD_KAFKA_EVENT_CREATETOPICS_RESULT,
                                           NULL, 15000);
        TEST_ASSERT(!err, "CreateTopics failed: %s", rd_kafka_err2str(err));

        rd_kafka_NewTopic_destroy_array(new_topics, MY_CRP_TOPICS_CNT);


        /*
         * Create new partitions
         */
        TIMING_START(&timing, "CreatePartitions");
        TEST_SAY("Creating partitions\n");
        rd_kafka_CreatePartitions(rk, crp_topics, MY_CRP_TOPICS_CNT,
                                    options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        err = test_wait_topic_admin_result(q,
                                           RD_KAFKA_EVENT_CREATEPARTITIONS_RESULT,
                                           NULL, 15000);
        TEST_ASSERT(!err, "CreatePartitions failed: %s", rd_kafka_err2str(err));

        rd_kafka_NewPartitions_destroy_array(crp_topics, MY_CRP_TOPICS_CNT);


        /**
         * Verify that the expected topics are deleted and the non-expected
         * are not. Allow it some time to propagate.
         */
        if (op_timeout > 0)
                metadata_tmout = op_timeout + 1000;
        else
                metadata_tmout = 10 * 1000;

        test_wait_metadata_update(rk,
                                  exp_mdtopics,
                                  exp_mdtopic_cnt,
                                  NULL, 0,
                                  metadata_tmout);

        for (i = 0 ; i < MY_CRP_TOPICS_CNT ; i++)
                rd_free(topics[i]);

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

#undef MY_CRP_TOPICS_CNT
}



/**
 * @brief Print the ConfigEntrys in the provided array.
 */
static void
test_print_ConfigEntry_array (const rd_kafka_ConfigEntry_t **entries,
                              size_t entry_cnt, unsigned int depth) {
        const char *indent = &"    "[4 - (depth > 4 ? 4 : depth)];
        size_t ei;

        for (ei = 0 ; ei < entry_cnt ; ei++) {
                const rd_kafka_ConfigEntry_t *e = entries[ei];
                const rd_kafka_ConfigEntry_t **syns;
                size_t syn_cnt;

                syns = rd_kafka_ConfigEntry_synonyms(e, &syn_cnt);

#define YN(v) ((v) ? "y" : "n")
                TEST_SAYL(3,
                          "%s#%"PRIusz"/%"PRIusz
                          ": Source %s (%d): \"%s\"=\"%s\" "
                          "[is read-only=%s, default=%s, sensitive=%s, "
                          "synonym=%s] with %"PRIusz" synonym(s)\n",
                          indent,
                          ei, entry_cnt,
                          rd_kafka_ConfigSource_name(
                                  rd_kafka_ConfigEntry_source(e)),
                          rd_kafka_ConfigEntry_source(e),
                          rd_kafka_ConfigEntry_name(e),
                          rd_kafka_ConfigEntry_value(e) ?
                          rd_kafka_ConfigEntry_value(e) : "(NULL)",
                          YN(rd_kafka_ConfigEntry_is_read_only(e)),
                          YN(rd_kafka_ConfigEntry_is_default(e)),
                          YN(rd_kafka_ConfigEntry_is_sensitive(e)),
                          YN(rd_kafka_ConfigEntry_is_synonym(e)),
                          syn_cnt);
#undef YN

                if (syn_cnt > 0)
                        test_print_ConfigEntry_array(syns, syn_cnt, depth+1);
        }
}


/**
 * @brief Test AlterConfigs
 */
static void do_test_AlterConfigs (rd_kafka_t *rk, rd_kafka_queue_t *rkqu) {
#define MY_CONFRES_CNT 3
        char *topics[MY_CONFRES_CNT];
        rd_kafka_ConfigResource_t *configs[MY_CONFRES_CNT];
        rd_kafka_AdminOptions_t *options;
        rd_kafka_resp_err_t exp_err[MY_CONFRES_CNT];
        rd_kafka_event_t *rkev;
        rd_kafka_resp_err_t err;
        const rd_kafka_AlterConfigs_result_t *res;
        const rd_kafka_ConfigResource_t **rconfigs;
        size_t rconfig_cnt;
        char errstr[128];
        const char *errstr2;
        int ci = 0;
        int i;
        int fails = 0;

        /*
         * Only create one topic, the others will be non-existent.
         */
        for (i = 0 ; i < MY_CONFRES_CNT ; i++)
                rd_strdupa(&topics[i], test_mk_topic_name(__FUNCTION__, 1));

        test_CreateTopics_simple(rk, NULL, topics, 1, 1, NULL);

        /*
         * ConfigResource #0: valid topic config
         */
        configs[ci] = rd_kafka_ConfigResource_new(
                RD_KAFKA_RESOURCE_TOPIC, topics[ci]);

        err = rd_kafka_ConfigResource_set_config(configs[ci],
                                                 "compression.type", "gzip");
        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

        err = rd_kafka_ConfigResource_set_config(configs[ci],
                                                 "flush.ms", "12345678");
        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

        exp_err[ci] = RD_KAFKA_RESP_ERR_NO_ERROR;
        ci++;


        if (test_broker_version >= TEST_BRKVER(1, 1, 0, 0)) {
                /*
                 * ConfigResource #1: valid broker config
                 */
                configs[ci] = rd_kafka_ConfigResource_new(
                        RD_KAFKA_RESOURCE_BROKER,
                        tsprintf("%"PRId32, avail_brokers[0]));

                err = rd_kafka_ConfigResource_set_config(
                        configs[ci],
                        "sasl.kerberos.min.time.before.relogin", "58000");
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

                exp_err[ci] = RD_KAFKA_RESP_ERR_NO_ERROR;
                ci++;
        } else {
                TEST_WARN("Skipping RESOURCE_BROKER test on unsupported "
                          "broker version\n");
        }

        /*
         * ConfigResource #2: valid topic config, non-existent topic
         */
        configs[ci] = rd_kafka_ConfigResource_new(
                RD_KAFKA_RESOURCE_TOPIC, topics[ci]);

        err = rd_kafka_ConfigResource_set_config(configs[ci],
                                                 "compression.type", "lz4");
        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

        err = rd_kafka_ConfigResource_set_config(configs[ci],
                                                 "offset.metadata.max.bytes",
                                                 "12345");
        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

        exp_err[ci] = RD_KAFKA_RESP_ERR_UNKNOWN;
        ci++;


        /*
         * Timeout options
         */
        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_ALTERCONFIGS);
        err = rd_kafka_AdminOptions_set_request_timeout(options, 10000, errstr,
                                                        sizeof(errstr));
        TEST_ASSERT(!err, "%s", errstr);


        /*
         * Fire off request
         */
        rd_kafka_AlterConfigs(rk, configs, ci, options, rkqu);

        rd_kafka_AdminOptions_destroy(options);

        /*
         * Wait for result
         */
        rkev = test_wait_admin_result(rkqu, RD_KAFKA_EVENT_ALTERCONFIGS_RESULT,
                                      10000+1000);

        /*
         * Extract result
         */
        res = rd_kafka_event_AlterConfigs_result(rkev);
        TEST_ASSERT(res, "Expected AlterConfigs result, not %s",
                    rd_kafka_event_name(rkev));

        err = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err,
                    "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        rconfigs = rd_kafka_AlterConfigs_result_resources(res, &rconfig_cnt);
        TEST_ASSERT((int)rconfig_cnt == ci,
                    "Expected %d result resources, got %"PRIusz"\n",
                    ci, rconfig_cnt);

        /*
         * Verify status per resource
         */
        for (i = 0 ; i < (int)rconfig_cnt ; i++) {
                const rd_kafka_ConfigEntry_t **entries;
                size_t entry_cnt;

                err = rd_kafka_ConfigResource_error(rconfigs[i]);
                errstr2 = rd_kafka_ConfigResource_error_string(rconfigs[i]);

                entries = rd_kafka_ConfigResource_configs(rconfigs[i],
                                                          &entry_cnt);

                TEST_SAY("ConfigResource #%d: type %s (%d), \"%s\": "
                         "%"PRIusz" ConfigEntries, error %s (%s)\n",
                         i,
                         rd_kafka_ResourceType_name(
                                 rd_kafka_ConfigResource_type(rconfigs[i])),
                         rd_kafka_ConfigResource_type(rconfigs[i]),
                         rd_kafka_ConfigResource_name(rconfigs[i]),
                         entry_cnt,
                         rd_kafka_err2name(err), errstr2 ? errstr2 : "");

                test_print_ConfigEntry_array(entries, entry_cnt, 1);

                if (rd_kafka_ConfigResource_type(rconfigs[i]) !=
                    rd_kafka_ConfigResource_type(configs[i]) ||
                    strcmp(rd_kafka_ConfigResource_name(rconfigs[i]),
                           rd_kafka_ConfigResource_name(configs[i]))) {
                        TEST_FAIL_LATER(
                                "ConfigResource #%d: "
                                "expected type %s name %s, "
                                "got type %s name %s",
                                i,
                                rd_kafka_ResourceType_name(rd_kafka_ConfigResource_type(configs[i])),
                                rd_kafka_ConfigResource_name(configs[i]),
                                rd_kafka_ResourceType_name(rd_kafka_ConfigResource_type(rconfigs[i])),
                                rd_kafka_ConfigResource_name(rconfigs[i]));
                        fails++;
                        continue;
                }


                if (err != exp_err[i]) {
                        TEST_FAIL_LATER("ConfigResource #%d: "
                                        "expected %s (%d), got %s (%s)",
                                        i,
                                        rd_kafka_err2name(exp_err[i]),
                                        exp_err[i],
                                        rd_kafka_err2name(err),
                                        errstr2 ? errstr2 : "");
                        fails++;
                }
        }

        TEST_ASSERT(!fails, "See %d previous failure(s)", fails);

        rd_kafka_event_destroy(rkev);

        rd_kafka_ConfigResource_destroy_array(configs, ci);

#undef MY_CONFRES_CNT
}



/**
 * @brief Test DescribeConfigs
 */
static void do_test_DescribeConfigs (rd_kafka_t *rk, rd_kafka_queue_t *rkqu) {
#define MY_CONFRES_CNT 3
        char *topics[MY_CONFRES_CNT];
        rd_kafka_ConfigResource_t *configs[MY_CONFRES_CNT];
        rd_kafka_AdminOptions_t *options;
        rd_kafka_resp_err_t exp_err[MY_CONFRES_CNT];
        rd_kafka_event_t *rkev;
        rd_kafka_resp_err_t err;
        const rd_kafka_DescribeConfigs_result_t *res;
        const rd_kafka_ConfigResource_t **rconfigs;
        size_t rconfig_cnt;
        char errstr[128];
        const char *errstr2;
        int ci = 0;
        int i;
        int fails = 0;
        int max_retry_describe = 3;

        /*
         * Only create one topic, the others will be non-existent.
         */
        rd_strdupa(&topics[0], test_mk_topic_name("DescribeConfigs_exist", 1));
        for (i = 1 ; i < MY_CONFRES_CNT ; i++)
                rd_strdupa(&topics[i],
                           test_mk_topic_name("DescribeConfigs_notexist", 1));

        test_CreateTopics_simple(rk, NULL, topics, 1, 1, NULL);

        /*
         * ConfigResource #0: topic config, no config entries.
         */
        configs[ci] = rd_kafka_ConfigResource_new(
                RD_KAFKA_RESOURCE_TOPIC, topics[ci]);
        exp_err[ci] = RD_KAFKA_RESP_ERR_NO_ERROR;
        ci++;

        /*
         * ConfigResource #1:broker config, no config entries
         */
        configs[ci] = rd_kafka_ConfigResource_new(
                RD_KAFKA_RESOURCE_BROKER,
                tsprintf("%"PRId32, avail_brokers[0]));

        exp_err[ci] = RD_KAFKA_RESP_ERR_NO_ERROR;
        ci++;

        /*
         * ConfigResource #2: topic config, non-existent topic, no config entr.
         */
        configs[ci] = rd_kafka_ConfigResource_new(
                RD_KAFKA_RESOURCE_TOPIC, topics[ci]);
        /* FIXME: This is a bug in the broker (<v2.0.0), it returns a full response
         *        for unknown topics.
         *        https://issues.apache.org/jira/browse/KAFKA-6778
         */
        if (test_broker_version < TEST_BRKVER(2,0,0,0))
                exp_err[ci] = RD_KAFKA_RESP_ERR_NO_ERROR;
        else
                exp_err[ci] = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
        ci++;


 retry_describe:
        /*
         * Timeout options
         */
        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_ANY);
        err = rd_kafka_AdminOptions_set_request_timeout(options, 10000, errstr,
                                                        sizeof(errstr));
        TEST_ASSERT(!err, "%s", errstr);


        /*
         * Fire off request
         */
        rd_kafka_DescribeConfigs(rk, configs, ci, options, rkqu);

        rd_kafka_AdminOptions_destroy(options);

        /*
         * Wait for result
         */
        rkev = test_wait_admin_result(rkqu,
                                      RD_KAFKA_EVENT_DESCRIBECONFIGS_RESULT,
                                      10000+1000);

        /*
         * Extract result
         */
        res = rd_kafka_event_DescribeConfigs_result(rkev);
        TEST_ASSERT(res, "Expected DescribeConfigs result, not %s",
                    rd_kafka_event_name(rkev));

        err = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err,
                    "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        rconfigs = rd_kafka_DescribeConfigs_result_resources(res, &rconfig_cnt);
        TEST_ASSERT((int)rconfig_cnt == ci,
                    "Expected %d result resources, got %"PRIusz"\n",
                    ci, rconfig_cnt);

        /*
         * Verify status per resource
         */
        for (i = 0 ; i < (int)rconfig_cnt ; i++) {
                const rd_kafka_ConfigEntry_t **entries;
                size_t entry_cnt;

                err = rd_kafka_ConfigResource_error(rconfigs[i]);
                errstr2 = rd_kafka_ConfigResource_error_string(rconfigs[i]);

                entries = rd_kafka_ConfigResource_configs(rconfigs[i],
                                                          &entry_cnt);

                TEST_SAY("ConfigResource #%d: type %s (%d), \"%s\": "
                         "%"PRIusz" ConfigEntries, error %s (%s)\n",
                         i,
                         rd_kafka_ResourceType_name(
                                 rd_kafka_ConfigResource_type(rconfigs[i])),
                         rd_kafka_ConfigResource_type(rconfigs[i]),
                         rd_kafka_ConfigResource_name(rconfigs[i]),
                         entry_cnt,
                         rd_kafka_err2name(err), errstr2 ? errstr2 : "");

                test_print_ConfigEntry_array(entries, entry_cnt, 1);

                if (rd_kafka_ConfigResource_type(rconfigs[i]) !=
                    rd_kafka_ConfigResource_type(configs[i]) ||
                    strcmp(rd_kafka_ConfigResource_name(rconfigs[i]),
                           rd_kafka_ConfigResource_name(configs[i]))) {
                        TEST_FAIL_LATER(
                                "ConfigResource #%d: "
                                "expected type %s name %s, "
                                "got type %s name %s",
                                i,
                                rd_kafka_ResourceType_name(rd_kafka_ConfigResource_type(configs[i])),
                                rd_kafka_ConfigResource_name(configs[i]),
                                rd_kafka_ResourceType_name(rd_kafka_ConfigResource_type(rconfigs[i])),
                                rd_kafka_ConfigResource_name(rconfigs[i]));
                        fails++;
                        continue;
                }


                if (err != exp_err[i]) {
                        if (err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART &&
                            max_retry_describe-- > 0) {
                                TEST_WARN("ConfigResource #%d: "
                                          "expected %s (%d), got %s (%s): "
                                          "this is typically a temporary "
                                          "error while the new resource "
                                          "is propagating: retrying",
                                          i,
                                          rd_kafka_err2name(exp_err[i]),
                                          exp_err[i],
                                          rd_kafka_err2name(err),
                                          errstr2 ? errstr2 : "");
                                rd_kafka_event_destroy(rkev);
                                rd_sleep(1);
                                goto retry_describe;
                        }

                        TEST_FAIL_LATER("ConfigResource #%d: "
                                        "expected %s (%d), got %s (%s)",
                                        i,
                                        rd_kafka_err2name(exp_err[i]),
                                        exp_err[i],
                                        rd_kafka_err2name(err),
                                        errstr2 ? errstr2 : "");
                        fails++;
                }
        }

        TEST_ASSERT(!fails, "See %d previous failure(s)", fails);

        rd_kafka_event_destroy(rkev);

        rd_kafka_ConfigResource_destroy_array(configs, ci);

#undef MY_CONFRES_CNT
}



/**
 * @brief Verify that an unclean rd_kafka_destroy() does not hang.
 */
static void do_test_unclean_destroy (rd_kafka_type_t cltype, int with_mainq) {
        rd_kafka_t *rk;
        char errstr[512];
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *q;
        rd_kafka_NewTopic_t *topic;
        test_timing_t t_destroy;

        test_conf_init(&conf, NULL, 0);

        rk = rd_kafka_new(cltype, conf, errstr, sizeof(errstr));
        TEST_ASSERT(rk, "kafka_new(%d): %s", cltype, errstr);

        TEST_SAY(_C_MAG "[ Test unclean destroy for %s using %s]\n", rd_kafka_name(rk),
                 with_mainq ? "mainq" : "tempq");

        if (with_mainq)
                q = rd_kafka_queue_get_main(rk);
        else
                q = rd_kafka_queue_new(rk);

        topic = rd_kafka_NewTopic_new(test_mk_topic_name(__FUNCTION__, 1),
                                      3, 1, NULL, 0);
        rd_kafka_CreateTopics(rk, &topic, 1, NULL, q);
        rd_kafka_NewTopic_destroy(topic);

        rd_kafka_queue_destroy(q);

        TEST_SAY("Giving rd_kafka_destroy() 5s to finish, "
                 "despite Admin API request being processed\n");
        test_timeout_set(5);
        TIMING_START(&t_destroy, "rd_kafka_destroy()");
        rd_kafka_destroy(rk);
        TIMING_STOP(&t_destroy);

        /* Restore timeout */
        test_timeout_set(60);;
}



static void do_test_apis (rd_kafka_type_t cltype) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *mainq;

        /* Get the available brokers, but use a separate rd_kafka_t instance
         * so we don't jinx the tests by having up-to-date metadata. */
        avail_brokers = test_get_broker_ids(NULL, &avail_broker_cnt);
        TEST_SAY("%"PRIusz" brokers in cluster "
                 "which will be used for replica sets\n",
                 avail_broker_cnt);

        do_test_unclean_destroy(cltype, 0/*tempq*/);
        do_test_unclean_destroy(cltype, 1/*mainq*/);

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "socket.timeout.ms", "10000");
        rk = test_create_handle(cltype, conf);

        mainq = rd_kafka_queue_get_main(rk);

        /* Create topics */
        do_test_CreateTopics("temp queue, op timeout 0",
                             rk, NULL, 0, 0);
        do_test_CreateTopics("temp queue, op timeout 15000",
                             rk, NULL, 15000, 0);
        do_test_CreateTopics("temp queue, op timeout 300, "
                             "validate only",
                             rk, NULL, 300, rd_true);
        do_test_CreateTopics("temp queue, op timeout 9000, validate_only",
                             rk, NULL, 9000, rd_true);
        do_test_CreateTopics("main queue, options", rk, mainq, -1, 0);

        /* Delete topics */
        do_test_DeleteTopics("temp queue, op timeout 0", rk, NULL, 0);
        do_test_DeleteTopics("main queue, op timeout 15000", rk, mainq, 1500);

        if (test_broker_version >= TEST_BRKVER(1,0,0,0)) {
                /* Create Partitions */
                do_test_CreatePartitions("temp queue, op timeout 6500",
                                         rk, NULL, 6500);
                do_test_CreatePartitions("main queue, op timeout 0",
                                         rk, mainq, 0);
        }

        /* AlterConfigs */
        do_test_AlterConfigs(rk, mainq);

        /* DescribeConfigs */
        do_test_DescribeConfigs(rk, mainq);

        rd_kafka_queue_destroy(mainq);

        rd_kafka_destroy(rk);

        free(avail_brokers);
}


int main_0081_admin (int argc, char **argv) {

        do_test_apis(RD_KAFKA_PRODUCER);

        if (test_quick) {
                TEST_SAY("Skipping further 0081 tests due to quick mode\n");
                return 0;
        }

        do_test_apis(RD_KAFKA_CONSUMER);

        return 0;
}

