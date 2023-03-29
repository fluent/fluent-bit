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



static void do_test_CreateTopics(const char *what,
                                 rd_kafka_t *rk,
                                 rd_kafka_queue_t *useq,
                                 int op_timeout,
                                 rd_bool_t validate_only) {
        rd_kafka_queue_t *q;
#define MY_NEW_TOPICS_CNT 7
        char *topics[MY_NEW_TOPICS_CNT];
        rd_kafka_NewTopic_t *new_topics[MY_NEW_TOPICS_CNT];
        rd_kafka_AdminOptions_t *options                    = NULL;
        rd_kafka_resp_err_t exp_topicerr[MY_NEW_TOPICS_CNT] = {0};
        rd_kafka_resp_err_t exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        /* Expected topics in metadata */
        rd_kafka_metadata_topic_t exp_mdtopics[MY_NEW_TOPICS_CNT] = {{0}};
        int exp_mdtopic_cnt                                       = 0;
        /* Not expected topics in metadata */
        rd_kafka_metadata_topic_t exp_not_mdtopics[MY_NEW_TOPICS_CNT] = {{0}};
        int exp_not_mdtopic_cnt                                       = 0;
        int i;
        char errstr[512];
        const char *errstr2;
        rd_kafka_resp_err_t err;
        test_timing_t timing;
        rd_kafka_event_t *rkev;
        const rd_kafka_CreateTopics_result_t *res;
        const rd_kafka_topic_result_t **restopics;
        size_t restopic_cnt;
        int metadata_tmout;
        int num_replicas = (int)avail_broker_cnt;
        int32_t *replicas;

        SUB_TEST_QUICK(
            "%s CreateTopics with %s, "
            "op_timeout %d, validate_only %d",
            rd_kafka_name(rk), what, op_timeout, validate_only);

        q = useq ? useq : rd_kafka_queue_new(rk);

        /* Set up replicas */
        replicas = rd_alloca(sizeof(*replicas) * num_replicas);
        for (i = 0; i < num_replicas; i++)
                replicas[i] = avail_brokers[i];

        /**
         * Construct NewTopic array with different properties for
         * different partitions.
         */
        for (i = 0; i < MY_NEW_TOPICS_CNT; i++) {
                char *topic = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
                int use_defaults =
                    i == 6 && test_broker_version >= TEST_BRKVER(2, 4, 0, 0);
                int num_parts          = !use_defaults ? (i * 7 + 1) : -1;
                int set_config         = (i & 1);
                int add_invalid_config = (i == 1);
                int set_replicas       = !use_defaults && !(i % 3);
                rd_kafka_resp_err_t this_exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;

                topics[i]     = topic;
                new_topics[i] = rd_kafka_NewTopic_new(
                    topic, num_parts, set_replicas ? -1 : num_replicas, NULL,
                    0);

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
                            new_topics[i], "dummy.doesntexist",
                            "broker is verifying this");
                        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
                        this_exp_err = RD_KAFKA_RESP_ERR_INVALID_CONFIG;
                }

                TEST_SAY(
                    "Expecting result for topic #%d: %s "
                    "(set_config=%d, add_invalid_config=%d, "
                    "set_replicas=%d, use_defaults=%d)\n",
                    i, rd_kafka_err2name(this_exp_err), set_config,
                    add_invalid_config, set_replicas, use_defaults);

                if (set_replicas) {
                        int32_t p;

                        /*
                         * Set valid replica assignments
                         */
                        for (p = 0; p < num_parts; p++) {
                                err = rd_kafka_NewTopic_set_replica_assignment(
                                    new_topics[i], p, replicas, num_replicas,
                                    errstr, sizeof(errstr));
                                TEST_ASSERT(!err, "%s", errstr);
                        }
                }

                if (this_exp_err || validate_only) {
                        exp_topicerr[i] = this_exp_err;
                        exp_not_mdtopics[exp_not_mdtopic_cnt++].topic = topic;

                } else {
                        exp_mdtopics[exp_mdtopic_cnt].topic         = topic;
                        exp_mdtopics[exp_mdtopic_cnt].partition_cnt = num_parts;
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
        rd_kafka_CreateTopics(rk, new_topics, MY_NEW_TOPICS_CNT, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /* Poll result queue for CreateTopics result.
         * Print but otherwise ignore other event types
         * (typically generic Error events). */
        TIMING_START(&timing, "CreateTopics.queue_poll");
        do {
                rkev = rd_kafka_queue_poll(q, tmout_multip(20 * 1000));
                TEST_SAY("CreateTopics: got %s in %.3fms\n",
                         rd_kafka_event_name(rkev),
                         TIMING_DURATION(&timing) / 1000.0f);
                if (rd_kafka_event_error(rkev))
                        TEST_SAY("%s: %s\n", rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));
        } while (rd_kafka_event_type(rkev) !=
                 RD_KAFKA_EVENT_CREATETOPICS_RESULT);

        /* Convert event to proper result */
        res = rd_kafka_event_CreateTopics_result(rkev);
        TEST_ASSERT(res, "expected CreateTopics_result, not %s",
                    rd_kafka_event_name(rkev));

        /* Expecting error */
        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(err == exp_err,
                    "expected CreateTopics to return %s, not %s (%s)",
                    rd_kafka_err2str(exp_err), rd_kafka_err2str(err),
                    err ? errstr2 : "n/a");

        TEST_SAY("CreateTopics: returned %s (%s)\n", rd_kafka_err2str(err),
                 err ? errstr2 : "n/a");

        /* Extract topics */
        restopics = rd_kafka_CreateTopics_result_topics(res, &restopic_cnt);


        /* Scan topics for proper fields and expected failures. */
        for (i = 0; i < (int)restopic_cnt; i++) {
                const rd_kafka_topic_result_t *terr = restopics[i];

                /* Verify that topic order matches our request. */
                if (strcmp(rd_kafka_topic_result_name(terr), topics[i]))
                        TEST_FAIL_LATER(
                            "Topic result order mismatch at #%d: "
                            "expected %s, got %s",
                            i, topics[i], rd_kafka_topic_result_name(terr));

                TEST_SAY("CreateTopics result: #%d: %s: %s: %s\n", i,
                         rd_kafka_topic_result_name(terr),
                         rd_kafka_err2name(rd_kafka_topic_result_error(terr)),
                         rd_kafka_topic_result_error_string(terr));
                if (rd_kafka_topic_result_error(terr) != exp_topicerr[i])
                        TEST_FAIL_LATER("Expected %s, not %d: %s",
                                        rd_kafka_err2name(exp_topicerr[i]),
                                        rd_kafka_topic_result_error(terr),
                                        rd_kafka_err2name(
                                            rd_kafka_topic_result_error(terr)));
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

        test_wait_metadata_update(rk, exp_mdtopics, exp_mdtopic_cnt,
                                  exp_not_mdtopics, exp_not_mdtopic_cnt,
                                  metadata_tmout);

        rd_kafka_event_destroy(rkev);

        for (i = 0; i < MY_NEW_TOPICS_CNT; i++) {
                rd_kafka_NewTopic_destroy(new_topics[i]);
                rd_free(topics[i]);
        }

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

        TEST_LATER_CHECK();
#undef MY_NEW_TOPICS_CNT

        SUB_TEST_PASS();
}



/**
 * @brief Test deletion of topics
 *
 *
 */
static void do_test_DeleteTopics(const char *what,
                                 rd_kafka_t *rk,
                                 rd_kafka_queue_t *useq,
                                 int op_timeout) {
        rd_kafka_queue_t *q;
        const int skip_topic_cnt = 2;
#define MY_DEL_TOPICS_CNT 9
        char *topics[MY_DEL_TOPICS_CNT];
        rd_kafka_DeleteTopic_t *del_topics[MY_DEL_TOPICS_CNT];
        rd_kafka_AdminOptions_t *options                    = NULL;
        rd_kafka_resp_err_t exp_topicerr[MY_DEL_TOPICS_CNT] = {0};
        rd_kafka_resp_err_t exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        /* Expected topics in metadata */
        rd_kafka_metadata_topic_t exp_mdtopics[MY_DEL_TOPICS_CNT] = {{0}};
        int exp_mdtopic_cnt                                       = 0;
        /* Not expected topics in metadata */
        rd_kafka_metadata_topic_t exp_not_mdtopics[MY_DEL_TOPICS_CNT] = {{0}};
        int exp_not_mdtopic_cnt                                       = 0;
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

        SUB_TEST_QUICK("%s DeleteTopics with %s, op_timeout %d",
                       rd_kafka_name(rk), what, op_timeout);

        q = useq ? useq : rd_kafka_queue_new(rk);

        /**
         * Construct DeleteTopic array
         */
        for (i = 0; i < MY_DEL_TOPICS_CNT; i++) {
                char *topic = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
                int notexist_topic = i >= MY_DEL_TOPICS_CNT - skip_topic_cnt;

                topics[i] = topic;

                del_topics[i] = rd_kafka_DeleteTopic_new(topic);

                if (notexist_topic)
                        exp_topicerr[i] =
                            RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
                else {
                        exp_topicerr[i] = RD_KAFKA_RESP_ERR_NO_ERROR;

                        exp_mdtopics[exp_mdtopic_cnt++].topic = topic;
                }

                exp_not_mdtopics[exp_not_mdtopic_cnt++].topic = topic;
        }

        if (op_timeout != -1) {
                options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_ANY);

                err = rd_kafka_AdminOptions_set_operation_timeout(
                    options, op_timeout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        }


        /* Create the topics first, minus the skip count. */
        test_CreateTopics_simple(rk, NULL, topics,
                                 MY_DEL_TOPICS_CNT - skip_topic_cnt,
                                 2 /*num_partitions*/, NULL);

        /* Verify that topics are reported by metadata */
        test_wait_metadata_update(rk, exp_mdtopics, exp_mdtopic_cnt, NULL, 0,
                                  15 * 1000);

        TIMING_START(&timing, "DeleteTopics");
        TEST_SAY("Call DeleteTopics\n");
        rd_kafka_DeleteTopics(rk, del_topics, MY_DEL_TOPICS_CNT, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /* Poll result queue for DeleteTopics result.
         * Print but otherwise ignore other event types
         * (typically generic Error events). */
        TIMING_START(&timing, "DeleteTopics.queue_poll");
        while (1) {
                rkev = rd_kafka_queue_poll(q, tmout_multip(20 * 1000));
                TEST_SAY("DeleteTopics: got %s in %.3fms\n",
                         rd_kafka_event_name(rkev),
                         TIMING_DURATION(&timing) / 1000.0f);
                if (rd_kafka_event_error(rkev))
                        TEST_SAY("%s: %s\n", rd_kafka_event_name(rkev),
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
        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(err == exp_err,
                    "expected DeleteTopics to return %s, not %s (%s)",
                    rd_kafka_err2str(exp_err), rd_kafka_err2str(err),
                    err ? errstr2 : "n/a");

        TEST_SAY("DeleteTopics: returned %s (%s)\n", rd_kafka_err2str(err),
                 err ? errstr2 : "n/a");

        /* Extract topics */
        restopics = rd_kafka_DeleteTopics_result_topics(res, &restopic_cnt);


        /* Scan topics for proper fields and expected failures. */
        for (i = 0; i < (int)restopic_cnt; i++) {
                const rd_kafka_topic_result_t *terr = restopics[i];

                /* Verify that topic order matches our request. */
                if (strcmp(rd_kafka_topic_result_name(terr), topics[i]))
                        TEST_FAIL_LATER(
                            "Topic result order mismatch at #%d: "
                            "expected %s, got %s",
                            i, topics[i], rd_kafka_topic_result_name(terr));

                TEST_SAY("DeleteTopics result: #%d: %s: %s: %s\n", i,
                         rd_kafka_topic_result_name(terr),
                         rd_kafka_err2name(rd_kafka_topic_result_error(terr)),
                         rd_kafka_topic_result_error_string(terr));
                if (rd_kafka_topic_result_error(terr) != exp_topicerr[i])
                        TEST_FAIL_LATER("Expected %s, not %d: %s",
                                        rd_kafka_err2name(exp_topicerr[i]),
                                        rd_kafka_topic_result_error(terr),
                                        rd_kafka_err2name(
                                            rd_kafka_topic_result_error(terr)));
        }

        /**
         * Verify that the expected topics are deleted and the non-expected
         * are not. Allow it some time to propagate.
         */
        if (op_timeout > 0)
                metadata_tmout = op_timeout + 1000;
        else
                metadata_tmout = 10 * 1000;

        test_wait_metadata_update(rk, NULL, 0, exp_not_mdtopics,
                                  exp_not_mdtopic_cnt, metadata_tmout);

        rd_kafka_event_destroy(rkev);

        for (i = 0; i < MY_DEL_TOPICS_CNT; i++) {
                rd_kafka_DeleteTopic_destroy(del_topics[i]);
                rd_free(topics[i]);
        }

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

        TEST_LATER_CHECK();
#undef MY_DEL_TOPICS_CNT

        SUB_TEST_PASS();
}



/**
 * @brief Test creation of partitions
 *
 *
 */
static void do_test_CreatePartitions(const char *what,
                                     rd_kafka_t *rk,
                                     rd_kafka_queue_t *useq,
                                     int op_timeout) {
        rd_kafka_queue_t *q;
#define MY_CRP_TOPICS_CNT 9
        char *topics[MY_CRP_TOPICS_CNT];
        rd_kafka_NewTopic_t *new_topics[MY_CRP_TOPICS_CNT];
        rd_kafka_NewPartitions_t *crp_topics[MY_CRP_TOPICS_CNT];
        rd_kafka_AdminOptions_t *options = NULL;
        /* Expected topics in metadata */
        rd_kafka_metadata_topic_t exp_mdtopics[MY_CRP_TOPICS_CNT] = {{0}};
        rd_kafka_metadata_partition_t exp_mdparts[2]              = {{0}};
        int exp_mdtopic_cnt                                       = 0;
        int i;
        char errstr[512];
        rd_kafka_resp_err_t err;
        test_timing_t timing;
        int metadata_tmout;
        int num_replicas = (int)avail_broker_cnt;

        SUB_TEST_QUICK("%s CreatePartitions with %s, op_timeout %d",
                       rd_kafka_name(rk), what, op_timeout);

        q = useq ? useq : rd_kafka_queue_new(rk);

        /* Set up two expected partitions with different replication sets
         * so they can be matched by the metadata checker later.
         * Even partitions use exp_mdparts[0] while odd partitions
         * use exp_mdparts[1]. */

        /* Set valid replica assignments (even, and odd (reverse) ) */
        exp_mdparts[0].replicas =
            rd_alloca(sizeof(*exp_mdparts[0].replicas) * num_replicas);
        exp_mdparts[1].replicas =
            rd_alloca(sizeof(*exp_mdparts[1].replicas) * num_replicas);
        exp_mdparts[0].replica_cnt = num_replicas;
        exp_mdparts[1].replica_cnt = num_replicas;
        for (i = 0; i < num_replicas; i++) {
                exp_mdparts[0].replicas[i] = avail_brokers[i];
                exp_mdparts[1].replicas[i] =
                    avail_brokers[num_replicas - i - 1];
        }

        /**
         * Construct CreatePartitions array
         */
        for (i = 0; i < MY_CRP_TOPICS_CNT; i++) {
                char *topic = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
                int initial_part_cnt = 1 + (i * 2);
                int new_part_cnt     = 1 + (i / 2);
                int final_part_cnt   = initial_part_cnt + new_part_cnt;
                int set_replicas     = !(i % 2);
                int pi;

                topics[i] = topic;

                /* Topic to create with initial partition count */
                new_topics[i] = rd_kafka_NewTopic_new(
                    topic, initial_part_cnt, set_replicas ? -1 : num_replicas,
                    NULL, 0);

                /* .. and later add more partitions to */
                crp_topics[i] = rd_kafka_NewPartitions_new(
                    topic, final_part_cnt, errstr, sizeof(errstr));

                if (set_replicas) {
                        exp_mdtopics[exp_mdtopic_cnt].partitions = rd_alloca(
                            final_part_cnt *
                            sizeof(*exp_mdtopics[exp_mdtopic_cnt].partitions));

                        for (pi = 0; pi < final_part_cnt; pi++) {
                                const rd_kafka_metadata_partition_t *exp_mdp =
                                    &exp_mdparts[pi & 1];

                                exp_mdtopics[exp_mdtopic_cnt].partitions[pi] =
                                    *exp_mdp; /* copy */

                                exp_mdtopics[exp_mdtopic_cnt]
                                    .partitions[pi]
                                    .id = pi;

                                if (pi < initial_part_cnt) {
                                        /* Set replica assignment
                                         * for initial partitions */
                                        err =
                                            rd_kafka_NewTopic_set_replica_assignment(
                                                new_topics[i], pi,
                                                exp_mdp->replicas,
                                                (size_t)exp_mdp->replica_cnt,
                                                errstr, sizeof(errstr));
                                        TEST_ASSERT(!err,
                                                    "NewTopic_set_replica_"
                                                    "assignment: %s",
                                                    errstr);
                                } else {
                                        /* Set replica assignment for new
                                         * partitions */
                                        err =
                                            rd_kafka_NewPartitions_set_replica_assignment(
                                                crp_topics[i],
                                                pi - initial_part_cnt,
                                                exp_mdp->replicas,
                                                (size_t)exp_mdp->replica_cnt,
                                                errstr, sizeof(errstr));
                                        TEST_ASSERT(!err,
                                                    "NewPartitions_set_replica_"
                                                    "assignment: %s",
                                                    errstr);
                                }
                        }
                }

                TEST_SAY(_C_YEL
                         "Topic %s with %d initial partitions will grow "
                         "by %d to %d total partitions with%s replicas set\n",
                         topics[i], initial_part_cnt, new_part_cnt,
                         final_part_cnt, set_replicas ? "" : "out");

                exp_mdtopics[exp_mdtopic_cnt].topic         = topic;
                exp_mdtopics[exp_mdtopic_cnt].partition_cnt = final_part_cnt;

                exp_mdtopic_cnt++;
        }

        if (op_timeout != -1) {
                options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_ANY);

                err = rd_kafka_AdminOptions_set_operation_timeout(
                    options, op_timeout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        }

        /*
         * Create topics with initial partition count
         */
        TIMING_START(&timing, "CreateTopics");
        TEST_SAY("Creating topics with initial partition counts\n");
        rd_kafka_CreateTopics(rk, new_topics, MY_CRP_TOPICS_CNT, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        err = test_wait_topic_admin_result(
            q, RD_KAFKA_EVENT_CREATETOPICS_RESULT, NULL, 15000);
        TEST_ASSERT(!err, "CreateTopics failed: %s", rd_kafka_err2str(err));

        rd_kafka_NewTopic_destroy_array(new_topics, MY_CRP_TOPICS_CNT);


        /*
         * Create new partitions
         */
        TIMING_START(&timing, "CreatePartitions");
        TEST_SAY("Creating partitions\n");
        rd_kafka_CreatePartitions(rk, crp_topics, MY_CRP_TOPICS_CNT, options,
                                  q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        err = test_wait_topic_admin_result(
            q, RD_KAFKA_EVENT_CREATEPARTITIONS_RESULT, NULL, 15000);
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

        test_wait_metadata_update(rk, exp_mdtopics, exp_mdtopic_cnt, NULL, 0,
                                  metadata_tmout);

        for (i = 0; i < MY_CRP_TOPICS_CNT; i++)
                rd_free(topics[i]);

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

        TEST_LATER_CHECK();
#undef MY_CRP_TOPICS_CNT

        SUB_TEST_PASS();
}



/**
 * @brief Print the ConfigEntrys in the provided array.
 */
static void test_print_ConfigEntry_array(const rd_kafka_ConfigEntry_t **entries,
                                         size_t entry_cnt,
                                         unsigned int depth) {
        const char *indent = &"    "[4 - (depth > 4 ? 4 : depth)];
        size_t ei;

        for (ei = 0; ei < entry_cnt; ei++) {
                const rd_kafka_ConfigEntry_t *e = entries[ei];
                const rd_kafka_ConfigEntry_t **syns;
                size_t syn_cnt;

                syns = rd_kafka_ConfigEntry_synonyms(e, &syn_cnt);

#define YN(v) ((v) ? "y" : "n")
                TEST_SAYL(
                    3,
                    "%s#%" PRIusz "/%" PRIusz
                    ": Source %s (%d): \"%s\"=\"%s\" "
                    "[is read-only=%s, default=%s, sensitive=%s, "
                    "synonym=%s] with %" PRIusz " synonym(s)\n",
                    indent, ei, entry_cnt,
                    rd_kafka_ConfigSource_name(rd_kafka_ConfigEntry_source(e)),
                    rd_kafka_ConfigEntry_source(e),
                    rd_kafka_ConfigEntry_name(e),
                    rd_kafka_ConfigEntry_value(e)
                        ? rd_kafka_ConfigEntry_value(e)
                        : "(NULL)",
                    YN(rd_kafka_ConfigEntry_is_read_only(e)),
                    YN(rd_kafka_ConfigEntry_is_default(e)),
                    YN(rd_kafka_ConfigEntry_is_sensitive(e)),
                    YN(rd_kafka_ConfigEntry_is_synonym(e)), syn_cnt);
#undef YN

                if (syn_cnt > 0)
                        test_print_ConfigEntry_array(syns, syn_cnt, depth + 1);
        }
}


/**
 * @brief Test AlterConfigs
 */
static void do_test_AlterConfigs(rd_kafka_t *rk, rd_kafka_queue_t *rkqu) {
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

        SUB_TEST_QUICK();

        /*
         * Only create one topic, the others will be non-existent.
         */
        for (i = 0; i < MY_CONFRES_CNT; i++)
                rd_strdupa(&topics[i], test_mk_topic_name(__FUNCTION__, 1));

        test_CreateTopics_simple(rk, NULL, topics, 1, 1, NULL);

        test_wait_topic_exists(rk, topics[0], 10000);

        /*
         * ConfigResource #0: valid topic config
         */
        configs[ci] =
            rd_kafka_ConfigResource_new(RD_KAFKA_RESOURCE_TOPIC, topics[ci]);

        err = rd_kafka_ConfigResource_set_config(configs[ci],
                                                 "compression.type", "gzip");
        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

        err = rd_kafka_ConfigResource_set_config(configs[ci], "flush.ms",
                                                 "12345678");
        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

        exp_err[ci] = RD_KAFKA_RESP_ERR_NO_ERROR;
        ci++;


        if (test_broker_version >= TEST_BRKVER(1, 1, 0, 0)) {
                /*
                 * ConfigResource #1: valid broker config
                 */
                configs[ci] = rd_kafka_ConfigResource_new(
                    RD_KAFKA_RESOURCE_BROKER,
                    tsprintf("%" PRId32, avail_brokers[0]));

                err = rd_kafka_ConfigResource_set_config(
                    configs[ci], "sasl.kerberos.min.time.before.relogin",
                    "58000");
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

                exp_err[ci] = RD_KAFKA_RESP_ERR_NO_ERROR;
                ci++;
        } else {
                TEST_WARN(
                    "Skipping RESOURCE_BROKER test on unsupported "
                    "broker version\n");
        }

        /*
         * ConfigResource #2: valid topic config, non-existent topic
         */
        configs[ci] =
            rd_kafka_ConfigResource_new(RD_KAFKA_RESOURCE_TOPIC, topics[ci]);

        err = rd_kafka_ConfigResource_set_config(configs[ci],
                                                 "compression.type", "lz4");
        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

        err = rd_kafka_ConfigResource_set_config(
            configs[ci], "offset.metadata.max.bytes", "12345");
        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));

        if (test_broker_version >= TEST_BRKVER(2, 7, 0, 0))
                exp_err[ci] = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
        else
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
                                      10000 + 1000);

        /*
         * Extract result
         */
        res = rd_kafka_event_AlterConfigs_result(rkev);
        TEST_ASSERT(res, "Expected AlterConfigs result, not %s",
                    rd_kafka_event_name(rkev));

        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err, "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        rconfigs = rd_kafka_AlterConfigs_result_resources(res, &rconfig_cnt);
        TEST_ASSERT((int)rconfig_cnt == ci,
                    "Expected %d result resources, got %" PRIusz "\n", ci,
                    rconfig_cnt);

        /*
         * Verify status per resource
         */
        for (i = 0; i < (int)rconfig_cnt; i++) {
                const rd_kafka_ConfigEntry_t **entries;
                size_t entry_cnt;

                err     = rd_kafka_ConfigResource_error(rconfigs[i]);
                errstr2 = rd_kafka_ConfigResource_error_string(rconfigs[i]);

                entries =
                    rd_kafka_ConfigResource_configs(rconfigs[i], &entry_cnt);

                TEST_SAY(
                    "ConfigResource #%d: type %s (%d), \"%s\": "
                    "%" PRIusz " ConfigEntries, error %s (%s)\n",
                    i,
                    rd_kafka_ResourceType_name(
                        rd_kafka_ConfigResource_type(rconfigs[i])),
                    rd_kafka_ConfigResource_type(rconfigs[i]),
                    rd_kafka_ConfigResource_name(rconfigs[i]), entry_cnt,
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
                            rd_kafka_ResourceType_name(
                                rd_kafka_ConfigResource_type(configs[i])),
                            rd_kafka_ConfigResource_name(configs[i]),
                            rd_kafka_ResourceType_name(
                                rd_kafka_ConfigResource_type(rconfigs[i])),
                            rd_kafka_ConfigResource_name(rconfigs[i]));
                        fails++;
                        continue;
                }


                if (err != exp_err[i]) {
                        TEST_FAIL_LATER(
                            "ConfigResource #%d: "
                            "expected %s (%d), got %s (%s)",
                            i, rd_kafka_err2name(exp_err[i]), exp_err[i],
                            rd_kafka_err2name(err), errstr2 ? errstr2 : "");
                        fails++;
                }
        }

        TEST_ASSERT(!fails, "See %d previous failure(s)", fails);

        rd_kafka_event_destroy(rkev);

        rd_kafka_ConfigResource_destroy_array(configs, ci);

        TEST_LATER_CHECK();
#undef MY_CONFRES_CNT

        SUB_TEST_PASS();
}



/**
 * @brief Test DescribeConfigs
 */
static void do_test_DescribeConfigs(rd_kafka_t *rk, rd_kafka_queue_t *rkqu) {
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
        int fails              = 0;
        int max_retry_describe = 3;

        SUB_TEST_QUICK();

        /*
         * Only create one topic, the others will be non-existent.
         */
        rd_strdupa(&topics[0], test_mk_topic_name("DescribeConfigs_exist", 1));
        for (i = 1; i < MY_CONFRES_CNT; i++)
                rd_strdupa(&topics[i],
                           test_mk_topic_name("DescribeConfigs_notexist", 1));

        test_CreateTopics_simple(rk, NULL, topics, 1, 1, NULL);

        /*
         * ConfigResource #0: topic config, no config entries.
         */
        configs[ci] =
            rd_kafka_ConfigResource_new(RD_KAFKA_RESOURCE_TOPIC, topics[ci]);
        exp_err[ci] = RD_KAFKA_RESP_ERR_NO_ERROR;
        ci++;

        /*
         * ConfigResource #1:broker config, no config entries
         */
        configs[ci] = rd_kafka_ConfigResource_new(
            RD_KAFKA_RESOURCE_BROKER, tsprintf("%" PRId32, avail_brokers[0]));

        exp_err[ci] = RD_KAFKA_RESP_ERR_NO_ERROR;
        ci++;

        /*
         * ConfigResource #2: topic config, non-existent topic, no config entr.
         */
        configs[ci] =
            rd_kafka_ConfigResource_new(RD_KAFKA_RESOURCE_TOPIC, topics[ci]);
        /* FIXME: This is a bug in the broker (<v2.0.0), it returns a full
         * response for unknown topics.
         *        https://issues.apache.org/jira/browse/KAFKA-6778
         */
        if (test_broker_version < TEST_BRKVER(2, 0, 0, 0))
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
        rkev = test_wait_admin_result(
            rkqu, RD_KAFKA_EVENT_DESCRIBECONFIGS_RESULT, 10000 + 1000);

        /*
         * Extract result
         */
        res = rd_kafka_event_DescribeConfigs_result(rkev);
        TEST_ASSERT(res, "Expected DescribeConfigs result, not %s",
                    rd_kafka_event_name(rkev));

        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err, "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        rconfigs = rd_kafka_DescribeConfigs_result_resources(res, &rconfig_cnt);
        TEST_ASSERT((int)rconfig_cnt == ci,
                    "Expected %d result resources, got %" PRIusz "\n", ci,
                    rconfig_cnt);

        /*
         * Verify status per resource
         */
        for (i = 0; i < (int)rconfig_cnt; i++) {
                const rd_kafka_ConfigEntry_t **entries;
                size_t entry_cnt;

                err     = rd_kafka_ConfigResource_error(rconfigs[i]);
                errstr2 = rd_kafka_ConfigResource_error_string(rconfigs[i]);

                entries =
                    rd_kafka_ConfigResource_configs(rconfigs[i], &entry_cnt);

                TEST_SAY(
                    "ConfigResource #%d: type %s (%d), \"%s\": "
                    "%" PRIusz " ConfigEntries, error %s (%s)\n",
                    i,
                    rd_kafka_ResourceType_name(
                        rd_kafka_ConfigResource_type(rconfigs[i])),
                    rd_kafka_ConfigResource_type(rconfigs[i]),
                    rd_kafka_ConfigResource_name(rconfigs[i]), entry_cnt,
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
                            rd_kafka_ResourceType_name(
                                rd_kafka_ConfigResource_type(configs[i])),
                            rd_kafka_ConfigResource_name(configs[i]),
                            rd_kafka_ResourceType_name(
                                rd_kafka_ConfigResource_type(rconfigs[i])),
                            rd_kafka_ConfigResource_name(rconfigs[i]));
                        fails++;
                        continue;
                }


                if (err != exp_err[i]) {
                        if (err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART &&
                            max_retry_describe-- > 0) {
                                TEST_WARN(
                                    "ConfigResource #%d: "
                                    "expected %s (%d), got %s (%s): "
                                    "this is typically a temporary "
                                    "error while the new resource "
                                    "is propagating: retrying",
                                    i, rd_kafka_err2name(exp_err[i]),
                                    exp_err[i], rd_kafka_err2name(err),
                                    errstr2 ? errstr2 : "");
                                rd_kafka_event_destroy(rkev);
                                rd_sleep(1);
                                goto retry_describe;
                        }

                        TEST_FAIL_LATER(
                            "ConfigResource #%d: "
                            "expected %s (%d), got %s (%s)",
                            i, rd_kafka_err2name(exp_err[i]), exp_err[i],
                            rd_kafka_err2name(err), errstr2 ? errstr2 : "");
                        fails++;
                }
        }

        TEST_ASSERT(!fails, "See %d previous failure(s)", fails);

        rd_kafka_event_destroy(rkev);

        rd_kafka_ConfigResource_destroy_array(configs, ci);

        TEST_LATER_CHECK();
#undef MY_CONFRES_CNT

        SUB_TEST_PASS();
}

/**
 * @brief Test CreateAcls
 */
static void
do_test_CreateAcls(rd_kafka_t *rk, rd_kafka_queue_t *useq, int version) {
        rd_kafka_queue_t *q = useq ? useq : rd_kafka_queue_new(rk);
        size_t resacl_cnt;
        test_timing_t timing;
        rd_kafka_resp_err_t err;
        char errstr[128];
        const char *errstr2;
        const char *user_test1 = "User:test1";
        const char *user_test2 = "User:test2";
        const char *base_topic_name;
        char topic1_name[512];
        char topic2_name[512];
        rd_kafka_AclBinding_t *acl_bindings[2];
        rd_kafka_ResourcePatternType_t pattern_type_first_topic =
            RD_KAFKA_RESOURCE_PATTERN_PREFIXED;
        rd_kafka_AdminOptions_t *admin_options;
        rd_kafka_event_t *rkev_acl_create;
        const rd_kafka_CreateAcls_result_t *acl_res;
        const rd_kafka_acl_result_t **acl_res_acls;
        unsigned int i;

        SUB_TEST_QUICK();

        if (version == 0)
                pattern_type_first_topic = RD_KAFKA_RESOURCE_PATTERN_LITERAL;

        base_topic_name = test_mk_topic_name(__FUNCTION__, 1);

        rd_snprintf(topic1_name, sizeof(topic1_name), "%s_1", base_topic_name);
        rd_snprintf(topic2_name, sizeof(topic2_name), "%s_2", base_topic_name);


        acl_bindings[0] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_TOPIC, topic1_name, pattern_type_first_topic,
            user_test1, "*", RD_KAFKA_ACL_OPERATION_READ,
            RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW, NULL, 0);
        acl_bindings[1] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_TOPIC, topic2_name,
            RD_KAFKA_RESOURCE_PATTERN_LITERAL, user_test2, "*",
            RD_KAFKA_ACL_OPERATION_WRITE, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);


        admin_options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_CREATEACLS);
        err = rd_kafka_AdminOptions_set_request_timeout(admin_options, 10000,
                                                        errstr, sizeof(errstr));
        TEST_ASSERT(!err, "%s", errstr);

        TIMING_START(&timing, "CreateAcls");
        TEST_SAY("Call CreateAcls\n");
        rd_kafka_CreateAcls(rk, acl_bindings, 2, admin_options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /*
         * Wait for result
         */
        rkev_acl_create = test_wait_admin_result(
            q, RD_KAFKA_EVENT_CREATEACLS_RESULT, 10000 + 1000);

        err     = rd_kafka_event_error(rkev_acl_create);
        errstr2 = rd_kafka_event_error_string(rkev_acl_create);

        if (test_broker_version < TEST_BRKVER(0, 11, 0, 0)) {
                TEST_ASSERT(err == RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE,
                            "Expected unsupported feature, not: %s",
                            rd_kafka_err2name(err));
                TEST_ASSERT(!strcmp(errstr2,
                                    "ACLs Admin API (KIP-140) not supported "
                                    "by broker, requires broker "
                                    "version >= 0.11.0.0"),
                            "Expected a different message, not: %s", errstr2);
                TEST_FAIL("Unexpected error: %s", rd_kafka_err2name(err));
        }

        if (version > 0 && test_broker_version < TEST_BRKVER(2, 0, 0, 0)) {
                TEST_ASSERT(err == RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE,
                            "Expected unsupported feature, not: %s",
                            rd_kafka_err2name(err));
                TEST_ASSERT(!strcmp(errstr2,
                                    "Broker only supports LITERAL "
                                    "resource pattern types"),
                            "Expected a different message, not: %s", errstr2);
                TEST_FAIL("Unexpected error: %s", rd_kafka_err2name(err));
        }

        TEST_ASSERT(!err, "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        /*
         * Extract result
         */
        acl_res = rd_kafka_event_CreateAcls_result(rkev_acl_create);
        TEST_ASSERT(acl_res, "Expected CreateAcls result, not %s",
                    rd_kafka_event_name(rkev_acl_create));

        acl_res_acls = rd_kafka_CreateAcls_result_acls(acl_res, &resacl_cnt);
        TEST_ASSERT(resacl_cnt == 2, "Expected 2, not %zu", resacl_cnt);

        for (i = 0; i < resacl_cnt; i++) {
                const rd_kafka_acl_result_t *acl_res_acl = *(acl_res_acls + i);
                const rd_kafka_error_t *error =
                    rd_kafka_acl_result_error(acl_res_acl);

                TEST_ASSERT(!error,
                            "Expected RD_KAFKA_RESP_ERR_NO_ERROR, not %s",
                            rd_kafka_error_string(error));
        }

        rd_kafka_AdminOptions_destroy(admin_options);
        rd_kafka_event_destroy(rkev_acl_create);
        rd_kafka_AclBinding_destroy_array(acl_bindings, 2);
        if (!useq)
                rd_kafka_queue_destroy(q);

        SUB_TEST_PASS();
}

/**
 * @brief Test DescribeAcls
 */
static void
do_test_DescribeAcls(rd_kafka_t *rk, rd_kafka_queue_t *useq, int version) {
        rd_kafka_queue_t *q = useq ? useq : rd_kafka_queue_new(rk);
        size_t acl_binding_results_cntp;
        test_timing_t timing;
        rd_kafka_resp_err_t err;
        uint32_t i;
        char errstr[128];
        const char *errstr2;
        const char *user_test1 = "User:test1";
        const char *user_test2 = "User:test2";
        const char *any_host   = "*";
        const char *topic_name;
        rd_kafka_AclBinding_t *acl_bindings_create[2];
        rd_kafka_AclBinding_t *acl_bindings_describe;
        rd_kafka_AclBinding_t *acl;
        const rd_kafka_DescribeAcls_result_t *acl_describe_result;
        const rd_kafka_AclBinding_t **acl_binding_results;
        rd_kafka_ResourcePatternType_t pattern_type_first_topic_create;
        rd_bool_t broker_version1 =
            test_broker_version >= TEST_BRKVER(2, 0, 0, 0);
        rd_kafka_resp_err_t create_err;
        rd_kafka_AdminOptions_t *admin_options;
        rd_kafka_event_t *rkev_acl_describe;
        const rd_kafka_error_t *error;

        SUB_TEST_QUICK();

        if (test_broker_version < TEST_BRKVER(0, 11, 0, 0)) {
                SUB_TEST_SKIP(
                    "Skipping DESCRIBE_ACLS test on unsupported "
                    "broker version\n");
                return;
        }

        pattern_type_first_topic_create = RD_KAFKA_RESOURCE_PATTERN_PREFIXED;
        if (!broker_version1)
                pattern_type_first_topic_create =
                    RD_KAFKA_RESOURCE_PATTERN_LITERAL;

        topic_name = test_mk_topic_name(__FUNCTION__, 1);

        acl_bindings_create[0] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_TOPIC, topic_name,
            pattern_type_first_topic_create, user_test1, any_host,
            RD_KAFKA_ACL_OPERATION_READ, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);
        acl_bindings_create[1] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_TOPIC, topic_name,
            RD_KAFKA_RESOURCE_PATTERN_LITERAL, user_test2, any_host,
            RD_KAFKA_ACL_OPERATION_WRITE, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);

        create_err =
            test_CreateAcls_simple(rk, NULL, acl_bindings_create, 2, NULL);

        TEST_ASSERT(!create_err, "create error: %s",
                    rd_kafka_err2str(create_err));

        acl_bindings_describe = rd_kafka_AclBindingFilter_new(
            RD_KAFKA_RESOURCE_TOPIC, topic_name,
            RD_KAFKA_RESOURCE_PATTERN_MATCH, NULL, NULL,
            RD_KAFKA_ACL_OPERATION_ANY, RD_KAFKA_ACL_PERMISSION_TYPE_ANY, NULL,
            0);

        admin_options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DESCRIBEACLS);
        err = rd_kafka_AdminOptions_set_request_timeout(admin_options, 10000,
                                                        errstr, sizeof(errstr));

        TIMING_START(&timing, "DescribeAcls");
        TEST_SAY("Call DescribeAcls\n");
        rd_kafka_DescribeAcls(rk, acl_bindings_describe, admin_options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /*
         * Wait for result
         */
        rkev_acl_describe = test_wait_admin_result(
            q, RD_KAFKA_EVENT_DESCRIBEACLS_RESULT, 10000 + 1000);

        err     = rd_kafka_event_error(rkev_acl_describe);
        errstr2 = rd_kafka_event_error_string(rkev_acl_describe);

        if (!broker_version1) {
                TEST_ASSERT(
                    err == RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE,
                    "expected RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE, not %s",
                    rd_kafka_err2str(err));
                TEST_ASSERT(strcmp(errstr2,
                                   "Broker only supports LITERAL and ANY "
                                   "resource pattern types") == 0,
                            "expected another message, not %s", errstr2);
        } else {
                TEST_ASSERT(!err, "expected RD_KAFKA_RESP_ERR_NO_ERROR not %s",
                            errstr2);
        }

        if (!err) {

                acl_describe_result =
                    rd_kafka_event_DescribeAcls_result(rkev_acl_describe);

                TEST_ASSERT(acl_describe_result,
                            "acl_describe_result should not be NULL");

                acl_binding_results_cntp = 0;
                acl_binding_results      = rd_kafka_DescribeAcls_result_acls(
                    acl_describe_result, &acl_binding_results_cntp);

                TEST_ASSERT(acl_binding_results_cntp == 2,
                            "acl_binding_results_cntp should be 2, not %zu",
                            acl_binding_results_cntp);

                for (i = 0; i < acl_binding_results_cntp; i++) {
                        acl = (rd_kafka_AclBinding_t *)acl_binding_results[i];

                        if (strcmp(rd_kafka_AclBinding_principal(acl),
                                   user_test1) == 0) {
                                TEST_ASSERT(
                                    rd_kafka_AclBinding_restype(acl) ==
                                        RD_KAFKA_RESOURCE_TOPIC,
                                    "acl->restype should be "
                                    "RD_KAFKA_RESOURCE_TOPIC, not %s",
                                    rd_kafka_ResourceType_name(
                                        rd_kafka_AclBinding_restype(acl)));
                                TEST_ASSERT(
                                    strcmp(rd_kafka_AclBinding_name(acl),
                                           topic_name) == 0,
                                    "acl->name should be %s, not %s",
                                    topic_name, rd_kafka_AclBinding_name(acl));
                                TEST_ASSERT(
                                    rd_kafka_AclBinding_resource_pattern_type(
                                        acl) == pattern_type_first_topic_create,
                                    "acl->resource_pattern_type should be %s, "
                                    "not %s",
                                    rd_kafka_ResourcePatternType_name(
                                        pattern_type_first_topic_create),
                                    rd_kafka_ResourcePatternType_name(
                                        rd_kafka_AclBinding_resource_pattern_type(
                                            acl)));
                                TEST_ASSERT(
                                    strcmp(rd_kafka_AclBinding_principal(acl),
                                           user_test1) == 0,
                                    "acl->principal should be %s, not %s",
                                    user_test1,
                                    rd_kafka_AclBinding_principal(acl));

                                TEST_ASSERT(
                                    strcmp(rd_kafka_AclBinding_host(acl),
                                           any_host) == 0,
                                    "acl->host should be %s, not %s", any_host,
                                    rd_kafka_AclBinding_host(acl));

                                TEST_ASSERT(
                                    rd_kafka_AclBinding_operation(acl) ==
                                        RD_KAFKA_ACL_OPERATION_READ,
                                    "acl->operation should be %s, not %s",
                                    rd_kafka_AclOperation_name(
                                        RD_KAFKA_ACL_OPERATION_READ),
                                    rd_kafka_AclOperation_name(
                                        rd_kafka_AclBinding_operation(acl)));

                                TEST_ASSERT(
                                    rd_kafka_AclBinding_permission_type(acl) ==
                                        RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
                                    "acl->permission_type should be %s, not %s",
                                    rd_kafka_AclPermissionType_name(
                                        RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW),
                                    rd_kafka_AclPermissionType_name(
                                        rd_kafka_AclBinding_permission_type(
                                            acl)));

                                error = rd_kafka_AclBinding_error(acl);
                                TEST_ASSERT(!error,
                                            "acl->error should be NULL, not %s",
                                            rd_kafka_error_string(error));

                        } else {
                                TEST_ASSERT(
                                    rd_kafka_AclBinding_restype(acl) ==
                                        RD_KAFKA_RESOURCE_TOPIC,
                                    "acl->restype should be "
                                    "RD_KAFKA_RESOURCE_TOPIC, not %s",
                                    rd_kafka_ResourceType_name(
                                        rd_kafka_AclBinding_restype(acl)));
                                TEST_ASSERT(
                                    strcmp(rd_kafka_AclBinding_name(acl),
                                           topic_name) == 0,
                                    "acl->name should be %s, not %s",
                                    topic_name, rd_kafka_AclBinding_name(acl));
                                TEST_ASSERT(
                                    rd_kafka_AclBinding_resource_pattern_type(
                                        acl) ==
                                        RD_KAFKA_RESOURCE_PATTERN_LITERAL,
                                    "acl->resource_pattern_type should be %s, "
                                    "not %s",
                                    rd_kafka_ResourcePatternType_name(
                                        RD_KAFKA_RESOURCE_PATTERN_LITERAL),
                                    rd_kafka_ResourcePatternType_name(
                                        rd_kafka_AclBinding_resource_pattern_type(
                                            acl)));
                                TEST_ASSERT(
                                    strcmp(rd_kafka_AclBinding_principal(acl),
                                           user_test2) == 0,
                                    "acl->principal should be %s, not %s",
                                    user_test2,
                                    rd_kafka_AclBinding_principal(acl));

                                TEST_ASSERT(
                                    strcmp(rd_kafka_AclBinding_host(acl),
                                           any_host) == 0,
                                    "acl->host should be %s, not %s", any_host,
                                    rd_kafka_AclBinding_host(acl));

                                TEST_ASSERT(
                                    rd_kafka_AclBinding_operation(acl) ==
                                        RD_KAFKA_ACL_OPERATION_WRITE,
                                    "acl->operation should be %s, not %s",
                                    rd_kafka_AclOperation_name(
                                        RD_KAFKA_ACL_OPERATION_WRITE),
                                    rd_kafka_AclOperation_name(
                                        rd_kafka_AclBinding_operation(acl)));

                                TEST_ASSERT(
                                    rd_kafka_AclBinding_permission_type(acl) ==
                                        RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
                                    "acl->permission_type should be %s, not %s",
                                    rd_kafka_AclPermissionType_name(
                                        RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW),
                                    rd_kafka_AclPermissionType_name(
                                        rd_kafka_AclBinding_permission_type(
                                            acl)));


                                error = rd_kafka_AclBinding_error(acl);
                                TEST_ASSERT(!error,
                                            "acl->error should be NULL, not %s",
                                            rd_kafka_error_string(error));
                        }
                }
        }

        rd_kafka_AclBinding_destroy(acl_bindings_describe);
        rd_kafka_event_destroy(rkev_acl_describe);

        acl_bindings_describe = rd_kafka_AclBindingFilter_new(
            RD_KAFKA_RESOURCE_TOPIC, topic_name,
            RD_KAFKA_RESOURCE_PATTERN_LITERAL, NULL, NULL,
            RD_KAFKA_ACL_OPERATION_WRITE, RD_KAFKA_ACL_PERMISSION_TYPE_ANY,
            NULL, 0);

        TIMING_START(&timing, "DescribeAcls");
        rd_kafka_DescribeAcls(rk, acl_bindings_describe, admin_options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /*
         * Wait for result
         */
        rkev_acl_describe = test_wait_admin_result(
            q, RD_KAFKA_EVENT_DESCRIBEACLS_RESULT, 10000 + 1000);

        err     = rd_kafka_event_error(rkev_acl_describe);
        errstr2 = rd_kafka_event_error_string(rkev_acl_describe);

        TEST_ASSERT(!err, "expected RD_KAFKA_RESP_ERR_NO_ERROR not %s",
                    errstr2);

        acl_describe_result =
            rd_kafka_event_DescribeAcls_result(rkev_acl_describe);

        TEST_ASSERT(acl_describe_result,
                    "acl_describe_result should not be NULL");

        acl_binding_results_cntp = 0;
        acl_binding_results      = rd_kafka_DescribeAcls_result_acls(
            acl_describe_result, &acl_binding_results_cntp);

        TEST_ASSERT(acl_binding_results_cntp == 1,
                    "acl_binding_results_cntp should be 1, not %zu",
                    acl_binding_results_cntp);

        acl = (rd_kafka_AclBinding_t *)acl_binding_results[0];

        TEST_ASSERT(
            rd_kafka_AclBinding_restype(acl) == RD_KAFKA_RESOURCE_TOPIC,
            "acl->restype should be RD_KAFKA_RESOURCE_TOPIC, not %s",
            rd_kafka_ResourceType_name(rd_kafka_AclBinding_restype(acl)));
        TEST_ASSERT(strcmp(rd_kafka_AclBinding_name(acl), topic_name) == 0,
                    "acl->name should be %s, not %s", topic_name,
                    rd_kafka_AclBinding_name(acl));
        TEST_ASSERT(rd_kafka_AclBinding_resource_pattern_type(acl) ==
                        RD_KAFKA_RESOURCE_PATTERN_LITERAL,
                    "acl->resource_pattern_type should be %s, not %s",
                    rd_kafka_ResourcePatternType_name(
                        RD_KAFKA_RESOURCE_PATTERN_LITERAL),
                    rd_kafka_ResourcePatternType_name(
                        rd_kafka_AclBinding_resource_pattern_type(acl)));
        TEST_ASSERT(strcmp(rd_kafka_AclBinding_principal(acl), user_test2) == 0,
                    "acl->principal should be %s, not %s", user_test2,
                    rd_kafka_AclBinding_principal(acl));

        TEST_ASSERT(strcmp(rd_kafka_AclBinding_host(acl), any_host) == 0,
                    "acl->host should be %s, not %s", any_host,
                    rd_kafka_AclBinding_host(acl));

        TEST_ASSERT(
            rd_kafka_AclBinding_permission_type(acl) ==
                RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            "acl->permission_type should be %s, not %s",
            rd_kafka_AclPermissionType_name(RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW),
            rd_kafka_AclPermissionType_name(
                rd_kafka_AclBinding_permission_type(acl)));

        error = rd_kafka_AclBinding_error(acl);
        TEST_ASSERT(!error, "acl->error should be NULL, not %s",
                    rd_kafka_error_string(error));

        rd_kafka_AclBinding_destroy(acl_bindings_describe);
        rd_kafka_event_destroy(rkev_acl_describe);
        rd_kafka_AdminOptions_destroy(admin_options);
        rd_kafka_AclBinding_destroy_array(acl_bindings_create, 2);

        if (!useq)
                rd_kafka_queue_destroy(q);

        SUB_TEST_PASS();
}

/**
 * @brief Count acls by acl filter
 */
static size_t
do_test_acls_count(rd_kafka_t *rk,
                   rd_kafka_AclBindingFilter_t *acl_bindings_describe,
                   rd_kafka_queue_t *q) {
        char errstr[128];
        rd_kafka_resp_err_t err;
        rd_kafka_AdminOptions_t *admin_options_describe;
        rd_kafka_event_t *rkev_acl_describe;
        const rd_kafka_DescribeAcls_result_t *acl_describe_result;
        const char *errstr2;
        size_t acl_binding_results_cntp;

        admin_options_describe =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DESCRIBEACLS);
        rd_kafka_AdminOptions_set_request_timeout(admin_options_describe, 10000,
                                                  errstr, sizeof(errstr));

        rd_kafka_DescribeAcls(rk, acl_bindings_describe, admin_options_describe,
                              q);
        /*
         * Wait for result
         */
        rkev_acl_describe = test_wait_admin_result(
            q, RD_KAFKA_EVENT_DESCRIBEACLS_RESULT, 10000 + 1000);

        err     = rd_kafka_event_error(rkev_acl_describe);
        errstr2 = rd_kafka_event_error_string(rkev_acl_describe);

        TEST_ASSERT(!err, "expected RD_KAFKA_RESP_ERR_NO_ERROR not %s",
                    errstr2);

        acl_describe_result =
            rd_kafka_event_DescribeAcls_result(rkev_acl_describe);

        TEST_ASSERT(acl_describe_result,
                    "acl_describe_result should not be NULL");

        acl_binding_results_cntp = 0;
        rd_kafka_DescribeAcls_result_acls(acl_describe_result,
                                          &acl_binding_results_cntp);
        rd_kafka_event_destroy(rkev_acl_describe);
        rd_kafka_AdminOptions_destroy(admin_options_describe);

        return acl_binding_results_cntp;
}

/**
 * @brief Test DeleteAcls
 */
static void
do_test_DeleteAcls(rd_kafka_t *rk, rd_kafka_queue_t *useq, int version) {
        rd_kafka_queue_t *q = useq ? useq : rd_kafka_queue_new(rk);
        test_timing_t timing;
        uint32_t i;
        char errstr[128];
        const char *user_test1 = "User:test1";
        const char *user_test2 = "User:test2";
        const char *any_host   = "*";
        const char *base_topic_name;
        char topic1_name[512];
        char topic2_name[512];
        size_t acl_binding_results_cntp;
        size_t DeleteAcls_result_responses_cntp;
        size_t matching_acls_cntp;
        rd_kafka_AclBinding_t *acl_bindings_create[3];
        rd_kafka_AclBindingFilter_t *acl_bindings_describe;
        rd_kafka_AclBindingFilter_t *acl_bindings_delete;
        rd_kafka_event_t *rkev_acl_delete;
        rd_kafka_AdminOptions_t *admin_options_delete;
        const rd_kafka_DeleteAcls_result_t *acl_delete_result;
        const rd_kafka_DeleteAcls_result_response_t *
            *DeleteAcls_result_responses;
        const rd_kafka_DeleteAcls_result_response_t *DeleteAcls_result_response;
        const rd_kafka_AclBinding_t **matching_acls;
        const rd_kafka_AclBinding_t *matching_acl;
        rd_kafka_ResourcePatternType_t pattern_type_first_topic_create;
        rd_kafka_ResourcePatternType_t pattern_type_delete;
        rd_bool_t broker_version1 =
            test_broker_version >= TEST_BRKVER(2, 0, 0, 0);
        rd_kafka_resp_err_t create_err;
        rd_kafka_ResourceType_t restype;
        rd_kafka_ResourcePatternType_t resource_pattern_type;
        rd_kafka_AclOperation_t operation;
        rd_kafka_AclPermissionType_t permission_type;
        const char *name;
        const char *principal;
        const rd_kafka_error_t *error;

        SUB_TEST_QUICK();

        if (test_broker_version < TEST_BRKVER(0, 11, 0, 0)) {
                SUB_TEST_SKIP(
                    "Skipping DELETE_ACLS test on unsupported "
                    "broker version\n");
                return;
        }

        pattern_type_first_topic_create = RD_KAFKA_RESOURCE_PATTERN_PREFIXED;
        pattern_type_delete             = RD_KAFKA_RESOURCE_PATTERN_MATCH;
        if (!broker_version1) {
                pattern_type_first_topic_create =
                    RD_KAFKA_RESOURCE_PATTERN_LITERAL;
                pattern_type_delete = RD_KAFKA_RESOURCE_PATTERN_LITERAL;
        }

        base_topic_name = test_mk_topic_name(__FUNCTION__, 1);

        rd_snprintf(topic1_name, sizeof(topic1_name), "%s_1", base_topic_name);
        rd_snprintf(topic2_name, sizeof(topic2_name), "%s_2", base_topic_name);

        acl_bindings_create[0] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_TOPIC, topic1_name,
            pattern_type_first_topic_create, user_test1, any_host,
            RD_KAFKA_ACL_OPERATION_READ, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);
        acl_bindings_create[1] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_TOPIC, topic1_name,
            RD_KAFKA_RESOURCE_PATTERN_LITERAL, user_test2, any_host,
            RD_KAFKA_ACL_OPERATION_WRITE, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);
        acl_bindings_create[2] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_TOPIC, topic2_name,
            RD_KAFKA_RESOURCE_PATTERN_LITERAL, user_test2, any_host,
            RD_KAFKA_ACL_OPERATION_WRITE, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);

        acl_bindings_delete = rd_kafka_AclBindingFilter_new(
            RD_KAFKA_RESOURCE_TOPIC, topic1_name, pattern_type_delete, NULL,
            NULL, RD_KAFKA_ACL_OPERATION_ANY, RD_KAFKA_ACL_PERMISSION_TYPE_ANY,
            NULL, 0);

        acl_bindings_describe = acl_bindings_delete;

        create_err =
            test_CreateAcls_simple(rk, NULL, acl_bindings_create, 3, NULL);

        TEST_ASSERT(!create_err, "create error: %s",
                    rd_kafka_err2str(create_err));

        admin_options_delete =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DELETEACLS);
        rd_kafka_AdminOptions_set_request_timeout(admin_options_delete, 10000,
                                                  errstr, sizeof(errstr));

        acl_binding_results_cntp =
            do_test_acls_count(rk, acl_bindings_describe, q);
        TEST_ASSERT(acl_binding_results_cntp == 2,
                    "acl_binding_results_cntp should not be 2, not %zu\n",
                    acl_binding_results_cntp);

        TIMING_START(&timing, "DeleteAcls");
        rd_kafka_DeleteAcls(rk, &acl_bindings_delete, 1, admin_options_delete,
                            q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /*
         * Wait for result
         */
        rkev_acl_delete = test_wait_admin_result(
            q, RD_KAFKA_EVENT_DELETEACLS_RESULT, 10000 + 1000);

        acl_delete_result = rd_kafka_event_DeleteAcls_result(rkev_acl_delete);

        TEST_ASSERT(acl_delete_result, "acl_delete_result should not be NULL");

        DeleteAcls_result_responses_cntp = 0;
        DeleteAcls_result_responses      = rd_kafka_DeleteAcls_result_responses(
            acl_delete_result, &DeleteAcls_result_responses_cntp);

        TEST_ASSERT(DeleteAcls_result_responses_cntp == 1,
                    "DeleteAcls_result_responses_cntp should be 1, not %zu\n",
                    DeleteAcls_result_responses_cntp);

        DeleteAcls_result_response = DeleteAcls_result_responses[0];

        TEST_CALL_ERROR__(rd_kafka_DeleteAcls_result_response_error(
            DeleteAcls_result_response));

        matching_acls = rd_kafka_DeleteAcls_result_response_matching_acls(
            DeleteAcls_result_response, &matching_acls_cntp);

        TEST_ASSERT(matching_acls_cntp == 2,
                    "matching_acls_cntp should be 2, not %zu\n",
                    matching_acls_cntp);

        for (i = 0; i < matching_acls_cntp; i++) {
                rd_kafka_ResourceType_t restype;
                rd_kafka_ResourcePatternType_t resource_pattern_type;
                rd_kafka_AclOperation_t operation;
                rd_kafka_AclPermissionType_t permission_type;
                const char *name;
                const char *principal;

                matching_acl = matching_acls[i];
                error        = rd_kafka_AclBinding_error(matching_acl);
                restype      = rd_kafka_AclBinding_restype(matching_acl);
                name         = rd_kafka_AclBinding_name(matching_acl);
                resource_pattern_type =
                    rd_kafka_AclBinding_resource_pattern_type(matching_acl);
                principal = rd_kafka_AclBinding_principal(matching_acl);
                operation = rd_kafka_AclBinding_operation(matching_acl);
                permission_type =
                    rd_kafka_AclBinding_permission_type(matching_acl);

                TEST_ASSERT(!error, "expected success, not %s",
                            rd_kafka_error_string(error));
                TEST_ASSERT(restype == RD_KAFKA_RESOURCE_TOPIC,
                            "expected RD_KAFKA_RESOURCE_TOPIC not %s",
                            rd_kafka_ResourceType_name(restype));
                TEST_ASSERT(strcmp(name, topic1_name) == 0,
                            "expected %s not %s", topic1_name, name);
                TEST_ASSERT(permission_type ==
                                RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
                            "expected %s not %s",
                            rd_kafka_AclPermissionType_name(
                                RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW),
                            rd_kafka_AclPermissionType_name(permission_type));

                if (strcmp(user_test1, principal) == 0) {
                        TEST_ASSERT(resource_pattern_type ==
                                        pattern_type_first_topic_create,
                                    "expected %s not %s",
                                    rd_kafka_ResourcePatternType_name(
                                        pattern_type_first_topic_create),
                                    rd_kafka_ResourcePatternType_name(
                                        resource_pattern_type));

                        TEST_ASSERT(operation == RD_KAFKA_ACL_OPERATION_READ,
                                    "expected %s not %s",
                                    rd_kafka_AclOperation_name(
                                        RD_KAFKA_ACL_OPERATION_READ),
                                    rd_kafka_AclOperation_name(operation));

                } else {
                        TEST_ASSERT(resource_pattern_type ==
                                        RD_KAFKA_RESOURCE_PATTERN_LITERAL,
                                    "expected %s not %s",
                                    rd_kafka_ResourcePatternType_name(
                                        RD_KAFKA_RESOURCE_PATTERN_LITERAL),
                                    rd_kafka_ResourcePatternType_name(
                                        resource_pattern_type));

                        TEST_ASSERT(operation == RD_KAFKA_ACL_OPERATION_WRITE,
                                    "expected %s not %s",
                                    rd_kafka_AclOperation_name(
                                        RD_KAFKA_ACL_OPERATION_WRITE),
                                    rd_kafka_AclOperation_name(operation));
                }
        }

        acl_binding_results_cntp =
            do_test_acls_count(rk, acl_bindings_describe, q);
        TEST_ASSERT(acl_binding_results_cntp == 0,
                    "acl_binding_results_cntp should be 0, not %zu\n",
                    acl_binding_results_cntp);

        rd_kafka_event_destroy(rkev_acl_delete);
        rd_kafka_AclBinding_destroy(acl_bindings_delete);

        acl_bindings_delete = rd_kafka_AclBindingFilter_new(
            RD_KAFKA_RESOURCE_TOPIC, topic2_name,
            RD_KAFKA_RESOURCE_PATTERN_LITERAL, NULL, NULL,
            RD_KAFKA_ACL_OPERATION_ANY, RD_KAFKA_ACL_PERMISSION_TYPE_ANY, NULL,
            0);
        acl_bindings_describe = acl_bindings_delete;

        TIMING_START(&timing, "DeleteAcls");
        rd_kafka_DeleteAcls(rk, &acl_bindings_delete, 1, admin_options_delete,
                            q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /*
         * Wait for result
         */
        rkev_acl_delete = test_wait_admin_result(
            q, RD_KAFKA_EVENT_DELETEACLS_RESULT, 10000 + 1000);

        acl_delete_result = rd_kafka_event_DeleteAcls_result(rkev_acl_delete);

        TEST_ASSERT(acl_delete_result, "acl_delete_result should not be NULL");

        DeleteAcls_result_responses_cntp = 0;
        DeleteAcls_result_responses      = rd_kafka_DeleteAcls_result_responses(
            acl_delete_result, &DeleteAcls_result_responses_cntp);

        TEST_ASSERT(DeleteAcls_result_responses_cntp == 1,
                    "DeleteAcls_result_responses_cntp should be 1, not %zu\n",
                    DeleteAcls_result_responses_cntp);

        DeleteAcls_result_response = DeleteAcls_result_responses[0];

        TEST_CALL_ERROR__(rd_kafka_DeleteAcls_result_response_error(
            DeleteAcls_result_response));

        matching_acls = rd_kafka_DeleteAcls_result_response_matching_acls(
            DeleteAcls_result_response, &matching_acls_cntp);

        TEST_ASSERT(matching_acls_cntp == 1,
                    "matching_acls_cntp should be 1, not %zu\n",
                    matching_acls_cntp);

        matching_acl = matching_acls[0];
        error        = rd_kafka_AclBinding_error(matching_acl);
        restype      = rd_kafka_AclBinding_restype(matching_acl);
        name         = rd_kafka_AclBinding_name(matching_acl);
        resource_pattern_type =
            rd_kafka_AclBinding_resource_pattern_type(matching_acl);
        principal       = rd_kafka_AclBinding_principal(matching_acl);
        operation       = rd_kafka_AclBinding_operation(matching_acl);
        permission_type = rd_kafka_AclBinding_permission_type(matching_acl);

        TEST_ASSERT(!error, "expected RD_KAFKA_RESP_ERR_NO_ERROR not %s",
                    rd_kafka_error_string(error));
        TEST_ASSERT(restype == RD_KAFKA_RESOURCE_TOPIC,
                    "expected RD_KAFKA_RESOURCE_TOPIC not %s",
                    rd_kafka_ResourceType_name(restype));
        TEST_ASSERT(strcmp(name, topic2_name) == 0, "expected %s not %s",
                    topic2_name, name);
        TEST_ASSERT(
            permission_type == RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            "expected %s not %s",
            rd_kafka_AclPermissionType_name(RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW),
            rd_kafka_AclPermissionType_name(permission_type));
        TEST_ASSERT(strcmp(user_test2, principal) == 0, "expected %s not %s",
                    user_test2, principal);
        TEST_ASSERT(resource_pattern_type == RD_KAFKA_RESOURCE_PATTERN_LITERAL,
                    "expected %s not %s",
                    rd_kafka_ResourcePatternType_name(
                        RD_KAFKA_RESOURCE_PATTERN_LITERAL),
                    rd_kafka_ResourcePatternType_name(resource_pattern_type));

        TEST_ASSERT(operation == RD_KAFKA_ACL_OPERATION_WRITE,
                    "expected %s not %s",
                    rd_kafka_AclOperation_name(RD_KAFKA_ACL_OPERATION_WRITE),
                    rd_kafka_AclOperation_name(operation));

        acl_binding_results_cntp =
            do_test_acls_count(rk, acl_bindings_describe, q);
        TEST_ASSERT(acl_binding_results_cntp == 0,
                    "acl_binding_results_cntp should be 0, not %zu\n",
                    acl_binding_results_cntp);

        rd_kafka_AclBinding_destroy(acl_bindings_delete);
        rd_kafka_event_destroy(rkev_acl_delete);
        rd_kafka_AdminOptions_destroy(admin_options_delete);

        rd_kafka_AclBinding_destroy_array(acl_bindings_create, 3);

        if (!useq)
                rd_kafka_queue_destroy(q);

        SUB_TEST_PASS();
}

/**
 * @brief Verify that an unclean rd_kafka_destroy() does not hang.
 */
static void do_test_unclean_destroy(rd_kafka_type_t cltype, int with_mainq) {
        rd_kafka_t *rk;
        char errstr[512];
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *q;
        rd_kafka_NewTopic_t *topic;
        test_timing_t t_destroy;

        SUB_TEST_QUICK("Test unclean destroy using %s",
                       with_mainq ? "mainq" : "tempq");

        test_conf_init(&conf, NULL, 0);

        rk = rd_kafka_new(cltype, conf, errstr, sizeof(errstr));
        TEST_ASSERT(rk, "kafka_new(%d): %s", cltype, errstr);

        if (with_mainq)
                q = rd_kafka_queue_get_main(rk);
        else
                q = rd_kafka_queue_new(rk);

        topic = rd_kafka_NewTopic_new(test_mk_topic_name(__FUNCTION__, 1), 3, 1,
                                      NULL, 0);
        rd_kafka_CreateTopics(rk, &topic, 1, NULL, q);
        rd_kafka_NewTopic_destroy(topic);

        rd_kafka_queue_destroy(q);

        TEST_SAY(
            "Giving rd_kafka_destroy() 5s to finish, "
            "despite Admin API request being processed\n");
        test_timeout_set(5);
        TIMING_START(&t_destroy, "rd_kafka_destroy()");
        rd_kafka_destroy(rk);
        TIMING_STOP(&t_destroy);

        SUB_TEST_PASS();

        /* Restore timeout */
        test_timeout_set(60);
}



/**
 * @brief Test deletion of records
 *
 *
 */
static void do_test_DeleteRecords(const char *what,
                                  rd_kafka_t *rk,
                                  rd_kafka_queue_t *useq,
                                  int op_timeout) {
        rd_kafka_queue_t *q;
        rd_kafka_AdminOptions_t *options         = NULL;
        rd_kafka_topic_partition_list_t *offsets = NULL;
        rd_kafka_event_t *rkev                   = NULL;
        rd_kafka_resp_err_t err;
        char errstr[512];
        const char *errstr2;
#define MY_DEL_RECORDS_CNT 3
        rd_kafka_topic_partition_list_t *results = NULL;
        int i;
        const int partitions_cnt = 3;
        const int msgs_cnt       = 100;
        char *topics[MY_DEL_RECORDS_CNT];
        rd_kafka_metadata_topic_t exp_mdtopics[MY_DEL_RECORDS_CNT] = {{0}};
        int exp_mdtopic_cnt                                        = 0;
        test_timing_t timing;
        rd_kafka_resp_err_t exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_kafka_DeleteRecords_t *del_records;
        const rd_kafka_DeleteRecords_result_t *res;

        SUB_TEST_QUICK("%s DeleteRecords with %s, op_timeout %d",
                       rd_kafka_name(rk), what, op_timeout);

        q = useq ? useq : rd_kafka_queue_new(rk);

        if (op_timeout != -1) {
                options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_ANY);

                err = rd_kafka_AdminOptions_set_operation_timeout(
                    options, op_timeout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        }


        for (i = 0; i < MY_DEL_RECORDS_CNT; i++) {
                char pfx[32];
                char *topic;

                rd_snprintf(pfx, sizeof(pfx), "DeleteRecords-topic%d", i);
                topic = rd_strdup(test_mk_topic_name(pfx, 1));

                topics[i]                             = topic;
                exp_mdtopics[exp_mdtopic_cnt++].topic = topic;
        }

        /* Create the topics first. */
        test_CreateTopics_simple(rk, NULL, topics, MY_DEL_RECORDS_CNT,
                                 partitions_cnt /*num_partitions*/, NULL);

        /* Verify that topics are reported by metadata */
        test_wait_metadata_update(rk, exp_mdtopics, exp_mdtopic_cnt, NULL, 0,
                                  15 * 1000);

        /* Produce 100 msgs / partition */
        for (i = 0; i < MY_DEL_RECORDS_CNT; i++) {
                int32_t partition;
                for (partition = 0; partition < partitions_cnt; partition++) {
                        test_produce_msgs_easy(topics[i], 0, partition,
                                               msgs_cnt);
                }
        }

        offsets = rd_kafka_topic_partition_list_new(10);

        /* Wipe all data from topic 0 */
        for (i = 0; i < partitions_cnt; i++)
                rd_kafka_topic_partition_list_add(offsets, topics[0], i)
                    ->offset = RD_KAFKA_OFFSET_END;

        /* Wipe all data from partition 0 in topic 1 */
        rd_kafka_topic_partition_list_add(offsets, topics[1], 0)->offset =
            RD_KAFKA_OFFSET_END;

        /* Wipe some data from partition 2 in topic 1 */
        rd_kafka_topic_partition_list_add(offsets, topics[1], 2)->offset =
            msgs_cnt / 2;

        /* Not changing the offset (out of range) for topic 2 partition 0 */
        rd_kafka_topic_partition_list_add(offsets, topics[2], 0);

        /* Offset out of range for topic 2 partition 1 */
        rd_kafka_topic_partition_list_add(offsets, topics[2], 1)->offset =
            msgs_cnt + 1;

        del_records = rd_kafka_DeleteRecords_new(offsets);

        TIMING_START(&timing, "DeleteRecords");
        TEST_SAY("Call DeleteRecords\n");
        rd_kafka_DeleteRecords(rk, &del_records, 1, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        rd_kafka_DeleteRecords_destroy(del_records);

        TIMING_START(&timing, "DeleteRecords.queue_poll");

        /* Poll result queue for DeleteRecords result.
         * Print but otherwise ignore other event types
         * (typically generic Error events). */
        while (1) {
                rkev = rd_kafka_queue_poll(q, tmout_multip(20 * 1000));
                TEST_SAY("DeleteRecords: got %s in %.3fms\n",
                         rd_kafka_event_name(rkev),
                         TIMING_DURATION(&timing) / 1000.0f);
                if (rkev == NULL)
                        continue;
                if (rd_kafka_event_error(rkev))
                        TEST_SAY("%s: %s\n", rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));

                if (rd_kafka_event_type(rkev) ==
                    RD_KAFKA_EVENT_DELETERECORDS_RESULT) {
                        break;
                }

                rd_kafka_event_destroy(rkev);
        }
        /* Convert event to proper result */
        res = rd_kafka_event_DeleteRecords_result(rkev);
        TEST_ASSERT(res, "expected DeleteRecords_result, not %s",
                    rd_kafka_event_name(rkev));

        /* Expecting error */
        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(err == exp_err,
                    "expected DeleteRecords to return %s, not %s (%s)",
                    rd_kafka_err2str(exp_err), rd_kafka_err2str(err),
                    err ? errstr2 : "n/a");

        TEST_SAY("DeleteRecords: returned %s (%s)\n", rd_kafka_err2str(err),
                 err ? errstr2 : "n/a");

        results = rd_kafka_topic_partition_list_copy(
            rd_kafka_DeleteRecords_result_offsets(res));

        /* Sort both input and output list */
        rd_kafka_topic_partition_list_sort(offsets, NULL, NULL);
        rd_kafka_topic_partition_list_sort(results, NULL, NULL);

        TEST_SAY("Input partitions:\n");
        test_print_partition_list(offsets);
        TEST_SAY("Result partitions:\n");
        test_print_partition_list(results);

        TEST_ASSERT(offsets->cnt == results->cnt,
                    "expected DeleteRecords_result_offsets to return %d items, "
                    "not %d",
                    offsets->cnt, results->cnt);

        for (i = 0; i < results->cnt; i++) {
                const rd_kafka_topic_partition_t *input  = &offsets->elems[i];
                const rd_kafka_topic_partition_t *output = &results->elems[i];
                int64_t expected_offset                  = input->offset;
                rd_kafka_resp_err_t expected_err         = 0;

                if (expected_offset == RD_KAFKA_OFFSET_END)
                        expected_offset = msgs_cnt;

                /* Expect Offset out of range error */
                if (input->offset < RD_KAFKA_OFFSET_END ||
                    input->offset > msgs_cnt)
                        expected_err = 1;

                TEST_SAY("DeleteRecords Returned %s for %s [%" PRId32
                         "] "
                         "low-watermark = %d\n",
                         rd_kafka_err2name(output->err), output->topic,
                         output->partition, (int)output->offset);

                if (strcmp(output->topic, input->topic))
                        TEST_FAIL_LATER(
                            "Result order mismatch at #%d: "
                            "expected topic %s, got %s",
                            i, input->topic, output->topic);

                if (output->partition != input->partition)
                        TEST_FAIL_LATER(
                            "Result order mismatch at #%d: "
                            "expected partition %d, got %d",
                            i, input->partition, output->partition);

                if (output->err != expected_err)
                        TEST_FAIL_LATER(
                            "%s [%" PRId32
                            "]: "
                            "expected error code %d (%s), "
                            "got %d (%s)",
                            output->topic, output->partition, expected_err,
                            rd_kafka_err2str(expected_err), output->err,
                            rd_kafka_err2str(output->err));

                if (output->err == 0 && output->offset != expected_offset)
                        TEST_FAIL_LATER("%s [%" PRId32
                                        "]: "
                                        "expected offset %" PRId64
                                        ", "
                                        "got %" PRId64,
                                        output->topic, output->partition,
                                        expected_offset, output->offset);
        }

        /* Check watermarks for partitions */
        for (i = 0; i < MY_DEL_RECORDS_CNT; i++) {
                int32_t partition;
                for (partition = 0; partition < partitions_cnt; partition++) {
                        const rd_kafka_topic_partition_t *del =
                            rd_kafka_topic_partition_list_find(
                                results, topics[i], partition);
                        int64_t expected_low  = 0;
                        int64_t expected_high = msgs_cnt;
                        int64_t low, high;

                        if (del && del->err == 0) {
                                expected_low = del->offset;
                        }

                        err = rd_kafka_query_watermark_offsets(
                            rk, topics[i], partition, &low, &high,
                            tmout_multip(10000));
                        if (err)
                                TEST_FAIL(
                                    "query_watermark_offsets failed: "
                                    "%s\n",
                                    rd_kafka_err2str(err));

                        if (low != expected_low)
                                TEST_FAIL_LATER("For %s [%" PRId32
                                                "] expected "
                                                "a low watermark of %" PRId64
                                                ", got %" PRId64,
                                                topics[i], partition,
                                                expected_low, low);

                        if (high != expected_high)
                                TEST_FAIL_LATER("For %s [%" PRId32
                                                "] expected "
                                                "a high watermark of %" PRId64
                                                ", got %" PRId64,
                                                topics[i], partition,
                                                expected_high, high);
                }
        }

        rd_kafka_event_destroy(rkev);

        for (i = 0; i < MY_DEL_RECORDS_CNT; i++)
                rd_free(topics[i]);

        if (results)
                rd_kafka_topic_partition_list_destroy(results);

        if (offsets)
                rd_kafka_topic_partition_list_destroy(offsets);

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

        TEST_LATER_CHECK();
#undef MY_DEL_RECORDS_CNT

        SUB_TEST_PASS();
}

/**
 * @brief Test deletion of groups
 *
 *
 */

typedef struct expected_group_result {
        char *group;
        rd_kafka_resp_err_t err;
} expected_group_result_t;

static void do_test_DeleteGroups(const char *what,
                                 rd_kafka_t *rk,
                                 rd_kafka_queue_t *useq,
                                 int op_timeout) {
        rd_kafka_queue_t *q;
        rd_kafka_AdminOptions_t *options = NULL;
        rd_kafka_event_t *rkev           = NULL;
        rd_kafka_resp_err_t err;
        char errstr[512];
        const char *errstr2;
#define MY_DEL_GROUPS_CNT 4
        int known_groups = MY_DEL_GROUPS_CNT - 1;
        int i;
        const int partitions_cnt = 1;
        const int msgs_cnt       = 100;
        char *topic;
        rd_kafka_metadata_topic_t exp_mdtopic = {0};
        int64_t testid                        = test_id_generate();
        test_timing_t timing;
        rd_kafka_resp_err_t exp_err             = RD_KAFKA_RESP_ERR_NO_ERROR;
        const rd_kafka_group_result_t **results = NULL;
        expected_group_result_t expected[MY_DEL_GROUPS_CNT] = {{0}};
        rd_kafka_DeleteGroup_t *del_groups[MY_DEL_GROUPS_CNT];
        const rd_kafka_DeleteGroups_result_t *res;

        SUB_TEST_QUICK("%s DeleteGroups with %s, op_timeout %d",
                       rd_kafka_name(rk), what, op_timeout);

        q = useq ? useq : rd_kafka_queue_new(rk);

        if (op_timeout != -1) {
                options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_ANY);

                err = rd_kafka_AdminOptions_set_operation_timeout(
                    options, op_timeout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        }


        topic             = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
        exp_mdtopic.topic = topic;

        /* Create the topics first. */
        test_CreateTopics_simple(rk, NULL, &topic, 1, partitions_cnt, NULL);

        /* Verify that topics are reported by metadata */
        test_wait_metadata_update(rk, &exp_mdtopic, 1, NULL, 0, 15 * 1000);

        /* Produce 100 msgs */
        test_produce_msgs_easy(topic, testid, 0, msgs_cnt);

        for (i = 0; i < MY_DEL_GROUPS_CNT; i++) {
                char *group = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
                if (i < known_groups) {
                        test_consume_msgs_easy(group, topic, testid, -1,
                                               msgs_cnt, NULL);
                        expected[i].group = group;
                        expected[i].err   = RD_KAFKA_RESP_ERR_NO_ERROR;
                } else {
                        expected[i].group = group;
                        expected[i].err = RD_KAFKA_RESP_ERR_GROUP_ID_NOT_FOUND;
                }
                del_groups[i] = rd_kafka_DeleteGroup_new(group);
        }

        TIMING_START(&timing, "DeleteGroups");
        TEST_SAY("Call DeleteGroups\n");
        rd_kafka_DeleteGroups(rk, del_groups, MY_DEL_GROUPS_CNT, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        TIMING_START(&timing, "DeleteGroups.queue_poll");

        /* Poll result queue for DeleteGroups result.
         * Print but otherwise ignore other event types
         * (typically generic Error events). */
        while (1) {
                rkev = rd_kafka_queue_poll(q, tmout_multip(20 * 1000));
                TEST_SAY("DeleteGroups: got %s in %.3fms\n",
                         rd_kafka_event_name(rkev),
                         TIMING_DURATION(&timing) / 1000.0f);
                if (rkev == NULL)
                        continue;
                if (rd_kafka_event_error(rkev))
                        TEST_SAY("%s: %s\n", rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));

                if (rd_kafka_event_type(rkev) ==
                    RD_KAFKA_EVENT_DELETEGROUPS_RESULT) {
                        break;
                }

                rd_kafka_event_destroy(rkev);
        }
        /* Convert event to proper result */
        res = rd_kafka_event_DeleteGroups_result(rkev);
        TEST_ASSERT(res, "expected DeleteGroups_result, not %s",
                    rd_kafka_event_name(rkev));

        /* Expecting error */
        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(err == exp_err,
                    "expected DeleteGroups to return %s, not %s (%s)",
                    rd_kafka_err2str(exp_err), rd_kafka_err2str(err),
                    err ? errstr2 : "n/a");

        TEST_SAY("DeleteGroups: returned %s (%s)\n", rd_kafka_err2str(err),
                 err ? errstr2 : "n/a");

        size_t cnt = 0;
        results    = rd_kafka_DeleteGroups_result_groups(res, &cnt);

        TEST_ASSERT(MY_DEL_GROUPS_CNT == cnt,
                    "expected DeleteGroups_result_groups to return %d items, "
                    "not %" PRIusz,
                    MY_DEL_GROUPS_CNT, cnt);

        for (i = 0; i < MY_DEL_GROUPS_CNT; i++) {
                const expected_group_result_t *exp = &expected[i];
                rd_kafka_resp_err_t exp_err        = exp->err;
                const rd_kafka_group_result_t *act = results[i];
                rd_kafka_resp_err_t act_err =
                    rd_kafka_error_code(rd_kafka_group_result_error(act));
                TEST_ASSERT(
                    strcmp(exp->group, rd_kafka_group_result_name(act)) == 0,
                    "Result order mismatch at #%d: expected group name to be "
                    "%s, not %s",
                    i, exp->group, rd_kafka_group_result_name(act));
                TEST_ASSERT(exp_err == act_err,
                            "expected err=%d for group %s, not %d (%s)",
                            exp_err, exp->group, act_err,
                            rd_kafka_err2str(act_err));
        }

        rd_kafka_event_destroy(rkev);

        for (i = 0; i < MY_DEL_GROUPS_CNT; i++) {
                rd_kafka_DeleteGroup_destroy(del_groups[i]);
                rd_free(expected[i].group);
        }

        rd_free(topic);

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

        TEST_LATER_CHECK();
#undef MY_DEL_GROUPS_CNT

        SUB_TEST_PASS();
}


/**
 * @brief Test deletion of committed offsets.
 *
 *
 */
static void do_test_DeleteConsumerGroupOffsets(const char *what,
                                               rd_kafka_t *rk,
                                               rd_kafka_queue_t *useq,
                                               int op_timeout,
                                               rd_bool_t sub_consumer) {
        rd_kafka_queue_t *q;
        rd_kafka_AdminOptions_t *options = NULL;
        rd_kafka_topic_partition_list_t *orig_offsets, *offsets, *to_delete,
            *committed, *deleted, *subscription = NULL;
        rd_kafka_event_t *rkev = NULL;
        rd_kafka_resp_err_t err;
        char errstr[512];
        const char *errstr2;
#define MY_TOPIC_CNT 3
        int i;
        const int partitions_cnt = 3;
        char *topics[MY_TOPIC_CNT];
        rd_kafka_metadata_topic_t exp_mdtopics[MY_TOPIC_CNT] = {{0}};
        int exp_mdtopic_cnt                                  = 0;
        test_timing_t timing;
        rd_kafka_resp_err_t exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_kafka_DeleteConsumerGroupOffsets_t *cgoffsets;
        const rd_kafka_DeleteConsumerGroupOffsets_result_t *res;
        const rd_kafka_group_result_t **gres;
        size_t gres_cnt;
        rd_kafka_t *consumer;
        char *groupid;

        SUB_TEST_QUICK("%s DeleteConsumerGroupOffsets with %s, op_timeout %d%s",
                       rd_kafka_name(rk), what, op_timeout,
                       sub_consumer ? ", with subscribing consumer" : "");

        if (sub_consumer)
                exp_err = RD_KAFKA_RESP_ERR_GROUP_SUBSCRIBED_TO_TOPIC;

        q = useq ? useq : rd_kafka_queue_new(rk);

        if (op_timeout != -1) {
                options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_ANY);

                err = rd_kafka_AdminOptions_set_operation_timeout(
                    options, op_timeout, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        }


        subscription = rd_kafka_topic_partition_list_new(MY_TOPIC_CNT);

        for (i = 0; i < MY_TOPIC_CNT; i++) {
                char pfx[64];
                char *topic;

                rd_snprintf(pfx, sizeof(pfx), "DCGO-topic%d", i);
                topic = rd_strdup(test_mk_topic_name(pfx, 1));

                topics[i]                             = topic;
                exp_mdtopics[exp_mdtopic_cnt++].topic = topic;

                rd_kafka_topic_partition_list_add(subscription, topic,
                                                  RD_KAFKA_PARTITION_UA);
        }

        groupid = topics[0];

        /* Create the topics first. */
        test_CreateTopics_simple(rk, NULL, topics, MY_TOPIC_CNT, partitions_cnt,
                                 NULL);

        /* Verify that topics are reported by metadata */
        test_wait_metadata_update(rk, exp_mdtopics, exp_mdtopic_cnt, NULL, 0,
                                  15 * 1000);

        rd_sleep(1); /* Additional wait time for cluster propagation */

        consumer = test_create_consumer(groupid, NULL, NULL, NULL);

        if (sub_consumer) {
                TEST_CALL_ERR__(rd_kafka_subscribe(consumer, subscription));
                test_consumer_wait_assignment(consumer, rd_true);
        }

        /* Commit some offsets */
        orig_offsets = rd_kafka_topic_partition_list_new(MY_TOPIC_CNT * 2);
        for (i = 0; i < MY_TOPIC_CNT * 2; i++)
                rd_kafka_topic_partition_list_add(orig_offsets, topics[i / 2],
                                                  i % MY_TOPIC_CNT)
                    ->offset = (i + 1) * 10;

        TEST_CALL_ERR__(rd_kafka_commit(consumer, orig_offsets, 0 /*sync*/));

        /* Verify committed offsets match */
        committed = rd_kafka_topic_partition_list_copy(orig_offsets);
        TEST_CALL_ERR__(
            rd_kafka_committed(consumer, committed, tmout_multip(5 * 1000)));

        if (test_partition_list_cmp(committed, orig_offsets)) {
                TEST_SAY("commit() list:\n");
                test_print_partition_list(orig_offsets);
                TEST_SAY("committed() list:\n");
                test_print_partition_list(committed);
                TEST_FAIL("committed offsets don't match");
        }

        rd_kafka_topic_partition_list_destroy(committed);

        /* Now delete second half of the commits */
        offsets   = rd_kafka_topic_partition_list_new(orig_offsets->cnt / 2);
        to_delete = rd_kafka_topic_partition_list_new(orig_offsets->cnt / 2);
        for (i = 0; i < orig_offsets->cnt; i++) {
                if (i < orig_offsets->cnt / 2)
                        rd_kafka_topic_partition_list_add(
                            offsets, orig_offsets->elems[i].topic,
                            orig_offsets->elems[i].partition);
                else {
                        rd_kafka_topic_partition_list_add(
                            to_delete, orig_offsets->elems[i].topic,
                            orig_offsets->elems[i].partition);
                        rd_kafka_topic_partition_list_add(
                            offsets, orig_offsets->elems[i].topic,
                            orig_offsets->elems[i].partition)
                            ->offset = RD_KAFKA_OFFSET_INVALID;
                }
        }

        cgoffsets = rd_kafka_DeleteConsumerGroupOffsets_new(groupid, to_delete);

        TIMING_START(&timing, "DeleteConsumerGroupOffsets");
        TEST_SAY("Call DeleteConsumerGroupOffsets\n");
        rd_kafka_DeleteConsumerGroupOffsets(rk, &cgoffsets, 1, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        rd_kafka_DeleteConsumerGroupOffsets_destroy(cgoffsets);

        TIMING_START(&timing, "DeleteConsumerGroupOffsets.queue_poll");
        /* Poll result queue for DeleteConsumerGroupOffsets result.
         * Print but otherwise ignore other event types
         * (typically generic Error events). */
        while (1) {
                rkev = rd_kafka_queue_poll(q, tmout_multip(10 * 1000));
                TEST_SAY("DeleteConsumerGroupOffsets: got %s in %.3fms\n",
                         rd_kafka_event_name(rkev),
                         TIMING_DURATION(&timing) / 1000.0f);
                if (rkev == NULL)
                        continue;
                if (rd_kafka_event_error(rkev))
                        TEST_SAY("%s: %s\n", rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));

                if (rd_kafka_event_type(rkev) ==
                    RD_KAFKA_EVENT_DELETECONSUMERGROUPOFFSETS_RESULT)
                        break;

                rd_kafka_event_destroy(rkev);
        }

        /* Convert event to proper result */
        res = rd_kafka_event_DeleteConsumerGroupOffsets_result(rkev);
        TEST_ASSERT(res, "expected DeleteConsumerGroupOffsets_result, not %s",
                    rd_kafka_event_name(rkev));

        /* Expecting error */
        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err,
                    "expected DeleteConsumerGroupOffsets to succeed, "
                    "got %s (%s)",
                    rd_kafka_err2name(err), err ? errstr2 : "n/a");

        TEST_SAY("DeleteConsumerGroupOffsets: returned %s (%s)\n",
                 rd_kafka_err2str(err), err ? errstr2 : "n/a");

        gres =
            rd_kafka_DeleteConsumerGroupOffsets_result_groups(res, &gres_cnt);
        TEST_ASSERT(gres && gres_cnt == 1,
                    "expected gres_cnt == 1, not %" PRIusz, gres_cnt);

        deleted = rd_kafka_topic_partition_list_copy(
            rd_kafka_group_result_partitions(gres[0]));

        if (test_partition_list_cmp(deleted, to_delete)) {
                TEST_SAY("Result list:\n");
                test_print_partition_list(deleted);
                TEST_SAY("Partitions passed to DeleteConsumerGroupOffsets:\n");
                test_print_partition_list(to_delete);
                TEST_FAIL("deleted/requested offsets don't match");
        }

        /* Verify expected errors */
        for (i = 0; i < deleted->cnt; i++) {
                TEST_ASSERT_LATER(deleted->elems[i].err == exp_err,
                                  "Result %s [%" PRId32
                                  "] has error %s, "
                                  "expected %s",
                                  deleted->elems[i].topic,
                                  deleted->elems[i].partition,
                                  rd_kafka_err2name(deleted->elems[i].err),
                                  rd_kafka_err2name(exp_err));
        }

        TEST_LATER_CHECK();

        rd_kafka_topic_partition_list_destroy(deleted);
        rd_kafka_topic_partition_list_destroy(to_delete);

        rd_kafka_event_destroy(rkev);


        /* Verify committed offsets match */
        committed = rd_kafka_topic_partition_list_copy(orig_offsets);
        TEST_CALL_ERR__(
            rd_kafka_committed(consumer, committed, tmout_multip(5 * 1000)));

        TEST_SAY("Original committed offsets:\n");
        test_print_partition_list(orig_offsets);

        TEST_SAY("Committed offsets after delete:\n");
        test_print_partition_list(committed);

        if (test_partition_list_cmp(committed, offsets)) {
                TEST_SAY("expected list:\n");
                test_print_partition_list(offsets);
                TEST_SAY("committed() list:\n");
                test_print_partition_list(committed);
                TEST_FAIL("committed offsets don't match");
        }

        rd_kafka_topic_partition_list_destroy(committed);
        rd_kafka_topic_partition_list_destroy(offsets);
        rd_kafka_topic_partition_list_destroy(orig_offsets);
        rd_kafka_topic_partition_list_destroy(subscription);

        for (i = 0; i < MY_TOPIC_CNT; i++)
                rd_free(topics[i]);

        rd_kafka_destroy(consumer);

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

        TEST_LATER_CHECK();
#undef MY_DEL_RECORDS_CNT

        SUB_TEST_PASS();
}


static void do_test_apis(rd_kafka_type_t cltype) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        rd_kafka_queue_t *mainq;

        /* Get the available brokers, but use a separate rd_kafka_t instance
         * so we don't jinx the tests by having up-to-date metadata. */
        avail_brokers = test_get_broker_ids(NULL, &avail_broker_cnt);
        TEST_SAY("%" PRIusz
                 " brokers in cluster "
                 "which will be used for replica sets\n",
                 avail_broker_cnt);

        do_test_unclean_destroy(cltype, 0 /*tempq*/);
        do_test_unclean_destroy(cltype, 1 /*mainq*/);

        test_conf_init(&conf, NULL, 180);
        test_conf_set(conf, "socket.timeout.ms", "10000");
        rk = test_create_handle(cltype, conf);

        mainq = rd_kafka_queue_get_main(rk);

        /* Create topics */
        do_test_CreateTopics("temp queue, op timeout 0", rk, NULL, 0, 0);
        do_test_CreateTopics("temp queue, op timeout 15000", rk, NULL, 15000,
                             0);
        do_test_CreateTopics(
            "temp queue, op timeout 300, "
            "validate only",
            rk, NULL, 300, rd_true);
        do_test_CreateTopics("temp queue, op timeout 9000, validate_only", rk,
                             NULL, 9000, rd_true);
        do_test_CreateTopics("main queue, options", rk, mainq, -1, 0);

        /* Delete topics */
        do_test_DeleteTopics("temp queue, op timeout 0", rk, NULL, 0);
        do_test_DeleteTopics("main queue, op timeout 15000", rk, mainq, 1500);

        if (test_broker_version >= TEST_BRKVER(1, 0, 0, 0)) {
                /* Create Partitions */
                do_test_CreatePartitions("temp queue, op timeout 6500", rk,
                                         NULL, 6500);
                do_test_CreatePartitions("main queue, op timeout 0", rk, mainq,
                                         0);
        }

        /* CreateAcls */
        do_test_CreateAcls(rk, mainq, 0);
        do_test_CreateAcls(rk, mainq, 1);

        /* DescribeAcls */
        do_test_DescribeAcls(rk, mainq, 0);
        do_test_DescribeAcls(rk, mainq, 1);

        /* DeleteAcls */
        do_test_DeleteAcls(rk, mainq, 0);
        do_test_DeleteAcls(rk, mainq, 1);

        /* AlterConfigs */
        do_test_AlterConfigs(rk, mainq);

        /* DescribeConfigs */
        do_test_DescribeConfigs(rk, mainq);

        /* Delete records */
        do_test_DeleteRecords("temp queue, op timeout 0", rk, NULL, 0);
        do_test_DeleteRecords("main queue, op timeout 1500", rk, mainq, 1500);

        /* Delete groups */
        do_test_DeleteGroups("temp queue, op timeout 0", rk, NULL, 0);
        do_test_DeleteGroups("main queue, op timeout 1500", rk, mainq, 1500);
        do_test_DeleteGroups("main queue, op timeout 1500", rk, mainq, 1500);

        if (test_broker_version >= TEST_BRKVER(2, 4, 0, 0)) {
                /* Delete committed offsets */
                do_test_DeleteConsumerGroupOffsets("temp queue, op timeout 0",
                                                   rk, NULL, 0, rd_false);
                do_test_DeleteConsumerGroupOffsets(
                    "main queue, op timeout 1500", rk, mainq, 1500, rd_false);
                do_test_DeleteConsumerGroupOffsets(
                    "main queue, op timeout 1500", rk, mainq, 1500,
                    rd_true /*with subscribing consumer*/);
        }

        rd_kafka_queue_destroy(mainq);

        rd_kafka_destroy(rk);

        free(avail_brokers);
}


int main_0081_admin(int argc, char **argv) {

        do_test_apis(RD_KAFKA_PRODUCER);

        if (test_quick) {
                TEST_SAY("Skipping further 0081 tests due to quick mode\n");
                return 0;
        }

        do_test_apis(RD_KAFKA_CONSUMER);

        return 0;
}
