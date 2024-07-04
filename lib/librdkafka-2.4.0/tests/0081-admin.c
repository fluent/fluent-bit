/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
 *               2023, Confluent Inc.
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
#include "../src/rdstring.h"

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
 * @brief Test IncrementalAlterConfigs
 */
static void do_test_IncrementalAlterConfigs(rd_kafka_t *rk,
                                            rd_kafka_queue_t *rkqu) {
#define MY_CONFRES_CNT 3
        char *topics[MY_CONFRES_CNT];
        rd_kafka_ConfigResource_t *configs[MY_CONFRES_CNT];
        rd_kafka_AdminOptions_t *options;
        rd_kafka_resp_err_t exp_err[MY_CONFRES_CNT];
        rd_kafka_event_t *rkev;
        rd_kafka_resp_err_t err;
        rd_kafka_error_t *error;
        const rd_kafka_IncrementalAlterConfigs_result_t *res;
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


        /** Test the test helper, for use in other tests. */
        do {
                const char *broker_id = tsprintf("%d", avail_brokers[0]);
                const char *confs_set_append[] = {
                    "compression.type", "SET",    "lz4",
                    "cleanup.policy",   "APPEND", "compact"};
                const char *confs_delete_subtract[] = {
                    "compression.type", "DELETE",   "lz4",
                    "cleanup.policy",   "SUBTRACT", "compact"};
                const char *confs_set_append_broker[] = {
                    "background.threads", "SET",    "9",
                    "log.cleanup.policy", "APPEND", "compact"};
                const char *confs_delete_subtract_broker[] = {
                    "background.threads", "DELETE",   "",
                    "log.cleanup.policy", "SUBTRACT", "compact"};

                TEST_SAY("Testing test helper with SET and APPEND\n");
                test_IncrementalAlterConfigs_simple(rk, RD_KAFKA_RESOURCE_TOPIC,
                                                    topics[0], confs_set_append,
                                                    2);
                TEST_SAY("Testing test helper with SUBTRACT and DELETE\n");
                test_IncrementalAlterConfigs_simple(rk, RD_KAFKA_RESOURCE_TOPIC,
                                                    topics[0],
                                                    confs_delete_subtract, 2);

                TEST_SAY(
                    "Testing test helper with SET and APPEND with BROKER "
                    "resource type\n");
                test_IncrementalAlterConfigs_simple(
                    rk, RD_KAFKA_RESOURCE_BROKER, broker_id,
                    confs_set_append_broker, 2);
                TEST_SAY(
                    "Testing test helper with SUBTRACT and DELETE with BROKER "
                    "resource type\n");
                test_IncrementalAlterConfigs_simple(
                    rk, RD_KAFKA_RESOURCE_BROKER, broker_id,
                    confs_delete_subtract_broker, 2);
                TEST_SAY("End testing test helper\n");
        } while (0);

        /*
         * ConfigResource #0: valid topic config
         */
        configs[ci] =
            rd_kafka_ConfigResource_new(RD_KAFKA_RESOURCE_TOPIC, topics[ci]);

        error = rd_kafka_ConfigResource_add_incremental_config(
            configs[ci], "compression.type", RD_KAFKA_ALTER_CONFIG_OP_TYPE_SET,
            "gzip");
        TEST_ASSERT(!error, "%s", rd_kafka_error_string(error));

        error = rd_kafka_ConfigResource_add_incremental_config(
            configs[ci], "flush.ms", RD_KAFKA_ALTER_CONFIG_OP_TYPE_SET,
            "12345678");
        TEST_ASSERT(!error, "%s", rd_kafka_error_string(error));

        exp_err[ci] = RD_KAFKA_RESP_ERR_NO_ERROR;
        ci++;


        if (test_broker_version >= TEST_BRKVER(1, 1, 0, 0)) {
                /*
                 * ConfigResource #1: valid broker config
                 */
                configs[ci] = rd_kafka_ConfigResource_new(
                    RD_KAFKA_RESOURCE_BROKER,
                    tsprintf("%" PRId32, avail_brokers[0]));

                error = rd_kafka_ConfigResource_add_incremental_config(
                    configs[ci], "sasl.kerberos.min.time.before.relogin",
                    RD_KAFKA_ALTER_CONFIG_OP_TYPE_SET, "58000");
                TEST_ASSERT(!error, "%s", rd_kafka_error_string(error));

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

        error = rd_kafka_ConfigResource_add_incremental_config(
            configs[ci], "compression.type", RD_KAFKA_ALTER_CONFIG_OP_TYPE_SET,
            "lz4");
        TEST_ASSERT(!error, "%s", rd_kafka_error_string(error));

        error = rd_kafka_ConfigResource_add_incremental_config(
            configs[ci], "offset.metadata.max.bytes",
            RD_KAFKA_ALTER_CONFIG_OP_TYPE_SET, "12345");
        TEST_ASSERT(!error, "%s", rd_kafka_error_string(error));

        if (test_broker_version >= TEST_BRKVER(2, 7, 0, 0))
                exp_err[ci] = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
        else
                exp_err[ci] = RD_KAFKA_RESP_ERR_UNKNOWN;
        ci++;

        /*
         * Timeout options
         */
        options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_INCREMENTALALTERCONFIGS);
        err = rd_kafka_AdminOptions_set_request_timeout(options, 10000, errstr,
                                                        sizeof(errstr));
        TEST_ASSERT(!err, "%s", errstr);


        /*
         * Fire off request
         */
        rd_kafka_IncrementalAlterConfigs(rk, configs, ci, options, rkqu);

        rd_kafka_AdminOptions_destroy(options);

        /*
         * Wait for result
         */
        rkev = test_wait_admin_result(
            rkqu, RD_KAFKA_EVENT_INCREMENTALALTERCONFIGS_RESULT, 10000 + 1000);

        /*
         * Extract result
         */
        res = rd_kafka_event_IncrementalAlterConfigs_result(rkev);
        TEST_ASSERT(res, "Expected AlterConfigs result, not %s",
                    rd_kafka_event_name(rkev));

        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err, "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        rconfigs = rd_kafka_IncrementalAlterConfigs_result_resources(
            res, &rconfig_cnt);
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
                                 int request_timeout) {
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

        SUB_TEST_QUICK("%s DeleteGroups with %s, request_timeout %d",
                       rd_kafka_name(rk), what, request_timeout);

        q = useq ? useq : rd_kafka_queue_new(rk);

        if (request_timeout != -1) {
                options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_ANY);

                err = rd_kafka_AdminOptions_set_request_timeout(
                    options, request_timeout, errstr, sizeof(errstr));
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
 * @brief Test list groups, creating consumers for a set of groups,
 * listing and deleting them at the end.
 */
static void do_test_ListConsumerGroups(const char *what,
                                       rd_kafka_t *rk,
                                       rd_kafka_queue_t *useq,
                                       int request_timeout,
                                       rd_bool_t match_states) {
#define TEST_LIST_CONSUMER_GROUPS_CNT 4
        rd_kafka_queue_t *q;
        rd_kafka_AdminOptions_t *options = NULL;
        rd_kafka_event_t *rkev           = NULL;
        rd_kafka_resp_err_t err;
        size_t valid_cnt, error_cnt;
        rd_bool_t is_simple_consumer_group;
        rd_kafka_consumer_group_state_t state;
        char errstr[512];
        const char *errstr2, *group_id;
        char *list_consumer_groups[TEST_LIST_CONSUMER_GROUPS_CNT];
        const int partitions_cnt = 1;
        const int msgs_cnt       = 100;
        size_t i, found;
        char *topic;
        rd_kafka_metadata_topic_t exp_mdtopic = {0};
        int64_t testid                        = test_id_generate();
        test_timing_t timing;
        rd_kafka_resp_err_t exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        const rd_kafka_ListConsumerGroups_result_t *res;
        const rd_kafka_ConsumerGroupListing_t **groups;
        rd_bool_t has_match_states =
            test_broker_version >= TEST_BRKVER(2, 7, 0, 0);

        SUB_TEST_QUICK(
            "%s ListConsumerGroups with %s, request_timeout %d"
            ", match_states %s",
            rd_kafka_name(rk), what, request_timeout, RD_STR_ToF(match_states));

        q = useq ? useq : rd_kafka_queue_new(rk);

        if (request_timeout != -1) {
                options = rd_kafka_AdminOptions_new(
                    rk, RD_KAFKA_ADMIN_OP_LISTCONSUMERGROUPS);

                if (match_states) {
                        rd_kafka_consumer_group_state_t empty =
                            RD_KAFKA_CONSUMER_GROUP_STATE_EMPTY;

                        TEST_CALL_ERROR__(
                            rd_kafka_AdminOptions_set_match_consumer_group_states(
                                options, &empty, 1));
                }

                TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
                    options, request_timeout, errstr, sizeof(errstr)));
        }


        topic             = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
        exp_mdtopic.topic = topic;

        /* Create the topics first. */
        test_CreateTopics_simple(rk, NULL, &topic, 1, partitions_cnt, NULL);

        /* Verify that topics are reported by metadata */
        test_wait_metadata_update(rk, &exp_mdtopic, 1, NULL, 0, 15 * 1000);

        /* Produce 100 msgs */
        test_produce_msgs_easy(topic, testid, 0, msgs_cnt);

        for (i = 0; i < TEST_LIST_CONSUMER_GROUPS_CNT; i++) {
                char *group = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
                test_consume_msgs_easy(group, topic, testid, -1, msgs_cnt,
                                       NULL);
                list_consumer_groups[i] = group;
        }

        TIMING_START(&timing, "ListConsumerGroups");
        TEST_SAY("Call ListConsumerGroups\n");
        rd_kafka_ListConsumerGroups(rk, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        TIMING_START(&timing, "ListConsumerGroups.queue_poll");

        /* Poll result queue for ListConsumerGroups result.
         * Print but otherwise ignore other event types
         * (typically generic Error events). */
        while (1) {
                rkev = rd_kafka_queue_poll(q, tmout_multip(20 * 1000));
                TEST_SAY("ListConsumerGroups: got %s in %.3fms\n",
                         rd_kafka_event_name(rkev),
                         TIMING_DURATION(&timing) / 1000.0f);
                if (rkev == NULL)
                        continue;
                if (rd_kafka_event_error(rkev))
                        TEST_SAY("%s: %s\n", rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));

                if (rd_kafka_event_type(rkev) ==
                    RD_KAFKA_EVENT_LISTCONSUMERGROUPS_RESULT) {
                        break;
                }

                rd_kafka_event_destroy(rkev);
        }
        /* Convert event to proper result */
        res = rd_kafka_event_ListConsumerGroups_result(rkev);
        TEST_ASSERT(res, "expected ListConsumerGroups_result, got %s",
                    rd_kafka_event_name(rkev));

        /* Expecting error */
        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(err == exp_err,
                    "expected ListConsumerGroups to return %s, got %s (%s)",
                    rd_kafka_err2str(exp_err), rd_kafka_err2str(err),
                    err ? errstr2 : "n/a");

        TEST_SAY("ListConsumerGroups: returned %s (%s)\n",
                 rd_kafka_err2str(err), err ? errstr2 : "n/a");

        groups = rd_kafka_ListConsumerGroups_result_valid(res, &valid_cnt);
        rd_kafka_ListConsumerGroups_result_errors(res, &error_cnt);

        /* Other tests could be running */
        TEST_ASSERT(valid_cnt >= TEST_LIST_CONSUMER_GROUPS_CNT,
                    "expected ListConsumerGroups to return at least %" PRId32
                    " valid groups,"
                    " got %zu",
                    TEST_LIST_CONSUMER_GROUPS_CNT, valid_cnt);

        TEST_ASSERT(error_cnt == 0,
                    "expected ListConsumerGroups to return 0 errors,"
                    " got %zu",
                    error_cnt);

        found = 0;
        for (i = 0; i < valid_cnt; i++) {
                int j;
                const rd_kafka_ConsumerGroupListing_t *group;
                group    = groups[i];
                group_id = rd_kafka_ConsumerGroupListing_group_id(group);
                is_simple_consumer_group =
                    rd_kafka_ConsumerGroupListing_is_simple_consumer_group(
                        group);
                state = rd_kafka_ConsumerGroupListing_state(group);
                for (j = 0; j < TEST_LIST_CONSUMER_GROUPS_CNT; j++) {
                        if (!strcmp(list_consumer_groups[j], group_id)) {
                                found++;
                                TEST_ASSERT(!is_simple_consumer_group,
                                            "expected a normal group,"
                                            " got a simple group");

                                if (!has_match_states)
                                        break;

                                TEST_ASSERT(
                                    state ==
                                        RD_KAFKA_CONSUMER_GROUP_STATE_EMPTY,
                                    "expected an Empty state,"
                                    " got state %s",
                                    rd_kafka_consumer_group_state_name(state));
                                break;
                        }
                }
        }
        TEST_ASSERT(found == TEST_LIST_CONSUMER_GROUPS_CNT,
                    "expected to find %d"
                    " started groups,"
                    " got %" PRIusz,
                    TEST_LIST_CONSUMER_GROUPS_CNT, found);

        rd_kafka_event_destroy(rkev);

        test_DeleteGroups_simple(rk, NULL, (char **)list_consumer_groups,
                                 TEST_LIST_CONSUMER_GROUPS_CNT, NULL);

        for (i = 0; i < TEST_LIST_CONSUMER_GROUPS_CNT; i++) {
                rd_free(list_consumer_groups[i]);
        }

        rd_free(topic);

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

        TEST_LATER_CHECK();
#undef TEST_LIST_CONSUMER_GROUPS_CNT

        SUB_TEST_PASS();
}

typedef struct expected_DescribeConsumerGroups_result {
        char *group_id;
        rd_kafka_resp_err_t err;
} expected_DescribeConsumerGroups_result_t;


/**
 * @brief Test describe groups, creating consumers for a set of groups,
 * describing and deleting them at the end.
 */
static void do_test_DescribeConsumerGroups(const char *what,
                                           rd_kafka_t *rk,
                                           rd_kafka_queue_t *useq,
                                           int request_timeout) {
        rd_kafka_queue_t *q;
        rd_kafka_AdminOptions_t *options = NULL;
        rd_kafka_event_t *rkev           = NULL;
        rd_kafka_resp_err_t err;
        char errstr[512];
        const char *errstr2;
#define TEST_DESCRIBE_CONSUMER_GROUPS_CNT 4
        int known_groups = TEST_DESCRIBE_CONSUMER_GROUPS_CNT - 1;
        int i;
        const int partitions_cnt = 1;
        const int msgs_cnt       = 100;
        char *topic;
        rd_kafka_metadata_topic_t exp_mdtopic = {0};
        int64_t testid                        = test_id_generate();
        test_timing_t timing;
        rd_kafka_resp_err_t exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        const rd_kafka_ConsumerGroupDescription_t **results = NULL;
        expected_DescribeConsumerGroups_result_t
            expected[TEST_DESCRIBE_CONSUMER_GROUPS_CNT] = RD_ZERO_INIT;
        const char *describe_groups[TEST_DESCRIBE_CONSUMER_GROUPS_CNT];
        char group_instance_ids[TEST_DESCRIBE_CONSUMER_GROUPS_CNT][512];
        char client_ids[TEST_DESCRIBE_CONSUMER_GROUPS_CNT][512];
        rd_kafka_t *rks[TEST_DESCRIBE_CONSUMER_GROUPS_CNT];
        const rd_kafka_DescribeConsumerGroups_result_t *res;
        size_t authorized_operation_cnt;
        rd_bool_t has_group_instance_id =
            test_broker_version >= TEST_BRKVER(2, 4, 0, 0);

        SUB_TEST_QUICK("%s DescribeConsumerGroups with %s, request_timeout %d",
                       rd_kafka_name(rk), what, request_timeout);

        q = useq ? useq : rd_kafka_queue_new(rk);

        if (request_timeout != -1) {
                options = rd_kafka_AdminOptions_new(
                    rk, RD_KAFKA_ADMIN_OP_DESCRIBECONSUMERGROUPS);

                err = rd_kafka_AdminOptions_set_request_timeout(
                    options, request_timeout, errstr, sizeof(errstr));
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

        for (i = 0; i < TEST_DESCRIBE_CONSUMER_GROUPS_CNT; i++) {
                rd_kafka_conf_t *conf;
                char *group_id = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
                if (i < known_groups) {
                        snprintf(group_instance_ids[i],
                                 sizeof(group_instance_ids[i]),
                                 "group_instance_id_%" PRId32, i);
                        snprintf(client_ids[i], sizeof(client_ids[i]),
                                 "client_id_%" PRId32, i);

                        test_conf_init(&conf, NULL, 0);
                        test_conf_set(conf, "client.id", client_ids[i]);
                        test_conf_set(conf, "group.instance.id",
                                      group_instance_ids[i]);
                        test_conf_set(conf, "session.timeout.ms", "5000");
                        test_conf_set(conf, "auto.offset.reset", "earliest");
                        rks[i] =
                            test_create_consumer(group_id, NULL, conf, NULL);
                        test_consumer_subscribe(rks[i], topic);
                        /* Consume messages */
                        test_consumer_poll("consumer", rks[i], testid, -1, -1,
                                           msgs_cnt, NULL);
                }
                expected[i].group_id = group_id;
                expected[i].err      = RD_KAFKA_RESP_ERR_NO_ERROR;
                describe_groups[i]   = group_id;
        }

        TIMING_START(&timing, "DescribeConsumerGroups");
        TEST_SAY("Call DescribeConsumerGroups\n");
        rd_kafka_DescribeConsumerGroups(
            rk, describe_groups, TEST_DESCRIBE_CONSUMER_GROUPS_CNT, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        TIMING_START(&timing, "DescribeConsumerGroups.queue_poll");

        /* Poll result queue for DescribeConsumerGroups result.
         * Print but otherwise ignore other event types
         * (typically generic Error events). */
        while (1) {
                rkev = rd_kafka_queue_poll(q, tmout_multip(20 * 1000));
                TEST_SAY("DescribeConsumerGroups: got %s in %.3fms\n",
                         rd_kafka_event_name(rkev),
                         TIMING_DURATION(&timing) / 1000.0f);
                if (rkev == NULL)
                        continue;
                if (rd_kafka_event_error(rkev))
                        TEST_SAY("%s: %s\n", rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));

                if (rd_kafka_event_type(rkev) ==
                    RD_KAFKA_EVENT_DESCRIBECONSUMERGROUPS_RESULT) {
                        break;
                }

                rd_kafka_event_destroy(rkev);
        }
        /* Convert event to proper result */
        res = rd_kafka_event_DescribeConsumerGroups_result(rkev);
        TEST_ASSERT(res, "expected DescribeConsumerGroups_result, got %s",
                    rd_kafka_event_name(rkev));

        /* Expecting error */
        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(err == exp_err,
                    "expected DescribeConsumerGroups to return %s, got %s (%s)",
                    rd_kafka_err2str(exp_err), rd_kafka_err2str(err),
                    err ? errstr2 : "n/a");

        TEST_SAY("DescribeConsumerGroups: returned %s (%s)\n",
                 rd_kafka_err2str(err), err ? errstr2 : "n/a");

        size_t cnt = 0;
        results    = rd_kafka_DescribeConsumerGroups_result_groups(res, &cnt);

        TEST_ASSERT(
            TEST_DESCRIBE_CONSUMER_GROUPS_CNT == cnt,
            "expected DescribeConsumerGroups_result_groups to return %d items, "
            "got %" PRIusz,
            TEST_DESCRIBE_CONSUMER_GROUPS_CNT, cnt);

        for (i = 0; i < TEST_DESCRIBE_CONSUMER_GROUPS_CNT; i++) {
                expected_DescribeConsumerGroups_result_t *exp  = &expected[i];
                rd_kafka_resp_err_t exp_err                    = exp->err;
                const rd_kafka_ConsumerGroupDescription_t *act = results[i];
                rd_kafka_resp_err_t act_err = rd_kafka_error_code(
                    rd_kafka_ConsumerGroupDescription_error(act));
                rd_kafka_consumer_group_state_t state =
                    rd_kafka_ConsumerGroupDescription_state(act);
                const rd_kafka_AclOperation_t *authorized_operations =
                    rd_kafka_ConsumerGroupDescription_authorized_operations(
                        act, &authorized_operation_cnt);
                TEST_ASSERT(
                    authorized_operation_cnt == 0,
                    "Authorized operation count should be 0, is %" PRIusz,
                    authorized_operation_cnt);
                TEST_ASSERT(
                    authorized_operations == NULL,
                    "Authorized operations should be NULL when not requested");
                TEST_ASSERT(
                    strcmp(exp->group_id,
                           rd_kafka_ConsumerGroupDescription_group_id(act)) ==
                        0,
                    "Result order mismatch at #%d: expected group id to be "
                    "%s, got %s",
                    i, exp->group_id,
                    rd_kafka_ConsumerGroupDescription_group_id(act));
                if (i < known_groups) {
                        int member_count;
                        const rd_kafka_MemberDescription_t *member;
                        const rd_kafka_MemberAssignment_t *assignment;
                        const char *client_id;
                        const char *group_instance_id;
                        const rd_kafka_topic_partition_list_t *partitions;

                        TEST_ASSERT(state ==
                                        RD_KAFKA_CONSUMER_GROUP_STATE_STABLE,
                                    "Expected Stable state, got %s.",
                                    rd_kafka_consumer_group_state_name(state));

                        TEST_ASSERT(
                            !rd_kafka_ConsumerGroupDescription_is_simple_consumer_group(
                                act),
                            "Expected a normal consumer group, got a simple "
                            "one.");

                        member_count =
                            rd_kafka_ConsumerGroupDescription_member_count(act);
                        TEST_ASSERT(member_count == 1,
                                    "Expected one member, got %d.",
                                    member_count);

                        member =
                            rd_kafka_ConsumerGroupDescription_member(act, 0);

                        client_id =
                            rd_kafka_MemberDescription_client_id(member);
                        TEST_ASSERT(!strcmp(client_id, client_ids[i]),
                                    "Expected client id \"%s\","
                                    " got \"%s\".",
                                    client_ids[i], client_id);

                        if (has_group_instance_id) {
                                group_instance_id =
                                    rd_kafka_MemberDescription_group_instance_id(
                                        member);
                                TEST_ASSERT(!strcmp(group_instance_id,
                                                    group_instance_ids[i]),
                                            "Expected group instance id \"%s\","
                                            " got \"%s\".",
                                            group_instance_ids[i],
                                            group_instance_id);
                        }

                        assignment =
                            rd_kafka_MemberDescription_assignment(member);
                        TEST_ASSERT(assignment != NULL,
                                    "Expected non-NULL member assignment");

                        partitions =
                            rd_kafka_MemberAssignment_partitions(assignment);
                        TEST_ASSERT(partitions != NULL,
                                    "Expected non-NULL member partitions");

                        TEST_SAY(
                            "Member client.id=\"%s\", "
                            "group.instance.id=\"%s\", "
                            "consumer_id=\"%s\", "
                            "host=\"%s\", assignment:\n",
                            rd_kafka_MemberDescription_client_id(member),
                            rd_kafka_MemberDescription_group_instance_id(
                                member),
                            rd_kafka_MemberDescription_consumer_id(member),
                            rd_kafka_MemberDescription_host(member));
                        /* This is just to make sure the returned memory
                         * is valid. */
                        test_print_partition_list(partitions);
                } else {
                        TEST_ASSERT(state == RD_KAFKA_CONSUMER_GROUP_STATE_DEAD,
                                    "Expected Dead state, got %s.",
                                    rd_kafka_consumer_group_state_name(state));
                }
                TEST_ASSERT(exp_err == act_err,
                            "expected err=%d for group %s, got %d (%s)",
                            exp_err, exp->group_id, act_err,
                            rd_kafka_err2str(act_err));
        }

        rd_kafka_event_destroy(rkev);

        for (i = 0; i < known_groups; i++) {
                test_consumer_close(rks[i]);
                rd_kafka_destroy(rks[i]);
        }

        /* Wait session timeout + 1s. Because using static group membership */
        rd_sleep(6);

        test_DeleteGroups_simple(rk, NULL, (char **)describe_groups,
                                 known_groups, NULL);

        for (i = 0; i < TEST_DESCRIBE_CONSUMER_GROUPS_CNT; i++) {
                rd_free(expected[i].group_id);
        }

        test_DeleteTopics_simple(rk, NULL, &topic, 1, NULL);

        rd_free(topic);

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

        TEST_LATER_CHECK();
#undef TEST_DESCRIBE_CONSUMER_GROUPS_CNT

        SUB_TEST_PASS();
}

/** @brief Helper function to check whether \p expected and \p actual contain
 * the same values. */
static void
test_match_authorized_operations(const rd_kafka_AclOperation_t *expected,
                                 size_t expected_cnt,
                                 const rd_kafka_AclOperation_t *actual,
                                 size_t actual_cnt) {
        size_t i, j;
        TEST_ASSERT(expected_cnt == actual_cnt,
                    "Expected %" PRIusz " authorized operations, got %" PRIusz,
                    expected_cnt, actual_cnt);

        for (i = 0; i < expected_cnt; i++) {
                for (j = 0; j < actual_cnt; j++)
                        if (expected[i] == actual[j])
                                break;

                if (j == actual_cnt)
                        TEST_FAIL(
                            "Did not find expected authorized operation in "
                            "result %s\n",
                            rd_kafka_AclOperation_name(expected[i]));
        }
}

/**
 * @brief Test DescribeTopics: create a topic, describe it, and then
 * delete it.
 *
 * @param include_authorized_operations if true, check authorized
 * operations included in topic descriptions, and if they're changed if
 * ACLs are defined.
 */
static void do_test_DescribeTopics(const char *what,
                                   rd_kafka_t *rk,
                                   rd_kafka_queue_t *rkqu,
                                   int request_timeout,
                                   rd_bool_t include_authorized_operations) {
        rd_kafka_queue_t *q;
#define TEST_DESCRIBE_TOPICS_CNT 3
        char *topic_names[TEST_DESCRIBE_TOPICS_CNT];
        rd_kafka_TopicCollection_t *topics, *empty_topics;
        rd_kafka_AdminOptions_t *options;
        rd_kafka_event_t *rkev;
        const rd_kafka_error_t *error;
        rd_kafka_resp_err_t err;
        test_timing_t timing;
        const rd_kafka_DescribeTopics_result_t *res;
        const rd_kafka_TopicDescription_t **result_topics;
        const rd_kafka_TopicPartitionInfo_t **partitions;
        const rd_kafka_Uuid_t *topic_id;
        size_t partitions_cnt;
        size_t result_topics_cnt;
        char errstr[128];
        const char *errstr2;
        const char *sasl_username;
        const char *sasl_mechanism;
        const char *principal;
        rd_kafka_AclBinding_t *acl_bindings[1];
        int i;
        const rd_kafka_AclOperation_t *authorized_operations;
        size_t authorized_operations_cnt;

        SUB_TEST_QUICK(
            "%s DescribeTopics with %s, request_timeout %d, "
            "%s authorized operations",
            rd_kafka_name(rk), what, request_timeout,
            include_authorized_operations ? "with" : "without");

        q = rkqu ? rkqu : rd_kafka_queue_new(rk);

        /* Only create one topic, the others will be non-existent. */
        for (i = 0; i < TEST_DESCRIBE_TOPICS_CNT; i++) {
                rd_strdupa(&topic_names[i],
                           test_mk_topic_name(__FUNCTION__, 1));
        }
        topics = rd_kafka_TopicCollection_of_topic_names(
            (const char **)topic_names, TEST_DESCRIBE_TOPICS_CNT);
        empty_topics = rd_kafka_TopicCollection_of_topic_names(NULL, 0);

        test_CreateTopics_simple(rk, NULL, topic_names, 1, 1, NULL);
        test_wait_topic_exists(rk, topic_names[0], 10000);

        options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DESCRIBETOPICS);
        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, request_timeout, errstr, sizeof(errstr)));
        TEST_CALL_ERROR__(
            rd_kafka_AdminOptions_set_include_authorized_operations(
                options, include_authorized_operations));

        /* Call DescribeTopics with empty topics. */
        TIMING_START(&timing, "DescribeTopics empty");
        rd_kafka_DescribeTopics(rk, empty_topics, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /* Check DescribeTopics results. */
        rkev = test_wait_admin_result(q, RD_KAFKA_EVENT_DESCRIBETOPICS_RESULT,
                                      tmout_multip(20 * 1000));
        TEST_ASSERT(rkev, "Expected DescribeTopicsResult on queue");

        /* Extract result. */
        res = rd_kafka_event_DescribeTopics_result(rkev);
        TEST_ASSERT(res, "Expected DescribeTopics result, not %s",
                    rd_kafka_event_name(rkev));

        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err, "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        result_topics =
            rd_kafka_DescribeTopics_result_topics(res, &result_topics_cnt);

        /* Check no result is received. */
        TEST_ASSERT((int)result_topics_cnt == 0,
                    "Expected 0 topics in result, got %d",
                    (int)result_topics_cnt);

        rd_kafka_event_destroy(rkev);

        /* Call DescribeTopics with all of them. */
        TIMING_START(&timing, "DescribeTopics all");
        rd_kafka_DescribeTopics(rk, topics, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        /* Check DescribeTopics results. */
        rkev = test_wait_admin_result(q, RD_KAFKA_EVENT_DESCRIBETOPICS_RESULT,
                                      tmout_multip(20 * 1000));
        TEST_ASSERT(rkev, "Expected DescribeTopicsResult on queue");

        /* Extract result. */
        res = rd_kafka_event_DescribeTopics_result(rkev);
        TEST_ASSERT(res, "Expected DescribeTopics result, not %s",
                    rd_kafka_event_name(rkev));

        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err, "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        result_topics =
            rd_kafka_DescribeTopics_result_topics(res, &result_topics_cnt);

        /* Check if results have been received for all topics. */
        TEST_ASSERT((int)result_topics_cnt == TEST_DESCRIBE_TOPICS_CNT,
                    "Expected %d topics in result, got %d",
                    TEST_DESCRIBE_TOPICS_CNT, (int)result_topics_cnt);

        /* Check if topics[0] succeeded. */
        error = rd_kafka_TopicDescription_error(result_topics[0]);
        TEST_ASSERT(rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected no error, not %s\n",
                    rd_kafka_error_string(error));

        /*
         * Check whether the topics which are non-existent have
         * RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART error.
         */
        for (i = 1; i < TEST_DESCRIBE_TOPICS_CNT; i++) {
                error = rd_kafka_TopicDescription_error(result_topics[i]);
                TEST_ASSERT(rd_kafka_error_code(error) ==
                                RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART,
                            "Expected unknown Topic or partition, not %s\n",
                            rd_kafka_error_string(error));
        }

        /* Check fields inside the first (existent) topic. */
        TEST_ASSERT(strcmp(rd_kafka_TopicDescription_name(result_topics[0]),
                           topic_names[0]) == 0,
                    "Expected topic name %s, got %s", topic_names[0],
                    rd_kafka_TopicDescription_name(result_topics[0]));

        topic_id = rd_kafka_TopicDescription_topic_id(result_topics[0]);

        TEST_ASSERT(topic_id, "Expected Topic Id to present.");

        partitions = rd_kafka_TopicDescription_partitions(result_topics[0],
                                                          &partitions_cnt);

        TEST_ASSERT(partitions_cnt == 1, "Expected %d partitions, got %" PRIusz,
                    1, partitions_cnt);

        TEST_ASSERT(rd_kafka_TopicPartitionInfo_partition(partitions[0]) == 0,
                    "Expected partion id to be %d, got %d", 0,
                    rd_kafka_TopicPartitionInfo_partition(partitions[0]));

        authorized_operations = rd_kafka_TopicDescription_authorized_operations(
            result_topics[0], &authorized_operations_cnt);
        if (include_authorized_operations) {
                const rd_kafka_AclOperation_t expected[] = {
                    RD_KAFKA_ACL_OPERATION_ALTER,
                    RD_KAFKA_ACL_OPERATION_ALTER_CONFIGS,
                    RD_KAFKA_ACL_OPERATION_CREATE,
                    RD_KAFKA_ACL_OPERATION_DELETE,
                    RD_KAFKA_ACL_OPERATION_DESCRIBE,
                    RD_KAFKA_ACL_OPERATION_DESCRIBE_CONFIGS,
                    RD_KAFKA_ACL_OPERATION_READ,
                    RD_KAFKA_ACL_OPERATION_WRITE};

                test_match_authorized_operations(expected, 8,
                                                 authorized_operations,
                                                 authorized_operations_cnt);
        } else {
                TEST_ASSERT(
                    authorized_operations_cnt == 0,
                    "Authorized operation count should be 0, is %" PRIusz,
                    authorized_operations_cnt);
                TEST_ASSERT(
                    authorized_operations == NULL,
                    "Authorized operations should be NULL when not requested");
        }

        rd_kafka_AdminOptions_destroy(options);
        rd_kafka_event_destroy(rkev);

        /* If we don't have authentication/authorization set up in our
         * broker, the following test doesn't make sense, since we're
         * testing ACLs and authorized operations for our principal. The
         * same goes for `include_authorized_operations`, if it's not
         * true, it doesn't make sense to change the ACLs and check. We
         * limit ourselves to SASL_PLAIN and SASL_SCRAM.*/
        if (!test_needs_auth() || !include_authorized_operations)
                goto done;

        sasl_mechanism = test_conf_get(NULL, "sasl.mechanism");
        if (strcmp(sasl_mechanism, "PLAIN") != 0 &&
            strncmp(sasl_mechanism, "SCRAM", 5) != 0)
                goto done;

        sasl_username = test_conf_get(NULL, "sasl.username");
        principal     = tsprintf("User:%s", sasl_username);

        /* Change authorized operations for the principal which we're
         * using to connect to the broker. */
        acl_bindings[0] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_TOPIC, topic_names[0],
            RD_KAFKA_RESOURCE_PATTERN_LITERAL, principal, "*",
            RD_KAFKA_ACL_OPERATION_READ, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);
        TEST_CALL_ERR__(
            test_CreateAcls_simple(rk, NULL, acl_bindings, 1, NULL));
        rd_kafka_AclBinding_destroy(acl_bindings[0]);

        /* Call DescribeTopics. */
        options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DESCRIBETOPICS);
        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, request_timeout, errstr, sizeof(errstr)));
        TEST_CALL_ERROR__(
            rd_kafka_AdminOptions_set_include_authorized_operations(options,
                                                                    1));

        TIMING_START(&timing, "DescribeTopics");
        rd_kafka_DescribeTopics(rk, topics, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);
        rd_kafka_AdminOptions_destroy(options);

        /* Check DescribeTopics results. */
        rkev = test_wait_admin_result(q, RD_KAFKA_EVENT_DESCRIBETOPICS_RESULT,
                                      tmout_multip(20 * 1000));
        TEST_ASSERT(rkev, "Expected DescribeTopicsResult on queue");

        /* Extract result. */
        res = rd_kafka_event_DescribeTopics_result(rkev);
        TEST_ASSERT(res, "Expected DescribeTopics result, not %s",
                    rd_kafka_event_name(rkev));

        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err, "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        result_topics =
            rd_kafka_DescribeTopics_result_topics(res, &result_topics_cnt);

        /* Check if results have been received for all topics. */
        TEST_ASSERT((int)result_topics_cnt == TEST_DESCRIBE_TOPICS_CNT,
                    "Expected %d topics in result, got %d",
                    TEST_DESCRIBE_TOPICS_CNT, (int)result_topics_cnt);

        /* Check if topics[0] succeeded. */
        error = rd_kafka_TopicDescription_error(result_topics[0]);
        TEST_ASSERT(rd_kafka_error_code(error) == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected no error, not %s\n",
                    rd_kafka_error_string(error));

        /* Check if ACLs changed. */
        {
                const rd_kafka_AclOperation_t expected[] = {
                    RD_KAFKA_ACL_OPERATION_READ,
                    RD_KAFKA_ACL_OPERATION_DESCRIBE};
                authorized_operations =
                    rd_kafka_TopicDescription_authorized_operations(
                        result_topics[0], &authorized_operations_cnt);

                test_match_authorized_operations(expected, 2,
                                                 authorized_operations,
                                                 authorized_operations_cnt);
        }
        rd_kafka_event_destroy(rkev);

        /*
         * Allow RD_KAFKA_ACL_OPERATION_DELETE to allow deletion
         * of the created topic as currently our principal only has read
         * and describe.
         */
        acl_bindings[0] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_TOPIC, topic_names[0],
            RD_KAFKA_RESOURCE_PATTERN_LITERAL, principal, "*",
            RD_KAFKA_ACL_OPERATION_DELETE, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);
        TEST_CALL_ERR__(
            test_CreateAcls_simple(rk, NULL, acl_bindings, 1, NULL));
        rd_kafka_AclBinding_destroy(acl_bindings[0]);

done:
        test_DeleteTopics_simple(rk, NULL, topic_names, 1, NULL);
        if (!rkqu)
                rd_kafka_queue_destroy(q);

        rd_kafka_TopicCollection_destroy(topics);
        rd_kafka_TopicCollection_destroy(empty_topics);


        TEST_LATER_CHECK();
#undef TEST_DESCRIBE_TOPICS_CNT

        SUB_TEST_PASS();
}

/**
 * @brief Test DescribeCluster for the test cluster.
 *
 * @param include_authorized_operations if true, check authorized operations
 * included in cluster description, and if they're changed if ACLs are defined.
 */
static void do_test_DescribeCluster(const char *what,
                                    rd_kafka_t *rk,
                                    rd_kafka_queue_t *rkqu,
                                    int request_timeout,
                                    rd_bool_t include_authorized_operations) {
        rd_kafka_queue_t *q;
        rd_kafka_AdminOptions_t *options;
        rd_kafka_event_t *rkev;
        rd_kafka_resp_err_t err;
        test_timing_t timing;
        const rd_kafka_DescribeCluster_result_t *res;
        const rd_kafka_Node_t **nodes;
        size_t node_cnt;
        char errstr[128];
        const char *errstr2;
        rd_kafka_AclBinding_t *acl_bindings[1];
        rd_kafka_AclBindingFilter_t *acl_bindings_delete;
        const rd_kafka_AclOperation_t *authorized_operations;
        size_t authorized_operations_cnt;
        const char *sasl_username;
        const char *sasl_mechanism;
        const char *principal;

        SUB_TEST_QUICK(
            "%s DescribeCluster with %s, request_timeout %d, %s authorized "
            "operations",
            rd_kafka_name(rk), what, request_timeout,
            include_authorized_operations ? "with" : "without");

        q = rkqu ? rkqu : rd_kafka_queue_new(rk);

        /* Call DescribeCluster. */
        options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DESCRIBECLUSTER);
        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, request_timeout, errstr, sizeof(errstr)));
        TEST_CALL_ERROR__(
            rd_kafka_AdminOptions_set_include_authorized_operations(
                options, include_authorized_operations));

        TIMING_START(&timing, "DescribeCluster");
        rd_kafka_DescribeCluster(rk, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);
        rd_kafka_AdminOptions_destroy(options);

        /* Wait for DescribeCluster result.*/
        rkev = test_wait_admin_result(q, RD_KAFKA_EVENT_DESCRIBECLUSTER_RESULT,
                                      tmout_multip(20 * 1000));
        TEST_ASSERT(rkev, "Should receive describe cluster event.");

        /* Extract result. */
        res = rd_kafka_event_DescribeCluster_result(rkev);
        TEST_ASSERT(res, "Expected DescribeCluster result, not %s",
                    rd_kafka_event_name(rkev));

        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err, "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        /* Sanity checks on fields inside the result. There's not much we can
         * say here deterministically, since it depends on the test environment.
         */
        TEST_ASSERT(strlen(rd_kafka_DescribeCluster_result_cluster_id(res)),
                    "Length of cluster id should be non-null.");

        nodes = rd_kafka_DescribeCluster_result_nodes(res, &node_cnt);
        TEST_ASSERT(node_cnt, "Expected non-zero node count for cluster.");

        TEST_ASSERT(rd_kafka_Node_host(nodes[0]),
                    "Expected first node of cluster to have a hostname");
        TEST_ASSERT(rd_kafka_Node_port(nodes[0]),
                    "Expected first node of cluster to have a port");

        authorized_operations =
            rd_kafka_DescribeCluster_result_authorized_operations(
                res, &authorized_operations_cnt);
        if (include_authorized_operations) {
                const rd_kafka_AclOperation_t expected[] = {
                    RD_KAFKA_ACL_OPERATION_ALTER,
                    RD_KAFKA_ACL_OPERATION_ALTER_CONFIGS,
                    RD_KAFKA_ACL_OPERATION_CLUSTER_ACTION,
                    RD_KAFKA_ACL_OPERATION_CREATE,
                    RD_KAFKA_ACL_OPERATION_DESCRIBE,
                    RD_KAFKA_ACL_OPERATION_DESCRIBE_CONFIGS,
                    RD_KAFKA_ACL_OPERATION_IDEMPOTENT_WRITE};

                test_match_authorized_operations(expected, 7,
                                                 authorized_operations,
                                                 authorized_operations_cnt);
        } else {
                TEST_ASSERT(
                    authorized_operations_cnt == 0,
                    "Authorized operation count should be 0, is %" PRIusz,
                    authorized_operations_cnt);
                TEST_ASSERT(
                    authorized_operations == NULL,
                    "Authorized operations should be NULL when not requested");
        }

        rd_kafka_event_destroy(rkev);

        /* If we don't have authentication/authorization set up in our broker,
         * the following test doesn't make sense, since we're testing ACLs and
         * authorized operations for our principal. The same goes for
         * `include_authorized_operations`, if it's not true, it doesn't make
         * sense to change the ACLs and check. We limit ourselves to SASL_PLAIN
         * and SASL_SCRAM.*/
        if (!test_needs_auth() || !include_authorized_operations)
                goto done;

        sasl_mechanism = test_conf_get(NULL, "sasl.mechanism");
        if (strcmp(sasl_mechanism, "PLAIN") != 0 &&
            strncmp(sasl_mechanism, "SCRAM", 5) != 0)
                goto done;

        sasl_username = test_conf_get(NULL, "sasl.username");
        principal     = tsprintf("User:%s", sasl_username);

        /* Change authorized operations for the principal which we're using to
         * connect to the broker. */
        acl_bindings[0] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_BROKER, "kafka-cluster",
            RD_KAFKA_RESOURCE_PATTERN_LITERAL, principal, "*",
            RD_KAFKA_ACL_OPERATION_ALTER, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);
        test_CreateAcls_simple(rk, NULL, acl_bindings, 1, NULL);
        rd_kafka_AclBinding_destroy(acl_bindings[0]);

        /* Call DescribeCluster. */
        options =
            rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_DESCRIBECLUSTER);

        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, request_timeout, errstr, sizeof(errstr)));
        TEST_CALL_ERROR__(
            rd_kafka_AdminOptions_set_include_authorized_operations(options,
                                                                    1));

        TIMING_START(&timing, "DescribeCluster");
        rd_kafka_DescribeCluster(rk, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);
        rd_kafka_AdminOptions_destroy(options);

        rkev = test_wait_admin_result(q, RD_KAFKA_EVENT_DESCRIBECLUSTER_RESULT,
                                      tmout_multip(20 * 1000));
        TEST_ASSERT(rkev, "Should receive describe cluster event.");

        /*  Extract result. */
        res = rd_kafka_event_DescribeCluster_result(rkev);
        TEST_ASSERT(res, "Expected DescribeCluster result, not %s",
                    rd_kafka_event_name(rkev));

        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err, "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        /*
         * After CreateAcls call with
         * only RD_KAFKA_ACL_OPERATION_ALTER allowed, the allowed operations
         * should be 2 (DESCRIBE is implicitly derived from ALTER).
         */
        {
                const rd_kafka_AclOperation_t expected[] = {
                    RD_KAFKA_ACL_OPERATION_ALTER,
                    RD_KAFKA_ACL_OPERATION_DESCRIBE};
                authorized_operations =
                    rd_kafka_DescribeCluster_result_authorized_operations(
                        res, &authorized_operations_cnt);

                test_match_authorized_operations(expected, 2,
                                                 authorized_operations,
                                                 authorized_operations_cnt);
        }

        rd_kafka_event_destroy(rkev);

        /*
         * Remove the previously created ACL so that it doesn't affect other
         * tests.
         */
        acl_bindings_delete = rd_kafka_AclBindingFilter_new(
            RD_KAFKA_RESOURCE_BROKER, "kafka-cluster",
            RD_KAFKA_RESOURCE_PATTERN_MATCH, principal, "*",
            RD_KAFKA_ACL_OPERATION_ALTER, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);
        test_DeleteAcls_simple(rk, NULL, &acl_bindings_delete, 1, NULL);
        rd_kafka_AclBinding_destroy(acl_bindings_delete);

done:
        TEST_LATER_CHECK();

        if (!rkqu)
                rd_kafka_queue_destroy(q);

        SUB_TEST_PASS();
}

/**
 * @brief Test DescribeConsumerGroups's authorized_operations, creating a
 * consumer for a group, describing it, changing ACLs, and describing it again.
 */
static void
do_test_DescribeConsumerGroups_with_authorized_ops(const char *what,
                                                   rd_kafka_t *rk,
                                                   rd_kafka_queue_t *useq,
                                                   int request_timeout) {
        rd_kafka_queue_t *q;
        rd_kafka_AdminOptions_t *options = NULL;
        rd_kafka_event_t *rkev           = NULL;
        rd_kafka_resp_err_t err;
        const rd_kafka_error_t *error;
        char errstr[512];
        const char *errstr2;
#define TEST_DESCRIBE_CONSUMER_GROUPS_CNT 4
        const int partitions_cnt = 1;
        const int msgs_cnt       = 100;
        char *topic, *group_id;
        rd_kafka_AclBinding_t *acl_bindings[TEST_DESCRIBE_CONSUMER_GROUPS_CNT];
        int64_t testid = test_id_generate();
        const rd_kafka_ConsumerGroupDescription_t **results = NULL;
        size_t results_cnt;
        const rd_kafka_DescribeConsumerGroups_result_t *res;
        const char *principal, *sasl_mechanism, *sasl_username;
        const rd_kafka_AclOperation_t *authorized_operations;
        size_t authorized_operations_cnt;

        SUB_TEST_QUICK("%s DescribeConsumerGroups with %s, request_timeout %d",
                       rd_kafka_name(rk), what, request_timeout);

        if (!test_needs_auth())
                SUB_TEST_SKIP("Test requires authorization to be setup.");

        sasl_mechanism = test_conf_get(NULL, "sasl.mechanism");
        if (strcmp(sasl_mechanism, "PLAIN") != 0 &&
            strncmp(sasl_mechanism, "SCRAM", 5) != 0)
                SUB_TEST_SKIP("Test requites SASL_PLAIN or SASL_SCRAM, got %s",
                              sasl_mechanism);

        sasl_username = test_conf_get(NULL, "sasl.username");
        principal     = tsprintf("User:%s", sasl_username);

        topic = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));

        /* Create the topic. */
        test_CreateTopics_simple(rk, NULL, &topic, 1, partitions_cnt, NULL);
        test_wait_topic_exists(rk, topic, 10000);

        /* Produce 100 msgs */
        test_produce_msgs_easy(topic, testid, 0, msgs_cnt);

        /* Create and consumer (and consumer group). */
        group_id = rd_strdup(test_mk_topic_name(__FUNCTION__, 1));
        test_consume_msgs_easy(group_id, topic, testid, -1, 100, NULL);

        q = useq ? useq : rd_kafka_queue_new(rk);

        options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_DESCRIBECONSUMERGROUPS);

        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, request_timeout, errstr, sizeof(errstr)));
        TEST_CALL_ERROR__(
            rd_kafka_AdminOptions_set_include_authorized_operations(options,
                                                                    1));

        rd_kafka_DescribeConsumerGroups(rk, (const char **)(&group_id), 1,
                                        options, q);
        rd_kafka_AdminOptions_destroy(options);

        rkev = test_wait_admin_result(
            q, RD_KAFKA_EVENT_DESCRIBECONSUMERGROUPS_RESULT,
            tmout_multip(20 * 1000));
        TEST_ASSERT(rkev, "Should receive describe consumer groups event.");

        /*  Extract result. */
        res = rd_kafka_event_DescribeConsumerGroups_result(rkev);
        TEST_ASSERT(res, "Expected DescribeConsumerGroup result, not %s",
                    rd_kafka_event_name(rkev));

        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err, "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        results =
            rd_kafka_DescribeConsumerGroups_result_groups(res, &results_cnt);
        TEST_ASSERT((int)results_cnt == 1, "Expected 1 group, got %d",
                    (int)results_cnt);

        error = rd_kafka_ConsumerGroupDescription_error(results[0]);
        TEST_ASSERT(!error, "Expected no error in describing group, got: %s",
                    rd_kafka_error_string(error));

        {
                const rd_kafka_AclOperation_t expected[] = {
                    RD_KAFKA_ACL_OPERATION_DELETE,
                    RD_KAFKA_ACL_OPERATION_DESCRIBE,
                    RD_KAFKA_ACL_OPERATION_READ};
                authorized_operations =
                    rd_kafka_ConsumerGroupDescription_authorized_operations(
                        results[0], &authorized_operations_cnt);
                test_match_authorized_operations(expected, 3,
                                                 authorized_operations,
                                                 authorized_operations_cnt);
        }

        rd_kafka_event_destroy(rkev);

        /* Change authorized operations for the principal which we're using to
         * connect to the broker. */
        acl_bindings[0] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_GROUP, group_id,
            RD_KAFKA_RESOURCE_PATTERN_LITERAL, principal, "*",
            RD_KAFKA_ACL_OPERATION_READ, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);
        test_CreateAcls_simple(rk, NULL, acl_bindings, 1, NULL);
        rd_kafka_AclBinding_destroy(acl_bindings[0]);

        /* It seems to be taking some time on the cluster for the ACLs to
         * propagate for a group.*/
        rd_sleep(tmout_multip(2));

        options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_DESCRIBECONSUMERGROUPS);

        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, request_timeout, errstr, sizeof(errstr)));
        TEST_CALL_ERROR__(
            rd_kafka_AdminOptions_set_include_authorized_operations(options,
                                                                    1));

        rd_kafka_DescribeConsumerGroups(rk, (const char **)(&group_id), 1,
                                        options, q);
        rd_kafka_AdminOptions_destroy(options);

        rkev = test_wait_admin_result(
            q, RD_KAFKA_EVENT_DESCRIBECONSUMERGROUPS_RESULT,
            tmout_multip(20 * 1000));
        TEST_ASSERT(rkev, "Should receive describe consumer groups event.");

        /*  Extract result. */
        res = rd_kafka_event_DescribeConsumerGroups_result(rkev);
        TEST_ASSERT(res, "Expected DescribeConsumerGroup result, not %s ",
                    rd_kafka_event_name(rkev));

        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err, "Expected success, not %s: %s",
                    rd_kafka_err2name(err), errstr2);

        results =
            rd_kafka_DescribeConsumerGroups_result_groups(res, &results_cnt);
        TEST_ASSERT((int)results_cnt == 1, "Expected 1 group, got %d",
                    (int)results_cnt);

        error = rd_kafka_ConsumerGroupDescription_error(results[0]);
        TEST_ASSERT(!error, "Expected no error in describing group, got: %s",
                    rd_kafka_error_string(error));


        {
                const rd_kafka_AclOperation_t expected[] = {
                    RD_KAFKA_ACL_OPERATION_DESCRIBE,
                    RD_KAFKA_ACL_OPERATION_READ};
                authorized_operations =
                    rd_kafka_ConsumerGroupDescription_authorized_operations(
                        results[0], &authorized_operations_cnt);
                test_match_authorized_operations(expected, 2,
                                                 authorized_operations,
                                                 authorized_operations_cnt);
        }

        rd_kafka_event_destroy(rkev);

        acl_bindings[0] = rd_kafka_AclBinding_new(
            RD_KAFKA_RESOURCE_GROUP, group_id,
            RD_KAFKA_RESOURCE_PATTERN_LITERAL, principal, "*",
            RD_KAFKA_ACL_OPERATION_DELETE, RD_KAFKA_ACL_PERMISSION_TYPE_ALLOW,
            NULL, 0);
        test_CreateAcls_simple(rk, NULL, acl_bindings, 1, NULL);
        rd_kafka_AclBinding_destroy(acl_bindings[0]);

        /* It seems to be taking some time on the cluster for the ACLs to
         * propagate for a group.*/
        rd_sleep(tmout_multip(2));

        test_DeleteGroups_simple(rk, NULL, &group_id, 1, NULL);
        test_DeleteTopics_simple(rk, q, &topic, 1, NULL);

        rd_free(topic);
        rd_free(group_id);

        if (!useq)
                rd_kafka_queue_destroy(q);


        TEST_LATER_CHECK();
#undef TEST_DESCRIBE_CONSUMER_GROUPS_CNT

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
                                               int req_timeout_ms,
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

        SUB_TEST_QUICK(
            "%s DeleteConsumerGroupOffsets with %s, req_timeout_ms %d%s",
            rd_kafka_name(rk), what, req_timeout_ms,
            sub_consumer ? ", with subscribing consumer" : "");

        if (sub_consumer)
                exp_err = RD_KAFKA_RESP_ERR_GROUP_SUBSCRIBED_TO_TOPIC;

        q = useq ? useq : rd_kafka_queue_new(rk);

        if (req_timeout_ms != -1) {
                options = rd_kafka_AdminOptions_new(
                    rk, RD_KAFKA_ADMIN_OP_DELETECONSUMERGROUPOFFSETS);

                err = rd_kafka_AdminOptions_set_request_timeout(
                    options, req_timeout_ms, errstr, sizeof(errstr));
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

        if (test_partition_list_and_offsets_cmp(committed, orig_offsets)) {
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
                rd_kafka_topic_partition_t *rktpar;
                if (i < orig_offsets->cnt / 2) {
                        rktpar = rd_kafka_topic_partition_list_add(
                            offsets, orig_offsets->elems[i].topic,
                            orig_offsets->elems[i].partition);
                        rktpar->offset = orig_offsets->elems[i].offset;
                } else {
                        rktpar = rd_kafka_topic_partition_list_add(
                            to_delete, orig_offsets->elems[i].topic,
                            orig_offsets->elems[i].partition);
                        rktpar->offset = RD_KAFKA_OFFSET_INVALID;
                        rktpar         = rd_kafka_topic_partition_list_add(
                            offsets, orig_offsets->elems[i].topic,
                            orig_offsets->elems[i].partition);
                        rktpar->offset = RD_KAFKA_OFFSET_INVALID;
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

        if (test_partition_list_and_offsets_cmp(deleted, to_delete)) {
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

        rd_kafka_topic_partition_list_t *expected = offsets;
        if (sub_consumer)
                expected = orig_offsets;

        if (test_partition_list_and_offsets_cmp(committed, expected)) {
                TEST_SAY("expected list:\n");
                test_print_partition_list(expected);
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
#undef MY_TOPIC_CNT

        SUB_TEST_PASS();
}


/**
 * @brief Test altering of committed offsets.
 *
 *
 */
static void do_test_AlterConsumerGroupOffsets(const char *what,
                                              rd_kafka_t *rk,
                                              rd_kafka_queue_t *useq,
                                              int req_timeout_ms,
                                              rd_bool_t sub_consumer,
                                              rd_bool_t create_topics) {
        rd_kafka_queue_t *q;
        rd_kafka_AdminOptions_t *options = NULL;
        rd_kafka_topic_partition_list_t *orig_offsets, *offsets, *to_alter,
            *committed, *alterd, *subscription = NULL;
        rd_kafka_event_t *rkev = NULL;
        rd_kafka_resp_err_t err;
        char errstr[512];
        const char *errstr2;
#define TEST_ALTER_CONSUMER_GROUP_OFFSETS_TOPIC_CNT 3
        int i;
        const int partitions_cnt = 3;
        char *topics[TEST_ALTER_CONSUMER_GROUP_OFFSETS_TOPIC_CNT];
        rd_kafka_metadata_topic_t
            exp_mdtopics[TEST_ALTER_CONSUMER_GROUP_OFFSETS_TOPIC_CNT] = {{0}};
        int exp_mdtopic_cnt                                           = 0;
        test_timing_t timing;
        rd_kafka_resp_err_t exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_kafka_AlterConsumerGroupOffsets_t *cgoffsets;
        const rd_kafka_AlterConsumerGroupOffsets_result_t *res;
        const rd_kafka_group_result_t **gres;
        size_t gres_cnt;
        rd_kafka_t *consumer = NULL;
        char *group_id;

        SUB_TEST_QUICK(
            "%s AlterConsumerGroupOffsets with %s, "
            "request_timeout %d%s",
            rd_kafka_name(rk), what, req_timeout_ms,
            sub_consumer ? ", with subscribing consumer" : "");

        if (!create_topics)
                exp_err = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
        else if (sub_consumer)
                exp_err = RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID;

        if (sub_consumer && !create_topics)
                TEST_FAIL(
                    "Can't use set sub_consumer and unset create_topics at the "
                    "same time");

        q = useq ? useq : rd_kafka_queue_new(rk);

        if (req_timeout_ms != -1) {
                options = rd_kafka_AdminOptions_new(
                    rk, RD_KAFKA_ADMIN_OP_ALTERCONSUMERGROUPOFFSETS);

                err = rd_kafka_AdminOptions_set_request_timeout(
                    options, req_timeout_ms, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        }


        subscription = rd_kafka_topic_partition_list_new(
            TEST_ALTER_CONSUMER_GROUP_OFFSETS_TOPIC_CNT);

        for (i = 0; i < TEST_ALTER_CONSUMER_GROUP_OFFSETS_TOPIC_CNT; i++) {
                char pfx[64];
                char *topic;

                rd_snprintf(pfx, sizeof(pfx), "DCGO-topic%d", i);
                topic = rd_strdup(test_mk_topic_name(pfx, 1));

                topics[i]                             = topic;
                exp_mdtopics[exp_mdtopic_cnt++].topic = topic;

                rd_kafka_topic_partition_list_add(subscription, topic,
                                                  RD_KAFKA_PARTITION_UA);
        }

        group_id = topics[0];

        /* Create the topics first if needed. */
        if (create_topics) {
                test_CreateTopics_simple(
                    rk, NULL, topics,
                    TEST_ALTER_CONSUMER_GROUP_OFFSETS_TOPIC_CNT, partitions_cnt,
                    NULL);

                /* Verify that topics are reported by metadata */
                test_wait_metadata_update(rk, exp_mdtopics, exp_mdtopic_cnt,
                                          NULL, 0, 15 * 1000);

                rd_sleep(1); /* Additional wait time for cluster propagation */

                consumer = test_create_consumer(group_id, NULL, NULL, NULL);

                if (sub_consumer) {
                        TEST_CALL_ERR__(
                            rd_kafka_subscribe(consumer, subscription));
                        test_consumer_wait_assignment(consumer, rd_true);
                }
        }

        orig_offsets = rd_kafka_topic_partition_list_new(
            TEST_ALTER_CONSUMER_GROUP_OFFSETS_TOPIC_CNT * partitions_cnt);
        for (i = 0;
             i < TEST_ALTER_CONSUMER_GROUP_OFFSETS_TOPIC_CNT * partitions_cnt;
             i++) {
                rd_kafka_topic_partition_t *rktpar;
                rktpar = rd_kafka_topic_partition_list_add(
                    orig_offsets, topics[i / partitions_cnt],
                    i % partitions_cnt);
                rktpar->offset = (i + 1) * 10;
                rd_kafka_topic_partition_set_leader_epoch(rktpar, 1);
        }

        /* Commit some offsets, if topics exists */
        if (create_topics) {
                TEST_CALL_ERR__(
                    rd_kafka_commit(consumer, orig_offsets, 0 /*sync*/));

                /* Verify committed offsets match */
                committed = rd_kafka_topic_partition_list_copy(orig_offsets);
                TEST_CALL_ERR__(rd_kafka_committed(consumer, committed,
                                                   tmout_multip(5 * 1000)));

                if (test_partition_list_and_offsets_cmp(committed,
                                                        orig_offsets)) {
                        TEST_SAY("commit() list:\n");
                        test_print_partition_list(orig_offsets);
                        TEST_SAY("committed() list:\n");
                        test_print_partition_list(committed);
                        TEST_FAIL("committed offsets don't match");
                }
                rd_kafka_topic_partition_list_destroy(committed);
        }

        /* Now alter second half of the commits */
        offsets  = rd_kafka_topic_partition_list_new(orig_offsets->cnt / 2);
        to_alter = rd_kafka_topic_partition_list_new(orig_offsets->cnt / 2);
        for (i = 0; i < orig_offsets->cnt; i++) {
                rd_kafka_topic_partition_t *rktpar;
                if (i < orig_offsets->cnt / 2) {
                        rktpar = rd_kafka_topic_partition_list_add(
                            offsets, orig_offsets->elems[i].topic,
                            orig_offsets->elems[i].partition);
                        rktpar->offset = orig_offsets->elems[i].offset;
                        rd_kafka_topic_partition_set_leader_epoch(
                            rktpar, rd_kafka_topic_partition_get_leader_epoch(
                                        &orig_offsets->elems[i]));
                } else {
                        rktpar = rd_kafka_topic_partition_list_add(
                            to_alter, orig_offsets->elems[i].topic,
                            orig_offsets->elems[i].partition);
                        rktpar->offset = 5;
                        rd_kafka_topic_partition_set_leader_epoch(rktpar, 2);
                        rktpar = rd_kafka_topic_partition_list_add(
                            offsets, orig_offsets->elems[i].topic,
                            orig_offsets->elems[i].partition);
                        rktpar->offset = 5;
                        rd_kafka_topic_partition_set_leader_epoch(rktpar, 2);
                }
        }

        cgoffsets = rd_kafka_AlterConsumerGroupOffsets_new(group_id, to_alter);

        TIMING_START(&timing, "AlterConsumerGroupOffsets");
        TEST_SAY("Call AlterConsumerGroupOffsets\n");
        rd_kafka_AlterConsumerGroupOffsets(rk, &cgoffsets, 1, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        rd_kafka_AlterConsumerGroupOffsets_destroy(cgoffsets);

        TIMING_START(&timing, "AlterConsumerGroupOffsets.queue_poll");
        /* Poll result queue for AlterConsumerGroupOffsets result.
         * Print but otherwise ignore other event types
         * (typically generic Error events). */
        while (1) {
                rkev = rd_kafka_queue_poll(q, tmout_multip(10 * 1000));
                TEST_SAY("AlterConsumerGroupOffsets: got %s in %.3fms\n",
                         rd_kafka_event_name(rkev),
                         TIMING_DURATION(&timing) / 1000.0f);
                if (rkev == NULL)
                        continue;
                if (rd_kafka_event_error(rkev))
                        TEST_SAY("%s: %s\n", rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));

                if (rd_kafka_event_type(rkev) ==
                    RD_KAFKA_EVENT_ALTERCONSUMERGROUPOFFSETS_RESULT)
                        break;

                rd_kafka_event_destroy(rkev);
        }

        /* Convert event to proper result */
        res = rd_kafka_event_AlterConsumerGroupOffsets_result(rkev);
        TEST_ASSERT(res, "expected AlterConsumerGroupOffsets_result, not %s",
                    rd_kafka_event_name(rkev));

        /* Expecting error */
        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err,
                    "expected AlterConsumerGroupOffsets to succeed, "
                    "got %s (%s)",
                    rd_kafka_err2name(err), err ? errstr2 : "n/a");

        TEST_SAY("AlterConsumerGroupOffsets: returned %s (%s)\n",
                 rd_kafka_err2str(err), err ? errstr2 : "n/a");

        gres = rd_kafka_AlterConsumerGroupOffsets_result_groups(res, &gres_cnt);
        TEST_ASSERT(gres && gres_cnt == 1,
                    "expected gres_cnt == 1, not %" PRIusz, gres_cnt);

        alterd = rd_kafka_topic_partition_list_copy(
            rd_kafka_group_result_partitions(gres[0]));

        if (test_partition_list_and_offsets_cmp(alterd, to_alter)) {
                TEST_SAY("Result list:\n");
                test_print_partition_list(alterd);
                TEST_SAY("Partitions passed to AlterConsumerGroupOffsets:\n");
                test_print_partition_list(to_alter);
                TEST_FAIL("altered/requested offsets don't match");
        }

        /* Verify expected errors */
        for (i = 0; i < alterd->cnt; i++) {
                TEST_ASSERT_LATER(alterd->elems[i].err == exp_err,
                                  "Result %s [%" PRId32
                                  "] has error %s, "
                                  "expected %s",
                                  alterd->elems[i].topic,
                                  alterd->elems[i].partition,
                                  rd_kafka_err2name(alterd->elems[i].err),
                                  rd_kafka_err2name(exp_err));
        }

        TEST_LATER_CHECK();

        rd_kafka_topic_partition_list_destroy(alterd);
        rd_kafka_topic_partition_list_destroy(to_alter);

        rd_kafka_event_destroy(rkev);


        /* Verify committed offsets match, if topics exist. */
        if (create_topics) {
                committed = rd_kafka_topic_partition_list_copy(orig_offsets);
                TEST_CALL_ERR__(rd_kafka_committed(consumer, committed,
                                                   tmout_multip(5 * 1000)));

                rd_kafka_topic_partition_list_t *expected = offsets;
                if (sub_consumer) {
                        /* Alter fails with an active consumer */
                        expected = orig_offsets;
                }
                TEST_SAY("Original committed offsets:\n");
                test_print_partition_list(orig_offsets);

                TEST_SAY("Committed offsets after alter:\n");
                test_print_partition_list(committed);

                if (test_partition_list_and_offsets_cmp(committed, expected)) {
                        TEST_SAY("expected list:\n");
                        test_print_partition_list(expected);
                        TEST_SAY("committed() list:\n");
                        test_print_partition_list(committed);
                        TEST_FAIL("committed offsets don't match");
                }
                rd_kafka_topic_partition_list_destroy(committed);
        }

        rd_kafka_topic_partition_list_destroy(offsets);
        rd_kafka_topic_partition_list_destroy(orig_offsets);
        rd_kafka_topic_partition_list_destroy(subscription);

        for (i = 0; i < TEST_ALTER_CONSUMER_GROUP_OFFSETS_TOPIC_CNT; i++)
                rd_free(topics[i]);

        if (create_topics) /* consumer is created only if topics are. */
                rd_kafka_destroy(consumer);

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

        TEST_LATER_CHECK();
#undef TEST_ALTER_CONSUMER_GROUP_OFFSETS_TOPIC_CNT

        SUB_TEST_PASS();
}

/**
 * @brief Test listing of committed offsets.
 *
 *
 */
static void do_test_ListConsumerGroupOffsets(const char *what,
                                             rd_kafka_t *rk,
                                             rd_kafka_queue_t *useq,
                                             int req_timeout_ms,
                                             rd_bool_t sub_consumer,
                                             rd_bool_t null_toppars) {
        rd_kafka_queue_t *q;
        rd_kafka_AdminOptions_t *options = NULL;
        rd_kafka_topic_partition_list_t *orig_offsets, *to_list, *committed,
            *listd, *subscription = NULL;
        rd_kafka_event_t *rkev = NULL;
        rd_kafka_resp_err_t err;
        char errstr[512];
        const char *errstr2;
#define TEST_LIST_CONSUMER_GROUP_OFFSETS_TOPIC_CNT 3
        int i;
        const int partitions_cnt = 3;
        char *topics[TEST_LIST_CONSUMER_GROUP_OFFSETS_TOPIC_CNT];
        rd_kafka_metadata_topic_t
            exp_mdtopics[TEST_LIST_CONSUMER_GROUP_OFFSETS_TOPIC_CNT] = {{0}};
        int exp_mdtopic_cnt                                          = 0;
        test_timing_t timing;
        rd_kafka_resp_err_t exp_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_kafka_ListConsumerGroupOffsets_t *cgoffsets;
        const rd_kafka_ListConsumerGroupOffsets_result_t *res;
        const rd_kafka_group_result_t **gres;
        size_t gres_cnt;
        rd_kafka_t *consumer;
        char *group_id;

        SUB_TEST_QUICK(
            "%s ListConsumerGroupOffsets with %s, "
            "request timeout %d%s",
            rd_kafka_name(rk), what, req_timeout_ms,
            sub_consumer ? ", with subscribing consumer" : "");

        q = useq ? useq : rd_kafka_queue_new(rk);

        if (req_timeout_ms != -1) {
                options = rd_kafka_AdminOptions_new(
                    rk, RD_KAFKA_ADMIN_OP_LISTCONSUMERGROUPOFFSETS);

                err = rd_kafka_AdminOptions_set_request_timeout(
                    options, req_timeout_ms, errstr, sizeof(errstr));
                TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        }


        subscription = rd_kafka_topic_partition_list_new(
            TEST_LIST_CONSUMER_GROUP_OFFSETS_TOPIC_CNT);

        for (i = 0; i < TEST_LIST_CONSUMER_GROUP_OFFSETS_TOPIC_CNT; i++) {
                char pfx[64];
                char *topic;

                rd_snprintf(pfx, sizeof(pfx), "DCGO-topic%d", i);
                topic = rd_strdup(test_mk_topic_name(pfx, 1));

                topics[i]                             = topic;
                exp_mdtopics[exp_mdtopic_cnt++].topic = topic;

                rd_kafka_topic_partition_list_add(subscription, topic,
                                                  RD_KAFKA_PARTITION_UA);
        }

        group_id = topics[0];

        /* Create the topics first. */
        test_CreateTopics_simple(rk, NULL, topics,
                                 TEST_LIST_CONSUMER_GROUP_OFFSETS_TOPIC_CNT,
                                 partitions_cnt, NULL);

        /* Verify that topics are reported by metadata */
        test_wait_metadata_update(rk, exp_mdtopics, exp_mdtopic_cnt, NULL, 0,
                                  15 * 1000);

        rd_sleep(1); /* Additional wait time for cluster propagation */

        consumer = test_create_consumer(group_id, NULL, NULL, NULL);

        if (sub_consumer) {
                TEST_CALL_ERR__(rd_kafka_subscribe(consumer, subscription));
                test_consumer_wait_assignment(consumer, rd_true);
        }

        /* Commit some offsets */
        orig_offsets = rd_kafka_topic_partition_list_new(
            TEST_LIST_CONSUMER_GROUP_OFFSETS_TOPIC_CNT * 2);
        for (i = 0; i < TEST_LIST_CONSUMER_GROUP_OFFSETS_TOPIC_CNT * 2; i++) {
                rd_kafka_topic_partition_t *rktpar;
                rktpar = rd_kafka_topic_partition_list_add(
                    orig_offsets, topics[i / 2],
                    i % TEST_LIST_CONSUMER_GROUP_OFFSETS_TOPIC_CNT);
                rktpar->offset = (i + 1) * 10;
                rd_kafka_topic_partition_set_leader_epoch(rktpar, 2);
        }

        TEST_CALL_ERR__(rd_kafka_commit(consumer, orig_offsets, 0 /*sync*/));

        /* Verify committed offsets match */
        committed = rd_kafka_topic_partition_list_copy(orig_offsets);
        TEST_CALL_ERR__(
            rd_kafka_committed(consumer, committed, tmout_multip(5 * 1000)));

        if (test_partition_list_and_offsets_cmp(committed, orig_offsets)) {
                TEST_SAY("commit() list:\n");
                test_print_partition_list(orig_offsets);
                TEST_SAY("committed() list:\n");
                test_print_partition_list(committed);
                TEST_FAIL("committed offsets don't match");
        }

        rd_kafka_topic_partition_list_destroy(committed);

        to_list = rd_kafka_topic_partition_list_new(orig_offsets->cnt);
        for (i = 0; i < orig_offsets->cnt; i++) {
                rd_kafka_topic_partition_list_add(
                    to_list, orig_offsets->elems[i].topic,
                    orig_offsets->elems[i].partition);
        }

        if (null_toppars) {
                cgoffsets =
                    rd_kafka_ListConsumerGroupOffsets_new(group_id, NULL);
        } else {
                cgoffsets =
                    rd_kafka_ListConsumerGroupOffsets_new(group_id, to_list);
        }

        TIMING_START(&timing, "ListConsumerGroupOffsets");
        TEST_SAY("Call ListConsumerGroupOffsets\n");
        rd_kafka_ListConsumerGroupOffsets(rk, &cgoffsets, 1, options, q);
        TIMING_ASSERT_LATER(&timing, 0, 50);

        rd_kafka_ListConsumerGroupOffsets_destroy(cgoffsets);

        TIMING_START(&timing, "ListConsumerGroupOffsets.queue_poll");
        /* Poll result queue for ListConsumerGroupOffsets result.
         * Print but otherwise ignore other event types
         * (typically generic Error events). */
        while (1) {
                rkev = rd_kafka_queue_poll(q, tmout_multip(10 * 1000));
                TEST_SAY("ListConsumerGroupOffsets: got %s in %.3fms\n",
                         rd_kafka_event_name(rkev),
                         TIMING_DURATION(&timing) / 1000.0f);
                if (rkev == NULL)
                        continue;
                if (rd_kafka_event_error(rkev))
                        TEST_SAY("%s: %s\n", rd_kafka_event_name(rkev),
                                 rd_kafka_event_error_string(rkev));

                if (rd_kafka_event_type(rkev) ==
                    RD_KAFKA_EVENT_LISTCONSUMERGROUPOFFSETS_RESULT)
                        break;

                rd_kafka_event_destroy(rkev);
        }

        /* Convert event to proper result */
        res = rd_kafka_event_ListConsumerGroupOffsets_result(rkev);
        TEST_ASSERT(res, "expected ListConsumerGroupOffsets_result, not %s",
                    rd_kafka_event_name(rkev));

        /* Expecting error */
        err     = rd_kafka_event_error(rkev);
        errstr2 = rd_kafka_event_error_string(rkev);
        TEST_ASSERT(!err,
                    "expected ListConsumerGroupOffsets to succeed, "
                    "got %s (%s)",
                    rd_kafka_err2name(err), err ? errstr2 : "n/a");

        TEST_SAY("ListConsumerGroupOffsets: returned %s (%s)\n",
                 rd_kafka_err2str(err), err ? errstr2 : "n/a");

        gres = rd_kafka_ListConsumerGroupOffsets_result_groups(res, &gres_cnt);
        TEST_ASSERT(gres && gres_cnt == 1,
                    "expected gres_cnt == 1, not %" PRIusz, gres_cnt);

        listd = rd_kafka_topic_partition_list_copy(
            rd_kafka_group_result_partitions(gres[0]));

        if (test_partition_list_and_offsets_cmp(listd, orig_offsets)) {
                TEST_SAY("Result list:\n");
                test_print_partition_list(listd);
                TEST_SAY("Partitions passed to ListConsumerGroupOffsets:\n");
                test_print_partition_list(orig_offsets);
                TEST_FAIL("listd/requested offsets don't match");
        }

        /* Verify expected errors */
        for (i = 0; i < listd->cnt; i++) {
                TEST_ASSERT_LATER(listd->elems[i].err == exp_err,
                                  "Result %s [%" PRId32
                                  "] has error %s, "
                                  "expected %s",
                                  listd->elems[i].topic,
                                  listd->elems[i].partition,
                                  rd_kafka_err2name(listd->elems[i].err),
                                  rd_kafka_err2name(exp_err));
        }

        TEST_LATER_CHECK();

        rd_kafka_topic_partition_list_destroy(listd);
        rd_kafka_topic_partition_list_destroy(to_list);

        rd_kafka_event_destroy(rkev);

        rd_kafka_topic_partition_list_destroy(orig_offsets);
        rd_kafka_topic_partition_list_destroy(subscription);

        for (i = 0; i < TEST_LIST_CONSUMER_GROUP_OFFSETS_TOPIC_CNT; i++)
                rd_free(topics[i]);

        rd_kafka_destroy(consumer);

        if (options)
                rd_kafka_AdminOptions_destroy(options);

        if (!useq)
                rd_kafka_queue_destroy(q);

        TEST_LATER_CHECK();

#undef TEST_LIST_CONSUMER_GROUP_OFFSETS_TOPIC_CNT

        SUB_TEST_PASS();
}

static void do_test_UserScramCredentials(const char *what,
                                         rd_kafka_t *rk,
                                         rd_kafka_queue_t *useq,
                                         rd_bool_t null_bytes) {
        rd_kafka_event_t *event;
        rd_kafka_resp_err_t err;
        const rd_kafka_DescribeUserScramCredentials_result_t *describe_result;
        const rd_kafka_UserScramCredentialsDescription_t **descriptions;
        const rd_kafka_UserScramCredentialsDescription_t *description;
        const rd_kafka_AlterUserScramCredentials_result_t *alter_result;
        const rd_kafka_AlterUserScramCredentials_result_response_t *
            *alter_responses;
        const rd_kafka_AlterUserScramCredentials_result_response_t *response;
        const rd_kafka_ScramCredentialInfo_t *scram_credential;
        rd_kafka_ScramMechanism_t mechanism;
        size_t response_cnt;
        size_t description_cnt;
        size_t num_credentials;
        char errstr[512];
        const char *username;
        const rd_kafka_error_t *error;
        int32_t iterations;
        rd_kafka_UserScramCredentialAlteration_t *alterations[1];
        char *salt           = tsprintf("%s", "salt");
        size_t salt_size     = 4;
        char *password       = tsprintf("%s", "password");
        size_t password_size = 8;
        rd_kafka_queue_t *queue;
        const char *users[1];
        users[0] = "testuserforscram";

        if (null_bytes) {
                salt[1]     = '\0';
                salt[3]     = '\0';
                password[0] = '\0';
                password[3] = '\0';
        }

        SUB_TEST_QUICK("%s, null bytes: %s", what, RD_STR_ToF(null_bytes));

        queue = useq ? useq : rd_kafka_queue_new(rk);

        rd_kafka_AdminOptions_t *options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_DESCRIBEUSERSCRAMCREDENTIALS);

        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, 30 * 1000 /* 30s */, errstr, sizeof(errstr)));

        /* Describe an unknown user */
        rd_kafka_DescribeUserScramCredentials(rk, users, RD_ARRAY_SIZE(users),
                                              options, queue);
        rd_kafka_AdminOptions_destroy(options);
        event = rd_kafka_queue_poll(queue, -1 /*indefinitely*/);

        /* Request level error code should be 0*/
        TEST_CALL_ERR__(rd_kafka_event_error(event));
        err = rd_kafka_event_error(event);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected NO_ERROR, not %s", rd_kafka_err2name(err));

        describe_result =
            rd_kafka_event_DescribeUserScramCredentials_result(event);
        descriptions =
            rd_kafka_DescribeUserScramCredentials_result_descriptions(
                describe_result, &description_cnt);

        /* Assert num_results should be 1 */
        TEST_ASSERT(description_cnt == 1,
                    "There should be exactly 1 description, got %" PRIusz,
                    description_cnt);

        description = descriptions[0];
        username = rd_kafka_UserScramCredentialsDescription_user(description);
        error    = rd_kafka_UserScramCredentialsDescription_error(description);
        err      = rd_kafka_error_code(error);

        num_credentials =
            rd_kafka_UserScramCredentialsDescription_scramcredentialinfo_count(
                description);
        /* username should be the same, err should be RESOURCE_NOT_FOUND
         * and num_credentials should be 0 */
        TEST_ASSERT(strcmp(users[0], username) == 0,
                    "Username should be %s, got %s", users[0], username);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_RESOURCE_NOT_FOUND,
                    "Error code should be RESOURCE_NOT_FOUND as user "
                    "does not exist, got %s",
                    rd_kafka_err2name(err));
        TEST_ASSERT(num_credentials == 0,
                    "Credentials count should be 0, got %" PRIusz,
                    num_credentials);
        rd_kafka_event_destroy(event);

        /* Create a credential for user 0 */
        mechanism      = RD_KAFKA_SCRAM_MECHANISM_SHA_256;
        iterations     = 10000;
        alterations[0] = rd_kafka_UserScramCredentialUpsertion_new(
            users[0], mechanism, iterations, (unsigned char *)password,
            password_size, (unsigned char *)salt, salt_size);

        options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_ALTERUSERSCRAMCREDENTIALS);

        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, 30 * 1000 /* 30s */, errstr, sizeof(errstr)));

        rd_kafka_AlterUserScramCredentials(
            rk, alterations, RD_ARRAY_SIZE(alterations), options, queue);
        rd_kafka_AdminOptions_destroy(options);
        rd_kafka_UserScramCredentialAlteration_destroy_array(
            alterations, RD_ARRAY_SIZE(alterations));

        /* Wait for results */
        event = rd_kafka_queue_poll(queue, -1 /*indefinitely*/);
        err   = rd_kafka_event_error(event);
#if !WITH_SSL
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__INVALID_ARG,
                    "Expected _INVALID_ARG, not %s", rd_kafka_err2name(err));
        rd_kafka_event_destroy(event);
        goto final_checks;
#else
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected NO_ERROR, not %s", rd_kafka_err2name(err));

        alter_result = rd_kafka_event_AlterUserScramCredentials_result(event);
        alter_responses = rd_kafka_AlterUserScramCredentials_result_responses(
            alter_result, &response_cnt);

        /* response_cnt should be 1*/
        TEST_ASSERT(response_cnt == 1,
                    "There should be exactly 1 response, got %" PRIusz,
                    response_cnt);

        response = alter_responses[0];
        username =
            rd_kafka_AlterUserScramCredentials_result_response_user(response);
        error =
            rd_kafka_AlterUserScramCredentials_result_response_error(response);

        err = rd_kafka_error_code(error);
        /* username should be the same and err should be NO_ERROR*/
        TEST_ASSERT(strcmp(users[0], username) == 0,
                    "Username should be %s, got %s", users[0], username);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Error code should be NO_ERROR, got %s",
                    rd_kafka_err2name(err));

        rd_kafka_event_destroy(event);
#endif

        /* Credential should be retrieved */
        options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_DESCRIBEUSERSCRAMCREDENTIALS);

        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, 30 * 1000 /* 30s */, errstr, sizeof(errstr)));

        rd_kafka_DescribeUserScramCredentials(rk, users, RD_ARRAY_SIZE(users),
                                              options, queue);
        rd_kafka_AdminOptions_destroy(options);

        /* Wait for results */
        event = rd_kafka_queue_poll(queue, -1 /*indefinitely*/);
        err   = rd_kafka_event_error(event);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected NO_ERROR, not %s", rd_kafka_err2name(err));

        describe_result =
            rd_kafka_event_DescribeUserScramCredentials_result(event);
        descriptions =
            rd_kafka_DescribeUserScramCredentials_result_descriptions(
                describe_result, &description_cnt);
        /* Assert description_cnt should be 1 , request level error code should
         * be 0*/
        TEST_ASSERT(description_cnt == 1,
                    "There should be exactly 1 description, got %" PRIusz,
                    description_cnt);

        description = descriptions[0];
        username = rd_kafka_UserScramCredentialsDescription_user(description);
        error    = rd_kafka_UserScramCredentialsDescription_error(description);
        err      = rd_kafka_error_code(error);

        num_credentials =
            rd_kafka_UserScramCredentialsDescription_scramcredentialinfo_count(
                description);
        /* username should be the same, err should be NO_ERROR and
         * num_credentials should be 1 */
        TEST_ASSERT(strcmp(users[0], username) == 0,
                    "Username should be %s, got %s", users[0], username);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Error code should be NO_ERROR, got %s",
                    rd_kafka_err2name(err));
        TEST_ASSERT(num_credentials == 1,
                    "Credentials count should be 1, got %" PRIusz,
                    num_credentials);

        scram_credential =
            rd_kafka_UserScramCredentialsDescription_scramcredentialinfo(
                description, 0);
        mechanism  = rd_kafka_ScramCredentialInfo_mechanism(scram_credential);
        iterations = rd_kafka_ScramCredentialInfo_iterations(scram_credential);
        /* mechanism should be SHA 256 and iterations 10000 */
        TEST_ASSERT(mechanism == RD_KAFKA_SCRAM_MECHANISM_SHA_256,
                    "Mechanism should be %d, got: %d",
                    RD_KAFKA_SCRAM_MECHANISM_SHA_256, mechanism);
        TEST_ASSERT(iterations == 10000,
                    "Iterations should be 10000, got %" PRId32, iterations);

        rd_kafka_event_destroy(event);

        /* Delete the credential */
        alterations[0] =
            rd_kafka_UserScramCredentialDeletion_new(users[0], mechanism);

        options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_ALTERUSERSCRAMCREDENTIALS);

        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, 30 * 1000 /* 30s */, errstr, sizeof(errstr)));

        rd_kafka_AlterUserScramCredentials(
            rk, alterations, RD_ARRAY_SIZE(alterations), options, queue);
        rd_kafka_AdminOptions_destroy(options);
        rd_kafka_UserScramCredentialAlteration_destroy_array(
            alterations, RD_ARRAY_SIZE(alterations));

        /* Wait for results */
        event = rd_kafka_queue_poll(queue, -1 /*indefinitely*/);
        err   = rd_kafka_event_error(event);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected NO_ERROR, not %s", rd_kafka_err2name(err));

        alter_result = rd_kafka_event_AlterUserScramCredentials_result(event);
        alter_responses = rd_kafka_AlterUserScramCredentials_result_responses(
            alter_result, &response_cnt);

        /* response_cnt should be 1*/
        TEST_ASSERT(response_cnt == 1,
                    "There should be exactly 1 response, got %" PRIusz,
                    response_cnt);

        response = alter_responses[0];
        username =
            rd_kafka_AlterUserScramCredentials_result_response_user(response);
        error =
            rd_kafka_AlterUserScramCredentials_result_response_error(response);

        err = rd_kafka_error_code(error);
        /* username should be the same and err should be NO_ERROR*/
        TEST_ASSERT(strcmp(users[0], username) == 0,
                    "Username should be %s, got %s", users[0], username);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Error code should be NO_ERROR, got %s",
                    rd_kafka_err2name(err));

        rd_kafka_event_destroy(event);

#if !WITH_SSL
final_checks:
#endif

        /* Credential doesn't exist anymore for this user */

        options = rd_kafka_AdminOptions_new(
            rk, RD_KAFKA_ADMIN_OP_DESCRIBEUSERSCRAMCREDENTIALS);

        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, 30 * 1000 /* 30s */, errstr, sizeof(errstr)));

        rd_kafka_DescribeUserScramCredentials(rk, users, RD_ARRAY_SIZE(users),
                                              options, queue);
        rd_kafka_AdminOptions_destroy(options);
        /* Wait for results */
        event = rd_kafka_queue_poll(queue, -1 /*indefinitely*/);
        err   = rd_kafka_event_error(event);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR,
                    "Expected NO_ERROR, not %s", rd_kafka_err2name(err));

        describe_result =
            rd_kafka_event_DescribeUserScramCredentials_result(event);
        descriptions =
            rd_kafka_DescribeUserScramCredentials_result_descriptions(
                describe_result, &description_cnt);
        /* Assert description_cnt should be 1, request level error code should
         * be 0*/
        TEST_ASSERT(description_cnt == 1,
                    "There should be exactly 1 description, got %" PRIusz,
                    description_cnt);

        description = descriptions[0];
        username = rd_kafka_UserScramCredentialsDescription_user(description);
        error    = rd_kafka_UserScramCredentialsDescription_error(description);
        err      = rd_kafka_error_code(error);
        num_credentials =
            rd_kafka_UserScramCredentialsDescription_scramcredentialinfo_count(
                description);
        /* username should be the same, err should be RESOURCE_NOT_FOUND
         * and num_credentials should be 0 */
        TEST_ASSERT(strcmp(users[0], username) == 0,
                    "Username should be %s, got %s", users[0], username);
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_RESOURCE_NOT_FOUND,
                    "Error code should be RESOURCE_NOT_FOUND, got %s",
                    rd_kafka_err2name(err));
        TEST_ASSERT(num_credentials == 0,
                    "Credentials count should be 0, got %" PRIusz,
                    num_credentials);

        rd_kafka_event_destroy(event);

        if (!useq)
                rd_kafka_queue_destroy(queue);

        SUB_TEST_PASS();
}

static void do_test_ListOffsets(const char *what,
                                rd_kafka_t *rk,
                                rd_kafka_queue_t *useq,
                                int req_timeout_ms) {
        char errstr[512];
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        char *message     = "Message";
        rd_kafka_AdminOptions_t *options;
        rd_kafka_event_t *event;
        rd_kafka_queue_t *q;
        rd_kafka_t *p;
        size_t i = 0, cnt = 0;
        rd_kafka_topic_partition_list_t *topic_partitions,
            *empty_topic_partitions;
        const rd_kafka_ListOffsets_result_t *result;
        const rd_kafka_ListOffsetsResultInfo_t **result_infos;
        int64_t basetimestamp = 10000000;
        int64_t timestamps[]  = {
            basetimestamp + 100,
            basetimestamp + 400,
            basetimestamp + 250,
        };
        struct test_fixture_s {
                int64_t query;
                int64_t expected;
                int min_broker_version;
        } test_fixtures[] = {
            {.query = RD_KAFKA_OFFSET_SPEC_EARLIEST, .expected = 0},
            {.query = RD_KAFKA_OFFSET_SPEC_LATEST, .expected = 3},
            {.query              = RD_KAFKA_OFFSET_SPEC_MAX_TIMESTAMP,
             .expected           = 1,
             .min_broker_version = TEST_BRKVER(3, 0, 0, 0)},
            {.query = basetimestamp + 50, .expected = 0},
            {.query = basetimestamp + 300, .expected = 1},
            {.query = basetimestamp + 150, .expected = 1},
        };

        SUB_TEST_QUICK(
            "%s ListOffsets with %s, "
            "request_timeout %d",
            rd_kafka_name(rk), what, req_timeout_ms);

        q = useq ? useq : rd_kafka_queue_new(rk);

        test_CreateTopics_simple(rk, NULL, (char **)&topic, 1, 1, NULL);

        p = test_create_producer();
        for (i = 0; i < RD_ARRAY_SIZE(timestamps); i++) {
                rd_kafka_producev(
                    /* Producer handle */
                    p,
                    /* Topic name */
                    RD_KAFKA_V_TOPIC(topic),
                    /* Make a copy of the payload. */
                    RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                    /* Message value and length */
                    RD_KAFKA_V_VALUE(message, strlen(message)),

                    RD_KAFKA_V_TIMESTAMP(timestamps[i]),
                    /* Per-Message opaque, provided in
                     * delivery report callback as
                     * msg_opaque. */
                    RD_KAFKA_V_OPAQUE(NULL),
                    /* End sentinel */
                    RD_KAFKA_V_END);
        }

        rd_kafka_flush(p, 20 * 1000);
        rd_kafka_destroy(p);

        /* Set timeout (optional) */
        options = rd_kafka_AdminOptions_new(rk, RD_KAFKA_ADMIN_OP_LISTOFFSETS);

        TEST_CALL_ERR__(rd_kafka_AdminOptions_set_request_timeout(
            options, 30 * 1000 /* 30s */, errstr, sizeof(errstr)));

        TEST_CALL_ERROR__(rd_kafka_AdminOptions_set_isolation_level(
            options, RD_KAFKA_ISOLATION_LEVEL_READ_COMMITTED));

        topic_partitions       = rd_kafka_topic_partition_list_new(1);
        empty_topic_partitions = rd_kafka_topic_partition_list_new(0);
        rd_kafka_topic_partition_list_add(topic_partitions, topic, 0);

        /* Call ListOffsets with empty partition list */
        rd_kafka_ListOffsets(rk, empty_topic_partitions, options, q);
        rd_kafka_topic_partition_list_destroy(empty_topic_partitions);
        /* Wait for results */
        event = rd_kafka_queue_poll(q, -1 /*indefinitely*/);
        if (!event)
                TEST_FAIL("Event missing");

        TEST_CALL_ERR__(rd_kafka_event_error(event));

        result       = rd_kafka_event_ListOffsets_result(event);
        result_infos = rd_kafka_ListOffsets_result_infos(result, &cnt);
        rd_kafka_event_destroy(event);

        TEST_ASSERT(!cnt,
                    "Expected empty result info array, got %" PRIusz
                    " result infos",
                    cnt);

        for (i = 0; i < RD_ARRAY_SIZE(test_fixtures); i++) {
                rd_bool_t retry = rd_true;
                rd_kafka_topic_partition_list_t *topic_partitions_copy;

                struct test_fixture_s test_fixture = test_fixtures[i];
                if (test_fixture.min_broker_version &&
                    test_broker_version < test_fixture.min_broker_version) {
                        TEST_SAY("Skipping offset %" PRId64
                                 ", as not supported\n",
                                 test_fixture.query);
                        continue;
                }

                TEST_SAY("Testing offset %" PRId64 "\n", test_fixture.query);

                topic_partitions_copy =
                    rd_kafka_topic_partition_list_copy(topic_partitions);

                /* Set OffsetSpec */
                topic_partitions_copy->elems[0].offset = test_fixture.query;

                while (retry) {
                        size_t j;
                        rd_kafka_resp_err_t err;
                        /* Call ListOffsets */
                        rd_kafka_ListOffsets(rk, topic_partitions_copy, options,
                                             q);
                        /* Wait for results */
                        event = rd_kafka_queue_poll(q, -1 /*indefinitely*/);
                        if (!event)
                                TEST_FAIL("Event missing");

                        err = rd_kafka_event_error(event);
                        if (err == RD_KAFKA_RESP_ERR__NOENT) {
                                rd_kafka_event_destroy(event);
                                /* Still looking for the leader */
                                rd_usleep(100000, 0);
                                continue;
                        } else if (err) {
                                TEST_FAIL("Failed with error: %s",
                                          rd_kafka_err2name(err));
                        }

                        result = rd_kafka_event_ListOffsets_result(event);
                        result_infos =
                            rd_kafka_ListOffsets_result_infos(result, &cnt);
                        for (j = 0; j < cnt; j++) {
                                const rd_kafka_topic_partition_t *topic_partition =
                                    rd_kafka_ListOffsetsResultInfo_topic_partition(
                                        result_infos[j]);
                                TEST_ASSERT(
                                    topic_partition->err == 0,
                                    "Expected error NO_ERROR, got %s",
                                    rd_kafka_err2name(topic_partition->err));
                                TEST_ASSERT(topic_partition->offset ==
                                                test_fixture.expected,
                                            "Expected offset %" PRId64
                                            ", got %" PRId64,
                                            test_fixture.expected,
                                            topic_partition->offset);
                        }
                        rd_kafka_event_destroy(event);
                        retry = rd_false;
                }
                rd_kafka_topic_partition_list_destroy(topic_partitions_copy);
        }

        rd_kafka_AdminOptions_destroy(options);
        rd_kafka_topic_partition_list_destroy(topic_partitions);

        test_DeleteTopics_simple(rk, NULL, (char **)&topic, 1, NULL);

        if (!useq)
                rd_kafka_queue_destroy(q);

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

        if (test_broker_version >= TEST_BRKVER(2, 3, 0, 0)) {
                /* IncrementalAlterConfigs */
                do_test_IncrementalAlterConfigs(rk, mainq);
        }

        /* DescribeConfigs */
        do_test_DescribeConfigs(rk, mainq);

        /* Delete records */
        do_test_DeleteRecords("temp queue, op timeout 0", rk, NULL, 0);
        do_test_DeleteRecords("main queue, op timeout 1500", rk, mainq, 1500);

        /* List groups */
        do_test_ListConsumerGroups("temp queue", rk, NULL, -1, rd_false);
        do_test_ListConsumerGroups("main queue", rk, mainq, 1500, rd_true);

        /* Describe groups */
        do_test_DescribeConsumerGroups("temp queue", rk, NULL, -1);
        do_test_DescribeConsumerGroups("main queue", rk, mainq, 1500);

        /* Describe topics */
        do_test_DescribeTopics("temp queue", rk, NULL, 15000, rd_false);
        do_test_DescribeTopics("main queue", rk, mainq, 15000, rd_false);

        /* Describe cluster */
        do_test_DescribeCluster("temp queue", rk, NULL, 1500, rd_false);
        do_test_DescribeCluster("main queue", rk, mainq, 1500, rd_false);

        if (test_broker_version >= TEST_BRKVER(2, 3, 0, 0)) {
                /* Describe topics */
                do_test_DescribeTopics("temp queue", rk, NULL, 15000, rd_true);
                do_test_DescribeTopics("main queue", rk, mainq, 15000, rd_true);

                do_test_DescribeCluster("temp queue", rk, NULL, 1500, rd_true);
                do_test_DescribeCluster("main queue", rk, mainq, 1500, rd_true);

                do_test_DescribeConsumerGroups_with_authorized_ops(
                    "temp queue", rk, NULL, 1500);
                do_test_DescribeConsumerGroups_with_authorized_ops(
                    "main queue", rk, mainq, 1500);
        }

        /* Delete groups */
        do_test_DeleteGroups("temp queue", rk, NULL, -1);
        do_test_DeleteGroups("main queue", rk, mainq, 1500);

        if (test_broker_version >= TEST_BRKVER(2, 4, 0, 0)) {
                /* Delete committed offsets */
                do_test_DeleteConsumerGroupOffsets("temp queue", rk, NULL, -1,
                                                   rd_false);
                do_test_DeleteConsumerGroupOffsets("main queue", rk, mainq,
                                                   1500, rd_false);
                do_test_DeleteConsumerGroupOffsets(
                    "main queue", rk, mainq, 1500,
                    rd_true /*with subscribing consumer*/);
        }

        if (test_broker_version >= TEST_BRKVER(2, 5, 0, 0)) {
                /* ListOffsets */
                do_test_ListOffsets("temp queue", rk, NULL, -1);
                do_test_ListOffsets("main queue", rk, mainq, 1500);

                /* Alter committed offsets */
                do_test_AlterConsumerGroupOffsets("temp queue", rk, NULL, -1,
                                                  rd_false, rd_true);
                do_test_AlterConsumerGroupOffsets("main queue", rk, mainq, 1500,
                                                  rd_false, rd_true);
                do_test_AlterConsumerGroupOffsets(
                    "main queue, nonexistent topics", rk, mainq, 1500, rd_false,
                    rd_false /* don't create topics */);
                do_test_AlterConsumerGroupOffsets(
                    "main queue", rk, mainq, 1500,
                    rd_true, /*with subscribing consumer*/
                    rd_true);
        }

        if (test_broker_version >= TEST_BRKVER(2, 0, 0, 0)) {
                /* List committed offsets */
                do_test_ListConsumerGroupOffsets("temp queue", rk, NULL, -1,
                                                 rd_false, rd_false);
                do_test_ListConsumerGroupOffsets(
                    "main queue, op timeout "
                    "1500",
                    rk, mainq, 1500, rd_false, rd_false);
                do_test_ListConsumerGroupOffsets(
                    "main queue", rk, mainq, 1500,
                    rd_true /*with subscribing consumer*/, rd_false);
                do_test_ListConsumerGroupOffsets("temp queue", rk, NULL, -1,
                                                 rd_false, rd_true);
                do_test_ListConsumerGroupOffsets("main queue", rk, mainq, 1500,
                                                 rd_false, rd_true);
                do_test_ListConsumerGroupOffsets(
                    "main queue", rk, mainq, 1500,
                    rd_true /*with subscribing consumer*/, rd_true);
        }

        if (test_broker_version >= TEST_BRKVER(2, 7, 0, 0)) {
                do_test_UserScramCredentials("main queue", rk, mainq, rd_false);
                do_test_UserScramCredentials("temp queue", rk, NULL, rd_false);
                do_test_UserScramCredentials("main queue", rk, mainq, rd_true);
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
