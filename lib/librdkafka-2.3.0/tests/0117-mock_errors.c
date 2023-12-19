/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020-2022, Magnus Edenhill
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

#include "../src/rdkafka_proto.h"
#include "../src/rdunittest.h"

#include <stdarg.h>


/**
 * @name Misc mock-injected errors.
 *
 */

/**
 * @brief Test producer handling (retry) of ERR_KAFKA_STORAGE_ERROR.
 */
static void do_test_producer_storage_error(rd_bool_t too_few_retries) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_resp_err_t err;

        SUB_TEST_QUICK("%s", too_few_retries ? "with too few retries" : "");

        test_conf_init(&conf, NULL, 10);

        test_conf_set(conf, "test.mock.num.brokers", "3");
        test_conf_set(conf, "retries", too_few_retries ? "1" : "10");
        test_conf_set(conf, "retry.backoff.ms", "500");
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        test_curr->ignore_dr_err = rd_false;
        if (too_few_retries) {
                test_curr->exp_dr_err = RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR;
                test_curr->exp_dr_status = RD_KAFKA_MSG_STATUS_NOT_PERSISTED;
        } else {
                test_curr->exp_dr_err    = RD_KAFKA_RESP_ERR_NO_ERROR;
                test_curr->exp_dr_status = RD_KAFKA_MSG_STATUS_PERSISTED;
        }

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        mcluster = rd_kafka_handle_mock_cluster(rk);
        TEST_ASSERT(mcluster, "missing mock cluster");

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Produce, 3,
            RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR,
            RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR,
            RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR);

        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC("mytopic"),
                                RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END);
        TEST_ASSERT(!err, "produce failed: %s", rd_kafka_err2str(err));

        /* Wait for delivery report. */
        test_flush(rk, 5000);

        rd_kafka_destroy(rk);

        SUB_TEST_PASS();
}


/**
 * @brief Issue #2933. Offset commit being retried when failing due to
 *        RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS and then causing fetchers
 *        to not start.
 */
static void do_test_offset_commit_error_during_rebalance(void) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *c1, *c2;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        const char *topic = "test";
        const int msgcnt  = 100;
        rd_kafka_resp_err_t err;

        SUB_TEST();

        test_conf_init(&conf, NULL, 60);

        mcluster = test_mock_cluster_new(3, &bootstraps);

        rd_kafka_mock_topic_create(mcluster, topic, 4, 3);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, 0, RD_KAFKA_PARTITION_UA, 0, msgcnt, 10,
                                 "bootstrap.servers", bootstraps,
                                 "batch.num.messages", "1", NULL);

        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");

        /* Make sure we don't consume the entire partition in one Fetch */
        test_conf_set(conf, "fetch.message.max.bytes", "100");

        c1 = test_create_consumer("mygroup", test_rebalance_cb,
                                  rd_kafka_conf_dup(conf), NULL);

        c2 = test_create_consumer("mygroup", test_rebalance_cb, conf, NULL);

        test_consumer_subscribe(c1, topic);
        test_consumer_subscribe(c2, topic);


        /* Wait for assignment and one message */
        test_consumer_poll("C1.PRE", c1, 0, -1, -1, 1, NULL);
        test_consumer_poll("C2.PRE", c2, 0, -1, -1, 1, NULL);

        /* Trigger rebalance */
        test_consumer_close(c2);
        rd_kafka_destroy(c2);

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_OffsetCommit, 6,
            RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS,
            RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS,
            RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS,
            RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS,
            RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS,
            RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS);

        /* This commit should fail (async) */
        TEST_SAY("Committing (should fail)\n");
        err = rd_kafka_commit(c1, NULL, 0 /*sync*/);
        TEST_SAY("Commit returned %s\n", rd_kafka_err2name(err));
        TEST_ASSERT(err == RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS,
                    "Expected commit to fail with ERR_REBALANCE_IN_PROGRESS, "
                    "not %s",
                    rd_kafka_err2name(err));

        /* Wait for new assignment and able to read all messages */
        test_consumer_poll("C1.PRE", c1, 0, -1, -1, msgcnt, NULL);

        rd_kafka_destroy(c1);

        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}



/**
 * @brief Issue #2933. Offset commit being retried when failing due to
 *        RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS and then causing fetchers
 *        to not start.
 */
static void do_test_offset_commit_request_timed_out(rd_bool_t auto_commit) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *c1, *c2;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        const char *topic = "test";
        const int msgcnt  = 1;
        rd_kafka_topic_partition_list_t *partitions;

        SUB_TEST_QUICK("enable.auto.commit=%s", auto_commit ? "true" : "false");

        test_conf_init(&conf, NULL, 60);

        mcluster = test_mock_cluster_new(1, &bootstraps);

        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, 0, RD_KAFKA_PARTITION_UA, 0, msgcnt, 10,
                                 "bootstrap.servers", bootstraps,
                                 "batch.num.messages", "1", NULL);

        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit",
                      auto_commit ? "true" : "false");
        /* Too high to be done by interval in this test */
        test_conf_set(conf, "auto.commit.interval.ms", "90000");

        /* Make sure we don't consume the entire partition in one Fetch */
        test_conf_set(conf, "fetch.message.max.bytes", "100");

        c1 = test_create_consumer("mygroup", NULL, rd_kafka_conf_dup(conf),
                                  NULL);


        test_consumer_subscribe(c1, topic);

        /* Wait for assignment and one message */
        test_consumer_poll("C1.PRE", c1, 0, -1, -1, 1, NULL);

        rd_kafka_mock_push_request_errors(mcluster, RD_KAFKAP_OffsetCommit, 2,
                                          RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT,
                                          RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT);

        if (!auto_commit)
                TEST_CALL_ERR__(rd_kafka_commit(c1, NULL, 0 /*sync*/));

        /* Rely on consumer_close() doing final commit
         * when auto commit is enabled */

        test_consumer_close(c1);

        rd_kafka_destroy(c1);

        /* Create a new consumer and retrieve the committed offsets to verify
         * they were properly committed */
        c2 = test_create_consumer("mygroup", NULL, conf, NULL);

        partitions = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(partitions, topic, 0)->offset =
            RD_KAFKA_OFFSET_INVALID;

        TEST_CALL_ERR__(rd_kafka_committed(c2, partitions, 10 * 1000));
        TEST_ASSERT(partitions->elems[0].offset == 1,
                    "Expected committed offset to be 1, not %" PRId64,
                    partitions->elems[0].offset);

        rd_kafka_topic_partition_list_destroy(partitions);

        rd_kafka_destroy(c2);

        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Verify that a cluster roll does not cause consumer_poll() to return
 * the temporary and retriable COORDINATOR_LOAD_IN_PROGRESS error. We should
 * backoff and retry in that case.
 */
static void do_test_joingroup_coordinator_load_in_progress() {
        rd_kafka_conf_t *conf;
        rd_kafka_t *consumer;
        rd_kafka_mock_cluster_t *mcluster;
        const char *bootstraps;
        const char *topic = "test";
        const int msgcnt  = 1;

        SUB_TEST();

        test_conf_init(&conf, NULL, 60);

        mcluster = test_mock_cluster_new(1, &bootstraps);

        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        test_produce_msgs_easy_v(topic, 0, RD_KAFKA_PARTITION_UA, 0, msgcnt, 10,
                                 "bootstrap.servers", bootstraps,
                                 "batch.num.messages", "1", NULL);

        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "auto.offset.reset", "earliest");

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_FindCoordinator, 1,
            RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS);

        consumer = test_create_consumer("mygroup", NULL, conf, NULL);

        test_consumer_subscribe(consumer, topic);

        /* Wait for assignment and one message */
        test_consumer_poll("consumer", consumer, 0, -1, -1, msgcnt, NULL);

        test_consumer_close(consumer);

        rd_kafka_destroy(consumer);

        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

int main_0117_mock_errors(int argc, char **argv) {

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        do_test_producer_storage_error(rd_false);
        do_test_producer_storage_error(rd_true);

        do_test_offset_commit_error_during_rebalance();

        do_test_offset_commit_request_timed_out(rd_true);
        do_test_offset_commit_request_timed_out(rd_false);

        do_test_joingroup_coordinator_load_in_progress();

        return 0;
}
