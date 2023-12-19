/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2023, Confluent Inc.
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

#include "../src/rdkafka_proto.h"


struct _produce_args {
        const char *topic;
        int sleep;
        rd_kafka_conf_t *conf;
};

static int produce_concurrent_thread(void *args) {
        rd_kafka_t *p1;
        test_curr->exp_dr_err    = RD_KAFKA_RESP_ERR_NO_ERROR;
        test_curr->exp_dr_status = RD_KAFKA_MSG_STATUS_PERSISTED;

        struct _produce_args *produce_args = args;
        rd_sleep(produce_args->sleep);

        p1 = test_create_handle(RD_KAFKA_PRODUCER, produce_args->conf);
        TEST_CALL_ERR__(
            rd_kafka_producev(p1, RD_KAFKA_V_TOPIC(produce_args->topic),
                              RD_KAFKA_V_VALUE("hi", 2), RD_KAFKA_V_END));
        rd_kafka_flush(p1, -1);
        rd_kafka_destroy(p1);
        return 0;
}

/**
 * @brief Send a produce request in the middle of an offset validation
 *        and expect that the fetched message is discarded, don't producing
 *        a duplicate when state becomes active again. See #4249.
 */
static void do_test_no_duplicates_during_offset_validation(void) {
        const char *topic      = test_mk_topic_name(__FUNCTION__, 1);
        const char *c1_groupid = topic;
        rd_kafka_t *c1;
        rd_kafka_conf_t *conf, *conf_producer;
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        int initial_msg_count = 5;
        thrd_t thrd;
        struct _produce_args args = RD_ZERO_INIT;
        uint64_t testid           = test_id_generate();

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        /* Slow down OffsetForLeaderEpoch so a produce and
         * subsequent fetch can happen while it's in-flight */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 1, RD_KAFKAP_OffsetForLeaderEpoch, 1,
            RD_KAFKA_RESP_ERR_NO_ERROR, 5000);

        test_conf_init(&conf_producer, NULL, 60);
        test_conf_set(conf_producer, "bootstrap.servers", bootstraps);


        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, testid, 0, 0, initial_msg_count, 10,
                                 "bootstrap.servers", bootstraps,
                                 "batch.num.messages", "1", NULL);

        args.topic = topic;
        /* Makes that the message is produced while an offset validation
         * is ongoing */
        args.sleep = 5;
        args.conf  = conf_producer;
        /* Spin up concurrent thread */
        if (thrd_create(&thrd, produce_concurrent_thread, (void *)&args) !=
            thrd_success)
                TEST_FAIL("Failed to create thread");

        test_conf_init(&conf, NULL, 60);

        test_conf_set(conf, "bootstrap.servers", bootstraps);
        /* Makes that an offset validation happens at the same
         * time a new message is being produced */
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "5000");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "enable.auto.offset.store", "false");
        test_conf_set(conf, "enable.partition.eof", "true");

        c1 = test_create_consumer(c1_groupid, NULL, conf, NULL);
        test_consumer_subscribe(c1, topic);

        /* Consume initial messages */
        test_consumer_poll("MSG_INIT", c1, testid, 0, 0, initial_msg_count,
                           NULL);
        /* EOF after initial messages */
        test_consumer_poll("MSG_EOF", c1, testid, 1, initial_msg_count, 0,
                           NULL);
        /* Concurrent producer message and EOF */
        test_consumer_poll("MSG_AND_EOF", c1, testid, 1, initial_msg_count, 1,
                           NULL);
        /* Only an EOF, not a duplicate message */
        test_consumer_poll("MSG_EOF2", c1, testid, 1, initial_msg_count, 0,
                           NULL);

        thrd_join(thrd, NULL);

        rd_kafka_destroy(c1);

        test_mock_cluster_destroy(mcluster);

        TEST_LATER_CHECK();
        SUB_TEST_PASS();
}


/**
 * @brief Test that a permanent error doesn't cause an offset reset.
 *        See issues #4293, #4427.
 * @param err The error OffsetForLeaderEpoch fails with.
 */
static void do_test_permanent_error_retried(rd_kafka_resp_err_t err) {
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_conf_t *conf;
        const char *bootstraps;
        const char *topic      = test_mk_topic_name(__FUNCTION__, 1);
        const char *c1_groupid = topic;
        rd_kafka_t *c1;
        rd_kafka_topic_partition_list_t *rktpars;
        rd_kafka_topic_partition_t *rktpar;
        int msg_count   = 5;
        uint64_t testid = test_id_generate();

        SUB_TEST_QUICK("err: %s", rd_kafka_err2name(err));

        mcluster = test_mock_cluster_new(3, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, testid, 0, 0, msg_count, 10,
                                 "bootstrap.servers", bootstraps,
                                 "batch.num.messages", "1", NULL);

        /* Make OffsetForLeaderEpoch fail with the corresponding error code */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_OffsetForLeaderEpoch, 1, err);

        test_conf_init(&conf, NULL, 60);

        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "5000");
        test_conf_set(conf, "auto.offset.reset", "latest");
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "enable.auto.offset.store", "false");
        test_conf_set(conf, "enable.partition.eof", "true");

        c1 = test_create_consumer(c1_groupid, NULL, conf, NULL);
        test_consumer_subscribe(c1, topic);

        /* EOF because of reset to latest */
        test_consumer_poll("MSG_EOF", c1, testid, 1, 0, 0, NULL);

        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 2);

        /* Seek to 0 for validating the offset. */
        rktpars        = rd_kafka_topic_partition_list_new(1);
        rktpar         = rd_kafka_topic_partition_list_add(rktpars, topic, 0);
        rktpar->offset = 0;

        /* Will validate the offset at start fetching again
         * from offset 0. */
        rd_kafka_topic_partition_set_leader_epoch(rktpar, 0);
        rd_kafka_seek_partitions(c1, rktpars, -1);
        rd_kafka_topic_partition_list_destroy(rktpars);

        /* Read all messages after seek to zero.
         * In case of permanent error instead it reset to latest and
         * gets an EOF. */
        test_consumer_poll("MSG_ALL", c1, testid, 0, 0, 5, NULL);

        rd_kafka_destroy(c1);

        test_mock_cluster_destroy(mcluster);

        TEST_LATER_CHECK();
        SUB_TEST_PASS();
}


/**
 * @brief If there's an OffsetForLeaderEpoch request which fails, and the leader
 * changes meanwhile, we end up in an infinite loop of OffsetForLeaderEpoch
 * requests.
 * Specifically:
 * a. Leader Change - causes OffsetForLeaderEpoch
 *     request 'A'.
 * b. Request 'A' fails with a retriable error, and we retry it.
 * c. While waiting for Request 'A', the leader changes again, and we send a
 *    Request 'B', but the leader epoch is not updated correctly in this
 *    request, causing a loop.
 *
 * See #4425.
 */
static void do_test_two_leader_changes(void) {
        const char *topic      = test_mk_topic_name(__FUNCTION__, 1);
        const char *c1_groupid = topic;
        rd_kafka_t *c1;
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        int msg_cnt     = 5;
        uint64_t testid = test_id_generate();
        rd_kafka_conf_t *conf;

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(2, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 2);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, testid, 0, 0, msg_cnt, 10,
                                 "bootstrap.servers", bootstraps,
                                 "batch.num.messages", "1", NULL);

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "auto.offset.reset", "earliest");

        c1 = test_create_consumer(c1_groupid, NULL, conf, NULL);
        test_consumer_subscribe(c1, topic);

        /* Consume initial messages and join the group, etc. */
        test_consumer_poll("MSG_INIT", c1, testid, 0, 0, msg_cnt, NULL);

        /* The leader will change from 1->2, and the OffsetForLeaderEpoch will
         * be sent to broker 2. We need to first fail it with
         * an error, and then give enough time to change the leader before
         * returning a success. */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 2, RD_KAFKAP_OffsetForLeaderEpoch, 2,
            RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR, 900,
            RD_KAFKA_RESP_ERR_NO_ERROR, 1000);

        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 2);
        rd_kafka_poll(c1, 1000);
        /* Enough time to make a request, fail with a retriable error, and
         * retry. */
        rd_sleep(1);

        /* Reset leader. */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        rd_kafka_poll(c1, 1000);
        rd_sleep(1);

        /* There should be no infinite loop of OffsetForLeaderEpoch, and
         * consequently, we should be able to consume these messages as a sign
         * of success. */
        test_produce_msgs_easy_v(topic, testid, 0, 0, msg_cnt, 10,
                                 "bootstrap.servers", bootstraps,
                                 "batch.num.messages", "1", NULL);

        test_consumer_poll("MSG_INIT", c1, testid, 0, 0, msg_cnt, NULL);


        rd_kafka_destroy(c1);

        test_mock_cluster_destroy(mcluster);

        TEST_LATER_CHECK();
        SUB_TEST_PASS();
}

/**
 * @brief Storing an offset without leader epoch should still be allowed
 *        and the greater than check should apply only to the offset.
 *        See #4384.
 */
static void do_test_store_offset_without_leader_epoch(void) {
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_conf_t *conf;
        const char *bootstraps;
        const char *topic      = test_mk_topic_name(__FUNCTION__, 1);
        const char *c1_groupid = topic;
        rd_kafka_t *c1;
        rd_kafka_topic_t *rdk_topic;
        uint64_t testid = test_id_generate();
        rd_kafka_topic_partition_list_t *rktpars;
        rd_kafka_topic_partition_t *rktpar;
        int32_t leader_epoch;

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(3, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "5000");
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "enable.auto.offset.store", "false");
        test_conf_set(conf, "enable.partition.eof", "true");

        c1 = test_create_consumer(c1_groupid, NULL, conf, NULL);
        test_consumer_subscribe(c1, topic);

        /* Leader epoch becomes 1. */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 2);

        /* Read EOF. */
        test_consumer_poll("MSG_ALL", c1, testid, 1, 0, 0, NULL);

        TEST_SAY(
            "Storing offset without leader epoch with rd_kafka_offset_store");
        rdk_topic = rd_kafka_topic_new(c1, topic, NULL);
        /* Legacy function stores offset + 1 */
        rd_kafka_offset_store(rdk_topic, 0, 1);
        rd_kafka_topic_destroy(rdk_topic);

        rd_kafka_commit(c1, NULL, rd_false);

        rktpars = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(rktpars, topic, 0);
        rd_kafka_committed(c1, rktpars, -1);

        TEST_ASSERT(rktpars->elems[0].offset == 2, "expected %d, got %" PRId64,
                    2, rktpars->elems[0].offset);
        leader_epoch =
            rd_kafka_topic_partition_get_leader_epoch(&rktpars->elems[0]);

        /* OffsetFetch returns the leader epoch even if not set. */
        TEST_ASSERT(leader_epoch == 1, "expected %d, got %" PRId32, 1,
                    leader_epoch);
        rd_kafka_topic_partition_list_destroy(rktpars);

        TEST_SAY(
            "Storing offset without leader epoch with rd_kafka_offsets_store");
        rktpars = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(rktpars, topic, 0)->offset = 5;
        rd_kafka_offsets_store(c1, rktpars);
        rd_kafka_topic_partition_list_destroy(rktpars);

        TEST_CALL_ERR__(rd_kafka_commit(c1, NULL, rd_false));

        rktpars = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(rktpars, topic, 0);
        rd_kafka_committed(c1, rktpars, -1);

        TEST_ASSERT(rktpars->elems[0].offset == 5, "expected %d, got %" PRId64,
                    5, rktpars->elems[0].offset);
        leader_epoch =
            rd_kafka_topic_partition_get_leader_epoch(&rktpars->elems[0]);
        /* OffsetFetch returns the leader epoch even if not set. */
        TEST_ASSERT(leader_epoch == 1, "expected %d, got %" PRId32, 1,
                    leader_epoch);
        rd_kafka_topic_partition_list_destroy(rktpars);

        TEST_SAY(
            "While storing offset with leader epoch it should check that value "
            "first");
        /* Setting it to (6,1), as last one has epoch -1. */
        rktpars        = rd_kafka_topic_partition_list_new(1);
        rktpar         = rd_kafka_topic_partition_list_add(rktpars, topic, 0);
        rktpar->offset = 6;
        rd_kafka_topic_partition_set_leader_epoch(rktpar, 1);
        rd_kafka_offsets_store(c1, rktpars);
        rd_kafka_topic_partition_list_destroy(rktpars);

        rd_kafka_commit(c1, NULL, rd_false);

        /* Trying to store (7,0), it should skip the commit. */
        rktpars        = rd_kafka_topic_partition_list_new(1);
        rktpar         = rd_kafka_topic_partition_list_add(rktpars, topic, 0);
        rktpar->offset = 7;
        rd_kafka_topic_partition_set_leader_epoch(rktpar, 0);
        rd_kafka_offsets_store(c1, rktpars);
        rd_kafka_topic_partition_list_destroy(rktpars);

        rd_kafka_commit(c1, NULL, rd_false);

        /* Committed offset is (6,1). */
        rktpars = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(rktpars, topic, 0);
        rd_kafka_committed(c1, rktpars, -1);

        TEST_ASSERT(rktpars->elems[0].offset == 6, "expected %d, got %" PRId64,
                    6, rktpars->elems[0].offset);
        leader_epoch =
            rd_kafka_topic_partition_get_leader_epoch(&rktpars->elems[0]);
        TEST_ASSERT(leader_epoch == 1, "expected %d, got %" PRId32, 1,
                    leader_epoch);
        rd_kafka_topic_partition_list_destroy(rktpars);

        rd_kafka_destroy(c1);

        test_mock_cluster_destroy(mcluster);

        TEST_LATER_CHECK();
        SUB_TEST_PASS();
}


int main_0139_offset_validation_mock(int argc, char **argv) {

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        do_test_no_duplicates_during_offset_validation();

        do_test_permanent_error_retried(RD_KAFKA_RESP_ERR__SSL);
        do_test_permanent_error_retried(RD_KAFKA_RESP_ERR__RESOLVE);

        do_test_two_leader_changes();

        do_test_store_offset_without_leader_epoch();

        return 0;
}
