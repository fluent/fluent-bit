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

        /* Will validate the offset and start fetching again
         * from offset 0. */
        rd_kafka_topic_partition_set_leader_epoch(rktpar, 0);
        rd_kafka_seek_partitions(c1, rktpars, -1);
        rd_kafka_topic_partition_list_destroy(rktpars);

        /* Read all messages after seek to zero.
         * In case of permanent error, instead, it resets to latest and
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

static rd_bool_t is_broker_fetch_request(rd_kafka_mock_request_t *request,
                                         void *opaque) {
        return rd_kafka_mock_request_id(request) == *(int *)(opaque) &&
               rd_kafka_mock_request_api_key(request) == RD_KAFKAP_Fetch;
}

static rd_bool_t
is_offset_for_leader_epoch_request(rd_kafka_mock_request_t *request,
                                   void *opaque) {
        return rd_kafka_mock_request_id(request) == *(int *)(opaque) &&
               rd_kafka_mock_request_api_key(request) ==
                   RD_KAFKAP_OffsetForLeaderEpoch;
}

static rd_bool_t is_metadata_request(rd_kafka_mock_request_t *request,
                                     void *opaque) {
        return rd_kafka_mock_request_api_key(request) == RD_KAFKAP_Metadata;
}

/**
 * @brief A second leader change is triggered after first one switches
 * to a leader supporting KIP-320, the second leader either:
 *
 * - variation 0: doesn't support KIP-320 (leader epoch -1).
 *   This can happed during a cluster roll for upgrading the cluster.
 *   See #4796.
 * - variation 1: the leader epoch is the same as previous leader.
 *   This can happen when the broker doesn't need that a validation
 *   should be performed after a leader change.
 *
 * In both cases no validation should be performed
 * and it should continue fetching messages on the new leader.
 */
static void do_test_leader_change_no_validation(int variation) {
        const char *topic      = test_mk_topic_name(__FUNCTION__, 1);
        const char *c1_groupid = topic;
        rd_kafka_t *c1;
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        int msg_cnt     = 5;
        uint64_t testid = test_id_generate();
        rd_kafka_conf_t *conf;
        int i, leader = 1;
        size_t matching_requests;
        /* No KIP-320 support on second leader change */
        int32_t leader_epoch = -1;
        if (variation == 1) {
                /* Same leader epoch on second leader change */
                leader_epoch = 2;
        }

        SUB_TEST_QUICK("variation: %d", variation);

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
        test_conf_set(conf, "enable.auto.commit", "false");

        c1 = test_create_consumer(c1_groupid, NULL, conf, NULL);
        test_consumer_subscribe(c1, topic);

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_SAY("Consume initial messages and join the group, etc.\n");
        test_consumer_poll("MSG_INIT", c1, testid, 0, 0, msg_cnt, NULL);

        TEST_SAY("Wait Fetch request to broker 1\n");
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 1, 1000, is_broker_fetch_request, &leader);
        TEST_ASSERT_LATER(matching_requests > 0,
                          "Expected at least one Fetch request to broker 1");

        /* No validation is performed on first fetch. */
        TEST_SAY("Wait no OffsetForLeaderEpoch request to broker 1\n");
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 0, 1000, is_offset_for_leader_epoch_request, &leader);
        TEST_ASSERT_LATER(matching_requests == 0,
                          "Expected no OffsetForLeaderEpoch request"
                          " to broker 1, got %" PRIusz,
                          matching_requests);
        rd_kafka_mock_stop_request_tracking(mcluster);

        /* The leader will change from 1->2, and the OffsetForLeaderEpoch will
         * be sent to broker 2. Leader epoch becomes 1. */
        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_SAY("Changing leader to broker 2\n");
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 2);
        leader = 2;
        rd_kafka_poll(c1, 1000);

        TEST_SAY("Wait Fetch request to broker 2\n");
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 1, 1000, is_broker_fetch_request, &leader);
        TEST_ASSERT_LATER(matching_requests > 0,
                          "Expected at least one fetch request to broker 2");

        TEST_SAY("Wait OffsetForLeaderEpoch request to broker 2\n");
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 1, 1000, is_offset_for_leader_epoch_request, &leader);
        TEST_ASSERT_LATER(matching_requests == 1,
                          "Expected one OffsetForLeaderEpoch request"
                          " to broker 2, got %" PRIusz,
                          matching_requests);
        rd_kafka_mock_stop_request_tracking(mcluster);

        /* Reset leader, set leader epoch to `leader_epoch`
         * to trigger this special case. */
        TEST_SAY("Changing leader to broker 1\n");
        for (i = 0; i < 5; i++) {
                rd_kafka_mock_partition_push_leader_response(mcluster, topic, 0,
                                                             1, leader_epoch);
        }
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        leader = 1;
        rd_kafka_mock_start_request_tracking(mcluster);
        rd_kafka_poll(c1, 1000);

        TEST_SAY("Wait Fetch request to broker 1\n");
        /* 0 is correct here as second parameter as we don't wait to receive
         * at least one Fetch request, given in the failure case it'll take more
         * than 1s and it's possible a OffsetForLeaderEpoch is received after
         * that, because we ran out of overridden leader responses. */
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 0, 1000, is_broker_fetch_request, &leader);
        TEST_ASSERT_LATER(matching_requests > 0,
                          "Expected at least one fetch request to broker 1");

        /* Given same leader epoch, or -1, is returned,
         * no validation is performed */
        TEST_SAY("Wait no OffsetForLeaderEpoch request to broker 1\n");
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 0, 1000, is_offset_for_leader_epoch_request, &leader);
        TEST_ASSERT_LATER(matching_requests == 0,
                          "Expected no OffsetForLeaderEpoch request"
                          " to broker 1, got %" PRIusz,
                          matching_requests);
        rd_kafka_mock_stop_request_tracking(mcluster);

        rd_kafka_destroy(c1);
        test_mock_cluster_destroy(mcluster);

        TEST_LATER_CHECK();
        SUB_TEST_PASS();
}

static int
is_fatal_cb(rd_kafka_t *rk, rd_kafka_resp_err_t err, const char *reason) {
        /* Ignore UNKNOWN_TOPIC_OR_PART errors. */
        TEST_SAY("is_fatal?: %s: %s\n", rd_kafka_err2str(err), reason);
        if (err == RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION ||
            err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART)
                return 0;
        return 1;
}

/**
 * @brief Test partition validation when it's temporarily delegated to
 * the internal broker. There are two variations:
 *
 * variation 1: leader epoch bump is simultaneous to the partition
 *              delegation returning from the internal broker to the
 *              new leader.
 * variation 2: leader epoch bump is triggered immediately by KIP-951
 *              and validation fails, later metadata request fails
 *              and partition is delegated to the internal broker.
 *              When partition is delegated back to the leader,
 *              it finds the same leader epoch but validation must
 *              be completed as state is still VALIDATE_EPOCH_WAIT.
 *
 * In both cases, fetch must continue with the new leader and
 * after the validation is completed.
 *
 * See #4804.
 */
static void do_test_leader_change_from_internal_broker(int variation) {
        const char *topic      = test_mk_topic_name(__FUNCTION__, 1);
        const char *c1_groupid = topic;
        rd_kafka_t *c1;
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        int msg_cnt     = 5;
        uint64_t testid = test_id_generate();
        rd_kafka_conf_t *conf;
        int leader = 1;
        size_t matching_requests, expected_offset_for_leader_epoch_requests = 1;

        SUB_TEST_QUICK("variation: %d", variation);

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
        test_conf_set(conf, "enable.auto.commit", "false");

        c1 = test_create_consumer(c1_groupid, NULL, conf, NULL);
        test_consumer_subscribe(c1, topic);
        test_curr->is_fatal_cb = is_fatal_cb;

        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_SAY("Consume initial messages and join the group, etc.\n");
        test_consumer_poll("MSG_INIT", c1, testid, 0, 0, msg_cnt, NULL);

        TEST_SAY("Wait Fetch request to broker 1\n");
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 1, 1000, is_broker_fetch_request, &leader);
        TEST_ASSERT_LATER(matching_requests > 0,
                          "Expected at least one Fetch request to broker 1");

        /* No validation is performed on first fetch. */
        TEST_SAY("Wait no OffsetForLeaderEpoch request to broker 1\n");
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 0, 1000, is_offset_for_leader_epoch_request, &leader);
        TEST_ASSERT_LATER(matching_requests == 0,
                          "Expected no OffsetForLeaderEpoch request"
                          " to broker 1, got %" PRIusz,
                          matching_requests);
        rd_kafka_mock_stop_request_tracking(mcluster);

        /* The leader will change from 1->2, and the OffsetForLeaderEpoch will
         * be sent to broker 2. Leader epoch becomes 1. */
        rd_kafka_mock_start_request_tracking(mcluster);
        TEST_SAY("Changing leader to broker 2\n");
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 2);
        leader = 2;
        rd_kafka_poll(c1, 1000);

        TEST_SAY("Wait Fetch request to broker 2\n");
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 1, 1000, is_broker_fetch_request, &leader);
        TEST_ASSERT_LATER(matching_requests > 0,
                          "Expected at least one fetch request to broker 2");

        TEST_SAY("Wait OffsetForLeaderEpoch request to broker 2\n");
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 1, 1000, is_offset_for_leader_epoch_request, &leader);
        TEST_ASSERT_LATER(matching_requests == 1,
                          "Expected one OffsetForLeaderEpoch request"
                          " to broker 2, got %" PRIusz,
                          matching_requests);
        rd_kafka_mock_stop_request_tracking(mcluster);

        /* Reset leader, Metadata request fails in between and delegates
         * the partition to the internal broker. */
        TEST_SAY("Changing leader to broker 1\n");
        if (variation == 0) {
                /* Fail Fetch request too, otherwise KIP-951 mechanism is faster
                 * than the Metadata request. */
                rd_kafka_mock_push_request_errors(
                    mcluster, RD_KAFKAP_Fetch, 1,
                    RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);
        } else if (variation == 1) {
                /* First OffsetForLeaderEpoch is triggered by KIP-951,
                 * it updates leader epoch, then it fails, triggers metadata
                 * refresh,
                 * Metadata fails too and partition is delegated to the internal
                 * broker.
                 * Validation is retried three times during this period
                 * and it should fail because we want to see what happens
                 * next when partition isn't delegated to the internal
                 * broker anymore. */
                rd_kafka_mock_push_request_errors(
                    mcluster, RD_KAFKAP_OffsetForLeaderEpoch, 3,
                    RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART,
                    RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART,
                    RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);
        }

        /* This causes a Metadata request error. */
        rd_kafka_mock_topic_set_error(mcluster, topic,
                                      RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        leader = 1;
        rd_kafka_mock_start_request_tracking(mcluster);
        rd_kafka_poll(c1, 1000);

        TEST_SAY(
            "Wait a Metadata request that fails and delegates partition to"
            " the internal broker.\n");
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 1, 1000, is_metadata_request, NULL);
        TEST_ASSERT_LATER(matching_requests > 0,
                          "Expected at least one Metadata request");
        TEST_SAY(
            "Reset partition error status."
            " Partition is delegated to broker 1.\n");
        rd_kafka_mock_topic_set_error(mcluster, topic,
                                      RD_KAFKA_RESP_ERR_NO_ERROR);

        TEST_SAY("Wait Fetch request to broker 1\n");
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 1, 2000, is_broker_fetch_request, &leader);
        TEST_ASSERT_LATER(matching_requests > 0,
                          "Expected at least one fetch request to broker 1");

        TEST_SAY("Wait OffsetForLeaderEpoch request to broker 1\n");
        if (variation == 1) {
                /* There's three OffsetForLeaderEpoch requests more in
                 * variation 1. See previous comment. */
                expected_offset_for_leader_epoch_requests += 3;
        }
        matching_requests = test_mock_wait_matching_requests(
            mcluster, 1, 1000, is_offset_for_leader_epoch_request, &leader);
        TEST_ASSERT_LATER(
            matching_requests == expected_offset_for_leader_epoch_requests,
            "Expected %" PRIusz
            " OffsetForLeaderEpoch request"
            " to broker 1, got %" PRIusz,
            expected_offset_for_leader_epoch_requests, matching_requests);
        rd_kafka_mock_stop_request_tracking(mcluster);

        rd_kafka_destroy(c1);
        test_mock_cluster_destroy(mcluster);

        TEST_LATER_CHECK();
        SUB_TEST_PASS();
        test_curr->is_fatal_cb = NULL;
}

/**
 * @brief Opaque for do_test_list_offsets_leader_change.
 */
typedef struct do_test_list_offsets_leader_change_s {
        rd_kafka_mock_cluster_t *mcluster;
        const char *topic;
        int msg_cnt;
        int variation;
} do_test_list_offsets_leader_change_t;

/**
 * @brief Rebalance callback for do_test_list_offsets_leader_change.
 */
static void do_test_list_offsets_leader_change_rebalance_cb(
    rd_kafka_t *rk,
    rd_kafka_resp_err_t err,
    rd_kafka_topic_partition_list_t *partitions,
    void *opaque) {
        TEST_SAY("Rebalance callback: %s with %d partition(s)\n",
                 rd_kafka_err2str(err), partitions->cnt);
        do_test_list_offsets_leader_change_t *test = opaque;
        switch (err) {
        case RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS: {
                int retries = 0;
                int64_t low, high;
                rd_kafka_resp_err_t list_offsets_err =
                    RD_KAFKA_RESP_ERR_NO_ERROR;

                TEST_ASSERT(partitions->cnt == 1,
                            "Expected 1 assigned partition, got %d",
                            partitions->cnt);

                /* Change leader to 2 */
                rd_kafka_mock_partition_set_leader(test->mcluster, test->topic,
                                                   0, 2);

                do {
                        /* Set a wrong leader epoch that should not be used
                         * for listing offsets. */
                        rd_kafka_topic_partition_set_leader_epoch(
                            &partitions->elems[0], 1234);

                        if (test->variation == 0) {
                                partitions->elems[0].offset = 1;
                                list_offsets_err = rd_kafka_offsets_for_times(
                                    rk, partitions, 1000);
                        } else {
                                list_offsets_err =
                                    rd_kafka_query_watermark_offsets(
                                        rk, partitions->elems[0].topic,
                                        partitions->elems[0].partition, &low,
                                        &high, 1000);
                        }
                        retries++;
                        if (retries == 1) {
                                TEST_ASSERT(
                                    list_offsets_err ==
                                        RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION,
                                    "Expected NOT_LEADER_FOR_PARTITION, got %s",
                                    rd_kafka_err2str(list_offsets_err));
                        }
                        if (retries > 2)
                                TEST_FAIL(
                                    "Offsets for times failed %d times "
                                    " during the rebalance callback",
                                    retries);
                } while (list_offsets_err != RD_KAFKA_RESP_ERR_NO_ERROR);

                TEST_ASSERT(retries == 2,
                            "There must be exactly 2 retries, "
                            "got %d",
                            retries);


                if (test->variation == 0) {
                        /* Mock handler currently returns
                         * RD_KAFKA_OFFSET_SPEC_LATEST
                         * in the offsets for times case */
                        TEST_ASSERT(partitions->elems[0].offset ==
                                        RD_KAFKA_OFFSET_SPEC_LATEST,
                                    "Expected offset for times LATEST,"
                                    " got %" PRId64,
                                    partitions->elems[0].offset);
                } else {
                        TEST_ASSERT(0 == low,
                                    "Expected low offset 0"
                                    ", got %" PRId64,
                                    low);
                        TEST_ASSERT(10 == high,
                                    "Expected high offset 10"
                                    ", got %" PRId64,
                                    high);
                        partitions->elems[0].offset = high;
                }

                test_consumer_assign_by_rebalance_protocol("rebalance", rk,
                                                           partitions);

                break;
        }
        case RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS:
                test_consumer_unassign_by_rebalance_protocol("rebalance", rk,
                                                             partitions);
                break;
        default:
                break;
        }
}

/**
 * @brief Test that listing offsets during a leader change works as expected.
 *        by returning a NOT_LEADER_FOR_PARTITION error and clearing the cache.
 *
 *        There are two variations:
 *        - variation 0: uses rd_kafka_offsets_for_times
 *        - variation 1: uses rd_kafka_query_watermark_offsets
 */
static void do_test_list_offsets_leader_change(int variation) {
        const char *topic      = test_mk_topic_name(__FUNCTION__, 1);
        const char *c1_groupid = topic;
        rd_kafka_t *c1;
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        int msg_cnt     = 10;
        uint64_t testid = test_id_generate();
        rd_kafka_conf_t *conf;
        do_test_list_offsets_leader_change_t opaque;

        SUB_TEST_QUICK("%s", variation == 0 ? "offsets_for_times"
                                            : "query_watermark_offsets");

        mcluster = test_mock_cluster_new(2, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 2);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);

        /* Seed the topic with messages */
        test_produce_msgs_easy_v(topic, testid, 0, 0, msg_cnt, 10,
                                 "bootstrap.servers", bootstraps, NULL);

        test_conf_init(&conf, NULL, 60);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "auto.offset.reset", "earliest");
        rd_kafka_conf_set_rebalance_cb(
            conf, do_test_list_offsets_leader_change_rebalance_cb);
        opaque.mcluster  = mcluster;
        opaque.topic     = topic;
        opaque.msg_cnt   = msg_cnt;
        opaque.variation = variation;
        rd_kafka_conf_set_opaque(conf, &opaque);

        c1 = test_create_consumer(c1_groupid, NULL, conf, NULL);
        test_consumer_subscribe(c1, topic);

        /* Consumes no messages if assignment starts from
         * latest as set in the rebalance callback,
         * otherwise it's configured as earliest. */
        test_consumer_poll_no_msgs("MSG_INIT", c1, testid, 5000);

        rd_kafka_destroy(c1);

        test_mock_cluster_destroy(mcluster);

        TEST_LATER_CHECK();
        SUB_TEST_PASS();
}

int main_0139_offset_validation_mock(int argc, char **argv) {

        TEST_SKIP_MOCK_CLUSTER(0);

        do_test_no_duplicates_during_offset_validation();

        do_test_permanent_error_retried(RD_KAFKA_RESP_ERR__SSL);
        do_test_permanent_error_retried(RD_KAFKA_RESP_ERR__RESOLVE);

        do_test_two_leader_changes();

        do_test_store_offset_without_leader_epoch();

        do_test_leader_change_no_validation(0);
        do_test_leader_change_no_validation(1);

        do_test_leader_change_from_internal_broker(0);
        do_test_leader_change_from_internal_broker(1);

        do_test_list_offsets_leader_change(0);
        do_test_list_offsets_leader_change(1);

        return 0;
}
