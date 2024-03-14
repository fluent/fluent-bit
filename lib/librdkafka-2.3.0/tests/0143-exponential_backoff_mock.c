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
#include "../src/rdkafka_mock.h"

const int32_t retry_ms     = 100;
const int32_t retry_max_ms = 1000;

static void free_mock_requests(rd_kafka_mock_request_t **requests,
                               size_t request_cnt) {
        size_t i;
        for (i = 0; i < request_cnt; i++)
                rd_kafka_mock_request_destroy(requests[i]);
        rd_free(requests);
}
/**
 * @brief find_coordinator test
 * We fail the request with RD_KAFKA_RESP_ERR_GROUP_COORDINATOR_NOT_AVAILABLE,
 * so that the request is tried via the intervalled mechanism. The intervalling
 * is done at 500 ms, with a 20% jitter. However, the actual code to retry the
 * request runs inside rd_kafka_cgrp_serve that is called every one second,
 * hence, the retry actually happens always in 1 second, no matter what the
 * jitter is. This will be fixed once rd_kafka_cgrp_serve is timer triggered.
 * The exponential backoff does not apply in this case we just apply the jitter
 * to the backoff of intervalled query The retry count is non - deterministic as
 * fresh request spawned on its own.
 */
static void test_find_coordinator(rd_kafka_mock_cluster_t *mcluster,
                                  const char *topic,
                                  rd_kafka_conf_t *conf) {
        rd_kafka_mock_request_t **requests = NULL;
        size_t request_cnt                 = 0;
        int64_t previous_request_ts        = -1;
        int32_t retry_count                = 0;
        int32_t num_retries                = 4;
        const int32_t low                  = 1000;
        int32_t buffer                     = 200;  // 200 ms buffer added
        rd_kafka_t *consumer;
        rd_kafka_message_t *rkm;
        size_t i;

        SUB_TEST();
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");

        consumer = test_create_consumer(topic, NULL, conf, NULL);

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_FindCoordinator, num_retries,
            RD_KAFKA_RESP_ERR_GROUP_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_GROUP_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_GROUP_COORDINATOR_NOT_AVAILABLE,
            RD_KAFKA_RESP_ERR_GROUP_COORDINATOR_NOT_AVAILABLE);
        /* This will trigger a find_coordinator request */
        rkm = rd_kafka_consumer_poll(consumer, 10 * 1000);
        if (rkm)
                rd_kafka_message_destroy(rkm);
        rd_sleep(4);
        requests = rd_kafka_mock_get_requests(mcluster, &request_cnt);
        for (i = 0; (i < request_cnt) && (retry_count < num_retries); i++) {
                TEST_SAY("Broker Id : %d API Key : %d Timestamp : %" PRId64
                         "\n",
                         rd_kafka_mock_request_id(requests[i]),
                         rd_kafka_mock_request_api_key(requests[i]),
                         rd_kafka_mock_request_timestamp(requests[i]));

                if (rd_kafka_mock_request_api_key(requests[i]) !=
                    RD_KAFKAP_FindCoordinator)
                        continue;

                if (previous_request_ts != -1) {
                        int64_t time_difference =
                            (rd_kafka_mock_request_timestamp(requests[i]) -
                             previous_request_ts) /
                            1000;
                        TEST_ASSERT(((time_difference > low - buffer) &&
                                     (time_difference < low + buffer)),
                                    "Time difference should be close "
                                    "to 1 second, it is %" PRId64
                                    " ms instead.\n",
                                    time_difference);
                        retry_count++;
                }
                previous_request_ts =
                    rd_kafka_mock_request_timestamp(requests[i]);
        }
        rd_kafka_destroy(consumer);
        free_mock_requests(requests, request_cnt);
        rd_kafka_mock_clear_requests(mcluster);
        SUB_TEST_PASS();
}

/**
 * Exponential Backoff needs to be checked for the request_type. Also the
 * request_type should only be retried if one previous has failed for correct
 * execution.
 */
static void helper_exponential_backoff(rd_kafka_mock_cluster_t *mcluster,
                                       int32_t request_type) {
        rd_kafka_mock_request_t **requests = NULL;
        size_t request_cnt                 = 0;
        int64_t previous_request_ts        = -1;
        int32_t retry_count                = 0;
        size_t i;
        requests = rd_kafka_mock_get_requests(mcluster, &request_cnt);
        for (i = 0; i < request_cnt; i++) {
                TEST_SAY("Broker Id : %d API Key : %d Timestamp : %" PRId64
                         "\n",
                         rd_kafka_mock_request_id(requests[i]),
                         rd_kafka_mock_request_api_key(requests[i]),
                         rd_kafka_mock_request_timestamp(requests[i]));

                if (rd_kafka_mock_request_api_key(requests[i]) != request_type)
                        continue;

                if (previous_request_ts != -1) {
                        int64_t time_difference =
                            (rd_kafka_mock_request_timestamp(requests[i]) -
                             previous_request_ts) /
                            1000;
                        /* Max Jitter is 20 percent each side so buffer chosen
                         * is 25 percent to account for latency delays */
                        int64_t low =
                            ((1 << retry_count) * (retry_ms)*75) / 100;
                        int64_t high =
                            ((1 << retry_count) * (retry_ms)*125) / 100;
                        if (high > ((retry_max_ms * 125) / 100))
                                high = (retry_max_ms * 125) / 100;
                        if (low > ((retry_max_ms * 75) / 100))
                                low = (retry_max_ms * 75) / 100;
                        TEST_ASSERT((time_difference < high) &&
                                        (time_difference > low),
                                    "Time difference is not respected, should "
                                    "be between %" PRId64 " and %" PRId64
                                    " where time difference is %" PRId64 "\n",
                                    low, high, time_difference);
                        retry_count++;
                }
                previous_request_ts =
                    rd_kafka_mock_request_timestamp(requests[i]);
        }
        free_mock_requests(requests, request_cnt);
}
/**
 * @brief offset_commit test
 * We fail the request with RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS so
 * that the request is retried with the exponential backoff. The max retries
 * allowed is 2 for offset_commit. The RPC calls rd_kafka_buf_retry for its
 * retry attempt so this tests all such RPCs which depend on it for retrying.
 * The retry number of request is deterministic i.e no fresh requests are
 * spawned on its own. Also the max retries is 2 for Offset Commit.
 */
static void test_offset_commit(rd_kafka_mock_cluster_t *mcluster,
                               const char *topic,
                               rd_kafka_conf_t *conf) {
        rd_kafka_t *consumer;
        rd_kafka_message_t *rkm;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_topic_partition_t *rktpar;
        SUB_TEST();
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");

        consumer = test_create_consumer(topic, NULL, conf, NULL);
        test_consumer_subscribe(consumer, topic);
        rkm = rd_kafka_consumer_poll(consumer, 10 * 1000);
        if (rkm)
                rd_kafka_message_destroy(rkm);
        rd_sleep(4);
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_OffsetCommit, 2,
            RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS,
            RD_KAFKA_RESP_ERR_COORDINATOR_LOAD_IN_PROGRESS);

        offsets = rd_kafka_topic_partition_list_new(1);
        rktpar  = rd_kafka_topic_partition_list_add(offsets, topic, 0);
        /* Setting Offset to an arbitrary number */
        rktpar->offset = 4;
        /* rd_kafka_commit will trigger OffsetCommit RPC call */
        rd_kafka_commit(consumer, offsets, 0);
        rd_kafka_topic_partition_list_destroy(offsets);
        rd_sleep(3);

        helper_exponential_backoff(mcluster, RD_KAFKAP_OffsetCommit);


        rd_kafka_destroy(consumer);
        rd_kafka_mock_clear_requests(mcluster);
        SUB_TEST_PASS();
}

/**
 * @brief produce test
 * We fail the request with RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS so
 * that the request is retried with the exponential backoff. The exponential
 * backoff is capped at retry_max_ms with jitter. The retry number of request is
 * deterministic i.e no fresh requests are spawned on its own.
 */
static void test_produce(rd_kafka_mock_cluster_t *mcluster,
                         const char *topic,
                         rd_kafka_conf_t *conf) {
        rd_kafka_t *producer;
        rd_kafka_topic_t *rkt;
        SUB_TEST();
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        producer = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt      = test_create_producer_topic(producer, topic, NULL);

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Produce, 7,
            RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS,
            RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS,
            RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS,
            RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS,
            RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS,
            RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS,
            RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS);

        test_produce_msgs(producer, rkt, 0, RD_KAFKA_PARTITION_UA, 0, 1,
                          "hello", 5);
        rd_sleep(3);

        helper_exponential_backoff(mcluster, RD_KAFKAP_Produce);


        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(producer);
        rd_kafka_mock_clear_requests(mcluster);
        SUB_TEST_PASS();
}

/**
 * Helper function for find coordinator trigger with the given request_type, the
 * find coordinator request should be triggered after a failing request of
 * request_type.
 */
static void helper_find_coordinator_trigger(rd_kafka_mock_cluster_t *mcluster,
                                            int32_t request_type) {
        rd_kafka_mock_request_t **requests = NULL;
        size_t request_cnt                 = 0;
        int32_t num_request                = 0;
        size_t i;
        requests = rd_kafka_mock_get_requests(mcluster, &request_cnt);
        for (i = 0; i < request_cnt; i++) {
                TEST_SAY("Broker Id : %d API Key : %d Timestamp : %" PRId64
                         "\n",
                         rd_kafka_mock_request_id(requests[i]),
                         rd_kafka_mock_request_api_key(requests[i]),
                         rd_kafka_mock_request_timestamp(requests[i]));
                if (num_request == 0) {
                        if (rd_kafka_mock_request_api_key(requests[i]) ==
                            request_type) {
                                num_request++;
                        }
                } else if (num_request == 1) {
                        if (rd_kafka_mock_request_api_key(requests[i]) ==
                            RD_KAFKAP_FindCoordinator) {
                                TEST_SAY(
                                    "FindCoordinator request made after "
                                    "failing request with NOT_COORDINATOR "
                                    "error.\n");
                                break;
                        } else if (rd_kafka_mock_request_api_key(requests[i]) ==
                                   request_type) {
                                num_request++;
                                TEST_FAIL(
                                    "Second request made without any "
                                    "FindCoordinator request.");
                        }
                }
        }
        free_mock_requests(requests, request_cnt);
        if (num_request != 1)
                TEST_FAIL("No request was made.");
}
/**
 * @brief heartbeat-find_coordinator test
 * We fail the request with RD_KAFKA_RESP_ERR_NOT_COORDINATOR_FOR_GROUP so that
 * the FindCoordinator request is triggered.
 */
static void test_heartbeat_find_coordinator(rd_kafka_mock_cluster_t *mcluster,
                                            const char *topic,
                                            rd_kafka_conf_t *conf) {
        rd_kafka_t *consumer;
        rd_kafka_message_t *rkm;
        SUB_TEST();
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");

        consumer = test_create_consumer(topic, NULL, conf, NULL);

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Heartbeat, 1,
            RD_KAFKA_RESP_ERR_NOT_COORDINATOR_FOR_GROUP);

        rd_kafka_mock_clear_requests(mcluster);
        test_consumer_subscribe(consumer, topic);
        /* This will trigger a find_coordinator request */
        rkm = rd_kafka_consumer_poll(consumer, 10 * 1000);
        if (rkm)
                rd_kafka_message_destroy(rkm);
        rd_sleep(6);


        helper_find_coordinator_trigger(mcluster, RD_KAFKAP_Heartbeat);


        rd_kafka_destroy(consumer);
        rd_kafka_mock_clear_requests(mcluster);
        SUB_TEST_PASS();
}

/**
 * @brief joingroup-find_coordinator test
 * We fail the request with RD_KAFKA_RESP_ERR_NOT_COORDINATOR_FOR_GROUP so that
 * the FindCoordinator request is triggered.
 */
static void test_joingroup_find_coordinator(rd_kafka_mock_cluster_t *mcluster,
                                            const char *topic,
                                            rd_kafka_conf_t *conf) {
        rd_kafka_t *consumer;
        rd_kafka_message_t *rkm;
        SUB_TEST();
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");

        consumer = test_create_consumer(topic, NULL, conf, NULL);
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_JoinGroup, 1,
            RD_KAFKA_RESP_ERR_NOT_COORDINATOR_FOR_GROUP);
        rd_kafka_mock_clear_requests(mcluster);
        test_consumer_subscribe(consumer, topic);
        /* This will trigger a find_coordinator request */
        rkm = rd_kafka_consumer_poll(consumer, 10 * 1000);
        if (rkm)
                rd_kafka_message_destroy(rkm);
        rd_sleep(4);

        helper_find_coordinator_trigger(mcluster, RD_KAFKAP_JoinGroup);

        rd_kafka_destroy(consumer);
        rd_kafka_mock_clear_requests(mcluster);
        SUB_TEST_PASS();
}

/**
 * @brief produce-fast_leader_query test
 * We fail a Produce request with RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER, so
 * that it triggers a fast leader query (a Metadata request). We don't update
 * the leader in this test, so the Metadata is always stale from the client's
 * perspective, and the fast leader query carries on, being backed off
 * exponentially until the max retry time is reached. The retry number of
 * request is non deterministic as it will keep retrying till the leader change.
 */
static void test_produce_fast_leader_query(rd_kafka_mock_cluster_t *mcluster,
                                           const char *topic,
                                           rd_kafka_conf_t *conf) {
        rd_kafka_mock_request_t **requests = NULL;
        size_t request_cnt                 = 0;
        int64_t previous_request_ts        = -1;
        int32_t retry_count                = 0;
        rd_bool_t produced                 = rd_false;
        rd_kafka_t *producer;
        rd_kafka_topic_t *rkt;
        size_t i;
        SUB_TEST();
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        producer = test_create_handle(RD_KAFKA_PRODUCER, conf);
        rkt      = test_create_producer_topic(producer, topic, NULL);

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER);
        rd_kafka_mock_clear_requests(mcluster);
        test_produce_msgs(producer, rkt, 0, RD_KAFKA_PARTITION_UA, 0, 1,
                          "hello", 1);
        rd_sleep(10);
        requests = rd_kafka_mock_get_requests(mcluster, &request_cnt);

        for (i = 0; i < request_cnt; i++) {
                TEST_SAY("Broker Id : %d API Key : %d Timestamp : %" PRId64
                         "\n",
                         rd_kafka_mock_request_id(requests[i]),
                         rd_kafka_mock_request_api_key(requests[i]),
                         rd_kafka_mock_request_timestamp(requests[i]));

                if (!produced && rd_kafka_mock_request_api_key(requests[i]) ==
                                     RD_KAFKAP_Produce)
                        produced = rd_true;
                else if (rd_kafka_mock_request_api_key(requests[i]) ==
                             RD_KAFKAP_Metadata &&
                         produced) {
                        if (previous_request_ts != -1) {
                                int64_t time_difference =
                                    (rd_kafka_mock_request_timestamp(
                                         requests[i]) -
                                     previous_request_ts) /
                                    1000;
                                /* Max Jitter is 20 percent each side so buffer
                                 * chosen is 25 percent to account for latency
                                 * delays */
                                int64_t low =
                                    ((1 << retry_count) * (retry_ms)*75) / 100;
                                int64_t high =
                                    ((1 << retry_count) * (retry_ms)*125) / 100;
                                if (high > ((retry_max_ms * 125) / 100))
                                        high = (retry_max_ms * 125) / 100;
                                if (low > ((retry_max_ms * 75) / 100))
                                        low = (retry_max_ms * 75) / 100;
                                TEST_ASSERT(
                                    (time_difference < high) &&
                                        (time_difference > low),
                                    "Time difference is not respected, should "
                                    "be between %" PRId64 " and %" PRId64
                                    " where time difference is %" PRId64 "\n",
                                    low, high, time_difference);
                                retry_count++;
                        }
                        previous_request_ts =
                            rd_kafka_mock_request_timestamp(requests[i]);
                }
        }
        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(producer);
        free_mock_requests(requests, request_cnt);
        rd_kafka_mock_clear_requests(mcluster);
        SUB_TEST_PASS();
}

/**
 * @brief fetch-fast_leader_query test
 * We fail a Fetch request by causing a leader change (the leader is the same,
 * but with a different leader epoch). It triggers fast leader query (Metadata
 * request). The request is able to obtain an updated leader, and hence, the
 * fast leader query terminates after one Metadata request.
 */
static void test_fetch_fast_leader_query(rd_kafka_mock_cluster_t *mcluster,
                                         const char *topic,
                                         rd_kafka_conf_t *conf) {
        rd_kafka_mock_request_t **requests   = NULL;
        size_t request_cnt                   = 0;
        rd_bool_t previous_request_was_Fetch = rd_false;
        rd_bool_t Metadata_after_Fetch       = rd_false;
        rd_kafka_t *consumer;
        rd_kafka_message_t *rkm;
        size_t i;
        SUB_TEST();
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");

        consumer = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(consumer, topic);
        rkm = rd_kafka_consumer_poll(consumer, 10 * 1000);

        if (rkm)
                rd_kafka_message_destroy(rkm);
        rd_kafka_mock_clear_requests(mcluster);

        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        rkm = rd_kafka_consumer_poll(consumer, 10 * 1000);
        if (rkm)
                rd_kafka_message_destroy(rkm);
        rd_sleep(3);
        requests = rd_kafka_mock_get_requests(mcluster, &request_cnt);
        for (i = 0; i < request_cnt; i++) {
                TEST_SAY("Broker Id : %d API Key : %d Timestamp : %" PRId64
                         "\n",
                         rd_kafka_mock_request_id(requests[i]),
                         rd_kafka_mock_request_api_key(requests[i]),
                         rd_kafka_mock_request_timestamp(requests[i]));

                if (rd_kafka_mock_request_api_key(requests[i]) ==
                    RD_KAFKAP_Fetch)
                        previous_request_was_Fetch = rd_true;
                else if (rd_kafka_mock_request_api_key(requests[i]) ==
                             RD_KAFKAP_Metadata &&
                         previous_request_was_Fetch) {
                        Metadata_after_Fetch = rd_true;
                        break;
                } else
                        previous_request_was_Fetch = rd_false;
        }
        rd_kafka_destroy(consumer);
        free_mock_requests(requests, request_cnt);
        rd_kafka_mock_clear_requests(mcluster);
        TEST_ASSERT(
            Metadata_after_Fetch,
            "Metadata Request should have been made after fetch atleast once.");
        SUB_TEST_PASS();
}

/**
 * @brief Exponential Backoff (KIP 580)
 * We test all the pipelines which affect the retry mechanism for both
 * intervalled queries where jitter is added and backed off queries where both
 * jitter and exponential backoff is applied with the max being retry_max_ms.
 */
int main_0143_exponential_backoff_mock(int argc, char **argv) {
        const char *topic = test_mk_topic_name("topic", 1);
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_conf_t *conf;
        const char *bootstraps;
        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL.\n");
                return 0;
        }
        mcluster = test_mock_cluster_new(1, &bootstraps);
        rd_kafka_mock_start_request_tracking(mcluster);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        test_conf_init(&conf, NULL, 30);
        /* This test may be slower when running with CI or Helgrind,
         * restart the timeout. */
        test_timeout_set(100);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "topic.metadata.refresh.interval.ms", "-1");

        test_produce(mcluster, topic, rd_kafka_conf_dup(conf));
        test_find_coordinator(mcluster, topic, rd_kafka_conf_dup(conf));
        test_offset_commit(mcluster, topic, rd_kafka_conf_dup(conf));
        test_heartbeat_find_coordinator(mcluster, topic,
                                        rd_kafka_conf_dup(conf));
        test_joingroup_find_coordinator(mcluster, topic,
                                        rd_kafka_conf_dup(conf));
        test_fetch_fast_leader_query(mcluster, topic, rd_kafka_conf_dup(conf));
        test_produce_fast_leader_query(mcluster, topic,
                                       rd_kafka_conf_dup(conf));
        test_mock_cluster_destroy(mcluster);
        rd_kafka_conf_destroy(conf);
        return 0;
}
