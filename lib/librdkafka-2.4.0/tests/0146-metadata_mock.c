/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2024, Confluent Inc.
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

static rd_bool_t is_metadata_request(rd_kafka_mock_request_t *request,
                                     void *opaque) {
        return rd_kafka_mock_request_api_key(request) == RD_KAFKAP_Metadata;
}

static rd_bool_t is_fetch_request(rd_kafka_mock_request_t *request,
                                  void *opaque) {
        return rd_kafka_mock_request_api_key(request) == RD_KAFKAP_Fetch;
}

/**
 * @brief Metadata should persists in cache after
 *        a full metadata refresh.
 *
 * @param assignor Assignor to use
 */
static void do_test_metadata_persists_in_cache(const char *assignor) {
        rd_kafka_t *rk;
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        rd_kafka_conf_t *conf;
        rd_kafka_topic_t *rkt;
        const rd_kafka_metadata_t *md;
        rd_kafka_topic_partition_list_t *subscription;

        SUB_TEST_QUICK("%s", assignor);

        mcluster = test_mock_cluster_new(3, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        test_conf_init(&conf, NULL, 10);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "partition.assignment.strategy", assignor);
        test_conf_set(conf, "group.id", topic);

        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

        subscription = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(subscription, topic, 0);

        rkt = test_create_consumer_topic(rk, topic);

        /* Metadata for topic is available */
        TEST_CALL_ERR__(rd_kafka_metadata(rk, 0, rkt, &md, 1000));
        rd_kafka_metadata_destroy(md);
        md = NULL;

        /* Subscribe to same topic */
        TEST_CALL_ERR__(rd_kafka_subscribe(rk, subscription));

        /* Request full metadata */
        TEST_CALL_ERR__(rd_kafka_metadata(rk, 1, NULL, &md, 1000));
        rd_kafka_metadata_destroy(md);
        md = NULL;

        /* Subscribing shouldn't give UNKNOWN_TOPIC_OR_PART err.
         * Verify no error was returned. */
        test_consumer_poll_no_msgs("no error", rk, 0, 100);

        rd_kafka_topic_partition_list_destroy(subscription);
        rd_kafka_topic_destroy(rkt);
        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief No loop of metadata requests should be started
 *        when a metadata request is made without leader epoch change.
 *        See issue #4577
 */
static void do_test_fast_metadata_refresh_stops(void) {
        rd_kafka_t *rk;
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        rd_kafka_conf_t *conf;
        int metadata_requests;

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(3, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        test_conf_init(&conf, NULL, 10);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        /* This error triggers a metadata refresh but no leader change
         * happened */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR);

        rd_kafka_mock_start_request_tracking(mcluster);
        test_produce_msgs2(rk, topic, 0, 0, 0, 1, NULL, 5);

        /* First call is for getting initial metadata,
         * second one happens after the error,
         * it should stop refreshing metadata after that. */
        metadata_requests = test_mock_wait_matching_requests(
            mcluster, 2, 500, is_metadata_request, NULL);
        TEST_ASSERT(metadata_requests == 2,
                    "Expected 2 metadata request, got %d", metadata_requests);
        rd_kafka_mock_stop_request_tracking(mcluster);

        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief A stale leader received while validating shouldn't
 *        migrate back the partition to that stale broker.
 */
static void do_test_stale_metadata_doesnt_migrate_partition(void) {
        int i, fetch_requests;
        rd_kafka_t *rk;
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        rd_kafka_conf_t *conf;

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(3, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 3);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);

        test_conf_init(&conf, NULL, 10);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", topic);
        test_conf_set(conf, "auto.offset.reset", "earliest");
        test_conf_set(conf, "enable.auto.commit", "false");
        test_conf_set(conf, "fetch.error.backoff.ms", "10");
        test_conf_set(conf, "fetch.wait.max.ms", "10");

        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

        test_consumer_subscribe(rk, topic);

        /* Produce and consume to leader 1 */
        test_produce_msgs_easy_v(topic, 0, 0, 0, 1, 0, "bootstrap.servers",
                                 bootstraps, NULL);
        test_consumer_poll_exact("read first", rk, 0, 0, 0, 1, rd_true, NULL);

        /* Change leader to 2, Fetch fails, refreshes metadata. */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 2);

        for (i = 0; i < 5; i++) {
                /* Validation fails, metadata refreshed again */
                rd_kafka_mock_broker_push_request_error_rtts(
                    mcluster, 2, RD_KAFKAP_OffsetForLeaderEpoch, 1,
                    RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR, 1000);
        }

        /* Wait partition migrates to broker 2 */
        rd_usleep(100 * 1000, 0);

        /* Return stale metadata */
        for (i = 0; i < 10; i++) {
                rd_kafka_mock_partition_push_leader_response(
                    mcluster, topic, 0, 1 /*leader id*/, 0 /*leader epoch*/);
        }

        /* Partition doesn't have to migrate back to broker 1 */
        rd_usleep(2000 * 1000, 0);
        rd_kafka_mock_start_request_tracking(mcluster);
        fetch_requests = test_mock_wait_matching_requests(
            mcluster, 0, 500, is_fetch_request, NULL);
        TEST_ASSERT(fetch_requests == 0,
                    "No fetch request should be received by broker 1, got %d",
                    fetch_requests);
        rd_kafka_mock_stop_request_tracking(mcluster);

        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief A metadata call for an existing topic, just after subscription,
 *        must not cause a UNKNOWN_TOPIC_OR_PART error.
 *        See issue #4589.
 */
static void do_test_metadata_call_before_join(void) {
        rd_kafka_t *rk;
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        rd_kafka_conf_t *conf;
        const struct rd_kafka_metadata *metadata;

        SUB_TEST_QUICK();

        mcluster = test_mock_cluster_new(3, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 3);

        test_conf_init(&conf, NULL, 10);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        test_conf_set(conf, "group.id", topic);

        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

        test_consumer_subscribe(rk, topic);

        TEST_CALL_ERR__(rd_kafka_metadata(rk, 1, 0, &metadata, 5000));
        rd_kafka_metadata_destroy(metadata);

        test_consumer_poll_no_msgs("no errors", rk, 0, 1000);

        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

int main_0146_metadata_mock(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);

        /* No need to test the "roundrobin" assignor case,
         * as this is just for checking the two code paths:
         * EAGER or COOPERATIVE one, and "range" is EAGER too. */
        do_test_metadata_persists_in_cache("range");
        do_test_metadata_persists_in_cache("cooperative-sticky");

        do_test_metadata_call_before_join();

        do_test_fast_metadata_refresh_stops();

        do_test_stale_metadata_doesnt_migrate_partition();

        return 0;
}
