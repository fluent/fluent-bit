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
        int32_t *broker_id = (int32_t *)opaque;
        rd_bool_t ret =
            rd_kafka_mock_request_api_key(request) == RD_KAFKAP_Fetch;
        if (broker_id)
                ret &= rd_kafka_mock_request_id(request) == *broker_id;
        return ret;
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
 * @brief Tests about the fast metadata refresh feature.
 *
 * - variation 0: no loop of metadata requests should be started
 *   when a metadata request is made without leader epoch change.
 *   It's expected it stops after the first request.
 *   See issue #4577
 *
 * - variation 1: an error is returned on subsequent metadata response too,
 *   metadata refreshes continue every second until the error is cleared.
 *
 * It's expected that the temporary error doesn't remove the topic from cache,
 * produce requests aren't blocked from metadata errors and no error is
 * to be surfaced to the application.
 */
static void do_test_fast_metadata_refresh(int variation) {
        rd_kafka_t *rk;
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        rd_kafka_conf_t *conf;
        int metadata_requests;
        int expected_metadata_requests;
        switch (variation) {
        case 0:
                expected_metadata_requests = 2;
                break;
        case 1:
                expected_metadata_requests = 7;
                break;
        default:
                TEST_FAIL("Invalid variation %d", variation);
                break;
        }

        SUB_TEST_QUICK("%s", variation == 0 ? "stops" : "retries");

        mcluster = test_mock_cluster_new(3, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 1);

        test_conf_init(&conf, NULL, 10);
        test_conf_set(conf, "bootstrap.servers", bootstraps);
        rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        rd_kafka_mock_start_request_tracking(mcluster);

        if (variation == 1) {
                /* Produce some messages to the topic
                 * and keep metadata in cache. */
                test_produce_msgs2(rk, topic, 0, 0, 0, 3, NULL, 5);
        }

        /* This error triggers a metadata refresh but no leader change
         * happened */
        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_Produce, 1,
            RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR);

        if (variation == 1) {
                rd_kafka_mock_topic_set_error(
                    mcluster, topic, RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR);
        }

        test_produce_msgs2(rk, topic, 0, 0, 0, 3, NULL, 5);

        /* Wait some time for seeing the retries */
        rd_sleep(3);

        if (variation == 1) {
                /* Clear topic error to stop the retries */
                rd_kafka_mock_topic_set_error(mcluster, topic,
                                              RD_KAFKA_RESP_ERR_NO_ERROR);
        }

        /* First call is for getting initial metadata,
         * second one happens after the error,
         * it should stop refreshing metadata after that.
         *
         * There can be an additional metadata request originating from
         * the 1s timer when the partition is being delegated or
         * the broker is connecting but still not up. */
        metadata_requests = test_mock_wait_matching_requests(
            mcluster, expected_metadata_requests, 500, is_metadata_request,
            NULL);
        TEST_ASSERT(expected_metadata_requests <= metadata_requests &&
                        metadata_requests <= expected_metadata_requests + 1,
                    "Expected %d or %d metadata request, got %d",
                    expected_metadata_requests, expected_metadata_requests + 1,
                    metadata_requests);
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
        int32_t expected_broker_id;

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
        test_conf_set(conf, "fetch.queue.backoff.ms", "10");

        rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

        test_consumer_subscribe(rk, topic);

        /* Produce and consume to leader 1 */
        test_produce_msgs_easy_v(topic, 0, 0, 0, 1, 0, "bootstrap.servers",
                                 bootstraps, NULL);
        test_consumer_poll_exact("read first", rk, 0, 0, 0, 1, rd_true, NULL);

        /* Change leader to 2, Fetch fails, refreshes metadata. */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 2);

        /* Validation fails, metadata refreshed again */
        rd_kafka_mock_broker_push_request_error_rtts(
            mcluster, 2, RD_KAFKAP_OffsetForLeaderEpoch, 1,
            RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR, 1000);

        /* Wait partition migrates to broker 2 */
        rd_usleep(100 * 1000, 0);

        /* Ask to return stale metadata while calling OffsetForLeaderEpoch */
        rd_kafka_mock_start_request_tracking(mcluster);
        for (i = 0; i < 10; i++) {
                rd_kafka_mock_partition_push_leader_response(
                    mcluster, topic, 0, 1 /*leader id*/, 0 /*leader epoch*/);
        }

        /* After the error on OffsetForLeaderEpoch metadata is refreshed
         * and it returns the stale metadata.
         * 1s for the OffsetForLeaderEpoch plus at least 500ms for
         * restarting the fetch requests */
        rd_usleep(2000 * 1000, 0);

        /* Partition doesn't have to migrate back to broker 1 */
        expected_broker_id = 1;
        fetch_requests     = test_mock_wait_matching_requests(
            mcluster, 0, 500, is_fetch_request, &expected_broker_id);
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

typedef struct expected_request_s {
        int16_t api_key;
        int32_t broker;
} expected_request_t;

/**
 * @brief Verify that a request with the expected ApiKey and broker
 *        was sent to the cluster.
 */
rd_bool_t verify_requests_after_metadata_update_operation(
    rd_kafka_mock_cluster_t *mcluster,
    expected_request_t *expected_request) {
        size_t cnt, i;
        rd_kafka_mock_request_t **requests =
            rd_kafka_mock_get_requests(mcluster, &cnt);
        rd_bool_t found = rd_false;

        for (i = 0; i < cnt; i++) {
                int16_t api_key;
                int32_t broker;
                rd_kafka_mock_request_t *request = requests[i];
                api_key = rd_kafka_mock_request_api_key(request);
                broker  = rd_kafka_mock_request_id(request);
                if (api_key == expected_request->api_key &&
                    broker == expected_request->broker) {
                        found = rd_true;
                        break;
                }
        }

        rd_kafka_mock_request_destroy_array(requests, cnt);

        return found;
}

/**
 * @brief A metadata update request should be triggered when a leader change
 *        happens while producing or consuming and cause a migration
 *        to the new leader.
 *
 * @param producer If true, the test will be for a producer, otherwise
 *                 for a consumer.
 * @param second_leader_change If true, a leader change will be triggered
 *                             for two partitions, otherwise for one.
 */
static void do_test_metadata_update_operation(rd_bool_t producer,
                                              rd_bool_t second_leader_change) {
        rd_kafka_t *rk;
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);
        rd_kafka_conf_t *conf;
        test_timing_t timing;
        rd_bool_t found;
        expected_request_t expected_request = {
            .api_key = producer ? RD_KAFKAP_Produce : RD_KAFKAP_Fetch,
            .broker  = 3};

        SUB_TEST_QUICK("%s, %s", producer ? "producer" : "consumer",
                       second_leader_change ? "two leader changes"
                                            : "single leader change");

        mcluster = test_mock_cluster_new(4, &bootstraps);
        rd_kafka_mock_topic_create(mcluster, topic, 2, 4);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 1, 2);

        test_conf_init(&conf, NULL, 20);
        test_conf_set(conf, "bootstrap.servers", bootstraps);

        if (producer) {
                test_conf_set(conf, "batch.num.messages", "1");
                rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
                rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

                /* Start producing to leader 1 and 2 */
                test_produce_msgs2(rk, topic, 0, 0, 0, 1, NULL, 0);
                test_produce_msgs2(rk, topic, 0, 1, 0, 1, NULL, 0);
                rd_kafka_flush(rk, 1000);
        } else {
                test_produce_msgs_easy_v(topic, 0, 0, 0, 1, 0,
                                         "bootstrap.servers", bootstraps, NULL);
                test_produce_msgs_easy_v(topic, 0, 1, 0, 1, 0,
                                         "bootstrap.servers", bootstraps, NULL);

                rd_kafka_topic_partition_list_t *assignment;
                test_conf_set(conf, "group.id", topic);
                test_conf_set(conf, "fetch.wait.max.ms", "100");
                test_conf_set(conf, "auto.offset.reset", "earliest");

                rk = test_create_handle(RD_KAFKA_CONSUMER, conf);

                assignment = rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(assignment, topic, 0);
                rd_kafka_topic_partition_list_add(assignment, topic, 1);
                test_consumer_assign("2 partitions", rk, assignment);
                rd_kafka_topic_partition_list_destroy(assignment);

                /* Start consuming from leader 1 and 2 */
                test_consumer_poll_timeout("initial leaders", rk, 0, -1, -1, 2,
                                           NULL, 5000);
        }

        TIMING_START(&timing, "Metadata update and partition migration");
        rd_kafka_mock_start_request_tracking(mcluster);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 3);
        if (second_leader_change)
                rd_kafka_mock_partition_set_leader(mcluster, topic, 1, 4);


        if (producer) {
                /* Produce two new messages to the new leaders */
                test_produce_msgs2(rk, topic, 0, 0, 1, 1, NULL, 0);
                test_produce_msgs2(rk, topic, 0, 1, 1, 1, NULL, 0);
                rd_kafka_flush(rk, 1000);
        } else {
                /* Produce two new messages and consume them from
                 * the new leaders */
                test_produce_msgs_easy_v(topic, 0, 0, 0, 1, 0,
                                         "bootstrap.servers", bootstraps, NULL);
                test_produce_msgs_easy_v(topic, 0, 1, 0, 1, 0,
                                         "bootstrap.servers", bootstraps, NULL);
                test_consumer_poll_timeout("changed leaders", rk, 0, -1, -1, 2,
                                           NULL, 5000);
        }
        TIMING_ASSERT_LATER(&timing, 0, 500);

        /* Leader change triggers the metadata update and migration
         * of partition 0 to brokers 3 and with 'second_leader_change' also
         * of partition 1 to broker 4. */
        found = verify_requests_after_metadata_update_operation(
            mcluster, &expected_request);
        if (!found)
                TEST_FAIL(
                    "Requests with ApiKey %s"
                    " were not found on broker %" PRId32,
                    rd_kafka_ApiKey2str(expected_request.api_key),
                    expected_request.broker);

        if (second_leader_change) {
                expected_request.broker = 4;
        } else {
                expected_request.broker = 2;
        }

        found = verify_requests_after_metadata_update_operation(
            mcluster, &expected_request);
        if (!found)
                TEST_FAIL(
                    "Requests with ApiKey %s"
                    " were not found on broker %" PRId32,
                    rd_kafka_ApiKey2str(expected_request.api_key),
                    expected_request.broker);

        rd_kafka_mock_stop_request_tracking(mcluster);
        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);

        TEST_LATER_CHECK();
        SUB_TEST_PASS();
}

int main_0146_metadata_mock(int argc, char **argv) {
        TEST_SKIP_MOCK_CLUSTER(0);
        int variation;

        /* No need to test the "roundrobin" assignor case,
         * as this is just for checking the two code paths:
         * EAGER or COOPERATIVE one, and "range" is EAGER too. */
        do_test_metadata_persists_in_cache("range");
        do_test_metadata_persists_in_cache("cooperative-sticky");

        do_test_metadata_call_before_join();

        do_test_fast_metadata_refresh(0);
        do_test_fast_metadata_refresh(1);

        do_test_stale_metadata_doesnt_migrate_partition();

        for (variation = 0; variation < 4; variation++) {
                do_test_metadata_update_operation(
                        variation / 2, /* 0-1: consumer, 2-3 producer */
                        variation % 2  /* 1-3: second leader change,
                                        * 0-2: single leader change */);
        }

        return 0;
}
