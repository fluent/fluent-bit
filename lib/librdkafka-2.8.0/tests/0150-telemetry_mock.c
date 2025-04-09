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

typedef struct {
        int16_t ApiKey;
        int64_t
            expected_diff_ms /* Expected time difference from last request */;
        int64_t jitter_percent; /* Jitter to be accounted for while checking
                                   expected diff*/
        int broker_id;          /* Broker id of request. */
} rd_kafka_telemetry_expected_request_t;

static void test_telemetry_check_protocol_request_times(
    rd_kafka_mock_cluster_t *mcluster,
    rd_kafka_telemetry_expected_request_t *requests_expected,
    size_t expected_cnt) {
        int64_t prev_timestamp = -1;
        int64_t curr_timestamp = -1;
        size_t expected_idx    = 0;
        size_t actual_idx      = 0;
        const int buffer       = 500 /* constant buffer time. */;

        rd_kafka_mock_request_t **requests = NULL;
        size_t request_cnt;

        if (expected_cnt < 1)
                return;

        requests = rd_kafka_mock_get_requests(mcluster, &request_cnt);

        TEST_ASSERT(request_cnt >= expected_cnt,
                    "Expected at least %" PRIusz " requests, have %" PRIusz,
                    expected_cnt, request_cnt);

        for (expected_idx = 0, actual_idx = 0;
             expected_idx < expected_cnt && actual_idx < request_cnt;
             actual_idx++) {
                rd_kafka_mock_request_t *request_actual = requests[actual_idx];
                int16_t actual_ApiKey =
                    rd_kafka_mock_request_api_key(request_actual);
                int actual_broker_id = rd_kafka_mock_request_id(request_actual);
                rd_kafka_telemetry_expected_request_t request_expected =
                    requests_expected[expected_idx];

                if (actual_ApiKey != RD_KAFKAP_GetTelemetrySubscriptions &&
                    actual_ApiKey != RD_KAFKAP_PushTelemetry)
                        continue;

                TEST_ASSERT(actual_ApiKey == request_expected.ApiKey,
                            "request[%" PRIusz
                            "]: Expected ApiKey %s, "
                            "got ApiKey %s",
                            expected_idx,
                            rd_kafka_ApiKey2str(request_expected.ApiKey),
                            rd_kafka_ApiKey2str(actual_ApiKey));

                if (request_expected.broker_id != -1)
                        TEST_ASSERT(request_expected.broker_id ==
                                        actual_broker_id,
                                    "request[%" PRIusz
                                    "]: Expected request to be "
                                    "sent to broker %d, was sent to %d",
                                    expected_idx, request_expected.broker_id,
                                    actual_broker_id);

                prev_timestamp = curr_timestamp;
                curr_timestamp =
                    rd_kafka_mock_request_timestamp(request_actual);
                if (prev_timestamp != -1 &&
                    request_expected.expected_diff_ms != -1) {
                        int64_t diff_ms =
                            (curr_timestamp - prev_timestamp) / 1000;
                        int64_t expected_diff_low =
                            request_expected.expected_diff_ms *
                                (100 - request_expected.jitter_percent) / 100 -
                            buffer;
                        int64_t expected_diff_hi =
                            request_expected.expected_diff_ms *
                                (100 + request_expected.jitter_percent) / 100 +
                            buffer;

                        TEST_ASSERT(diff_ms > expected_diff_low,
                                    "request[%" PRIusz
                                    "]: Expected difference to be "
                                    "more than %" PRId64 ", was %" PRId64,
                                    expected_idx, expected_diff_low, diff_ms);
                        TEST_ASSERT(diff_ms < expected_diff_hi,
                                    "request[%" PRIusz
                                    "]: Expected difference to be "
                                    "less than %" PRId64 ", was %" PRId64,
                                    expected_idx, expected_diff_hi, diff_ms);
                }
                expected_idx++;
        }

        if (expected_idx < expected_cnt) {
                TEST_FAIL("Expected %lu requests, got %lu", expected_cnt,
                          expected_idx);
        }
        rd_kafka_mock_request_destroy_array(requests, request_cnt);
}

static void
test_poll_timeout(rd_kafka_t *rk, int64_t duration_ms, const char *topic) {
        int64_t start_time = test_clock(), now, iteration_start_time = 0;
        rd_kafka_topic_t *rkt = NULL;
        rd_kafka_type_t type  = rd_kafka_type(rk);
        if (type == RD_KAFKA_PRODUCER)
                rkt = test_create_topic_object(rk, topic, NULL);

        now = test_clock();
        while ((now - start_time) / 1000 < duration_ms) {
                if (now - iteration_start_time < 500 * 1000) {
                        int64_t sleep_interval =
                            500 * 1000 - (now - iteration_start_time);
                        if (sleep_interval >
                            start_time + duration_ms * 1000 - now)
                                sleep_interval =
                                    start_time + duration_ms * 1000 - now;
                        rd_usleep(sleep_interval, 0);
                }
                iteration_start_time = test_clock();
                /* Generate some metrics to report */
                if (type == RD_KAFKA_CONSUMER) {
                        test_consumer_poll_timeout("Consume", rk, 0, -1, -1, 1,
                                                   NULL, 10000);
                } else {
                        test_produce_msgs(rk, rkt, 0, 0, 0, 10, NULL, 64);
                }
                now = test_clock();
        }
        if (rkt)
                rd_kafka_topic_destroy(rkt);
}

static rd_kafka_mock_cluster_t *create_mcluster(const char **bootstraps,
                                                char **expected_metrics,
                                                size_t expected_metrics_cnt,
                                                int64_t push_interval,
                                                const char *topic) {
        rd_kafka_mock_cluster_t *mcluster =
            test_mock_cluster_new(2, bootstraps);
        if (expected_metrics_cnt)
                rd_kafka_mock_telemetry_set_requested_metrics(
                    mcluster, expected_metrics, expected_metrics_cnt);
        rd_kafka_mock_telemetry_set_push_interval(mcluster, push_interval);
        rd_kafka_mock_topic_create(mcluster, topic, 1, 2);
        rd_kafka_mock_group_initial_rebalance_delay_ms(mcluster, 0);
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 1);
        rd_kafka_mock_coordinator_set(mcluster, "group", topic, 1);

        /* Seed the topic so the consumer has always messages to read */
        test_produce_msgs_easy_v(topic, 0, 0, 0, 100, 0, "bootstrap.servers",
                                 *bootstraps, "batch.num.messages", "10", NULL);

        rd_kafka_mock_start_request_tracking(mcluster);
        return mcluster;
}

static rd_kafka_t *
create_handle(const char *bootstraps, rd_kafka_type_t type, const char *topic) {
        rd_kafka_conf_t *conf;
        rd_kafka_t *rk;
        test_conf_init(&conf, NULL, 30);
        test_conf_set(conf, "bootstrap.servers", bootstraps);

        if (type == RD_KAFKA_CONSUMER) {
                test_conf_set(conf, "group.id", topic);
                test_conf_set(conf, "auto.offset.reset", "earliest");
                rk = test_create_handle(RD_KAFKA_CONSUMER, conf);
                test_consumer_subscribe(rk, topic);
        } else {
                rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
                rk = test_create_handle(RD_KAFKA_PRODUCER, conf);
        }
        return rk;
}

/**
 * @brief Tests the 'happy path' of GetTelemetrySubscriptions, followed by
 *        successful PushTelemetry requests.
 *        See `requests_expected` for detailed expected flow.
 */
static void
do_test_telemetry_get_subscription_push_telemetry(rd_kafka_type_t type) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        char *expected_metrics[]    = {"*"};
        rd_kafka_t *rk              = NULL;
        const int64_t push_interval = 5000;
        const char *topic           = test_mk_topic_name(__FUNCTION__, 1);

        rd_kafka_telemetry_expected_request_t requests_expected[] = {
            /* T= 0 : The initial GetTelemetrySubscriptions request. */
            {.ApiKey           = RD_KAFKAP_GetTelemetrySubscriptions,
             .broker_id        = -1,
             .expected_diff_ms = -1,
             .jitter_percent   = 0},
            /* T = push_interval + jitter : The first PushTelemetry request */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = -1,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 30},
            /* T = push_interval*2 + jitter : The second PushTelemetry request.
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = -1,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 30},
        };

        SUB_TEST("type %s",
                 type == RD_KAFKA_PRODUCER ? "PRODUCER" : "CONSUMER");

        mcluster = create_mcluster(&bootstraps, expected_metrics,
                                   RD_ARRAY_SIZE(expected_metrics),
                                   push_interval, topic);

        rk = create_handle(bootstraps, type, topic);

        /* Poll for enough time for two pushes to be triggered, and a little
         * extra, so 2.5 x push interval. */
        test_poll_timeout(rk, push_interval * 2.5, topic);

        test_telemetry_check_protocol_request_times(
            mcluster, requests_expected, RD_ARRAY_SIZE(requests_expected));

        /* Clean up. */
        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}


/**
 * @brief When there are no subscriptions, GetTelemetrySubscriptions should be
 *        resent after the push interval until there are subscriptions.
 *        See `requests_expected` for detailed expected flow.
 */
static void
do_test_telemetry_empty_subscriptions_list(rd_kafka_type_t type,
                                           char *subscription_regex) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        char *expected_metrics[]    = {subscription_regex};
        rd_kafka_t *rk              = NULL;
        const int64_t push_interval = 5000;
        const char *topic           = test_mk_topic_name(__FUNCTION__, 1);

        rd_kafka_telemetry_expected_request_t requests_expected[] = {
            /* T= 0 : The initial GetTelemetrySubscriptions request, returns
             * empty subscription. */
            {.ApiKey           = RD_KAFKAP_GetTelemetrySubscriptions,
             .broker_id        = -1,
             .expected_diff_ms = -1,
             .jitter_percent   = 0},
            /* T = push_interval : The second GetTelemetrySubscriptions request,
             * returns non-empty subscription */
            {.ApiKey           = RD_KAFKAP_GetTelemetrySubscriptions,
             .broker_id        = -1,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 0},
            /* T = push_interval*2 + jitter : The first PushTelemetry request.
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = -1,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 30},
        };


        SUB_TEST("type %s, subscription regex: %s",
                 type == RD_KAFKA_PRODUCER ? "PRODUCER" : "CONSUMER",
                 subscription_regex);

        mcluster = create_mcluster(&bootstraps, NULL, 0, push_interval, topic);


        rk = create_handle(bootstraps, type, topic);

        /* Poll for enough time so that the first GetTelemetrySubscription
         * request is triggered. */
        test_poll_timeout(rk, (push_interval * 0.5), topic);

        /* Set expected_metrics before the second GetTelemetrySubscription is
         * triggered. */
        rd_kafka_mock_telemetry_set_requested_metrics(mcluster,
                                                      expected_metrics, 1);

        /* Poll for enough time so that the second GetTelemetrySubscriptions and
         * subsequent PushTelemetry request is triggered. */
        test_poll_timeout(rk, (push_interval * 2), topic);

        test_telemetry_check_protocol_request_times(mcluster, requests_expected,
                                                    3);

        /* Clean up. */
        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief When a client is terminating, PushIntervalMs is overriden and a final
 *        push telemetry request should be sent immediately.
 *        See `requests_expected` for detailed expected flow.
 */
static void do_test_telemetry_terminating_push(rd_kafka_type_t type) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        char *expected_metrics[]              = {"*"};
        rd_kafka_t *rk                        = NULL;
        const int64_t wait_before_termination = 2000;

        const char *topic           = test_mk_topic_name(__FUNCTION__, 1);
        const int64_t push_interval = 5000; /* Needs to be comfortably larger
                                               than wait_before_termination. */

        rd_kafka_telemetry_expected_request_t requests_expected[] = {
            /* T= 0 : The initial GetTelemetrySubscriptions request. */
            {.ApiKey           = RD_KAFKAP_GetTelemetrySubscriptions,
             .broker_id        = -1,
             .expected_diff_ms = -1,
             .jitter_percent   = 0},
            /* T = wait_before_termination : The second PushTelemetry request is
             * sent immediately (terminating).
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = -1,
             .expected_diff_ms = wait_before_termination,
             .jitter_percent   = 30},
        };

        SUB_TEST("type %s",
                 type == RD_KAFKA_PRODUCER ? "PRODUCER" : "CONSUMER");

        mcluster = create_mcluster(&bootstraps, expected_metrics,
                                   RD_ARRAY_SIZE(expected_metrics),
                                   push_interval, topic);

        rk = create_handle(bootstraps, type, topic);

        /* Poll for enough time so that the initial GetTelemetrySubscriptions
         * can be sent and handled, and keep polling till it's time to
         * terminate. */
        test_poll_timeout(rk, wait_before_termination, topic);

        /* Destroy the client to trigger a terminating push request
         * immediately. */
        rd_kafka_destroy(rk);

        test_telemetry_check_protocol_request_times(mcluster, requests_expected,
                                                    2);

        /* Clean up. */
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Preferred broker should be 'sticky' and should not change unless the
 *        old preferred broker goes down.
 *        See `requests_expected` for detailed expected flow.
 */
void do_test_telemetry_preferred_broker_change(rd_kafka_type_t type) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        char *expected_metrics[]    = {"*"};
        rd_kafka_t *rk              = NULL;
        const char *topic           = test_mk_topic_name(__FUNCTION__, 1);
        const int64_t push_interval = 5000;

        rd_kafka_telemetry_expected_request_t requests_expected[] = {
            /* T= 0 : The initial GetTelemetrySubscriptions request. */
            {.ApiKey           = RD_KAFKAP_GetTelemetrySubscriptions,
             .broker_id        = 1,
             .expected_diff_ms = -1,
             .jitter_percent   = 0},
            /* T = push_interval + jitter : The first PushTelemetry request,
             * sent to the preferred broker 1.
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = 1,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 30},
            /* T = 2*push_interval + jitter : The second PushTelemetry request,
             * sent to the preferred broker 1.
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = 1,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 30},
            /* T = 3*push_interval + jitter: The old preferred broker is set
             * down, and this is the first PushTelemetry request to the new
             * preferred broker.
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = 2,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 30},
            /* T = 4*push_interval + jitter + arbitraryT + jitter2 : The second
             * PushTelemetry request to the new preferred broker. The old
             * broker will be up, but the preferred broker will not chnage.
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = 2,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 30},
        };

        SUB_TEST("type %s",
                 type == RD_KAFKA_PRODUCER ? "PRODUCER" : "CONSUMER");

        mcluster = create_mcluster(&bootstraps, expected_metrics,
                                   RD_ARRAY_SIZE(expected_metrics),
                                   push_interval, topic);
        /* Set broker 2 down, to make sure broker 1 is the first preferred
         * broker. */
        rd_kafka_mock_broker_set_down(mcluster, 2);

        test_curr->is_fatal_cb = test_error_is_not_fatal_cb;
        rk                     = create_handle(bootstraps, type, topic);

        /* Poll for enough time that the initial GetTelemetrySubscription can be
         * sent and the first PushTelemetry request can be scheduled. */
        test_poll_timeout(rk, 0.5 * push_interval, topic);

        /* Poll for enough time that 2 PushTelemetry requests can be sent. Set
         * the all brokers up during this time, but the preferred broker (1)
         * should remain sticky. */
        rd_kafka_mock_broker_set_up(mcluster, 2);
        test_poll_timeout(rk, 2 * push_interval, topic);

        /* Set the preferred broker (1) down. */
        rd_kafka_mock_broker_set_down(mcluster, 1);
        /* Change partition leader to broker 2. */
        rd_kafka_mock_partition_set_leader(mcluster, topic, 0, 2);
        /* Change coordinator to broker 2. */
        rd_kafka_mock_coordinator_set(mcluster, "group", topic, 2);

        /* Poll for enough time that 1 PushTelemetry request can be sent. */
        test_poll_timeout(rk, 1.25 * push_interval, topic);

        /* Poll for enough time that 1 PushTelemetry request can be sent.  Set
         * the all brokers up during this time, but the preferred broker (2)
         * should remain sticky. */
        rd_kafka_mock_broker_set_up(mcluster, 1);
        test_poll_timeout(rk, 1.25 * push_interval, topic);

        test_telemetry_check_protocol_request_times(mcluster, requests_expected,
                                                    5);

        /* Clean up. */
        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}

/**
 * @brief Subscription Id change at the broker should trigger a new
 *       GetTelemetrySubscriptions request.
 */
void do_test_subscription_id_change(rd_kafka_type_t type) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        char *expected_metrics[]    = {"*"};
        rd_kafka_t *rk              = NULL;
        const char *topic           = test_mk_topic_name(__FUNCTION__, 1);
        const int64_t push_interval = 2000;

        rd_kafka_telemetry_expected_request_t requests_expected[] = {
            /* T= 0 : The initial GetTelemetrySubscriptions request. */
            {.ApiKey           = RD_KAFKAP_GetTelemetrySubscriptions,
             .broker_id        = -1,
             .expected_diff_ms = -1,
             .jitter_percent   = 0},
            /* T = push_interval + jitter : The first PushTelemetry request,
             * sent to the preferred broker 1.
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = -1,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 30},
            /* T = 2*push_interval + jitter : The second PushTelemetry request,
             * which will fail with unknown subscription id.
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = -1,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 30},
            /* New GetTelemetrySubscriptions request will be sent immediately.
             */
            {.ApiKey           = RD_KAFKAP_GetTelemetrySubscriptions,
             .broker_id        = -1,
             .expected_diff_ms = 0,
             .jitter_percent   = 0},
            /* T = 3*push_interval + jitter : The third PushTelemetry request,
             * sent to the preferred broker 1 with new subscription id.
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = -1,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 30},
        };

        SUB_TEST("type %s",
                 type == RD_KAFKA_PRODUCER ? "PRODUCER" : "CONSUMER");

        mcluster = create_mcluster(&bootstraps, expected_metrics,
                                   RD_ARRAY_SIZE(expected_metrics),
                                   push_interval, topic);

        rk = create_handle(bootstraps, type, topic);

        test_poll_timeout(rk, push_interval * 1.5, topic);

        rd_kafka_mock_push_request_errors(
            mcluster, RD_KAFKAP_PushTelemetry, 1,
            RD_KAFKA_RESP_ERR_UNKNOWN_SUBSCRIPTION_ID);

        test_poll_timeout(rk, push_interval * 2.5, topic);

        test_telemetry_check_protocol_request_times(
            mcluster, requests_expected, RD_ARRAY_SIZE(requests_expected));

        /* Clean up. */
        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}


/**
 * @brief Invalid record from broker should stop metrics
 */
void do_test_invalid_record(rd_kafka_type_t type) {
        const char *bootstraps;
        rd_kafka_mock_cluster_t *mcluster;
        char *expected_metrics[]    = {"*"};
        rd_kafka_t *rk              = NULL;
        const int64_t push_interval = 1000;
        const char *topic           = test_mk_topic_name(__FUNCTION__, 1);

        rd_kafka_telemetry_expected_request_t requests_expected[] = {
            /* T= 0 : The initial GetTelemetrySubscriptions request. */
            {.ApiKey           = RD_KAFKAP_GetTelemetrySubscriptions,
             .broker_id        = -1,
             .expected_diff_ms = -1,
             .jitter_percent   = 0},
            /* T = push_interval + jitter : The first PushTelemetry request,
             * sent to the preferred broker 1.
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = -1,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 20},
            /* T = 2*push_interval  : The second PushTelemetry request,
             * which will fail with RD_KAFKA_RESP_ERR_INVALID_RECORD and no
             * further telemetry requests would be sent.
             */
            {.ApiKey           = RD_KAFKAP_PushTelemetry,
             .broker_id        = -1,
             .expected_diff_ms = push_interval,
             .jitter_percent   = 0},
        };
        SUB_TEST("type %s",
                 type == RD_KAFKA_PRODUCER ? "PRODUCER" : "CONSUMER");

        mcluster = create_mcluster(&bootstraps, expected_metrics,
                                   RD_ARRAY_SIZE(expected_metrics),
                                   push_interval, topic);

        rk = create_handle(bootstraps, type, topic);

        test_poll_timeout(rk, push_interval * 1.2, topic);

        rd_kafka_mock_push_request_errors(mcluster, RD_KAFKAP_PushTelemetry, 1,
                                          RD_KAFKA_RESP_ERR_INVALID_RECORD);

        test_poll_timeout(rk, push_interval * 2.5, topic);

        test_telemetry_check_protocol_request_times(
            mcluster, requests_expected, RD_ARRAY_SIZE(requests_expected));

        /* Clean up. */
        rd_kafka_destroy(rk);
        test_mock_cluster_destroy(mcluster);

        SUB_TEST_PASS();
}


int main_0150_telemetry_mock(int argc, char **argv) {
        int type;

        if (test_needs_auth()) {
                TEST_SKIP("Mock cluster does not support SSL/SASL\n");
                return 0;
        }

        for (type = RD_KAFKA_PRODUCER; type <= RD_KAFKA_CONSUMER; type++) {
                do_test_telemetry_get_subscription_push_telemetry(type);
                // All metrics are subscribed
                do_test_telemetry_empty_subscriptions_list(type, "*");
                // No metrics are subscribed
                do_test_telemetry_empty_subscriptions_list(
                    type, "non-existent-metric");
                do_test_telemetry_terminating_push(type);
                do_test_telemetry_preferred_broker_change(type);
                do_test_subscription_id_change(type);
                do_test_invalid_record(type);
        };

        return 0;
}
