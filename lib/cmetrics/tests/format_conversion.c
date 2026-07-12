/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2026 The CMetrics Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_decode_statsd.h>
#include <cmetrics/cmt_decode_prometheus_remote_write.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_encode_prometheus_remote_write.h>
#include <cmetrics/cmt_encode_opentelemetry.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_encode_influx.h>
#include <cmetrics/cmt_encode_splunk_hec.h>
#include <cmetrics/cmt_encode_cloudwatch_emf.h>

#ifdef CMT_HAVE_PROMETHEUS_TEXT_DECODER
#include <cmetrics/cmt_decode_prometheus.h>
#endif

#include "cmt_tests.h"

static struct cmt *msgpack_round_trip(struct cmt *input)
{
    int result;
    char *first_buffer;
    char *second_buffer;
    size_t first_size;
    size_t second_size;
    size_t offset;
    struct cmt *output;

    first_buffer = NULL;
    second_buffer = NULL;
    output = NULL;

    result = cmt_encode_msgpack_create(input, &first_buffer, &first_size);
    TEST_ASSERT(result == 0);

    offset = 0;
    result = cmt_decode_msgpack_create(&output, first_buffer, first_size,
                                       &offset);
    TEST_ASSERT(result == CMT_DECODE_MSGPACK_SUCCESS);
    TEST_ASSERT(output != NULL);
    TEST_CHECK(offset == first_size);

    result = cmt_encode_msgpack_create(output, &second_buffer, &second_size);
    TEST_ASSERT(result == 0);
    TEST_CHECK(second_size == first_size);
    if (second_size == first_size) {
        TEST_CHECK(memcmp(first_buffer, second_buffer, first_size) == 0);
    }

    cmt_encode_msgpack_destroy(second_buffer);
    cmt_encode_msgpack_destroy(first_buffer);

    return output;
}

static void check_all_encoders(struct cmt *context)
{
    int result;
    char *cloudwatch;
    size_t cloudwatch_size;
    char *msgpack;
    size_t msgpack_size;
    cfl_sds_t output;

    output = cmt_encode_prometheus_create(context, CMT_TRUE);
    TEST_CHECK(output != NULL);
    cmt_encode_prometheus_destroy(output);

    output = cmt_encode_text_create(context);
    TEST_CHECK(output != NULL);
    cmt_encode_text_destroy(output);

    output = cmt_encode_influx_create(context);
    TEST_CHECK(output != NULL);
    cmt_encode_influx_destroy(output);

    output = cmt_encode_splunk_hec_create(context, "localhost", "metrics",
                                          NULL, NULL);
    TEST_CHECK(output != NULL);
    cmt_encode_splunk_hec_destroy(output);

    cloudwatch = NULL;
    cloudwatch_size = 0;
    result = cmt_encode_cloudwatch_emf_create(context, &cloudwatch,
                                              &cloudwatch_size, CMT_TRUE);
    TEST_CHECK(result == 0);
    TEST_CHECK(cloudwatch != NULL);
    if (cloudwatch != NULL) {
        cmt_encode_cloudwatch_emf_destroy(cloudwatch);
    }

    output = cmt_encode_prometheus_remote_write_create(context);
    TEST_CHECK(output != NULL);
    cmt_encode_prometheus_remote_write_destroy(output);

    output = cmt_encode_opentelemetry_create(context);
    TEST_CHECK(output != NULL);
    cmt_encode_opentelemetry_destroy(output);

    msgpack = NULL;
    msgpack_size = 0;
    result = cmt_encode_msgpack_create(context, &msgpack, &msgpack_size);
    TEST_CHECK(result == 0);
    TEST_CHECK(msgpack != NULL);
    cmt_encode_msgpack_destroy(msgpack);
}

static struct cmt *create_native_fixture(void)
{
    int result;
    uint64_t now;
    uint64_t positive_buckets[] = {3, 5};
    uint64_t negative_buckets[] = {2};
    double quantiles[] = {0.5, 0.9};
    double quantile_values[] = {4.0, 8.0};
    struct cmt *cmt;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary *summary;
    struct cmt_histogram_buckets *buckets;
    struct cmt_metric *metric;

    now = cfl_time_now();
    cmt = cmt_create();
    if (cmt == NULL) {
        return NULL;
    }

    cmt_label_add(cmt, "environment", "test");

    counter = cmt_counter_create(cmt, "matrix", "native", "requests_total",
                                 "Requests", 1, (char *[]) {"route"});
    if (counter == NULL ||
        cmt_counter_set(counter, now, 7, 1, (char *[]) {"/api"}) != 0) {
        cmt_destroy(cmt);
        return NULL;
    }

    gauge = cmt_gauge_create(cmt, "matrix", "native", "large_integer",
                             "Large integer", 0, NULL);
    if (gauge == NULL) {
        cmt_destroy(cmt);
        return NULL;
    }
    metric = &gauge->map->metric;
    cmt_metric_set_int64(metric, now, 9007199254740993LL);

    untyped = cmt_untyped_create(cmt, "matrix", "native", "temperature",
                                 "Temperature", 1, (char *[]) {"room"});
    if (untyped == NULL ||
        cmt_untyped_set(untyped, now, 21.5, 1, (char *[]) {"office"}) != 0) {
        cmt_destroy(cmt);
        return NULL;
    }

    buckets = cmt_histogram_buckets_create(2, 1.0, 5.0);
    if (buckets == NULL) {
        cmt_destroy(cmt);
        return NULL;
    }
    histogram = cmt_histogram_create(cmt, "matrix", "native", "latency",
                                     "Latency", buckets, 1,
                                     (char *[]) {"method"});
    if (histogram == NULL ||
        cmt_histogram_observe(histogram, now, 2.0, 1,
                              (char *[]) {"GET"}) != 0) {
        cmt_destroy(cmt);
        return NULL;
    }
    histogram->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;

    summary = cmt_summary_create(cmt, "matrix", "native", "size",
                                 "Size", 2, quantiles, 1,
                                 (char *[]) {"operation"});
    if (summary == NULL ||
        cmt_summary_set_default(summary, now, quantile_values, 12.0, 3,
                                1, (char *[]) {"write"}) != 0) {
        cmt_destroy(cmt);
        return NULL;
    }

    exp_histogram = cmt_exp_histogram_create(cmt, "matrix", "native",
                                             "payload", "Payload", 1,
                                             (char *[]) {"protocol"});
    if (exp_histogram == NULL) {
        cmt_destroy(cmt);
        return NULL;
    }
    result = cmt_exp_histogram_set_default(exp_histogram, now, 1, 2, 0.0,
                                           -1, 2, positive_buckets,
                                           0, 1, negative_buckets,
                                           CMT_TRUE, 9.5, 10, 1,
                                           (char *[]) {"http"});
    if (result != 0) {
        cmt_destroy(cmt);
        return NULL;
    }
    exp_histogram->aggregation_type = CMT_AGGREGATION_TYPE_CUMULATIVE;

    return cmt;
}

void test_native_msgpack_conversion_matrix(void)
{
    struct cmt *input;
    struct cmt *output;
    struct cmt_gauge *gauge;

    input = create_native_fixture();
    TEST_ASSERT(input != NULL);

    output = msgpack_round_trip(input);
    TEST_ASSERT(output != NULL);

    TEST_CHECK(cfl_list_size(&output->counters) == 1);
    TEST_CHECK(cfl_list_size(&output->gauges) == 1);
    TEST_CHECK(cfl_list_size(&output->untypeds) == 1);
    TEST_CHECK(cfl_list_size(&output->histograms) == 1);
    TEST_CHECK(cfl_list_size(&output->summaries) == 1);
    TEST_CHECK(cfl_list_size(&output->exp_histograms) == 1);

    gauge = cfl_list_entry_first(&output->gauges, struct cmt_gauge, _head);
    TEST_CHECK(cmt_metric_get_value_type(&gauge->map->metric) ==
               CMT_METRIC_VALUE_INT64);
    TEST_CHECK(cmt_metric_get_int64_value(&gauge->map->metric) ==
               9007199254740993LL);

    check_all_encoders(output);

    cmt_decode_msgpack_destroy(output);
    cmt_destroy(input);
}

#ifdef CMT_HAVE_PROMETHEUS_TEXT_DECODER
void test_prometheus_msgpack_conversion_matrix(void)
{
    int result;
    const char input_text[] =
        "# HELP http_requests_total Requests\n"
        "# TYPE http_requests_total counter\n"
        "http_requests_total{method=\"GET\"} 7\n"
        "# HELP queue_depth Queue depth\n"
        "# TYPE queue_depth gauge\n"
        "queue_depth{queue=\"main\"} 3\n"
        "# HELP request_size Request size\n"
        "# TYPE request_size histogram\n"
        "request_size_bucket{route=\"/\",le=\"1\"} 1\n"
        "request_size_bucket{route=\"/\",le=\"5\"} 2\n"
        "request_size_bucket{route=\"/\",le=\"+Inf\"} 2\n"
        "request_size_sum{route=\"/\"} 4\n"
        "request_size_count{route=\"/\"} 2\n";
    struct cmt *decoded;
    struct cmt *roundtrip;
    cfl_sds_t prometheus;

    decoded = NULL;
    result = cmt_decode_prometheus_create(&decoded, input_text,
                                          sizeof(input_text) - 1, NULL);
    TEST_ASSERT(result == CMT_DECODE_PROMETHEUS_SUCCESS);
    TEST_ASSERT(decoded != NULL);

    roundtrip = msgpack_round_trip(decoded);
    TEST_ASSERT(roundtrip != NULL);

    prometheus = cmt_encode_prometheus_create(roundtrip, CMT_FALSE);
    TEST_ASSERT(prometheus != NULL);
    TEST_CHECK(strstr(prometheus, "http_requests_total{method=\"GET\"} 7") != NULL);
    TEST_CHECK(strstr(prometheus, "queue_depth{queue=\"main\"} 3") != NULL);
    TEST_CHECK(strstr(prometheus, "request_size_count{route=\"/\"} 2") != NULL);
    cmt_encode_prometheus_destroy(prometheus);

    check_all_encoders(roundtrip);

    cmt_decode_msgpack_destroy(roundtrip);
    cmt_decode_prometheus_destroy(decoded);
}
#endif

void test_remote_write_msgpack_conversion_matrix(void)
{
    int result;
    cfl_sds_t remote_payload;
    struct cmt *source;
    struct cmt *decoded;
    struct cmt *roundtrip;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    uint64_t now;

    now = cfl_time_now();
    source = cmt_create();
    TEST_ASSERT(source != NULL);

    counter = cmt_counter_create(source, "matrix", "remote", "requests_total",
                                 "Requests", 1, (char *[]) {"method"});
    gauge = cmt_gauge_create(source, "matrix", "remote", "depth",
                             "Depth", 1, (char *[]) {"queue"});
    TEST_ASSERT(counter != NULL);
    TEST_ASSERT(gauge != NULL);
    TEST_ASSERT(cmt_counter_set(counter, now, 5, 1,
                               (char *[]) {"POST"}) == 0);
    TEST_ASSERT(cmt_gauge_set(gauge, now, 2, 1,
                             (char *[]) {"main"}) == 0);

    remote_payload = cmt_encode_prometheus_remote_write_create(source);
    TEST_ASSERT(remote_payload != NULL);

    decoded = NULL;
    result = cmt_decode_prometheus_remote_write_create(&decoded,
                                                       remote_payload,
                                                       cfl_sds_len(remote_payload));
    TEST_ASSERT(result == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS);
    TEST_ASSERT(decoded != NULL);

    roundtrip = msgpack_round_trip(decoded);
    TEST_ASSERT(roundtrip != NULL);
    /*
     * The encoder intentionally omits remote-write metadata, so the decoder
     * must apply the protocol's safe fallback and represent scalar series as
     * gauges. The MessagePack conversion must preserve that decoded model.
     */
    TEST_CHECK(cfl_list_size(&roundtrip->counters) == 0);
    TEST_CHECK(cfl_list_size(&roundtrip->gauges) == 2);
    check_all_encoders(roundtrip);

    cmt_decode_msgpack_destroy(roundtrip);
    cmt_decode_prometheus_remote_write_destroy(decoded);
    cmt_encode_prometheus_remote_write_destroy(remote_payload);
    cmt_destroy(source);
}

void test_statsd_msgpack_conversion_matrix(void)
{
    int result;
    char statsd_payload[] =
        "requests:5|c|#environment:test,method:GET\n"
        "temperature:21.5|g|#environment:test,room:office\n"
        "latency:12|ms|#environment:test,route:/api\n";
    struct cmt *decoded;
    struct cmt *roundtrip;
    cfl_sds_t prometheus;

    decoded = NULL;
    result = cmt_decode_statsd_create(&decoded, statsd_payload,
                                      sizeof(statsd_payload) - 1,
                                      0);
    TEST_ASSERT(result == CMT_DECODE_STATSD_SUCCESS);
    TEST_ASSERT(decoded != NULL);

    roundtrip = msgpack_round_trip(decoded);
    TEST_ASSERT(roundtrip != NULL);

    prometheus = cmt_encode_prometheus_create(roundtrip, CMT_FALSE);
    TEST_ASSERT(prometheus != NULL);
    TEST_CHECK(strstr(prometheus, "requests") != NULL);
    TEST_CHECK(strstr(prometheus, "temperature") != NULL);
    cmt_encode_prometheus_destroy(prometheus);

    check_all_encoders(roundtrip);

    cmt_decode_msgpack_destroy(roundtrip);
    cmt_decode_statsd_destroy(decoded);
}

void test_otlp_msgpack_conversion_matrix(void)
{
    int result;
    size_t offset;
    cfl_sds_t otlp_payload;
    struct cfl_list decoded_list;
    struct cmt *source;
    struct cmt *decoded;
    struct cmt *roundtrip;

    source = create_native_fixture();
    TEST_ASSERT(source != NULL);

    otlp_payload = cmt_encode_opentelemetry_create(source);
    TEST_ASSERT(otlp_payload != NULL);

    offset = 0;
    result = cmt_decode_opentelemetry_create(&decoded_list, otlp_payload,
                                             cfl_sds_len(otlp_payload),
                                             &offset);
    TEST_ASSERT(result == CMT_DECODE_OPENTELEMETRY_SUCCESS);
    TEST_ASSERT(cfl_list_size(&decoded_list) == 1);

    decoded = cfl_list_entry_first(&decoded_list, struct cmt, _head);
    roundtrip = msgpack_round_trip(decoded);
    TEST_ASSERT(roundtrip != NULL);
    check_all_encoders(roundtrip);

    cmt_decode_msgpack_destroy(roundtrip);
    cmt_decode_opentelemetry_destroy(&decoded_list);
    cmt_encode_opentelemetry_destroy(otlp_payload);
    cmt_destroy(source);
}

TEST_LIST = {
    {"native_msgpack_conversion_matrix", test_native_msgpack_conversion_matrix},
#ifdef CMT_HAVE_PROMETHEUS_TEXT_DECODER
    {"prometheus_msgpack_conversion_matrix", test_prometheus_msgpack_conversion_matrix},
#endif
    {"remote_write_msgpack_conversion_matrix", test_remote_write_msgpack_conversion_matrix},
    {"statsd_msgpack_conversion_matrix", test_statsd_msgpack_conversion_matrix},
    {"otlp_msgpack_conversion_matrix", test_otlp_msgpack_conversion_matrix},
    {NULL, NULL}
};
