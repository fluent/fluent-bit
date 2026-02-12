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
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <cmetrics/cmt_encode_opentelemetry.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>

#include "cmt_tests.h"

static struct cmt *generate_api_test_data()
{
    double                        quantiles[5];
    struct cmt_histogram_buckets *buckets;
    double                        val;
    uint64_t                      ts;
    uint64_t                      exp_positive[3] = {3, 5, 7};
    uint64_t                      exp_negative[2] = {2, 1};
    struct cmt                   *cmt;
    struct cmt_counter           *counter;
    struct cmt_gauge             *gauge;
    struct cmt_summary           *summary;
    struct cmt_histogram         *histogram;
    struct cmt_untyped           *untyped;
    struct cmt_exp_histogram     *exp_histogram;

    ts = 123456789;
    cmt = cmt_create();
    if (cmt == NULL) {
        return NULL;
    }

    counter = cmt_counter_create(cmt, "kubernetes", "network", "load_counter", "Network load counter",
                                 2, (char *[]) {"hostname", "app"});
    if (counter == NULL) {
        cmt_destroy(cmt);
        return NULL;
    }

    cmt_counter_get_val(counter, 0, NULL, &val);
    cmt_counter_inc(counter, ts, 0, NULL);
    cmt_counter_add(counter, ts, 2, 0, NULL);
    cmt_counter_inc(counter, ts, 2, (char *[]) {"localhost", "cmetrics"});
    cmt_counter_add(counter, ts, 10.55, 2, (char *[]) {"localhost", "test"});
    cmt_counter_set(counter, ts, 12.15, 2, (char *[]) {"localhost", "test"});

    gauge = cmt_gauge_create(cmt, "kubernetes", "network", "load_gauge", "Network load gauge", 0, NULL);
    if (gauge == NULL) {
        cmt_destroy(cmt);
        return NULL;
    }

    cmt_gauge_set(gauge, ts, 2.0, 0, NULL);
    cmt_gauge_inc(gauge, ts, 0, NULL);
    cmt_gauge_sub(gauge, ts, 5.0, 0, NULL);

    untyped = cmt_untyped_create(cmt, "kubernetes", "network", "load_untyped", "Network load untyped", 0, NULL);
    if (untyped == NULL) {
        cmt_destroy(cmt);
        return NULL;
    }
    cmt_untyped_set(untyped, ts, -7.0, 0, NULL);

    buckets = cmt_histogram_buckets_create(3, 0.05, 5.0, 10.0);
    histogram = cmt_histogram_create(cmt,
                                     "k8s", "network", "load_histogram", "Network load histogram",
                                     buckets,
                                     1, (char *[]) {"my_label"});
    if (histogram == NULL) {
        cmt_destroy(cmt);
        return NULL;
    }

    cmt_histogram_observe(histogram, ts, 0.001, 0, NULL);
    cmt_histogram_observe(histogram, ts, 8.0, 0, NULL);
    cmt_histogram_observe(histogram, ts, 1000, 1, (char *[]) {"my_val"});

    quantiles[0] = 0.1;
    quantiles[1] = 0.2;
    quantiles[2] = 0.3;
    quantiles[3] = 0.4;
    quantiles[4] = 0.5;

    summary = cmt_summary_create(cmt,
                                 "k8s", "disk", "load_summary", "Disk load summary",
                                 5, quantiles,
                                 1, (char *[]) {"my_label"});
    if (summary == NULL) {
        cmt_destroy(cmt);
        return NULL;
    }

    quantiles[0] = 11.11;
    quantiles[1] = 22.22;
    quantiles[2] = 33.33;
    quantiles[3] = 44.44;
    quantiles[4] = 55.55;
    cmt_summary_set_default(summary, ts, quantiles, 51.612894511314444, 10, 1, (char *[]) {"my_val"});

    exp_histogram = cmt_exp_histogram_create(cmt, "cm", "native", "exp_hist", "native exp histogram",
                                             1, (char *[]) {"endpoint"});
    if (exp_histogram == NULL) {
        cmt_destroy(cmt);
        return NULL;
    }

    cmt_exp_histogram_set_default(exp_histogram,
                                  ts,
                                  2,
                                  11,
                                  0.5,
                                  -2,
                                  3,
                                  exp_positive,
                                  -1,
                                  2,
                                  exp_negative,
                                  CMT_TRUE,
                                  42.25,
                                  29,
                                  1,
                                  (char *[]) {"api"});

    return cmt;
}

static int compare_text_lines(const void *a, const void *b)
{
    const char *line_a;
    const char *line_b;

    line_a = *(const char * const *) a;
    line_b = *(const char * const *) b;

    return strcmp(line_a, line_b);
}

static int are_texts_equivalent_ignoring_line_order(const char *left, const char *right)
{
    char   *left_copy;
    char   *right_copy;
    char   *saveptr;
    char   *line;
    char  **left_lines;
    char  **right_lines;
    size_t  left_count;
    size_t  right_count;
    size_t  index;
    size_t  max_lines;

    if (left == NULL || right == NULL) {
        return CMT_FALSE;
    }

    left_copy = strdup(left);
    right_copy = strdup(right);
    if (left_copy == NULL || right_copy == NULL) {
        free(left_copy);
        free(right_copy);
        return CMT_FALSE;
    }

    max_lines = 1;
    for (index = 0; left[index] != '\0'; index++) {
        if (left[index] == '\n') {
            max_lines++;
        }
    }
    for (index = 0; right[index] != '\0'; index++) {
        if (right[index] == '\n') {
            max_lines++;
        }
    }

    left_lines = calloc(max_lines, sizeof(char *));
    right_lines = calloc(max_lines, sizeof(char *));
    if (left_lines == NULL || right_lines == NULL) {
        free(left_lines);
        free(right_lines);
        free(left_copy);
        free(right_copy);
        return CMT_FALSE;
    }

    left_count = 0;
    saveptr = NULL;
    line = strtok_r(left_copy, "\n", &saveptr);
    while (line != NULL) {
        left_lines[left_count++] = line;
        line = strtok_r(NULL, "\n", &saveptr);
    }

    right_count = 0;
    saveptr = NULL;
    line = strtok_r(right_copy, "\n", &saveptr);
    while (line != NULL) {
        right_lines[right_count++] = line;
        line = strtok_r(NULL, "\n", &saveptr);
    }

    if (left_count != right_count) {
        free(left_lines);
        free(right_lines);
        free(left_copy);
        free(right_copy);
        return CMT_FALSE;
    }

    qsort(left_lines, left_count, sizeof(char *), compare_text_lines);
    qsort(right_lines, right_count, sizeof(char *), compare_text_lines);

    for (index = 0; index < left_count; index++) {
        if (strcmp(left_lines[index], right_lines[index]) != 0) {
            free(left_lines);
            free(right_lines);
            free(left_copy);
            free(right_copy);
            return CMT_FALSE;
        }
    }

    free(left_lines);
    free(right_lines);
    free(left_copy);
    free(right_copy);

    return CMT_TRUE;
}

static cfl_sds_t generate_exponential_histogram_otlp_payload()
{
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest   request;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics                           resource_metrics;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics                              scope_metrics;
    Opentelemetry__Proto__Metrics__V1__Metric                                    metric;
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogram                      exponential_histogram;
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint             data_point;
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint__Buckets    positive_buckets;
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint__Buckets    negative_buckets;
    Opentelemetry__Proto__Metrics__V1__Exemplar                                  exemplar;
    Opentelemetry__Proto__Common__V1__KeyValue                                   metric_metadata_kv;
    Opentelemetry__Proto__Common__V1__AnyValue                                   metric_metadata_value;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics                          *resource_metrics_list[1];
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics                             *scope_metrics_list[1];
    Opentelemetry__Proto__Metrics__V1__Metric                                   *metric_list[1];
    Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint            *data_point_list[1];
    Opentelemetry__Proto__Metrics__V1__Exemplar                                 *exemplar_list[1];
    Opentelemetry__Proto__Common__V1__KeyValue                                  *metric_metadata_list[1];
    uint64_t                                                                      positive_bucket_counts[2];
    uint64_t                                                                      negative_bucket_counts[1];
    uint8_t                                                                       span_id[8];
    uint8_t                                                                       trace_id[16];
    size_t                                                                        payload_size;
    unsigned char                                                                *packed_payload;
    cfl_sds_t                                                                     payload;

    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__init(&request);
    opentelemetry__proto__metrics__v1__resource_metrics__init(&resource_metrics);
    opentelemetry__proto__metrics__v1__scope_metrics__init(&scope_metrics);
    opentelemetry__proto__metrics__v1__metric__init(&metric);
    opentelemetry__proto__metrics__v1__exponential_histogram__init(&exponential_histogram);
    opentelemetry__proto__metrics__v1__exponential_histogram_data_point__init(&data_point);
    opentelemetry__proto__metrics__v1__exponential_histogram_data_point__buckets__init(&positive_buckets);
    opentelemetry__proto__metrics__v1__exponential_histogram_data_point__buckets__init(&negative_buckets);
    opentelemetry__proto__metrics__v1__exemplar__init(&exemplar);
    opentelemetry__proto__common__v1__key_value__init(&metric_metadata_kv);
    opentelemetry__proto__common__v1__any_value__init(&metric_metadata_value);

    positive_bucket_counts[0] = 3;
    positive_bucket_counts[1] = 2;
    negative_bucket_counts[0] = 1;

    positive_buckets.offset = 0;
    positive_buckets.n_bucket_counts = 2;
    positive_buckets.bucket_counts = positive_bucket_counts;

    negative_buckets.offset = 0;
    negative_buckets.n_bucket_counts = 1;
    negative_buckets.bucket_counts = negative_bucket_counts;

    memset(span_id, 0xAB, sizeof(span_id));
    memset(trace_id, 0xCD, sizeof(trace_id));

    exemplar.time_unix_nano = 5;
    exemplar.span_id.data = span_id;
    exemplar.span_id.len = sizeof(span_id);
    exemplar.trace_id.data = trace_id;
    exemplar.trace_id.len = sizeof(trace_id);
    exemplar.value_case = OPENTELEMETRY__PROTO__METRICS__V1__EXEMPLAR__VALUE_AS_DOUBLE;
    exemplar.as_double = 3.25;
    exemplar_list[0] = &exemplar;

    data_point.time_unix_nano = 1;
    data_point.start_time_unix_nano = 123;
    data_point.count = 7;
    data_point.has_sum = CMT_TRUE;
    data_point.sum = 8.0;
    data_point.scale = 0;
    data_point.zero_count = 1;
    data_point.zero_threshold = 0.0;
    data_point.flags = OPENTELEMETRY__PROTO__METRICS__V1__DATA_POINT_FLAGS__DATA_POINT_FLAGS_NO_RECORDED_VALUE_MASK;
    data_point.has_min = CMT_TRUE;
    data_point.min = -2.5;
    data_point.has_max = CMT_TRUE;
    data_point.max = 4.5;
    data_point.positive = &positive_buckets;
    data_point.negative = &negative_buckets;
    data_point.exemplars = exemplar_list;
    data_point.n_exemplars = 1;

    metric_metadata_value.value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    metric_metadata_value.string_value = "decode-roundtrip";
    metric_metadata_kv.key = "origin";
    metric_metadata_kv.value = &metric_metadata_value;
    metric_metadata_list[0] = &metric_metadata_kv;

    data_point_list[0] = &data_point;
    exponential_histogram.n_data_points = 1;
    exponential_histogram.data_points = data_point_list;
    exponential_histogram.aggregation_temporality =
        OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_CUMULATIVE;

    metric.name = "exp_hist";
    metric.n_metadata = 1;
    metric.metadata = metric_metadata_list;
    metric.data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_EXPONENTIAL_HISTOGRAM;
    metric.exponential_histogram = &exponential_histogram;

    metric_list[0] = &metric;
    scope_metrics.n_metrics = 1;
    scope_metrics.metrics = metric_list;

    scope_metrics_list[0] = &scope_metrics;
    resource_metrics.n_scope_metrics = 1;
    resource_metrics.scope_metrics = scope_metrics_list;

    resource_metrics_list[0] = &resource_metrics;
    request.n_resource_metrics = 1;
    request.resource_metrics = resource_metrics_list;

    payload_size = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__get_packed_size(&request);
    packed_payload = calloc(1, payload_size);
    if (packed_payload == NULL) {
        return NULL;
    }

    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__pack(&request,
                                                                                         packed_payload);

    payload = cfl_sds_create_len((char *) packed_payload, payload_size);
    free(packed_payload);

    return payload;
}

static cfl_sds_t generate_gauge_int_otlp_payload_with_unit()
{
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest request;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics resource_metrics;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics scope_metrics;
    Opentelemetry__Proto__Metrics__V1__Metric metric;
    Opentelemetry__Proto__Metrics__V1__Gauge gauge;
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint data_point;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *resource_metrics_list[1];
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *scope_metrics_list[1];
    Opentelemetry__Proto__Metrics__V1__Metric *metric_list[1];
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint *data_point_list[1];
    size_t payload_size;
    unsigned char *packed_payload;
    cfl_sds_t payload;

    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__init(&request);
    opentelemetry__proto__metrics__v1__resource_metrics__init(&resource_metrics);
    opentelemetry__proto__metrics__v1__scope_metrics__init(&scope_metrics);
    opentelemetry__proto__metrics__v1__metric__init(&metric);
    opentelemetry__proto__metrics__v1__gauge__init(&gauge);
    opentelemetry__proto__metrics__v1__number_data_point__init(&data_point);

    data_point.time_unix_nano = 123;
    data_point.start_time_unix_nano = 0;
    data_point.value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT;
    data_point.as_int = -7;

    data_point_list[0] = &data_point;
    gauge.n_data_points = 1;
    gauge.data_points = data_point_list;

    metric.name = "g_int";
    metric.unit = "bytes";
    metric.data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE;
    metric.gauge = &gauge;

    metric_list[0] = &metric;
    scope_metrics.n_metrics = 1;
    scope_metrics.metrics = metric_list;

    scope_metrics_list[0] = &scope_metrics;
    resource_metrics.n_scope_metrics = 1;
    resource_metrics.scope_metrics = scope_metrics_list;

    resource_metrics_list[0] = &resource_metrics;
    request.n_resource_metrics = 1;
    request.resource_metrics = resource_metrics_list;

    payload_size = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__get_packed_size(&request);
    packed_payload = calloc(1, payload_size);
    if (packed_payload == NULL) {
        return NULL;
    }

    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__pack(&request,
                                                                                         packed_payload);

    payload = cfl_sds_create_len((char *) packed_payload, payload_size);
    free(packed_payload);

    return payload;
}

static cfl_sds_t generate_sum_non_monotonic_int_otlp_payload()
{
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest request;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics resource_metrics;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics scope_metrics;
    Opentelemetry__Proto__Metrics__V1__Metric metric;
    Opentelemetry__Proto__Metrics__V1__Sum sum;
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint data_point;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *resource_metrics_list[1];
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *scope_metrics_list[1];
    Opentelemetry__Proto__Metrics__V1__Metric *metric_list[1];
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint *data_point_list[1];
    size_t payload_size;
    unsigned char *packed_payload;
    cfl_sds_t payload;

    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__init(&request);
    opentelemetry__proto__metrics__v1__resource_metrics__init(&resource_metrics);
    opentelemetry__proto__metrics__v1__scope_metrics__init(&scope_metrics);
    opentelemetry__proto__metrics__v1__metric__init(&metric);
    opentelemetry__proto__metrics__v1__sum__init(&sum);
    opentelemetry__proto__metrics__v1__number_data_point__init(&data_point);

    data_point.time_unix_nano = 321;
    data_point.start_time_unix_nano = 100;
    data_point.value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT;
    data_point.as_int = -7;

    data_point_list[0] = &data_point;
    sum.n_data_points = 1;
    sum.data_points = data_point_list;
    sum.aggregation_temporality =
        OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_CUMULATIVE;
    sum.is_monotonic = CMT_FALSE;

    metric.name = "sum_non_monotonic_int";
    metric.data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM;
    metric.sum = &sum;

    metric_list[0] = &metric;
    scope_metrics.n_metrics = 1;
    scope_metrics.metrics = metric_list;

    scope_metrics_list[0] = &scope_metrics;
    resource_metrics.n_scope_metrics = 1;
    resource_metrics.scope_metrics = scope_metrics_list;

    resource_metrics_list[0] = &resource_metrics;
    request.n_resource_metrics = 1;
    request.resource_metrics = resource_metrics_list;

    payload_size = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__get_packed_size(&request);
    packed_payload = calloc(1, payload_size);
    if (packed_payload == NULL) {
        return NULL;
    }

    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__pack(&request,
                                                                                         packed_payload);

    payload = cfl_sds_create_len((char *) packed_payload, payload_size);
    free(packed_payload);

    return payload;
}

static cfl_sds_t generate_gauge_large_int_otlp_payload()
{
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest request;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics resource_metrics;
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics scope_metrics;
    Opentelemetry__Proto__Metrics__V1__Metric metric;
    Opentelemetry__Proto__Metrics__V1__Gauge gauge;
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint data_point;
    Opentelemetry__Proto__Metrics__V1__ResourceMetrics *resource_metrics_list[1];
    Opentelemetry__Proto__Metrics__V1__ScopeMetrics *scope_metrics_list[1];
    Opentelemetry__Proto__Metrics__V1__Metric *metric_list[1];
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint *data_point_list[1];
    size_t payload_size;
    unsigned char *packed_payload;
    cfl_sds_t payload;

    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__init(&request);
    opentelemetry__proto__metrics__v1__resource_metrics__init(&resource_metrics);
    opentelemetry__proto__metrics__v1__scope_metrics__init(&scope_metrics);
    opentelemetry__proto__metrics__v1__metric__init(&metric);
    opentelemetry__proto__metrics__v1__gauge__init(&gauge);
    opentelemetry__proto__metrics__v1__number_data_point__init(&data_point);

    data_point.time_unix_nano = 456;
    data_point.start_time_unix_nano = 0;
    data_point.value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT;
    data_point.as_int = 9007199254740993LL;

    data_point_list[0] = &data_point;
    gauge.n_data_points = 1;
    gauge.data_points = data_point_list;

    metric.name = "g_int_large";
    metric.data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE;
    metric.gauge = &gauge;

    metric_list[0] = &metric;
    scope_metrics.n_metrics = 1;
    scope_metrics.metrics = metric_list;

    scope_metrics_list[0] = &scope_metrics;
    resource_metrics.n_scope_metrics = 1;
    resource_metrics.scope_metrics = scope_metrics_list;

    resource_metrics_list[0] = &resource_metrics;
    request.n_resource_metrics = 1;
    request.resource_metrics = resource_metrics_list;

    payload_size = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__get_packed_size(&request);
    packed_payload = calloc(1, payload_size);
    if (packed_payload == NULL) {
        return NULL;
    }

    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__pack(&request,
                                                                                         packed_payload);

    payload = cfl_sds_create_len((char *) packed_payload, payload_size);
    free(packed_payload);

    return payload;
}

void test_opentelemetry_encode_multi_resource_scope_containers()
{
    struct cmt *cmt;
    struct cmt_gauge *gauge;
    struct cfl_array *resource_metrics_list;
    struct cfl_array *scope_metrics_list;
    struct cfl_kvlist *resource_entry;
    struct cfl_kvlist *scope_entry;
    struct cfl_kvlist *rm_root;
    struct cfl_kvlist *rm_meta;
    struct cfl_kvlist *sm_root;
    struct cfl_kvlist *sm_meta;
    cfl_sds_t payload;
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest *service_request;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);
    if (cmt == NULL) {
        return;
    }

    gauge = cmt_gauge_create(cmt, "ns", "sub", "multi_container_gauge", "g", 0, NULL);
    TEST_CHECK(gauge != NULL);
    if (gauge == NULL) {
        cmt_destroy(cmt);
        return;
    }
    cmt_gauge_set(gauge, 123, 1.5, 0, NULL);

    resource_metrics_list = cfl_array_create(2);
    TEST_CHECK(resource_metrics_list != NULL);
    if (resource_metrics_list == NULL) {
        cmt_destroy(cmt);
        return;
    }

    resource_entry = cfl_kvlist_create();
    rm_root = cfl_kvlist_create();
    rm_meta = cfl_kvlist_create();
    cfl_kvlist_insert_string(rm_meta, "schema_url", "rm-schema-1");
    cfl_kvlist_insert_kvlist(rm_root, "metadata", rm_meta);
    cfl_kvlist_insert_kvlist(resource_entry, "resource_metrics", rm_root);

    scope_metrics_list = cfl_array_create(2);
    scope_entry = cfl_kvlist_create();
    sm_root = cfl_kvlist_create();
    sm_meta = cfl_kvlist_create();
    cfl_kvlist_insert_string(sm_meta, "schema_url", "sm-schema-1");
    cfl_kvlist_insert_kvlist(sm_root, "metadata", sm_meta);
    cfl_kvlist_insert_kvlist(scope_entry, "scope_metrics", sm_root);
    cfl_array_append_kvlist(scope_metrics_list, scope_entry);

    scope_entry = cfl_kvlist_create();
    sm_root = cfl_kvlist_create();
    sm_meta = cfl_kvlist_create();
    cfl_kvlist_insert_string(sm_meta, "schema_url", "sm-schema-2");
    cfl_kvlist_insert_kvlist(sm_root, "metadata", sm_meta);
    cfl_kvlist_insert_kvlist(scope_entry, "scope_metrics", sm_root);
    cfl_array_append_kvlist(scope_metrics_list, scope_entry);

    cfl_kvlist_insert_array(resource_entry, "scope_metrics_list", scope_metrics_list);
    cfl_array_append_kvlist(resource_metrics_list, resource_entry);

    resource_entry = cfl_kvlist_create();
    rm_root = cfl_kvlist_create();
    rm_meta = cfl_kvlist_create();
    cfl_kvlist_insert_string(rm_meta, "schema_url", "rm-schema-2");
    cfl_kvlist_insert_kvlist(rm_root, "metadata", rm_meta);
    cfl_kvlist_insert_kvlist(resource_entry, "resource_metrics", rm_root);

    scope_metrics_list = cfl_array_create(1);
    scope_entry = cfl_kvlist_create();
    sm_root = cfl_kvlist_create();
    sm_meta = cfl_kvlist_create();
    cfl_kvlist_insert_string(sm_meta, "schema_url", "sm-schema-3");
    cfl_kvlist_insert_kvlist(sm_root, "metadata", sm_meta);
    cfl_kvlist_insert_kvlist(scope_entry, "scope_metrics", sm_root);
    cfl_array_append_kvlist(scope_metrics_list, scope_entry);
    cfl_kvlist_insert_array(resource_entry, "scope_metrics_list", scope_metrics_list);
    cfl_array_append_kvlist(resource_metrics_list, resource_entry);

    cfl_kvlist_insert_array(cmt->external_metadata, "resource_metrics_list", resource_metrics_list);

    payload = cmt_encode_opentelemetry_create(cmt);
    TEST_CHECK(payload != NULL);
    if (payload != NULL) {
        service_request = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__unpack(
            NULL, cfl_sds_len(payload), (uint8_t *) payload);
        TEST_CHECK(service_request != NULL);
        if (service_request != NULL) {
            TEST_CHECK(service_request->n_resource_metrics == 2);
            if (service_request->n_resource_metrics == 2) {
                TEST_CHECK(service_request->resource_metrics[0]->n_scope_metrics == 2);
                TEST_CHECK(service_request->resource_metrics[1]->n_scope_metrics == 1);
                TEST_CHECK(strcmp(service_request->resource_metrics[0]->schema_url, "rm-schema-1") == 0);
                TEST_CHECK(strcmp(service_request->resource_metrics[1]->schema_url, "rm-schema-2") == 0);
                TEST_CHECK(strcmp(service_request->resource_metrics[0]->scope_metrics[0]->schema_url, "sm-schema-1") == 0);
                TEST_CHECK(strcmp(service_request->resource_metrics[0]->scope_metrics[1]->schema_url, "sm-schema-2") == 0);
                TEST_CHECK(strcmp(service_request->resource_metrics[1]->scope_metrics[0]->schema_url, "sm-schema-3") == 0);
                TEST_CHECK(service_request->resource_metrics[0]->scope_metrics[0]->n_metrics == 1);
                TEST_CHECK(service_request->resource_metrics[0]->scope_metrics[1]->n_metrics == 1);
                TEST_CHECK(service_request->resource_metrics[1]->scope_metrics[0]->n_metrics == 1);
            }

            opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(service_request, NULL);
        }

        cmt_encode_opentelemetry_destroy(payload);
    }

    cmt_destroy(cmt);
}

void test_opentelemetry_api_full_roundtrip_with_msgpack()
{
    int ret;
    size_t offset;
    size_t msgpack_offset;
    cfl_sds_t otlp_payload_1;
    cfl_sds_t otlp_payload_2;
    cfl_sds_t reference_text;
    cfl_sds_t result_text;
    char *msgpack_buffer;
    size_t msgpack_size;
    struct cfl_list decoded_list_1;
    struct cfl_list decoded_list_2;
    struct cmt *api_context;
    struct cmt *decoded_context_1;
    struct cmt *decoded_context_2;
    struct cmt *msgpack_context;

    cmt_initialize();

    api_context = generate_api_test_data();
    TEST_CHECK(api_context != NULL);
    if (api_context == NULL) {
        return;
    }

    reference_text = cmt_encode_text_create(api_context);
    TEST_CHECK(reference_text != NULL);

    otlp_payload_1 = cmt_encode_opentelemetry_create(api_context);
    TEST_CHECK(otlp_payload_1 != NULL);
    if (otlp_payload_1 == NULL) {
        cmt_encode_text_destroy(reference_text);
        cmt_destroy(api_context);
        return;
    }

    offset = 0;
    ret = cmt_decode_opentelemetry_create(&decoded_list_1, otlp_payload_1, cfl_sds_len(otlp_payload_1), &offset);
    TEST_CHECK(ret == CMT_DECODE_OPENTELEMETRY_SUCCESS);
    if (ret != CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        cmt_encode_opentelemetry_destroy(otlp_payload_1);
        cmt_encode_text_destroy(reference_text);
        cmt_destroy(api_context);
        return;
    }

    decoded_context_1 = cfl_list_entry_first(&decoded_list_1, struct cmt, _head);
    TEST_CHECK(decoded_context_1 != NULL);
    if (decoded_context_1 == NULL) {
        cmt_decode_opentelemetry_destroy(&decoded_list_1);
        cmt_encode_opentelemetry_destroy(otlp_payload_1);
        cmt_encode_text_destroy(reference_text);
        cmt_destroy(api_context);
        return;
    }

    ret = cmt_encode_msgpack_create(decoded_context_1, &msgpack_buffer, &msgpack_size);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        cmt_decode_opentelemetry_destroy(&decoded_list_1);
        cmt_encode_opentelemetry_destroy(otlp_payload_1);
        cmt_encode_text_destroy(reference_text);
        cmt_destroy(api_context);
        return;
    }

    msgpack_offset = 0;
    msgpack_context = NULL;
    ret = cmt_decode_msgpack_create(&msgpack_context, msgpack_buffer, msgpack_size, &msgpack_offset);
    TEST_CHECK(ret == 0);
    if (ret != 0 || msgpack_context == NULL) {
        cmt_encode_msgpack_destroy(msgpack_buffer);
        cmt_decode_opentelemetry_destroy(&decoded_list_1);
        cmt_encode_opentelemetry_destroy(otlp_payload_1);
        cmt_encode_text_destroy(reference_text);
        cmt_destroy(api_context);
        return;
    }

    otlp_payload_2 = cmt_encode_opentelemetry_create(msgpack_context);
    TEST_CHECK(otlp_payload_2 != NULL);
    if (otlp_payload_2 == NULL) {
        cmt_decode_msgpack_destroy(msgpack_context);
        cmt_encode_msgpack_destroy(msgpack_buffer);
        cmt_decode_opentelemetry_destroy(&decoded_list_1);
        cmt_encode_opentelemetry_destroy(otlp_payload_1);
        cmt_encode_text_destroy(reference_text);
        cmt_destroy(api_context);
        return;
    }

    offset = 0;
    ret = cmt_decode_opentelemetry_create(&decoded_list_2, otlp_payload_2, cfl_sds_len(otlp_payload_2), &offset);
    TEST_CHECK(ret == CMT_DECODE_OPENTELEMETRY_SUCCESS);
    if (ret == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        decoded_context_2 = cfl_list_entry_first(&decoded_list_2, struct cmt, _head);
        TEST_CHECK(decoded_context_2 != NULL);

        if (decoded_context_2 != NULL) {
            result_text = cmt_encode_text_create(decoded_context_2);
            TEST_CHECK(result_text != NULL);

            if (result_text != NULL && reference_text != NULL) {
                TEST_CHECK(are_texts_equivalent_ignoring_line_order(reference_text,
                                                                     result_text) == CMT_TRUE);
                cmt_encode_text_destroy(result_text);
            }
        }

        cmt_decode_opentelemetry_destroy(&decoded_list_2);
    }

    cmt_encode_opentelemetry_destroy(otlp_payload_2);
    cmt_decode_msgpack_destroy(msgpack_context);
    cmt_encode_msgpack_destroy(msgpack_buffer);
    cmt_decode_opentelemetry_destroy(&decoded_list_1);
    cmt_encode_opentelemetry_destroy(otlp_payload_1);
    cmt_encode_text_destroy(reference_text);
    cmt_destroy(api_context);
}

void test_opentelemetry_gauge_int_and_unit_decode()
{
    cfl_sds_t payload;
    struct cfl_list decoded_context_list;
    struct cmt *decoded_context;
    struct cmt_gauge *gauge;
    double val;
    size_t offset;
    int result;

    cmt_initialize();

    payload = generate_gauge_int_otlp_payload_with_unit();
    TEST_CHECK(payload != NULL);

    if (payload == NULL) {
        return;
    }

    offset = 0;
    result = cmt_decode_opentelemetry_create(&decoded_context_list,
                                             payload,
                                             cfl_sds_len(payload),
                                             &offset);
    TEST_CHECK(result == CMT_DECODE_OPENTELEMETRY_SUCCESS);

    if (result != CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        cfl_sds_destroy(payload);
        return;
    }

    decoded_context = cfl_list_entry_first(&decoded_context_list, struct cmt, _head);
    TEST_CHECK(decoded_context != NULL);

    if (decoded_context != NULL) {
        TEST_CHECK(cfl_list_size(&decoded_context->gauges) == 1);
        gauge = cfl_list_entry_first(&decoded_context->gauges, struct cmt_gauge, _head);
        TEST_CHECK(gauge != NULL);

        if (gauge != NULL) {
            TEST_CHECK(gauge->map != NULL);
            if (gauge->map != NULL) {
                TEST_CHECK(gauge->map->unit != NULL);
                if (gauge->map->unit != NULL) {
                    TEST_CHECK(strcmp(gauge->map->unit, "bytes") == 0);
                }
            }

            result = cmt_gauge_get_val(gauge, 0, NULL, &val);
            TEST_CHECK(result == 0);
            if (result == 0) {
                TEST_CHECK(val == -7.0);
            }
        }
    }

    cmt_decode_opentelemetry_destroy(&decoded_context_list);
    cfl_sds_destroy(payload);
}

void test_opentelemetry_exponential_histogram()
{
    cfl_sds_t       payload;
    cfl_sds_t       first_prometheus_context;
    cfl_sds_t       first_text_context;
    cfl_sds_t       second_payload;
    cfl_sds_t       second_prometheus_context;
    struct cfl_list first_decoded_context_list;
    struct cfl_list second_decoded_context_list;
    struct cmt     *first_decoded_context;
    struct cmt     *second_decoded_context;
    size_t          offset;
    int             result;

    cmt_initialize();

    payload = generate_exponential_histogram_otlp_payload();
    TEST_CHECK(payload != NULL);

    if (payload == NULL) {
        return;
    }

    offset = 0;
    result = cmt_decode_opentelemetry_create(&first_decoded_context_list,
                                             payload,
                                             cfl_sds_len(payload),
                                             &offset);
    TEST_CHECK(result == CMT_DECODE_OPENTELEMETRY_SUCCESS);

    if (result != CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        cfl_sds_destroy(payload);
        return;
    }

    first_decoded_context = cfl_list_entry_first(&first_decoded_context_list, struct cmt, _head);
    TEST_CHECK(first_decoded_context != NULL);

    if (first_decoded_context == NULL) {
        cmt_decode_opentelemetry_destroy(&first_decoded_context_list);
        cfl_sds_destroy(payload);
        return;
    }

    first_prometheus_context = cmt_encode_prometheus_create(first_decoded_context, CMT_TRUE);
    TEST_CHECK(first_prometheus_context != NULL);

    if (first_prometheus_context != NULL) {
        TEST_CHECK(strstr(first_prometheus_context, "exp_hist_bucket{le=\"-1.0\"} 1 0") != NULL);
        TEST_CHECK(strstr(first_prometheus_context, "exp_hist_bucket{le=\"0.0\"} 2 0") != NULL);
        TEST_CHECK(strstr(first_prometheus_context, "exp_hist_bucket{le=\"2.0\"} 5 0") != NULL);
        TEST_CHECK(strstr(first_prometheus_context, "exp_hist_bucket{le=\"4.0\"} 7 0") != NULL);
        TEST_CHECK(strstr(first_prometheus_context, "exp_hist_bucket{le=\"+Inf\"} 7 0") != NULL);
        TEST_CHECK(strstr(first_prometheus_context, "exp_hist_sum 8 0") != NULL);
        TEST_CHECK(strstr(first_prometheus_context, "exp_hist_count 7 0") != NULL);
    }

    first_text_context = cmt_encode_text_create(first_decoded_context);
    TEST_CHECK(first_text_context != NULL);
    if (first_text_context != NULL) {
        TEST_CHECK(strstr(first_text_context, "exemplars=[") != NULL);
        TEST_CHECK(strstr(first_text_context, "as_double=3.25") != NULL);
        TEST_CHECK(strstr(first_text_context, "time_unix_nano=5") != NULL);
        cmt_encode_text_destroy(first_text_context);
    }

    second_payload = cmt_encode_opentelemetry_create(first_decoded_context);
    TEST_CHECK(second_payload != NULL);

    if (second_payload != NULL) {
        Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest *service_request;
        Opentelemetry__Proto__Metrics__V1__Metric *roundtrip_metric;
        Opentelemetry__Proto__Metrics__V1__ExponentialHistogramDataPoint *roundtrip_dp;

        offset = 0;
        result = cmt_decode_opentelemetry_create(&second_decoded_context_list,
                                                 second_payload,
                                                 cfl_sds_len(second_payload),
                                                 &offset);
        TEST_CHECK(result == CMT_DECODE_OPENTELEMETRY_SUCCESS);

        if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
            second_decoded_context = cfl_list_entry_first(&second_decoded_context_list, struct cmt, _head);
            TEST_CHECK(second_decoded_context != NULL);

            if (second_decoded_context != NULL) {
                second_prometheus_context = cmt_encode_prometheus_create(second_decoded_context, CMT_TRUE);
                TEST_CHECK(second_prometheus_context != NULL);

                if (second_prometheus_context != NULL && first_prometheus_context != NULL) {
                    TEST_CHECK(strcmp(first_prometheus_context, second_prometheus_context) == 0);
                    cmt_encode_prometheus_destroy(second_prometheus_context);
                }
            }

            cmt_decode_opentelemetry_destroy(&second_decoded_context_list);
        }

        service_request = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__unpack(
            NULL, cfl_sds_len(second_payload), (uint8_t *) second_payload);
        TEST_CHECK(service_request != NULL);

        if (service_request != NULL &&
            service_request->n_resource_metrics == 1 &&
            service_request->resource_metrics[0]->n_scope_metrics == 1 &&
            service_request->resource_metrics[0]->scope_metrics[0]->n_metrics == 1) {
            roundtrip_metric = service_request->resource_metrics[0]->scope_metrics[0]->metrics[0];
            TEST_CHECK(roundtrip_metric->n_metadata == 1);
            if (roundtrip_metric->n_metadata == 1) {
                TEST_CHECK(strcmp(roundtrip_metric->metadata[0]->key, "origin") == 0);
            }

            TEST_CHECK(roundtrip_metric->data_case ==
                       OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_EXPONENTIAL_HISTOGRAM);
            if (roundtrip_metric->data_case ==
                OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_EXPONENTIAL_HISTOGRAM) {
                roundtrip_dp = roundtrip_metric->exponential_histogram->data_points[0];
                TEST_CHECK(roundtrip_dp->start_time_unix_nano == 123);
                TEST_CHECK(roundtrip_dp->flags ==
                           OPENTELEMETRY__PROTO__METRICS__V1__DATA_POINT_FLAGS__DATA_POINT_FLAGS_NO_RECORDED_VALUE_MASK);
                TEST_CHECK(roundtrip_dp->has_min == CMT_TRUE);
                TEST_CHECK(roundtrip_dp->has_max == CMT_TRUE);
                TEST_CHECK(roundtrip_dp->min == -2.5);
                TEST_CHECK(roundtrip_dp->max == 4.5);
                TEST_CHECK(roundtrip_dp->n_exemplars == 1);
            }
        }

        if (service_request != NULL) {
            opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(service_request, NULL);
        }

        cmt_encode_opentelemetry_destroy(second_payload);
    }

    if (first_prometheus_context != NULL) {
        cmt_encode_prometheus_destroy(first_prometheus_context);
    }

    cmt_decode_opentelemetry_destroy(&first_decoded_context_list);
    cfl_sds_destroy(payload);
}

void test_opentelemetry_sum_non_monotonic_int_roundtrip()
{
    cfl_sds_t payload;
    cfl_sds_t encoded_payload;
    struct cfl_list decoded_context_list;
    struct cmt *decoded_context;
    struct cmt_counter *counter;
    double value;
    size_t offset;
    int result;
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest *service_request;
    Opentelemetry__Proto__Metrics__V1__Metric *roundtrip_metric;
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint *roundtrip_dp;

    cmt_initialize();

    payload = generate_sum_non_monotonic_int_otlp_payload();
    TEST_CHECK(payload != NULL);
    if (payload == NULL) {
        return;
    }

    offset = 0;
    result = cmt_decode_opentelemetry_create(&decoded_context_list,
                                             payload,
                                             cfl_sds_len(payload),
                                             &offset);
    TEST_CHECK(result == CMT_DECODE_OPENTELEMETRY_SUCCESS);
    if (result != CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        cfl_sds_destroy(payload);
        return;
    }

    decoded_context = cfl_list_entry_first(&decoded_context_list, struct cmt, _head);
    TEST_CHECK(decoded_context != NULL);

    if (decoded_context != NULL) {
        TEST_CHECK(cfl_list_size(&decoded_context->counters) == 1);
        counter = cfl_list_entry_first(&decoded_context->counters, struct cmt_counter, _head);
        TEST_CHECK(counter != NULL);

        if (counter != NULL) {
            TEST_CHECK(counter->allow_reset == CMT_TRUE);
            result = cmt_counter_get_val(counter, 0, NULL, &value);
            TEST_CHECK(result == 0);
            if (result == 0) {
                TEST_CHECK(value == -7.0);
            }
        }

        encoded_payload = cmt_encode_opentelemetry_create(decoded_context);
        TEST_CHECK(encoded_payload != NULL);
        if (encoded_payload != NULL) {
            service_request = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__unpack(
                NULL, cfl_sds_len(encoded_payload), (uint8_t *) encoded_payload);
            TEST_CHECK(service_request != NULL);

            if (service_request != NULL &&
                service_request->n_resource_metrics == 1 &&
                service_request->resource_metrics[0]->n_scope_metrics == 1 &&
                service_request->resource_metrics[0]->scope_metrics[0]->n_metrics == 1) {
                roundtrip_metric = service_request->resource_metrics[0]->scope_metrics[0]->metrics[0];
                TEST_CHECK(roundtrip_metric->data_case ==
                           OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM);
                if (roundtrip_metric->data_case ==
                    OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM) {
                    TEST_CHECK(roundtrip_metric->sum->is_monotonic == CMT_FALSE);
                    TEST_CHECK(roundtrip_metric->sum->aggregation_temporality ==
                               OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_CUMULATIVE);
                    TEST_CHECK(roundtrip_metric->sum->n_data_points == 1);
                    roundtrip_dp = roundtrip_metric->sum->data_points[0];
                    TEST_CHECK(roundtrip_dp->value_case ==
                               OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT);
                    TEST_CHECK(roundtrip_dp->as_int == -7);
                }
            }

            if (service_request != NULL) {
                opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(service_request, NULL);
            }

            cmt_encode_opentelemetry_destroy(encoded_payload);
        }
    }

    cmt_decode_opentelemetry_destroy(&decoded_context_list);
    cfl_sds_destroy(payload);
}

void test_opentelemetry_large_int_roundtrip_with_msgpack()
{
    cfl_sds_t payload;
    cfl_sds_t encoded_payload;
    char *msgpack_buffer;
    size_t msgpack_size;
    size_t offset;
    size_t msgpack_offset;
    int result;
    struct cfl_list decoded_context_list;
    struct cmt *decoded_context;
    struct cmt *msgpack_context;
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest *service_request;
    Opentelemetry__Proto__Metrics__V1__Metric *roundtrip_metric;
    Opentelemetry__Proto__Metrics__V1__NumberDataPoint *roundtrip_dp;

    cmt_initialize();

    payload = generate_gauge_large_int_otlp_payload();
    TEST_CHECK(payload != NULL);
    if (payload == NULL) {
        return;
    }

    offset = 0;
    result = cmt_decode_opentelemetry_create(&decoded_context_list,
                                             payload,
                                             cfl_sds_len(payload),
                                             &offset);
    TEST_CHECK(result == CMT_DECODE_OPENTELEMETRY_SUCCESS);
    if (result != CMT_DECODE_OPENTELEMETRY_SUCCESS) {
        cfl_sds_destroy(payload);
        return;
    }

    decoded_context = cfl_list_entry_first(&decoded_context_list, struct cmt, _head);
    TEST_CHECK(decoded_context != NULL);
    if (decoded_context == NULL) {
        cmt_decode_opentelemetry_destroy(&decoded_context_list);
        cfl_sds_destroy(payload);
        return;
    }

    result = cmt_encode_msgpack_create(decoded_context, &msgpack_buffer, &msgpack_size);
    TEST_CHECK(result == 0);
    if (result != 0) {
        cmt_decode_opentelemetry_destroy(&decoded_context_list);
        cfl_sds_destroy(payload);
        return;
    }

    msgpack_offset = 0;
    msgpack_context = NULL;
    result = cmt_decode_msgpack_create(&msgpack_context, msgpack_buffer, msgpack_size, &msgpack_offset);
    TEST_CHECK(result == 0);
    if (result != 0 || msgpack_context == NULL) {
        cmt_encode_msgpack_destroy(msgpack_buffer);
        cmt_decode_opentelemetry_destroy(&decoded_context_list);
        cfl_sds_destroy(payload);
        return;
    }

    encoded_payload = cmt_encode_opentelemetry_create(msgpack_context);
    TEST_CHECK(encoded_payload != NULL);
    if (encoded_payload != NULL) {
        service_request = opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__unpack(
            NULL, cfl_sds_len(encoded_payload), (uint8_t *) encoded_payload);
        TEST_CHECK(service_request != NULL);

        if (service_request != NULL &&
            service_request->n_resource_metrics == 1 &&
            service_request->resource_metrics[0]->n_scope_metrics == 1 &&
            service_request->resource_metrics[0]->scope_metrics[0]->n_metrics == 1) {
            roundtrip_metric = service_request->resource_metrics[0]->scope_metrics[0]->metrics[0];
            TEST_CHECK(roundtrip_metric->data_case ==
                       OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE);
            if (roundtrip_metric->data_case ==
                OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE &&
                roundtrip_metric->gauge->n_data_points == 1) {
                roundtrip_dp = roundtrip_metric->gauge->data_points[0];
                TEST_CHECK(roundtrip_dp->value_case ==
                           OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT);
                TEST_CHECK(roundtrip_dp->as_int == 9007199254740993LL);
            }
        }

        if (service_request != NULL) {
            opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(service_request, NULL);
        }
        cmt_encode_opentelemetry_destroy(encoded_payload);
    }

    cmt_decode_msgpack_destroy(msgpack_context);
    cmt_encode_msgpack_destroy(msgpack_buffer);
    cmt_decode_opentelemetry_destroy(&decoded_context_list);
    cfl_sds_destroy(payload);
}

TEST_LIST = {
    {"opentelemetry_api_full_roundtrip_with_msgpack", test_opentelemetry_api_full_roundtrip_with_msgpack},
    {"opentelemetry_encode_multi_resource_scope_containers", test_opentelemetry_encode_multi_resource_scope_containers},
    {"opentelemetry_exponential_histogram",           test_opentelemetry_exponential_histogram},
    {"opentelemetry_gauge_int_and_unit_decode",       test_opentelemetry_gauge_int_and_unit_decode},
    {"opentelemetry_sum_non_monotonic_int_roundtrip", test_opentelemetry_sum_non_monotonic_int_roundtrip},
    {"opentelemetry_large_int_roundtrip_with_msgpack", test_opentelemetry_large_int_roundtrip_with_msgpack},
    { 0 }
};
