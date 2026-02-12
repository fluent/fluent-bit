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
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_math.h>
#include <cmetrics/cmt_cat.h>
#include <cmetrics/cmt_filter.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_text.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_encode_influx.h>
#include <cmetrics/cmt_encode_splunk_hec.h>
#include <cmetrics/cmt_encode_cloudwatch_emf.h>
#include <cmetrics/cmt_encode_prometheus_remote_write.h>
#include <cmetrics/cmt_encode_opentelemetry.h>

#include <math.h>
#include <string.h>

#include "cmt_tests.h"

static void print_splunk_payload(cfl_sds_t payload)
{
    size_t index;

    for (index = 0; index < cfl_sds_len(payload); index++) {
        putchar(payload[index]);

        if (payload[index] == '}' &&
            index + 1 < cfl_sds_len(payload) &&
            payload[index + 1] == '{') {
            putchar('\n');
        }
    }

    putchar('\n');
}

static struct cmt_exp_histogram *create_test_metric(struct cmt *cmt, uint64_t timestamp)
{
    int result;
    uint64_t positive[3] = {3, 5, 7};
    uint64_t negative[2] = {2, 1};
    struct cmt_exp_histogram *exp_histogram;

    exp_histogram = cmt_exp_histogram_create(cmt,
                                             "cm", "native", "exp_hist", "native exp histogram",
                                             1, (char *[]) {"endpoint"});
    TEST_CHECK(exp_histogram != NULL);

    if (exp_histogram == NULL) {
        return NULL;
    }

    result = cmt_exp_histogram_set_default(exp_histogram,
                                           timestamp,
                                           2,
                                           11,
                                           0.0,
                                           -2,
                                           3,
                                           positive,
                                           -1,
                                           2,
                                           negative,
                                           CMT_TRUE,
                                           42.25,
                                           29,
                                           1,
                                           (char *[]) {"api"});
    TEST_CHECK(result == 0);

    if (result != 0) {
        cmt_exp_histogram_destroy(exp_histogram);
        return NULL;
    }

    return exp_histogram;
}

static struct cmt_exp_histogram *create_test_metric_with_zero_threshold(
    struct cmt *cmt,
    uint64_t timestamp,
    double zero_threshold,
    uint64_t zero_count,
    double sum,
    uint64_t count)
{
    int result;
    uint64_t positive[3] = {3, 5, 7};
    uint64_t negative[2] = {2, 1};
    struct cmt_exp_histogram *exp_histogram;

    exp_histogram = cmt_exp_histogram_create(cmt,
                                             "cm", "native", "exp_hist", "native exp histogram",
                                             1, (char *[]) {"endpoint"});
    TEST_CHECK(exp_histogram != NULL);

    if (exp_histogram == NULL) {
        return NULL;
    }

    result = cmt_exp_histogram_set_default(exp_histogram,
                                           timestamp,
                                           2,
                                           zero_count,
                                           zero_threshold,
                                           -2,
                                           3,
                                           positive,
                                           -1,
                                           2,
                                           negative,
                                           CMT_TRUE,
                                           sum,
                                           count,
                                           1,
                                           (char *[]) {"api"});
    TEST_CHECK(result == 0);

    if (result != 0) {
        cmt_exp_histogram_destroy(exp_histogram);
        return NULL;
    }

    return exp_histogram;
}

static struct cmt_exp_histogram *create_test_metric_custom(
    struct cmt *cmt,
    uint64_t timestamp,
    int32_t scale,
    uint64_t zero_count,
    double zero_threshold,
    int32_t positive_offset,
    size_t positive_count,
    uint64_t *positive_buckets,
    int32_t negative_offset,
    size_t negative_count,
    uint64_t *negative_buckets,
    int sum_set,
    double sum,
    uint64_t count)
{
    int result;
    struct cmt_exp_histogram *exp_histogram;

    exp_histogram = cmt_exp_histogram_create(cmt,
                                             "cm", "native", "exp_hist", "native exp histogram",
                                             1, (char *[]) {"endpoint"});
    TEST_CHECK(exp_histogram != NULL);

    if (exp_histogram == NULL) {
        return NULL;
    }

    result = cmt_exp_histogram_set_default(exp_histogram,
                                           timestamp,
                                           scale,
                                           zero_count,
                                           zero_threshold,
                                           positive_offset,
                                           positive_count,
                                           positive_buckets,
                                           negative_offset,
                                           negative_count,
                                           negative_buckets,
                                           sum_set,
                                           sum,
                                           count,
                                           1,
                                           (char *[]) {"api"});
    TEST_CHECK(result == 0);

    if (result != 0) {
        cmt_exp_histogram_destroy(exp_histogram);
        return NULL;
    }

    return exp_histogram;
}

static int get_prometheus_bucket_value(cfl_sds_t encoded_prometheus,
                                       const char *le,
                                       double *out_value)
{
    char needle[128];
    char *cursor;

    snprintf(needle, sizeof(needle) - 1,
             "cm_native_exp_hist_bucket{le=\"%s\",endpoint=\"api\"} ",
             le);

    cursor = strstr(encoded_prometheus, needle);
    if (cursor == NULL) {
        return -1;
    }

    cursor += strlen(needle);
    *out_value = strtod(cursor, NULL);

    return 0;
}

static int remote_write_contains_metric_name(Prometheus__WriteRequest *request,
                                             const char *metric_name)
{
    size_t index;
    size_t label_index;

    for (index = 0; index < request->n_timeseries; index++) {
        if (request->timeseries[index] == NULL) {
            continue;
        }

        for (label_index = 0; label_index < request->timeseries[index]->n_labels; label_index++) {
            if (request->timeseries[index]->labels[label_index] == NULL) {
                continue;
            }

            if (request->timeseries[index]->labels[label_index]->name != NULL &&
                request->timeseries[index]->labels[label_index]->value != NULL &&
                strcmp(request->timeseries[index]->labels[label_index]->name, "__name__") == 0 &&
                strcmp(request->timeseries[index]->labels[label_index]->value, metric_name) == 0) {
                return CMT_TRUE;
            }
        }
    }

    return CMT_FALSE;
}

static int assert_prometheus_bucket_monotonicity(cfl_sds_t encoded_prometheus,
                                                 double *out_last_finite,
                                                 double *out_plus_inf)
{
    char *cursor;
    char *line_end;
    char *value_cursor;
    char *parsed_end;
    char le_buffer[64];
    size_t le_length;
    double previous_value;
    double current_value;
    int found_any;

    previous_value = -1.0;
    *out_last_finite = -1.0;
    *out_plus_inf = -1.0;
    found_any = CMT_FALSE;

    cursor = encoded_prometheus;

    while (cursor != NULL) {
        cursor = strstr(cursor, "cm_native_exp_hist_bucket{le=\"");
        if (cursor == NULL) {
            break;
        }

        cursor += strlen("cm_native_exp_hist_bucket{le=\"");
        line_end = strstr(cursor, "\"");
        if (line_end == NULL) {
            return -1;
        }

        le_length = line_end - cursor;
        if (le_length >= sizeof(le_buffer)) {
            return -1;
        }

        memcpy(le_buffer, cursor, le_length);
        le_buffer[le_length] = '\0';

        value_cursor = strstr(line_end, "} ");
        if (value_cursor == NULL) {
            return -1;
        }
        value_cursor += 2;

        current_value = strtod(value_cursor, &parsed_end);
        if (parsed_end == value_cursor) {
            return -1;
        }

        if (found_any && current_value < previous_value) {
            return -1;
        }

        if (strcmp(le_buffer, "+Inf") == 0) {
            *out_plus_inf = current_value;
        }
        else {
            *out_last_finite = current_value;
        }

        previous_value = current_value;
        found_any = CMT_TRUE;
        cursor = parsed_end;
    }

    if (!found_any || *out_plus_inf < 0.0 || *out_last_finite < 0.0) {
        return -1;
    }

    if (*out_last_finite > *out_plus_inf) {
        return -1;
    }

    return 0;
}

void test_exp_histogram_msgpack_roundtrip()
{
    int result;
    size_t offset;
    char *packed_buffer;
    size_t packed_size;
    struct cmt *input_context;
    struct cmt *output_context;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_metric *metric;

    cmt_initialize();

    input_context = cmt_create();
    TEST_CHECK(input_context != NULL);

    exp_histogram = create_test_metric(input_context, 123);
    TEST_CHECK(exp_histogram != NULL);

    result = cmt_encode_msgpack_create(input_context, &packed_buffer, &packed_size);
    TEST_CHECK(result == CMT_DECODE_MSGPACK_SUCCESS);

    offset = 0;
    output_context = NULL;
    result = cmt_decode_msgpack_create(&output_context, packed_buffer, packed_size, &offset);
    TEST_CHECK(result == CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(output_context != NULL);
    TEST_CHECK(cfl_list_size(&output_context->exp_histograms) == 1);

    exp_histogram = cfl_list_entry_first(&output_context->exp_histograms,
                                         struct cmt_exp_histogram, _head);
    metric = cmt_map_metric_get(&exp_histogram->opts, exp_histogram->map,
                                1, (char *[]) {"api"}, CMT_FALSE);
    TEST_CHECK(metric != NULL);

    if (metric != NULL) {
        printf("\n========== EXP HIST MSGPACK ROUNDTRIP ==========\n");
        printf("scale=%d zero_count=%" PRIu64 " count=%" PRIu64 " sum=%.17g\n\n",
               metric->exp_hist_scale,
               metric->exp_hist_zero_count,
               metric->exp_hist_count,
               cmt_math_uint64_to_d64(metric->exp_hist_sum));

        TEST_CHECK(metric->exp_hist_scale == 2);
        TEST_CHECK(metric->exp_hist_zero_count == 11);
        TEST_CHECK(metric->exp_hist_positive_offset == -2);
        TEST_CHECK(metric->exp_hist_negative_offset == -1);
        TEST_CHECK(metric->exp_hist_positive_count == 3);
        TEST_CHECK(metric->exp_hist_negative_count == 2);
        TEST_CHECK(metric->exp_hist_count == 29);
        TEST_CHECK(metric->exp_hist_sum_set == CMT_TRUE);
        TEST_CHECK(fabs(cmt_math_uint64_to_d64(metric->exp_hist_sum) - 42.25) < 0.00001);
        TEST_CHECK(metric->exp_hist_positive_buckets != NULL);
        TEST_CHECK(metric->exp_hist_negative_buckets != NULL);

        if (metric->exp_hist_positive_buckets != NULL &&
            metric->exp_hist_negative_buckets != NULL) {
            TEST_CHECK(metric->exp_hist_positive_buckets[0] == 3);
            TEST_CHECK(metric->exp_hist_positive_buckets[1] == 5);
            TEST_CHECK(metric->exp_hist_positive_buckets[2] == 7);
            TEST_CHECK(metric->exp_hist_negative_buckets[0] == 2);
            TEST_CHECK(metric->exp_hist_negative_buckets[1] == 1);
        }
    }

    cmt_destroy(input_context);
    cmt_decode_msgpack_destroy(output_context);
    cmt_encode_msgpack_destroy(packed_buffer);
}

void test_exp_histogram_encoder_smoke()
{
    int result;
    uint64_t timestamp;
    size_t packed_size;
    char *packed_buffer;
    cfl_sds_t encoded_text;
    cfl_sds_t encoded_prometheus;
    cfl_sds_t encoded_influx;
    cfl_sds_t encoded_splunk_hec;
    cfl_sds_t encoded_remote_write;
    cfl_sds_t encoded_opentelemetry;
    char *encoded_cloudwatch_emf;
    size_t encoded_cloudwatch_emf_size;
    struct cmt *context;

    cmt_initialize();
    timestamp = cfl_time_now();

    context = cmt_create();
    TEST_CHECK(context != NULL);

    TEST_CHECK(create_test_metric(context, timestamp) != NULL);

    result = cmt_encode_msgpack_create(context, &packed_buffer, &packed_size);
    TEST_CHECK(result == 0);
    cmt_encode_msgpack_destroy(packed_buffer);

    encoded_text = cmt_encode_text_create(context);
    TEST_CHECK(encoded_text != NULL);
    if (encoded_text != NULL) {
        printf("\n========== EXP HIST TEXT ==========\n%s\n", encoded_text);
        TEST_CHECK(strstr(encoded_text, "scale=2") != NULL);
        TEST_CHECK(strstr(encoded_text, "zero_count=11") != NULL);
        TEST_CHECK(strstr(encoded_text, "positive={offset=-2, bucket_counts=[3, 5, 7]}") != NULL);
        TEST_CHECK(strstr(encoded_text, "negative={offset=-1, bucket_counts=[2, 1]}") != NULL);
        TEST_CHECK(strstr(encoded_text, "count=29") != NULL);
        TEST_CHECK(strstr(encoded_text, "sum=42.25") != NULL);
    }
    cmt_encode_text_destroy(encoded_text);

    encoded_prometheus = cmt_encode_prometheus_create(context, CMT_TRUE);
    TEST_CHECK(encoded_prometheus != NULL);
    if (encoded_prometheus != NULL) {
        double last_finite_bucket;
        double plus_inf_bucket;

        printf("\n========== EXP HIST PROMETHEUS ==========\n%s\n", encoded_prometheus);

        result = assert_prometheus_bucket_monotonicity(encoded_prometheus,
                                                       &last_finite_bucket,
                                                       &plus_inf_bucket);
        TEST_CHECK(result == 0);
        if (result == 0) {
            TEST_CHECK(plus_inf_bucket == 29.0);
            TEST_CHECK(last_finite_bucket <= plus_inf_bucket);
        }
    }
    cmt_encode_prometheus_destroy(encoded_prometheus);

    encoded_influx = cmt_encode_influx_create(context);
    TEST_CHECK(encoded_influx != NULL);
    if (encoded_influx != NULL) {
        printf("\n========== EXP HIST INFLUX ==========\n%s\n", encoded_influx);
    }
    cmt_encode_influx_destroy(encoded_influx);

    encoded_splunk_hec = cmt_encode_splunk_hec_create(context,
                                                      "localhost", "test-index",
                                                      NULL, NULL);
    TEST_CHECK(encoded_splunk_hec != NULL);
    if (encoded_splunk_hec != NULL) {
        printf("\n========== EXP HIST SPLUNK HEC ==========\n");
        print_splunk_payload(encoded_splunk_hec);
        printf("\n");
    }
    cmt_encode_splunk_hec_destroy(encoded_splunk_hec);

    result = cmt_encode_cloudwatch_emf_create(context,
                                              &encoded_cloudwatch_emf,
                                              &encoded_cloudwatch_emf_size,
                                              CMT_TRUE);
    TEST_CHECK(result == 0);
    if (result == 0) {
        printf("========== EXP HIST CLOUDWATCH EMF ==========\n");
        printf("payload_size=%zu\n\n", encoded_cloudwatch_emf_size);
    }
    cmt_encode_cloudwatch_emf_destroy(encoded_cloudwatch_emf);

    encoded_remote_write = cmt_encode_prometheus_remote_write_create(context);
    TEST_CHECK(encoded_remote_write != NULL);
    if (encoded_remote_write != NULL) {
        printf("========== EXP HIST REMOTE WRITE ==========\n");
        printf("payload_size=%zu\n\n", cfl_sds_len(encoded_remote_write));
    }
    cmt_encode_prometheus_remote_write_destroy(encoded_remote_write);

    encoded_opentelemetry = cmt_encode_opentelemetry_create(context);
    TEST_CHECK(encoded_opentelemetry != NULL);
    if (encoded_opentelemetry != NULL) {
        printf("========== EXP HIST OPENTELEMETRY ==========\n");
        printf("payload_size=%zu\n\n", cfl_sds_len(encoded_opentelemetry));
    }
    cmt_encode_opentelemetry_destroy(encoded_opentelemetry);

    cmt_destroy(context);
}

void test_exp_histogram_nonzero_zero_threshold()
{
    int result;
    double bucket_value;
    cfl_sds_t encoded_text;
    cfl_sds_t encoded_prometheus;
    cfl_sds_t encoded_influx;
    cfl_sds_t encoded_splunk_hec;
    struct cmt *context;

    cmt_initialize();

    context = cmt_create();
    TEST_CHECK(context != NULL);

    TEST_CHECK(create_test_metric_with_zero_threshold(context,
                                                      cfl_time_now(),
                                                      0.5,
                                                      4,
                                                      42.25,
                                                      22) != NULL);

    encoded_text = cmt_encode_text_create(context);
    TEST_CHECK(encoded_text != NULL);
    if (encoded_text != NULL) {
        printf("\n========== EXP HIST NON-ZERO ZERO_THRESHOLD TEXT ==========\n%s\n",
               encoded_text);
        TEST_CHECK(strstr(encoded_text, "zero_threshold=0.5") != NULL);
    }
    cmt_encode_text_destroy(encoded_text);

    encoded_prometheus = cmt_encode_prometheus_create(context, CMT_TRUE);
    TEST_CHECK(encoded_prometheus != NULL);
    if (encoded_prometheus != NULL) {
        double last_finite_bucket;
        double plus_inf_bucket;

        printf("\n========== EXP HIST NON-ZERO ZERO_THRESHOLD PROMETHEUS ==========\n%s\n",
               encoded_prometheus);

        result = assert_prometheus_bucket_monotonicity(encoded_prometheus,
                                                       &last_finite_bucket,
                                                       &plus_inf_bucket);
        TEST_CHECK(result == 0);
        if (result == 0) {
            TEST_CHECK(plus_inf_bucket == 22.0);
            TEST_CHECK(last_finite_bucket <= plus_inf_bucket);
        }

        result = get_prometheus_bucket_value(encoded_prometheus, "0.0", &bucket_value);
        TEST_CHECK(result == 0);
        if (result == 0) {
            TEST_CHECK(bucket_value == 7.0);
        }

        result = get_prometheus_bucket_value(encoded_prometheus, "+Inf", &bucket_value);
        TEST_CHECK(result == 0);
        if (result == 0) {
            TEST_CHECK(bucket_value == 22.0);
        }

        TEST_CHECK(strstr(encoded_prometheus, "cm_native_exp_hist_sum{endpoint=\"api\"} 42.25 ") != NULL);
    }
    cmt_encode_prometheus_destroy(encoded_prometheus);

    encoded_influx = cmt_encode_influx_create(context);
    TEST_CHECK(encoded_influx != NULL);
    if (encoded_influx != NULL) {
        printf("\n========== EXP HIST NON-ZERO ZERO_THRESHOLD INFLUX ==========\n%s\n",
               encoded_influx);
        TEST_CHECK(strstr(encoded_influx, "sum=42.25") != NULL);
        TEST_CHECK(strstr(encoded_influx, "+Inf=22") != NULL);
    }
    cmt_encode_influx_destroy(encoded_influx);

    encoded_splunk_hec = cmt_encode_splunk_hec_create(context,
                                                      "localhost", "test-index",
                                                      NULL, NULL);
    TEST_CHECK(encoded_splunk_hec != NULL);
    if (encoded_splunk_hec != NULL) {
        printf("\n========== EXP HIST NON-ZERO ZERO_THRESHOLD SPLUNK HEC ==========\n");
        print_splunk_payload(encoded_splunk_hec);
        printf("\n");
        TEST_CHECK(strstr(encoded_splunk_hec, "\"metric_name:native.exp_hist_sum\":42.25") != NULL);
        TEST_CHECK(strstr(encoded_splunk_hec, "\"metric_name:native.exp_hist_count\":22.0") != NULL);
    }
    cmt_encode_splunk_hec_destroy(encoded_splunk_hec);

    cmt_destroy(context);
}

void test_exp_histogram_cat_filter_smoke()
{
    int result;
    struct cmt *source;
    struct cmt *cat_target;
    struct cmt *filter_target;

    cmt_initialize();

    source = cmt_create();
    cat_target = cmt_create();
    filter_target = cmt_create();

    TEST_CHECK(source != NULL);
    TEST_CHECK(cat_target != NULL);
    TEST_CHECK(filter_target != NULL);
    TEST_CHECK(create_test_metric(source, cfl_time_now()) != NULL);

    result = cmt_cat(cat_target, source);
    TEST_CHECK(result == 0);
    TEST_CHECK(cfl_list_size(&cat_target->exp_histograms) == 1);
    printf("\n========== EXP HIST CAT ==========\n");
    printf("exp_histograms=%d\n\n", cfl_list_size(&cat_target->exp_histograms));

    result = cmt_filter(filter_target, source, "cm_native_exp", NULL,
                        NULL, NULL, CMT_FILTER_PREFIX);
    TEST_CHECK(result == 0);
    TEST_CHECK(cfl_list_size(&filter_target->exp_histograms) == 1);
    printf("========== EXP HIST FILTER ==========\n");
    printf("exp_histograms=%d\n\n", cfl_list_size(&filter_target->exp_histograms));

    cmt_destroy(source);
    cmt_destroy(cat_target);
    cmt_destroy(filter_target);
}

void test_exp_histogram_cat_sparse_merge()
{
    int result;
    uint64_t positive_a[3] = {3, 5, 7};
    uint64_t negative_a[2] = {2, 1};
    uint64_t positive_b[2] = {10, 11};
    uint64_t negative_b[3] = {4, 5, 6};
    struct cmt *source_a;
    struct cmt *source_b;
    struct cmt *target;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_metric *metric;

    cmt_initialize();

    source_a = cmt_create();
    source_b = cmt_create();
    target = cmt_create();

    TEST_CHECK(source_a != NULL);
    TEST_CHECK(source_b != NULL);
    TEST_CHECK(target != NULL);

    TEST_CHECK(create_test_metric_custom(source_a, cfl_time_now(),
                                         2, 4, 0.0,
                                         -2, 3, positive_a,
                                         -1, 2, negative_a,
                                         CMT_TRUE, 42.25, 22) != NULL);
    TEST_CHECK(create_test_metric_custom(source_b, cfl_time_now(),
                                         2, 1, 0.0,
                                         -1, 2, positive_b,
                                         -3, 3, negative_b,
                                         CMT_TRUE, 10.5, 31) != NULL);

    result = cmt_cat(target, source_a);
    TEST_CHECK(result == 0);
    result = cmt_cat(target, source_b);
    TEST_CHECK(result == 0);

    TEST_CHECK(cfl_list_size(&target->exp_histograms) == 1);

    exp_histogram = cfl_list_entry_first(&target->exp_histograms,
                                         struct cmt_exp_histogram, _head);
    metric = cmt_map_metric_get(&exp_histogram->opts, exp_histogram->map,
                                1, (char *[]) {"api"}, CMT_FALSE);
    TEST_CHECK(metric != NULL);

    if (metric != NULL) {
        TEST_CHECK(metric->exp_hist_scale == 2);
        TEST_CHECK(metric->exp_hist_zero_threshold == 0.0);
        TEST_CHECK(metric->exp_hist_zero_count == 5);
        TEST_CHECK(metric->exp_hist_count == 53);
        TEST_CHECK(metric->exp_hist_sum_set == CMT_TRUE);
        TEST_CHECK(fabs(cmt_math_uint64_to_d64(metric->exp_hist_sum) - 52.75) < 0.00001);

        TEST_CHECK(metric->exp_hist_positive_offset == -2);
        TEST_CHECK(metric->exp_hist_positive_count == 3);
        TEST_CHECK(metric->exp_hist_positive_buckets != NULL);
        if (metric->exp_hist_positive_buckets != NULL) {
            TEST_CHECK(metric->exp_hist_positive_buckets[0] == 3);
            TEST_CHECK(metric->exp_hist_positive_buckets[1] == 15);
            TEST_CHECK(metric->exp_hist_positive_buckets[2] == 18);
        }

        TEST_CHECK(metric->exp_hist_negative_offset == -3);
        TEST_CHECK(metric->exp_hist_negative_count == 4);
        TEST_CHECK(metric->exp_hist_negative_buckets != NULL);
        if (metric->exp_hist_negative_buckets != NULL) {
            TEST_CHECK(metric->exp_hist_negative_buckets[0] == 4);
            TEST_CHECK(metric->exp_hist_negative_buckets[1] == 5);
            TEST_CHECK(metric->exp_hist_negative_buckets[2] == 8);
            TEST_CHECK(metric->exp_hist_negative_buckets[3] == 1);
        }
    }

    cmt_destroy(source_a);
    cmt_destroy(source_b);
    cmt_destroy(target);
}

void test_exp_histogram_prometheus_no_sum()
{
    uint64_t positive[3] = {3, 5, 7};
    uint64_t negative[2] = {2, 1};
    cfl_sds_t encoded_prometheus;
    struct cmt *context;

    cmt_initialize();

    context = cmt_create();
    TEST_CHECK(context != NULL);

    TEST_CHECK(create_test_metric_custom(context, cfl_time_now(),
                                         2, 11, 0.0,
                                         -2, 3, positive,
                                         -1, 2, negative,
                                         CMT_FALSE, 123.75, 29) != NULL);

    encoded_prometheus = cmt_encode_prometheus_create(context, CMT_TRUE);
    TEST_CHECK(encoded_prometheus != NULL);
    if (encoded_prometheus != NULL) {
        TEST_CHECK(strstr(encoded_prometheus, "cm_native_exp_hist_count{endpoint=\"api\"} 29 ") != NULL);
        TEST_CHECK(strstr(encoded_prometheus, "cm_native_exp_hist_sum{endpoint=\"api\"}") == NULL);
    }
    cmt_encode_prometheus_destroy(encoded_prometheus);

    cmt_destroy(context);
}

void test_exp_histogram_remote_write_no_sum()
{
    uint64_t positive[3] = {3, 5, 7};
    uint64_t negative[2] = {2, 1};
    cfl_sds_t encoded_remote_write;
    struct cmt *context;
    Prometheus__WriteRequest *request;

    cmt_initialize();

    context = cmt_create();
    TEST_CHECK(context != NULL);
    if (context == NULL) {
        return;
    }

    TEST_CHECK(create_test_metric_custom(context, cfl_time_now(),
                                         2, 11, 0.0,
                                         -2, 3, positive,
                                         -1, 2, negative,
                                         CMT_FALSE, 123.75, 29) != NULL);

    encoded_remote_write = cmt_encode_prometheus_remote_write_create(context);
    TEST_CHECK(encoded_remote_write != NULL);
    if (encoded_remote_write != NULL) {
        request = prometheus__write_request__unpack(NULL,
                                                    cfl_sds_len(encoded_remote_write),
                                                    (uint8_t *) encoded_remote_write);
        TEST_CHECK(request != NULL);
        if (request != NULL) {
            TEST_CHECK(remote_write_contains_metric_name(request, "cm_native_exp_hist_count") == CMT_TRUE);
            TEST_CHECK(remote_write_contains_metric_name(request, "cm_native_exp_hist_sum") == CMT_FALSE);
            TEST_CHECK(remote_write_contains_metric_name(request, "cm_native_exp_hist_bucket") == CMT_TRUE);
            prometheus__write_request__free_unpacked(request, NULL);
        }
    }

    cmt_encode_prometheus_remote_write_destroy(encoded_remote_write);
    cmt_destroy(context);
}

TEST_LIST = {
    {"exp_histogram_msgpack_roundtrip", test_exp_histogram_msgpack_roundtrip},
    {"exp_histogram_encoder_smoke",     test_exp_histogram_encoder_smoke},
    {"exp_histogram_nonzero_zero_threshold", test_exp_histogram_nonzero_zero_threshold},
    {"exp_histogram_cat_filter_smoke",  test_exp_histogram_cat_filter_smoke},
    {"exp_histogram_cat_sparse_merge",  test_exp_histogram_cat_sparse_merge},
    {"exp_histogram_prometheus_no_sum", test_exp_histogram_prometheus_no_sum},
    {"exp_histogram_remote_write_no_sum", test_exp_histogram_remote_write_no_sum},
    { 0 }
};
