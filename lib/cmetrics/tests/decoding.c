/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_encode_prometheus.h>
#include <cmetrics/cmt_encode_prometheus_remote_write.h>
#include <cmetrics/cmt_decode_prometheus_remote_write.h>
#include <cmetrics/cmt_decode_statsd.h>

#include "cmt_tests.h"

static cfl_sds_t generate_remote_write_payload(char *extra_label_name,
                                               char *extra_label_value)
{
    Prometheus__WriteRequest request;
    Prometheus__TimeSeries time_series;
    Prometheus__Label name_label;
    Prometheus__Label extra_label;
    Prometheus__Sample sample;
    Prometheus__TimeSeries *time_series_list[1];
    Prometheus__Label *label_list[2];
    Prometheus__Sample *sample_list[1];
    size_t payload_size;
    unsigned char *packed_payload;
    cfl_sds_t payload;

    prometheus__write_request__init(&request);
    prometheus__time_series__init(&time_series);
    prometheus__label__init(&name_label);
    prometheus__label__init(&extra_label);
    prometheus__sample__init(&sample);

    name_label.name = "__name__";
    name_label.value = "rw_metric";
    extra_label.name = extra_label_name;
    extra_label.value = extra_label_value;

    label_list[0] = &name_label;
    label_list[1] = &extra_label;
    time_series.n_labels = 2;
    time_series.labels = label_list;

    sample.value = 1.0;
    sample.timestamp = 123;
    sample_list[0] = &sample;
    time_series.n_samples = 1;
    time_series.samples = sample_list;

    time_series_list[0] = &time_series;
    request.n_timeseries = 1;
    request.timeseries = time_series_list;

    payload_size = prometheus__write_request__get_packed_size(&request);
    packed_payload = calloc(1, payload_size);
    if (packed_payload == NULL) {
        return NULL;
    }

    prometheus__write_request__pack(&request, packed_payload);
    payload = cfl_sds_create_len((char *) packed_payload, payload_size);
    free(packed_payload);

    return payload;
}

static cfl_sds_t generate_remote_write_out_of_order_metadata_payload()
{
    Prometheus__WriteRequest request;
    Prometheus__MetricMetadata metadata;
    Prometheus__TimeSeries gauge_series;
    Prometheus__TimeSeries counter_series;
    Prometheus__Label gauge_name_label;
    Prometheus__Label counter_name_label;
    Prometheus__Sample gauge_sample;
    Prometheus__Sample counter_sample;
    Prometheus__MetricMetadata *metadata_list[1];
    Prometheus__TimeSeries *time_series_list[2];
    Prometheus__Label *gauge_label_list[1];
    Prometheus__Label *counter_label_list[1];
    Prometheus__Sample *gauge_sample_list[1];
    Prometheus__Sample *counter_sample_list[1];
    size_t payload_size;
    unsigned char *packed_payload;
    cfl_sds_t payload;

    prometheus__write_request__init(&request);
    prometheus__metric_metadata__init(&metadata);
    prometheus__time_series__init(&gauge_series);
    prometheus__time_series__init(&counter_series);
    prometheus__label__init(&gauge_name_label);
    prometheus__label__init(&counter_name_label);
    prometheus__sample__init(&gauge_sample);
    prometheus__sample__init(&counter_sample);

    metadata.type = PROMETHEUS__METRIC_METADATA__METRIC_TYPE__COUNTER;
    metadata.metric_family_name = "rw_counter";
    metadata.help = "remote write counter";
    metadata_list[0] = &metadata;
    request.n_metadata = 1;
    request.metadata = metadata_list;

    gauge_name_label.name = "__name__";
    gauge_name_label.value = "rw_gauge";
    gauge_label_list[0] = &gauge_name_label;
    gauge_series.n_labels = 1;
    gauge_series.labels = gauge_label_list;
    gauge_sample.value = 1.0;
    gauge_sample.timestamp = 123;
    gauge_sample_list[0] = &gauge_sample;
    gauge_series.n_samples = 1;
    gauge_series.samples = gauge_sample_list;

    counter_name_label.name = "__name__";
    counter_name_label.value = "rw_counter";
    counter_label_list[0] = &counter_name_label;
    counter_series.n_labels = 1;
    counter_series.labels = counter_label_list;
    counter_sample.value = 2.0;
    counter_sample.timestamp = 124;
    counter_sample_list[0] = &counter_sample;
    counter_series.n_samples = 1;
    counter_series.samples = counter_sample_list;

    time_series_list[0] = &gauge_series;
    time_series_list[1] = &counter_series;
    request.n_timeseries = 2;
    request.timeseries = time_series_list;

    payload_size = prometheus__write_request__get_packed_size(&request);
    packed_payload = calloc(1, payload_size);
    if (packed_payload == NULL) {
        return NULL;
    }

    prometheus__write_request__pack(&request, packed_payload);
    payload = cfl_sds_create_len((char *) packed_payload, payload_size);
    free(packed_payload);

    return payload;
}

static cfl_sds_t generate_remote_write_sparse_metadata_histogram_payload()
{
    Prometheus__WriteRequest request;
    Prometheus__MetricMetadata metadata;
    Prometheus__TimeSeries gauge_series;
    Prometheus__TimeSeries histogram_series;
    Prometheus__Label gauge_name_label;
    Prometheus__Label histogram_name_label;
    Prometheus__Sample sample;
    Prometheus__Histogram histogram;
    Prometheus__BucketSpan span;
    Prometheus__MetricMetadata *metadata_list[1];
    Prometheus__TimeSeries *time_series_list[2];
    Prometheus__Label *gauge_label_list[1];
    Prometheus__Label *histogram_label_list[1];
    Prometheus__Sample *sample_list[1];
    Prometheus__Histogram *histogram_list[1];
    Prometheus__BucketSpan *span_list[1];
    double positive_counts[3] = {1.0, 2.0, 3.0};
    size_t payload_size;
    unsigned char *packed_payload;
    cfl_sds_t payload;

    prometheus__write_request__init(&request);
    prometheus__metric_metadata__init(&metadata);
    prometheus__time_series__init(&gauge_series);
    prometheus__time_series__init(&histogram_series);
    prometheus__label__init(&gauge_name_label);
    prometheus__label__init(&histogram_name_label);
    prometheus__sample__init(&sample);
    prometheus__histogram__init(&histogram);
    prometheus__bucket_span__init(&span);

    metadata.type = PROMETHEUS__METRIC_METADATA__METRIC_TYPE__GAUGE;
    metadata.metric_family_name = "rw_gauge";
    metadata.help = "remote write gauge";
    metadata_list[0] = &metadata;
    request.n_metadata = 1;
    request.metadata = metadata_list;

    gauge_name_label.name = "__name__";
    gauge_name_label.value = "rw_gauge";
    gauge_label_list[0] = &gauge_name_label;
    gauge_series.n_labels = 1;
    gauge_series.labels = gauge_label_list;

    sample.value = 1.0;
    sample.timestamp = 123;
    sample_list[0] = &sample;
    gauge_series.n_samples = 1;
    gauge_series.samples = sample_list;

    histogram_name_label.name = "__name__";
    histogram_name_label.value = "rw_native_hist";
    histogram_label_list[0] = &histogram_name_label;
    histogram_series.n_labels = 1;
    histogram_series.labels = histogram_label_list;

    span.offset = 1;
    span.length = 3;
    span_list[0] = &span;
    histogram.n_positive_spans = 1;
    histogram.positive_spans = span_list;
    histogram.n_positive_counts = 3;
    histogram.positive_counts = positive_counts;
    histogram.sum = 6.0;
    histogram.timestamp = 456;
    histogram.count_case = PROMETHEUS__HISTOGRAM__COUNT_COUNT_INT;
    histogram.count_int = 6;

    histogram_list[0] = &histogram;
    histogram_series.n_histograms = 1;
    histogram_series.histograms = histogram_list;

    time_series_list[0] = &gauge_series;
    time_series_list[1] = &histogram_series;
    request.n_timeseries = 2;
    request.timeseries = time_series_list;

    payload_size = prometheus__write_request__get_packed_size(&request);
    packed_payload = calloc(1, payload_size);
    if (packed_payload == NULL) {
        return NULL;
    }

    prometheus__write_request__pack(&request, packed_payload);
    payload = cfl_sds_create_len((char *) packed_payload, payload_size);
    free(packed_payload);

    return payload;
}


void test_prometheus_remote_write()
{
    int ret;
    struct cmt *decoded_context = NULL;
    cfl_sds_t payload = read_file(CMT_TESTS_DATA_PATH "/remote_write_dump_originally_from_node_exporter.bin");

    cmt_initialize();

    ret = cmt_decode_prometheus_remote_write_create(&decoded_context, payload, cfl_sds_len(payload));
    TEST_CHECK(ret == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS);

    if (decoded_context != NULL) {
        cmt_decode_prometheus_remote_write_destroy(decoded_context);
        decoded_context = NULL;
    }

    cfl_sds_destroy(payload);
}

void test_prometheus_remote_write_missing_label_name_rejected()
{
    int ret;
    struct cmt *decoded_context = NULL;
    cfl_sds_t payload;

    cmt_initialize();

    payload = generate_remote_write_payload(NULL, "value");
    TEST_CHECK(payload != NULL);
    if (payload != NULL) {
        ret = cmt_decode_prometheus_remote_write_create(&decoded_context,
                                                        payload,
                                                        cfl_sds_len(payload));
        TEST_CHECK(ret != CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS);
        if (decoded_context != NULL) {
            cmt_decode_prometheus_remote_write_destroy(decoded_context);
            decoded_context = NULL;
        }
        cfl_sds_destroy(payload);
    }
}

void test_prometheus_remote_write_missing_label_value_no_crash()
{
    int ret;
    struct cmt *decoded_context = NULL;
    cfl_sds_t payload;
    cfl_sds_t encoded_payload;

    cmt_initialize();

    payload = generate_remote_write_payload("zone", NULL);
    TEST_CHECK(payload != NULL);
    if (payload != NULL) {
        ret = cmt_decode_prometheus_remote_write_create(&decoded_context,
                                                        payload,
                                                        cfl_sds_len(payload));
        TEST_CHECK(ret == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS);
        if (ret == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            encoded_payload = cmt_encode_prometheus_remote_write_create(decoded_context);
            TEST_CHECK(encoded_payload != NULL);
            if (encoded_payload != NULL) {
                cmt_encode_prometheus_remote_write_destroy(encoded_payload);
            }
        }
        if (decoded_context != NULL) {
            cmt_decode_prometheus_remote_write_destroy(decoded_context);
            decoded_context = NULL;
        }
        cfl_sds_destroy(payload);
    }
}

void test_prometheus_remote_write_sparse_metadata_histogram()
{
    int ret;
    struct cmt_metric *metric;
    struct cmt_histogram *histogram;
    struct cmt *decoded_context = NULL;
    cfl_sds_t payload;

    cmt_initialize();

    payload = generate_remote_write_sparse_metadata_histogram_payload();
    TEST_CHECK(payload != NULL);
    if (payload != NULL) {
        ret = cmt_decode_prometheus_remote_write_create(&decoded_context,
                                                        payload,
                                                        cfl_sds_len(payload));
        TEST_CHECK(ret == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS);
        if (ret == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            TEST_CHECK(cfl_list_size(&decoded_context->gauges) == 1);
            TEST_CHECK(cfl_list_size(&decoded_context->histograms) == 1);

            histogram = cfl_list_entry_first(&decoded_context->histograms,
                                             struct cmt_histogram, _head);
            TEST_CHECK(histogram != NULL);
            if (histogram != NULL) {
                TEST_CHECK(histogram->buckets != NULL);
                if (histogram->buckets != NULL) {
                    TEST_CHECK(histogram->buckets->count == 3);
                    TEST_CHECK(histogram->buckets->upper_bounds[0] == 1.0);
                    TEST_CHECK(histogram->buckets->upper_bounds[1] == 2.0);
                    TEST_CHECK(histogram->buckets->upper_bounds[2] == 3.0);
                }

                TEST_CHECK(cfl_list_size(&histogram->map->metrics) == 1);
                metric = cfl_list_entry_first(&histogram->map->metrics,
                                              struct cmt_metric, _head);
                TEST_CHECK(metric != NULL);
                if (metric != NULL) {
                    TEST_CHECK(metric->hist_buckets != NULL);
                    if (metric->hist_buckets != NULL) {
                        TEST_CHECK(cmt_metric_hist_get_value(metric, 0) == 1);
                        TEST_CHECK(cmt_metric_hist_get_value(metric, 1) == 2);
                        TEST_CHECK(cmt_metric_hist_get_value(metric, 2) == 3);
                    }
                    TEST_CHECK(cmt_metric_hist_get_count_value(metric) == 6);
                }
            }
        }
        if (decoded_context != NULL) {
            cmt_decode_prometheus_remote_write_destroy(decoded_context);
            decoded_context = NULL;
        }
        cfl_sds_destroy(payload);
    }
}

void test_prometheus_remote_write_metadata_matched_by_name()
{
    int ret;
    struct cmt *decoded_context = NULL;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    cfl_sds_t payload;

    cmt_initialize();

    payload = generate_remote_write_out_of_order_metadata_payload();
    TEST_CHECK(payload != NULL);
    if (payload != NULL) {
        ret = cmt_decode_prometheus_remote_write_create(&decoded_context,
                                                        payload,
                                                        cfl_sds_len(payload));
        TEST_CHECK(ret == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS);
        if (ret == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            TEST_CHECK(cfl_list_size(&decoded_context->gauges) == 1);
            TEST_CHECK(cfl_list_size(&decoded_context->counters) == 1);

            gauge = cfl_list_entry_first(&decoded_context->gauges,
                                         struct cmt_gauge, _head);
            counter = cfl_list_entry_first(&decoded_context->counters,
                                           struct cmt_counter, _head);
            TEST_CHECK(gauge != NULL);
            TEST_CHECK(counter != NULL);
            if (gauge != NULL) {
                TEST_CHECK(strcmp(gauge->opts.name, "rw_gauge") == 0);
            }
            if (counter != NULL) {
                TEST_CHECK(strcmp(counter->opts.name, "rw_counter") == 0);
            }
        }
        if (decoded_context != NULL) {
            cmt_decode_prometheus_remote_write_destroy(decoded_context);
            decoded_context = NULL;
        }
        cfl_sds_destroy(payload);
    }
}

void test_statsd()
{
    int ret;
    struct cmt *decoded_context;
    cfl_sds_t payload = read_file(CMT_TESTS_DATA_PATH "/statsd_payload.txt");
    size_t len = 0;
    cfl_sds_t text = NULL;
    int flags = 0;

    /* For strtok_r, fill the last byte as \0. */
    len = cfl_sds_len(payload);
    cfl_sds_set_len(payload, len + 1);
    payload[len] = '\0';

    cmt_initialize();

    flags |= CMT_DECODE_STATSD_GAUGE_OBSERVER;

    ret = cmt_decode_statsd_create(&decoded_context, payload, cfl_sds_len(payload), flags);
    TEST_CHECK(ret == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS);
    text = cmt_encode_prometheus_create(decoded_context, CMT_FALSE);

    printf("%s\n", text);
    cmt_encode_prometheus_destroy(text);

    cmt_decode_statsd_destroy(decoded_context);

    cfl_sds_destroy(payload);
}


TEST_LIST = {
    {"prometheus_remote_write", test_prometheus_remote_write},
    {"prometheus_remote_write_missing_label_name_rejected", test_prometheus_remote_write_missing_label_name_rejected},
    {"prometheus_remote_write_missing_label_value_no_crash", test_prometheus_remote_write_missing_label_value_no_crash},
    {"prometheus_remote_write_sparse_metadata_histogram", test_prometheus_remote_write_sparse_metadata_histogram},
    {"prometheus_remote_write_metadata_matched_by_name", test_prometheus_remote_write_metadata_matched_by_name},
    {"statsd", test_statsd},
    { 0 }
};
