/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2024 The CMetrics Authors
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
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_decode_prometheus_remote_write.h>

static void *__cmt_allocator_alloc(void *data, size_t size) {
    return malloc(size);
}
static void __cmt_allocator_free(void *data, void *ptr) {
    free(ptr);
}

static ProtobufCAllocator __cmt_allocator = {
  .alloc = __cmt_allocator_alloc,
  .free = __cmt_allocator_free,
  .allocator_data = NULL
};

#define cmt_system_allocator __cmt_allocator

static char *cmt_metric_name_from_labels(Prometheus__TimeSeries *ts)
{
    int i;
    int count;

    count = ts->n_labels;
    for (i = 0; i < count; i++) {
        if (strncmp("__name__", ts->labels[i]->name, 8) == 0) {
            return strdup(ts->labels[i]->value);
        }
    }

    return NULL;
}

static struct cmt_map_label *create_map_label(char *caption, size_t length)
{
    struct cmt_map_label *map_label;

    map_label = calloc(1, sizeof(struct cmt_map_label));
    if (!map_label) {
        return NULL;
    }

    if (map_label != NULL) {
        if (caption != NULL) {
            if (length == 0) {
                length = strlen(caption);
            }

            map_label->name = cfl_sds_create_len(caption, length);

            if (map_label->name == NULL) {
                cmt_errno();

                free(map_label);

                map_label = NULL;
            }
        }
    }

    return map_label;
}

static int append_new_map_label_key(struct cmt_map *map, char *name)
{
    struct cmt_map_label *label;

    label = create_map_label(name, 0);

    if (label == NULL) {
        return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    cfl_list_add(&label->_head, &map->label_keys);
    map->label_count++;

    return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;
}

static int append_new_metric_label_value(struct cmt_metric *metric, char *name, size_t length)
{
    struct cmt_map_label *label;

    label = create_map_label(name, length);

    if (label == NULL) {
        return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    cfl_list_add(&label->_head, &metric->labels);

    return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;
}

static int decode_labels(struct cmt *cmt,
                         struct cmt_map *map,
                         struct cmt_metric *metric,
                         size_t n_labels,
                         Prometheus__Label **labels)
{
    void                 **value_index_list;
    size_t                 prom_label_index;
    size_t                 map_label_index;
    size_t                 map_label_count;
    struct cfl_list       *label_iterator;
    struct cmt_map_label  *current_label;
    size_t                 label_index;
    int                    label_found;
    Prometheus__Label     *label;
    int                    result;

    result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    if (n_labels == 0) {
        return result;
    }

    if (n_labels > 127) {
        return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_INVALID_ARGUMENT_ERROR;
    }

    value_index_list = calloc(128, sizeof(void *));

    if (value_index_list == NULL) {
        return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    for (prom_label_index = 0;
         result == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS &&
         prom_label_index < n_labels;
         prom_label_index++) {

        label = labels[prom_label_index];

        label_found = CMT_FALSE;
        label_index = 0;

        cfl_list_foreach(label_iterator, &map->label_keys) {
            current_label = cfl_list_entry(label_iterator, struct cmt_map_label, _head);

            if (strcmp(current_label->name, label->name) == 0) {
                label_found = CMT_TRUE;

                break;
            }

            label_index++;
        }

        if (label_found == CMT_FALSE) {
            result = append_new_map_label_key(map, label->name);
        }

        if (result == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
            value_index_list[label_index] = (void *) label;
        }
    }

    map_label_count = cfl_list_size(&map->label_keys);

    for (map_label_index = 0 ;
         result == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS &&
         map_label_index < map_label_count ;
         map_label_index++) {

        if (value_index_list[map_label_index] != NULL) {
            label = (Prometheus__Label *) value_index_list[map_label_index];
            result = append_new_metric_label_value(metric, label->value, 0);
        }
    }

    free(value_index_list);

    return result;
}

static int decode_numerical_samples(struct cmt *cmt,
                                    struct cmt_map *map,
                                    size_t n_samples,
                                    Prometheus__Sample *sample,
                                    size_t n_labels,
                                    Prometheus__Label **labels)
{
    int                static_metric_detected;
    struct cmt_metric *metric;
    int                result;

    static_metric_detected = CMT_FALSE;

    result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    if (n_samples == 0) {
        if (map->metric_static_set == CMT_FALSE) {
            static_metric_detected = CMT_TRUE;
        }
    }

    if (static_metric_detected == CMT_FALSE) {
        metric = calloc(1, sizeof(struct cmt_metric));

        if (metric == NULL) {
            return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
        }

        cfl_list_init(&metric->labels);

        result = decode_labels(cmt,
                               map,
                               metric,
                               n_labels,
                               labels);

        if (result) {
            destroy_label_list(&metric->labels);

            free(metric);
        }
        else {
            cfl_list_add(&metric->_head, &map->metrics);
        }
    }
    else {
        metric = &map->metric;

        map->metric_static_set = CMT_TRUE;
    }

    if (result == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        cmt_metric_set(metric, sample->timestamp * 1000000, sample->value);
    }

    return result;
}

static int decode_numerical_time_series(struct cmt *cmt,
                                        struct cmt_map *map,
                                        size_t ts_count,
                                        Prometheus__TimeSeries *ts)
{
    size_t              index;
    int                 result;
    Prometheus__Sample *sample = NULL;

    result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    for (index = 0; index < ts->n_samples; index++) {
        sample = ts->samples[index];
        result = decode_numerical_samples(cmt, map,
                                          ts->n_samples, sample,
                                          ts->n_labels, ts->labels);
    }

    return result;
}

static int decode_counter_entry(struct cmt *cmt,
                                void *instance,
                                Prometheus__TimeSeries *ts)
{
    struct cmt_counter *counter;
    int                 result;

    result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    counter = (struct cmt_counter *) instance;

    counter->map->metric_static_set = 0;

    result = decode_numerical_time_series(cmt,
                                          counter->map,
                                          ts->n_samples,
                                          ts);

    return result;
}

static int decode_gauge_entry(struct cmt *cmt,
                              void *instance,
                              Prometheus__TimeSeries *ts)
{
    struct cmt_gauge *gauge;
    int               result;

    result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    gauge = (struct cmt_gauge *) instance;

    gauge->map->metric_static_set = 0;

    result = decode_numerical_time_series(cmt,
                                          gauge->map,
                                          ts->n_samples,
                                          ts);

    return result;
}

static int decode_untyped_entry(struct cmt *cmt,
                                void *instance,
                                Prometheus__TimeSeries *ts)
{
    struct cmt_untyped *untyped;
    int                 result;

    result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    untyped = (struct cmt_untyped *) instance;

    untyped->map->metric_static_set = 0;

    result = decode_numerical_time_series(cmt,
                                          untyped->map,
                                          ts->n_samples,
                                          ts);

    return result;
}

static int decode_histogram_points(struct cmt *cmt,
                                   struct cmt_map *map,
                                   size_t n_histograms,
                                   Prometheus__Histogram *hist,
                                   size_t n_labels,
                                   Prometheus__Label **labels)
{
    int                   i;
    int                   static_metric_detected;
    struct cmt_histogram *histogram;
    struct cmt_metric    *metric;
    int                   result;
    double               *spans;

    static_metric_detected = CMT_FALSE;

    result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    histogram = (struct cmt_histogram *) map->parent;

    if (histogram->buckets == NULL) {
        if (hist->n_negative_spans > 0) {
            spans = calloc(1, sizeof(double) * hist->n_negative_spans);

            for (i = 0; i < hist->n_negative_spans; i++) {
                spans[i] = (double) hist->negative_spans[i]->offset;
            }
            histogram->buckets = cmt_histogram_buckets_create_size(spans,
                                                                   hist->n_negative_spans);
            free(spans);
        }
        else if (hist->n_positive_spans > 0) {
            spans = calloc(1, sizeof(double) * hist->n_positive_spans);

            for (i = 0; i < hist->n_positive_spans; i++) {
                spans[i] = (double) hist->positive_spans[i]->offset;
            }
            histogram->buckets = cmt_histogram_buckets_create_size(spans,
                                                                   hist->n_positive_spans);
            free(spans);
        }

        if (histogram->buckets == NULL) {
            return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
        }
    }

    if (n_histograms == 0) {
        if (map->metric_static_set == CMT_FALSE) {
            static_metric_detected = CMT_TRUE;
        }
    }

    if (static_metric_detected == CMT_FALSE) {
        metric = calloc(1, sizeof(struct cmt_metric));

        if (metric == NULL) {
            return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
        }

        cfl_list_init(&metric->labels);

        result = decode_labels(cmt,
                               map,
                               metric,
                               n_labels,
                               labels);

        if (result) {
            destroy_label_list(&metric->labels);

            free(metric);

            return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_DECODE_ERROR;
        }
        else {
            cfl_list_add(&metric->_head, &map->metrics);
        }
    }
    else {
        metric = &map->metric;

        map->metric_static_set = CMT_TRUE;
    }

    if (result == CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        if (hist->n_negative_spans > 0) {
            for (i = 0; i < hist->n_negative_counts; i++) {
                cmt_metric_hist_set(metric, hist->timestamp * 1000000,
                                    i, hist->negative_counts[i]);
            }
        }
        else if (hist->n_positive_spans > 0) {
            for (i = 0; i < hist->n_positive_counts; i++) {
                cmt_metric_hist_set(metric, hist->timestamp * 1000000,
                                    i, hist->positive_counts[i]);
            }
        }
        else {
            if (static_metric_detected == CMT_FALSE) {
                destroy_label_list(&metric->labels);

                cfl_list_del(&metric->_head);

                free(metric);
            }

            return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_DECODE_ERROR;
        }
    }

    cmt_metric_hist_sum_set(metric, hist->timestamp * 1000000, hist->sum);
    if (hist->count_case == PROMETHEUS__HISTOGRAM__COUNT_COUNT_INT) {
        cmt_metric_hist_count_set(metric, hist->timestamp * 1000000,
                                  hist->count_int);
    }
    else if (hist->count_case == PROMETHEUS__HISTOGRAM__COUNT_COUNT_FLOAT) {
        cmt_metric_hist_count_set(metric, hist->timestamp * 1000000,
                                  hist->count_float);
    }
    else {
        if (static_metric_detected == CMT_FALSE) {
            destroy_label_list(&metric->labels);

            cfl_list_del(&metric->_head);

            free(metric);
        }

        return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_DECODE_ERROR;
    }

    return result;
}

static int decode_histogram_time_series(struct cmt *cmt,
                                        struct cmt_map *map,
                                        size_t hist_count,
                                        Prometheus__TimeSeries *ts)
{
    size_t index;
    int    result;
    Prometheus__Histogram *histogram = NULL;

    result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    for (index = 0; result == 0 && index < hist_count; index++) {
        histogram = ts->histograms[index];
        result = decode_histogram_points(cmt, map,
                                         ts->n_histograms,
                                         histogram,
                                         ts->n_labels,
                                         ts->labels);
    }

    return result;
}

static int decode_histogram_entry(struct cmt *cmt,
                                  void *instance,
                                  Prometheus__TimeSeries *ts)
{
    struct cmt_histogram *histogram;
    int                   result;

    result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    histogram = (struct cmt_histogram *) instance;

    histogram->map->metric_static_set = 0;

    result = decode_histogram_time_series(cmt,
                                          histogram->map,
                                          ts->n_histograms,
                                          ts);

    return result;
}

static int decode_metrics_entry(struct cmt *cmt,
                                Prometheus__WriteRequest *write)
{
    int   i;
    char *metric_name = NULL;
    char *metric_subsystem   = NULL;
    char *metric_namespace   = NULL;
    char *metric_description = NULL;
    void *instance;
    int   result;
    int   ts_count = 0;
    int   hist_count = 0;
    int   meta_count = 0;
    Prometheus__MetricMetadata             *metadata = NULL;
    Prometheus__MetricMetadata__MetricType  type;
    Prometheus__TimeSeries                 *ts = NULL;

    result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS;

    ts_count = write->n_timeseries;
    for (i = 0; i < ts_count; i++) {
        ts = write->timeseries[i];
        meta_count = write->n_metadata;
        hist_count = ts->n_histograms;
        if (meta_count > 0) {
            metadata = write->metadata[i];
        }
        if (metadata == NULL) {
            type = PROMETHEUS__METRIC_METADATA__METRIC_TYPE__GAUGE;
            metric_description = "-";
        }
        else if (hist_count > 0) {
            type = PROMETHEUS__METRIC_METADATA__METRIC_TYPE__HISTOGRAM;
            metric_description = "-";
        }
        else {
            type = write->metadata[i]->type;
            metric_description = write->metadata[i]->help;
            if (metric_description == NULL) {
                metric_description = "-";
            }
        }

        metric_name = cmt_metric_name_from_labels(ts);
        if (metric_name == NULL) {
            continue;
        }

        metric_namespace = "";
        metric_subsystem = "";

        switch (type) {
        case PROMETHEUS__METRIC_METADATA__METRIC_TYPE__COUNTER:
            instance = cmt_counter_create(cmt,
                                          metric_namespace,
                                          metric_subsystem,
                                          metric_name,
                                          metric_description,
                                          0, NULL);

            if (instance == NULL) {
                free(metric_name);
                return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
            }

            result = decode_counter_entry(cmt, instance, ts);

            if (result) {
                cmt_counter_destroy(instance);
            }
            break;
        case PROMETHEUS__METRIC_METADATA__METRIC_TYPE__GAUGE:
            instance = cmt_gauge_create(cmt,
                                        metric_namespace,
                                        metric_subsystem,
                                        metric_name,
                                        metric_description,
                                        0, NULL);

            if (instance == NULL) {
                free(metric_name);
                return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
            }

            result = decode_gauge_entry(cmt, instance, ts);

            if (result) {
                cmt_gauge_destroy(instance);
            }
            break;
        case PROMETHEUS__METRIC_METADATA__METRIC_TYPE__UNKNOWN:
            instance = cmt_untyped_create(cmt,
                                          metric_namespace,
                                          metric_subsystem,
                                          metric_name,
                                          metric_description,
                                          0, NULL);

            if (instance == NULL) {
                free(metric_name);
                return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
            }

            result = decode_untyped_entry(cmt, instance, ts);

            if (result) {
                cmt_untyped_destroy(instance);
            }
            break;
        case PROMETHEUS__METRIC_METADATA__METRIC_TYPE__HISTOGRAM:
            instance = cmt_histogram_create(cmt,
                                            metric_namespace,
                                            metric_subsystem,
                                            metric_name,
                                            metric_description,
                                            (struct cmt_histogram_buckets *) cmt,
                                            0, NULL);

            if (instance == NULL) {
                free(metric_name);
                return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
            }

            result = decode_histogram_entry(cmt, instance, ts);

            if (result) {
                cmt_histogram_destroy(instance);
            }
            break;
        /* case PROMETHEUS__METRIC_METADATA__METRIC_TYPE__SUMMARY: */

        default:
            result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_UNSUPPORTED_METRIC_TYPE;
            break;
        }

        free(metric_name);
    }

    return result;
}

int cmt_decode_prometheus_remote_write_create(struct cmt **out_cmt, char *in_buf, size_t in_size)
{
    int                       result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_INVALID_ARGUMENT_ERROR;
    Prometheus__WriteRequest *write  = NULL;
    struct cmt               *cmt    = NULL;

    cmt = cmt_create();

    if (cmt == NULL) {
        return CMT_DECODE_PROMETHEUS_REMOTE_WRITE_ALLOCATION_ERROR;
    }

    write = prometheus__write_request__unpack(&cmt_system_allocator,
                                              in_size,
                                              (uint8_t *) in_buf);
    if (write == NULL) {
        result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_UNPACK_ERROR;
        cmt_destroy(cmt);
        return result;
    }

    result = decode_metrics_entry(cmt, write);
    if (result != CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        cmt_destroy(cmt);
        prometheus__write_request__free_unpacked(write, &cmt_system_allocator);
        result = CMT_DECODE_PROMETHEUS_REMOTE_WRITE_DECODE_ERROR;

        return result;
    }

    prometheus__write_request__free_unpacked(write, &cmt_system_allocator);

    *out_cmt = cmt;

    return result;
}

void cmt_decode_prometheus_remote_write_destroy(struct cmt *cmt)
{
    cmt_destroy(cmt);
}
