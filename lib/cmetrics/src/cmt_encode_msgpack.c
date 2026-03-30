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
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_atomic.h>
#include <cmetrics/cmt_compat.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_variant_utils.h>

struct cmt_map_label *create_label(char *label_text)
{
    struct cmt_map_label *new_label;

    new_label = calloc(1, sizeof(struct cmt_map_label));

    if (NULL != new_label) {
        new_label->name = cfl_sds_create(label_text);

        if (NULL == new_label->name) {
            free(new_label);

            new_label = NULL;
        }
    }

    return new_label;
}

static void pack_header(mpack_writer_t *writer, struct cmt *cmt, struct cmt_map *map)
{
    struct cmt_opts      *opts;
    struct cfl_list       *head;
    struct cmt_map_label *label;
    size_t                index;
    struct cmt_summary   *summary = NULL;
    struct cmt_histogram *histogram = NULL;
    struct cmt_counter   *counter = NULL;
    size_t                meta_field_count;

    opts = map->opts;
    meta_field_count = 4;

    if (map->type == CMT_HISTOGRAM) {
        histogram = (struct cmt_histogram *) map->parent;

        meta_field_count++;
    }
    else if (map->type == CMT_SUMMARY) {
        summary = (struct cmt_summary *) map->parent;

        meta_field_count++;
    }
    else if (map->type == CMT_COUNTER){
        counter = (struct cmt_counter *) map->parent;

        meta_field_count++;
    }

    /* 'meta' */
    mpack_write_cstr(writer, "meta");
    mpack_start_map(writer, meta_field_count);

    /* 'ver' */
    mpack_write_cstr(writer, "ver");
    mpack_write_uint(writer, MSGPACK_ENCODER_VERSION);

    /* 'type' */
    mpack_write_cstr(writer, "type");
    mpack_write_uint(writer, map->type);

    /* 'opts' */
    mpack_write_cstr(writer, "opts");
    mpack_start_map(writer, 4);

    /* opts['ns'] */
    mpack_write_cstr(writer, "ns");
    mpack_write_cstr(writer, opts->ns);

    /* opts['subsystem'] */
    mpack_write_cstr(writer, "ss");
    mpack_write_cstr(writer, opts->subsystem);

    /* opts['name'] */
    mpack_write_cstr(writer, "name");
    mpack_write_cstr(writer, opts->name);

    /* opts['description'] */
    mpack_write_cstr(writer, "desc");
    mpack_write_cstr(writer, opts->description);

    mpack_finish_map(writer); /* 'opts' */

    /* 'labels' (label keys) */
    mpack_write_cstr(writer, "labels");
    mpack_start_array(writer, map->label_count);
    cfl_list_foreach(head, &map->label_keys) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);

        mpack_write_cstr(writer, label->name);
    }
    mpack_finish_array(writer);

    if (map->type == CMT_HISTOGRAM) {
        /* 'buckets' (histogram buckets) */
        mpack_write_cstr(writer, "buckets");

        if (histogram->buckets != NULL) {
            mpack_start_array(writer, histogram->buckets->count);

            for (index = 0 ;
                 index < histogram->buckets->count ;
                 index++) {
                mpack_write_double(writer, histogram->buckets->upper_bounds[index]);
            }
        }
        else {
            mpack_start_array(writer, 0);
        }

        mpack_finish_array(writer);
    }
    else if (map->type == CMT_SUMMARY) {
        /* 'quantiles' (summary quantiles) */
        mpack_write_cstr(writer, "quantiles");

        mpack_start_array(writer, summary->quantiles_count);

        for (index = 0 ;
             index < summary->quantiles_count ;
             index++) {
            mpack_write_double(writer, summary->quantiles[index]);
        }

        mpack_finish_array(writer);
    }
    else if (map->type == CMT_COUNTER){
        /* aggregation_type */
        mpack_write_cstr(writer, "aggregation_type");
        mpack_write_int(writer, counter->aggregation_type);
    }

    mpack_finish_map(writer); /* 'meta' */
}

static int pack_metric(mpack_writer_t *writer, struct cmt_map *map, struct cmt_metric *metric)
{
    int c_labels;
    int has_start_timestamp;
    int has_exp_hist_snapshot;
    int s;
    double val;
    size_t index;
    uint64_t start_timestamp;
    struct cfl_list *head;
    struct cmt_map_label *label;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram_snapshot snapshot;

    c_labels = cfl_list_size(&metric->labels);

    s = 3;

    if (c_labels > 0) {
        s++;
    }

    if (map->type != CMT_HISTOGRAM &&
        map->type != CMT_EXP_HISTOGRAM &&
        map->type != CMT_SUMMARY &&
        cmt_metric_get_value_type(metric) != CMT_METRIC_VALUE_DOUBLE) {
        s += 2;
    }

    has_start_timestamp = cmt_metric_has_start_timestamp(metric);
    if (has_start_timestamp) {
        start_timestamp = cmt_metric_get_start_timestamp(metric);
        s++;
    }
    else {
        start_timestamp = 0;
    }

    has_exp_hist_snapshot = CMT_FALSE;

    if (map->type == CMT_EXP_HISTOGRAM) {
        if (cmt_metric_exp_hist_get_snapshot(metric, &snapshot) != 0) {
            return -1;
        }
        has_exp_hist_snapshot = CMT_TRUE;
    }

    mpack_start_map(writer, s);

    mpack_write_cstr(writer, "ts");
    mpack_write_uint(writer, cmt_metric_get_timestamp(metric));

    if (has_start_timestamp) {
        mpack_write_cstr(writer, "start_ts");
        mpack_write_uint(writer, start_timestamp);
    }

    if (map->type == CMT_HISTOGRAM) {
        histogram = (struct cmt_histogram *) map->parent;

        mpack_write_cstr(writer, "histogram");
        mpack_start_map(writer, 3);

        mpack_write_cstr(writer, "buckets");
        mpack_start_array(writer, histogram->buckets->count + 1);
        for (index = 0 ;
             index <= histogram->buckets->count ;
             index++) {
            mpack_write_uint(writer, cmt_metric_hist_get_value(metric, index));
        }

        mpack_finish_array(writer);

        mpack_write_cstr(writer, "sum");
        mpack_write_double(writer, cmt_metric_hist_get_sum_value(metric));

        mpack_write_cstr(writer, "count");
        mpack_write_uint(writer, cmt_metric_hist_get_count_value(metric));

        mpack_finish_map(writer); /* 'histogram' */
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        mpack_write_cstr(writer, "exp_histogram");
        mpack_start_map(writer, 10);

        mpack_write_cstr(writer, "scale");
        mpack_write_int(writer, snapshot.scale);

        mpack_write_cstr(writer, "zero_count");
        mpack_write_uint(writer, snapshot.zero_count);

        mpack_write_cstr(writer, "zero_threshold");
        mpack_write_double(writer, snapshot.zero_threshold);

        mpack_write_cstr(writer, "positive_offset");
        mpack_write_int(writer, snapshot.positive_offset);

        mpack_write_cstr(writer, "positive_buckets");
        mpack_start_array(writer, snapshot.positive_count);
        for (index = 0 ; index < snapshot.positive_count ; index++) {
            mpack_write_uint(writer, snapshot.positive_buckets[index]);
        }
        mpack_finish_array(writer);

        mpack_write_cstr(writer, "negative_offset");
        mpack_write_int(writer, snapshot.negative_offset);

        mpack_write_cstr(writer, "negative_buckets");
        mpack_start_array(writer, snapshot.negative_count);
        for (index = 0 ; index < snapshot.negative_count ; index++) {
            mpack_write_uint(writer, snapshot.negative_buckets[index]);
        }
        mpack_finish_array(writer);

        mpack_write_cstr(writer, "count");
        mpack_write_uint(writer, snapshot.count);

        mpack_write_cstr(writer, "sum_set");
        mpack_write_uint(writer, snapshot.sum_set);

        mpack_write_cstr(writer, "sum");
        mpack_write_uint(writer, snapshot.sum);

        mpack_finish_map(writer); /* 'exp_histogram' */
    }
    else if (map->type == CMT_SUMMARY) {
        summary = (struct cmt_summary *) map->parent;

        mpack_write_cstr(writer, "summary");
        mpack_start_map(writer, 4);

        mpack_write_cstr(writer, "quantiles_set");
        mpack_write_uint(writer, cmt_atomic_load(&metric->sum_quantiles_set));

        mpack_write_cstr(writer, "quantiles");
        mpack_start_array(writer, summary->quantiles_count);

        for (index = 0 ; index < summary->quantiles_count ; index++) {
            mpack_write_uint(writer,
                             cmt_atomic_load(&metric->sum_quantiles[index]));
        }

        mpack_finish_array(writer);

        mpack_write_cstr(writer, "count");
        mpack_write_uint(writer, cmt_summary_get_count_value(metric));

        mpack_write_cstr(writer, "sum");
        mpack_write_uint(writer, cmt_atomic_load(&metric->sum_sum));

        mpack_finish_map(writer); /* 'summary' */
    }
    else {
        mpack_write_cstr(writer, "value");
        val = cmt_metric_get_value(metric);
        mpack_write_double(writer, val);

        if (cmt_metric_get_value_type(metric) == CMT_METRIC_VALUE_INT64) {
            mpack_write_cstr(writer, "value_type");
            mpack_write_uint(writer, CMT_METRIC_VALUE_INT64);
            mpack_write_cstr(writer, "value_int64");
            mpack_write_i64(writer, cmt_metric_get_int64_value(metric));
        }
        else if (cmt_metric_get_value_type(metric) == CMT_METRIC_VALUE_UINT64) {
            mpack_write_cstr(writer, "value_type");
            mpack_write_uint(writer, CMT_METRIC_VALUE_UINT64);
            mpack_write_cstr(writer, "value_uint64");
            mpack_write_u64(writer, cmt_metric_get_uint64_value(metric));
        }
    }

    s = cfl_list_size(&metric->labels);
    if (s > 0) {
        mpack_write_cstr(writer, "labels");
        mpack_start_array(writer, c_labels);

        cfl_list_foreach(head, &metric->labels) {
            label = cfl_list_entry(head, struct cmt_map_label, _head);

            if (label->name != NULL) {
                mpack_write_cstr(writer, label->name);
            }
            else {
                mpack_write_nil(writer);
            }
        }

        mpack_finish_array(writer);
    }

    mpack_write_cstr(writer, "hash");
    mpack_write_uint(writer, metric->hash);

    mpack_finish_map(writer);

    if (has_exp_hist_snapshot) {
        cmt_metric_exp_hist_snapshot_destroy(&snapshot);
    }

    return 0;
}

static int pack_basic_type(mpack_writer_t *writer, struct cmt *cmt, struct cmt_map *map)
{
    int values_size = 0;
    struct cfl_list *head;
    struct cmt_metric *metric;

    /* metric scope dictionary that holds meta and values*/
    mpack_start_map(writer, 2);

    pack_header(writer, cmt, map);

    if (map->metric_static_set) {
        values_size++;
    }
    values_size += cfl_list_size(&map->metrics);

    mpack_write_cstr(writer, "values");
    mpack_start_array(writer, values_size);

    if (map->metric_static_set) {
        pack_metric(writer, map, &map->metric);
    }

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        pack_metric(writer, map, metric);
    }
    mpack_finish_array(writer);

    mpack_finish_map(writer);

    return 0;
}

static void pack_static_labels(mpack_writer_t *writer, struct cmt *cmt)
{
    struct cmt_label *static_label;
    struct cfl_list  *head;

    /* 'static_labels' (static labels) */
    mpack_write_cstr(writer, "static_labels");

    mpack_start_array(writer, cfl_list_size(&cmt->static_labels->list));

    cfl_list_foreach(head, &cmt->static_labels->list) {
        static_label = cfl_list_entry(head, struct cmt_label, _head);

        mpack_start_array(writer, 2);

        mpack_write_cstr(writer, static_label->key);
        mpack_write_cstr(writer, static_label->val);

        mpack_finish_array(writer);
    }

    mpack_finish_array(writer);
}

static int pack_static_processing_section(mpack_writer_t *writer, struct cmt *cmt)
{
    mpack_write_cstr(writer, "processing");

    mpack_start_map(writer, 1);

    pack_static_labels(writer, cmt);

    mpack_finish_map(writer); /* 'processing' */

    return 0;
}

static int pack_context_header(mpack_writer_t *writer, struct cmt *cmt)
{
    int result;

    mpack_write_cstr(writer, "meta");
    mpack_start_map(writer, 3);

    mpack_write_cstr(writer, "cmetrics");
    result = pack_cfl_variant_kvlist(writer, cmt->internal_metadata);

    if (result != 0) {
        return -1;
    }

    mpack_write_cstr(writer, "external");
    result = pack_cfl_variant_kvlist(writer, cmt->external_metadata);

    if (result != 0) {
        return -2;
    }

    pack_static_processing_section(writer, cmt);

    mpack_finish_map(writer); /* 'context_header' */

    return 0;
}

static int pack_context_metrics(mpack_writer_t *writer, struct cmt *cmt)
{
    size_t                metric_count;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_summary   *summary;
    struct cmt_untyped   *untyped;
    struct cmt_counter   *counter;
    struct cmt_gauge     *gauge;
    struct cfl_list      *head;

    metric_count  = 0;
    metric_count += cfl_list_size(&cmt->counters);
    metric_count += cfl_list_size(&cmt->gauges);
    metric_count += cfl_list_size(&cmt->untypeds);
    metric_count += cfl_list_size(&cmt->summaries);
    metric_count += cfl_list_size(&cmt->histograms);
    metric_count += cfl_list_size(&cmt->exp_histograms);

    mpack_write_cstr(writer, "metrics");
    mpack_start_array(writer, metric_count);

    /* Counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        pack_basic_type(writer, cmt, counter->map);
    }

    /* Gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        pack_basic_type(writer, cmt, gauge->map);
    }

    /* Untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        pack_basic_type(writer, cmt, untyped->map);
    }

    /* Summary */
    cfl_list_foreach(head, &cmt->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        pack_basic_type(writer, cmt, summary->map);
    }

    /* Histogram */
    cfl_list_foreach(head, &cmt->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        pack_basic_type(writer, cmt, histogram->map);
    }

    /* Exponential Histogram */
    cfl_list_foreach(head, &cmt->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        pack_basic_type(writer, cmt, exp_histogram->map);
    }

    mpack_finish_array(writer);

    return 0;
}

static int pack_context(mpack_writer_t *writer, struct cmt *cmt)
{
    int result;

    mpack_start_map(writer, 2);

    result = pack_context_header(writer, cmt);

    if (result != 0) {
        return -1;
    }

    result = pack_context_metrics(writer, cmt);

    if (result != 0) {
        return -2;
    }

    mpack_finish_map(writer); /* outermost context scope */

    return 0;
}

/* Takes a cmetrics context and serialize it using msgpack */
int cmt_encode_msgpack_create(struct cmt *cmt, char **out_buf, size_t *out_size)
{
    char *data;
    size_t size;
    mpack_writer_t writer;
    int result;

    /*
     * CMetrics data schema

        {
            'meta' => {
                'cmetrics' => {
                                'producer': STRING
                },
                'external' => { ... },
                'processing' => {
                                    'static_labels' =>  [
                                                            [STRING, STRING], ...
                                                        ]
                                }
            },
            'metrics' =>    [
                                {
                                    'meta' => {
                                                'ver'  => INTEGER
                                                'type' => INTEGER
                                                            '0' = counter
                                                            '1' = gauge
                                                            '2' = histogram (WIP)
                                                'opts' => {
                                                            'ns'          => ns
                                                            'subsystem'   => subsystem
                                                            'name'        => name
                                                            'description' => description
                                                },
                                                'label_keys' => [STRING, ...],
                                                'buckets' => [n, ...]
                                    },
                                    'values' => [
                                        {
                                            'ts'   : nanosec timestamp,
                                            'value': float64 value,
                                            'label_values': [STRING, ...],
                                            'histogram':{
                                                            'sum': float64,
                                                            'count': uint64,
                                                            'buckets': [n, ...]
                                                        },
                                            'summary':  {
                                                            'sum': float64,
                                                            'count': uint64,
                                                            'quantiles': [n, ...],
                                                            'quantiles_set': uint64
                                                        },
                                            'hash': uint64 value
                                        }
                                    ]
                                }, ...
            ]
        }
     *
     *
     * The following fields are metric type specific and are only
     * included for histograms :
     *      meta->buckets
     *      values[n]->buckets
     *      values[n]->count
     *      values[n]->sum
     */

    if (cmt == NULL) {
        return -1;
    }

    mpack_writer_init_growable(&writer, &data, &size);

    result = pack_context(&writer, cmt);

    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");

        return -1;
    }

    if (result != 0) {
        return result;
    }

    *out_buf = data;
    *out_size = size;

    return 0;
}

void cmt_encode_msgpack_destroy(char *out_buf)
{
    if (NULL != out_buf) {
        MPACK_FREE(out_buf);
    }
}
