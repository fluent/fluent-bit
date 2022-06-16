/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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
#include <cmetrics/cmt_sds.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_compat.h>
#include <cmetrics/cmt_encode_msgpack.h>

#include <mpack/mpack.h>

static ptrdiff_t find_label_index(struct mk_list *label_list, cmt_sds_t label_name)
{
    struct mk_list       *head;
    struct cmt_map_label *label;
    size_t                entry_index;

    entry_index = 0;

    mk_list_foreach(head, label_list) {
        label = mk_list_entry(head, struct cmt_map_label, _head);

        if (0 == strcmp(label_name, label->name)) {
            return entry_index;
        }

        entry_index++;
    }

    return -1;
}

struct cmt_map_label *create_label(char *label_text)
{
    struct cmt_map_label *new_label;

    new_label = calloc(1, sizeof(struct cmt_map_label));

    if (NULL != new_label) {
        new_label->name = cmt_sds_create(label_text);

        if (NULL == new_label->name) {
            free(new_label);

            new_label = NULL;
        }
    }

    return new_label;
}

static int gather_label_entries(struct mk_list *unique_label_list,
                                struct mk_list *source_label_list)
{
    struct mk_list       *head;
    struct cmt_map_label *label;
    struct cmt_map_label *new_label;
    ptrdiff_t             label_index;

    mk_list_foreach(head, source_label_list) {
        label = mk_list_entry(head, struct cmt_map_label, _head);

        label_index = find_label_index(unique_label_list, label->name);

        if (-1 == label_index) {
            new_label = create_label(label->name);

            if(NULL == new_label) {
                return 1;
            }

            mk_list_add(&new_label->_head, unique_label_list);
        }
    }

    return 0;
}

static int gather_label_entries_in_map(struct mk_list *unique_label_list,
                                       struct cmt_map *map)
{
    struct mk_list       *head;
    struct cmt_metric    *metric;
    int                   result;

    result = gather_label_entries(unique_label_list, &map->label_keys);

    if (0 == result) {
        mk_list_foreach(head, &map->metrics) {
            metric = mk_list_entry(head, struct cmt_metric, _head);

            result = gather_label_entries(unique_label_list, &metric->labels);

            if (0 != result) {
                break;
            }
        }
    }

    return result;
}

static int gather_static_label_entries(struct mk_list *unique_label_list,
                                       struct cmt *cmt)
{
    struct mk_list       *head;
    struct cmt_map_label *new_label;
    ptrdiff_t             label_index;
    struct cmt_label     *static_label;

    mk_list_foreach(head, &cmt->static_labels->list) {
        static_label = mk_list_entry(head, struct cmt_label, _head);

        label_index = find_label_index(unique_label_list, static_label->key);

        if (-1 == label_index) {
            new_label = create_label(static_label->key);

            if(NULL == new_label) {
                return 1;
            }

            mk_list_add(&new_label->_head, unique_label_list);
        }

        label_index = find_label_index(unique_label_list, static_label->val);

        if (-1 == label_index) {
            new_label = create_label(static_label->val);

            if(NULL == new_label) {
                return 1;
            }

            mk_list_add(&new_label->_head, unique_label_list);
        }

        /* If we got this far then we are sure we have the entry in the list */
    }

    return 0;
}

static void pack_header(mpack_writer_t *writer, struct cmt *cmt, struct cmt_map *map, struct mk_list *unique_label_list)
{
    struct cmt_opts      *opts;
    struct mk_list       *head;
    struct cmt_map_label *label;
    size_t                index;
    struct cmt_summary   *summary;
    struct cmt_histogram *histogram;
    ptrdiff_t             label_index;
    struct cmt_label     *static_label;
    size_t                meta_field_count;

    opts = map->opts;
    meta_field_count = 6;

    if (map->type == CMT_HISTOGRAM) {
        histogram = (struct cmt_histogram *) map->parent;

        meta_field_count++;
    }
    if (map->type == CMT_SUMMARY) {
        summary = (struct cmt_summary *) map->parent;

        meta_field_count++;
    }

    mpack_start_map(writer, 2);

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

    /* 'label_dictionary' (unique label key text) */
    mpack_write_cstr(writer, "label_dictionary");
    mpack_start_array(writer, mk_list_size(unique_label_list));
    mk_list_foreach(head, unique_label_list) {
        label = mk_list_entry(head, struct cmt_map_label, _head);
        mpack_write_cstr(writer, label->name);
    }
    mpack_finish_array(writer);

    /* 'static_labels' (static labels) */
    mpack_write_cstr(writer, "static_labels");
    mpack_start_array(writer, mk_list_size(&cmt->static_labels->list) * 2);
    mk_list_foreach(head, &cmt->static_labels->list) {
        static_label = mk_list_entry(head, struct cmt_label, _head);

        label_index = find_label_index(unique_label_list, static_label->key);

        mpack_write_uint(writer, (uint16_t) label_index);

        label_index = find_label_index(unique_label_list, static_label->val);

        mpack_write_uint(writer, (uint16_t) label_index);
        /* If we got this far then we are sure we have the entry in the list */
    }
    mpack_finish_array(writer);

    /* 'labels' (label keys) */
    mpack_write_cstr(writer, "labels");
    mpack_start_array(writer, map->label_count);
    mk_list_foreach(head, &map->label_keys) {
        label = mk_list_entry(head, struct cmt_map_label, _head);

        label_index = find_label_index(unique_label_list, label->name);

        mpack_write_uint(writer, (uint16_t) label_index);
        /* If we got this far then we are sure we have the entry in the list */
    }
    mpack_finish_array(writer);

    if (map->type == CMT_HISTOGRAM) {
        /* 'buckets' (histogram buckets) */
        mpack_write_cstr(writer, "buckets");

        mpack_start_array(writer, histogram->buckets->count);

        for (index = 0 ;
             index < histogram->buckets->count ;
             index++) {
            mpack_write_double(writer, histogram->buckets->upper_bounds[index]);
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

    mpack_finish_map(writer); /* 'meta' */
}

static int pack_metric(mpack_writer_t *writer, struct cmt_map *map, struct cmt_metric *metric, struct mk_list *unique_label_list)
{
    int c_labels;
    int s;
    double val;
    size_t index;
    struct mk_list *head;
    struct cmt_map_label *label;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;
    ptrdiff_t label_index;

    c_labels = mk_list_size(&metric->labels);

    s = 3;

    if (c_labels > 0) {
        s++;
    }

    mpack_start_map(writer, s);

    mpack_write_cstr(writer, "ts");
    mpack_write_uint(writer, metric->timestamp);

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
    else if (map->type == CMT_SUMMARY) {
        summary = (struct cmt_summary *) map->parent;

        mpack_write_cstr(writer, "summary");
        mpack_start_map(writer, 4);

        mpack_write_cstr(writer, "quantiles_set");
        mpack_write_uint(writer, metric->sum_quantiles_set);

        mpack_write_cstr(writer, "quantiles");
        mpack_start_array(writer, summary->quantiles_count);

        for (index = 0 ; index < summary->quantiles_count ; index++) {
            mpack_write_uint(writer, metric->sum_quantiles[index]);
        }

        mpack_finish_array(writer);

        mpack_write_cstr(writer, "count");
        mpack_write_uint(writer, cmt_summary_get_count_value(metric));

        mpack_write_cstr(writer, "sum");
        mpack_write_uint(writer, metric->sum_sum);

        mpack_finish_map(writer); /* 'summary' */
    }
    else {
        mpack_write_cstr(writer, "value");
        val = cmt_metric_get_value(metric);
        mpack_write_double(writer, val);
    }

    s = mk_list_size(&metric->labels);
    if (s > 0) {
        mpack_write_cstr(writer, "labels");
        mpack_start_array(writer, c_labels);

        mk_list_foreach(head, &metric->labels) {
            label = mk_list_entry(head, struct cmt_map_label, _head);

            label_index = find_label_index(unique_label_list, label->name);

            mpack_write_uint(writer, (uint16_t) label_index);
        }

        mpack_finish_array(writer);
    }

    mpack_write_cstr(writer, "hash");
    mpack_write_uint(writer, metric->hash);

    mpack_finish_map(writer);

    return 0;
}

static int pack_basic_type(mpack_writer_t *writer, struct cmt *cmt, struct cmt_map *map)
{
    int result;
    int values_size = 0;
    struct mk_list *head;
    struct cmt_metric *metric;
    struct mk_list unique_label_list;

    mk_list_init(&unique_label_list);


    result = gather_static_label_entries(&unique_label_list, cmt);

    if (0 != result) {
        fprintf(stderr, "An error occurred preprocessing the data!\n");
        return -1;
    }

    result = gather_label_entries_in_map(&unique_label_list, map);

    if (0 != result) {
        fprintf(stderr, "An error occurred preprocessing the data!\n");
        return -1;
    }

    pack_header(writer, cmt, map, &unique_label_list);

    if (map->metric_static_set) {
        values_size++;
    }
    values_size += mk_list_size(&map->metrics);

    mpack_write_cstr(writer, "values");
    mpack_start_array(writer, values_size);

    if (map->metric_static_set) {
        pack_metric(writer, map, &map->metric, &unique_label_list);
    }

    mk_list_foreach(head, &map->metrics) {
        metric = mk_list_entry(head, struct cmt_metric, _head);
        pack_metric(writer, map, metric, &unique_label_list);
    }
    mpack_finish_array(writer);

    mpack_finish_map(writer);

    destroy_label_list(&unique_label_list);

    return 0;
}


/* Takes a cmetrics context and serialize it using msgpack */
int cmt_encode_msgpack_create(struct cmt *cmt, char **out_buf, size_t *out_size)
{
    char *data;
    size_t size;
    mpack_writer_t writer;
    struct mk_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;
    size_t metric_count;

    /*
     * CMetrics data schema
     *  [
     *      {
     *        'meta' => {
     *                      'ver' => INTEGER
     *                      'type' => INTEGER
     *                                '0' = counter
     *                                '1' = gauge
     *                                '2' = histogram (WIP)
     *                      'opts' => {
     *                                 'ns'   => ns
     *                                 'subsystem'   => subsystem
     *                                 'name'        => name
     *                                 'description' => description
     *                                },
     *                      'label_dictionary' => ['', ...],
     *                      'static_labels' => [n, ...],
     *                      'label_keys' => [n, ...],
     *                      'buckets' => [n, ...]
     *                    },
     *        'values' => [
     *                      {
     *                       'ts'   : nanosec timestamp,
     *                       'value': float64 value,
     *                       'label_values': [n, ...],
     *                       'histogram': {
     *                                         'sum': float64,
     *                                         'count': uint64,
     *                                         'buckets': [n, ...]
     *                                     },
     *                       'summary': {
     *                                      'sum': float64,
     *                                      'count': uint64,
     *                                      'quantiles': [n, ...],
     *                                      'quantiles_set': uint64
     *                                  },
     *                       'hash': uint64 value
     *                      }
     *                    ]
     *      }
     *  , ...]
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

    metric_count  = 0;
    metric_count += mk_list_size(&cmt->counters);
    metric_count += mk_list_size(&cmt->gauges);
    metric_count += mk_list_size(&cmt->untypeds);
    metric_count += mk_list_size(&cmt->summaries);
    metric_count += mk_list_size(&cmt->histograms);

    /* We want an array to group all these metrics in a context */
    mpack_start_array(&writer, metric_count);

    /* Counters */
    mk_list_foreach(head, &cmt->counters) {
        counter = mk_list_entry(head, struct cmt_counter, _head);
        pack_basic_type(&writer, cmt, counter->map);
    }

    /* Gauges */
    mk_list_foreach(head, &cmt->gauges) {
        gauge = mk_list_entry(head, struct cmt_gauge, _head);
        pack_basic_type(&writer, cmt, gauge->map);
    }

    /* Untyped */
    mk_list_foreach(head, &cmt->untypeds) {
        untyped = mk_list_entry(head, struct cmt_untyped, _head);
        pack_basic_type(&writer, cmt, untyped->map);
    }

    /* Summary */
    mk_list_foreach(head, &cmt->summaries) {
        summary = mk_list_entry(head, struct cmt_summary, _head);
        pack_basic_type(&writer, cmt, summary->map);
    }

    /* Histogram */
    mk_list_foreach(head, &cmt->histograms) {
        histogram = mk_list_entry(head, struct cmt_histogram, _head);
        pack_basic_type(&writer, cmt, histogram->map);
    }

    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");
        return -1;
    }

    mpack_finish_array(&writer);

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
