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
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_time.h>
#include <cmetrics/cmt_compat.h>

static const char *map_type_to_otlp_key(int map_type)
{
    switch (map_type) {
    case CMT_COUNTER:
        return "counter";
    case CMT_GAUGE:
        return "gauge";
    case CMT_UNTYPED:
        return "untyped";
    case CMT_SUMMARY:
        return "summary";
    case CMT_HISTOGRAM:
        return "histogram";
    case CMT_EXP_HISTOGRAM:
        return "exp_histogram";
    default:
        return NULL;
    }
}

static struct cfl_kvlist *fetch_metadata_kvlist_key(struct cfl_kvlist *kvlist, const char *key)
{
    struct cfl_variant *entry_variant;

    if (kvlist == NULL) {
        return NULL;
    }

    entry_variant = cfl_kvlist_fetch(kvlist, (char *) key);
    if (entry_variant == NULL || entry_variant->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    return entry_variant->data.as_kvlist;
}

static void append_variant_value(cfl_sds_t *buf, struct cfl_variant *value);

static void append_kvlist_value(cfl_sds_t *buf, struct cfl_kvlist *kvlist)
{
    int count;
    struct cfl_list *head;
    struct cfl_kvpair *kvpair;

    cfl_sds_cat_safe(buf, "{", 1);

    count = 0;
    cfl_list_foreach(head, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        if (count > 0) {
            cfl_sds_cat_safe(buf, ", ", 2);
        }

        cfl_sds_cat_safe(buf, kvpair->key, cfl_sds_len(kvpair->key));
        cfl_sds_cat_safe(buf, "=", 1);
        append_variant_value(buf, kvpair->val);

        count++;
    }

    cfl_sds_cat_safe(buf, "}", 1);
}

static void append_array_value(cfl_sds_t *buf, struct cfl_array *array)
{
    size_t index;
    struct cfl_variant *entry;

    cfl_sds_cat_safe(buf, "[", 1);

    for (index = 0; index < array->entry_count; index++) {
        entry = cfl_array_fetch_by_index(array, index);
        if (entry == NULL) {
            continue;
        }

        if (index > 0) {
            cfl_sds_cat_safe(buf, ", ", 2);
        }

        append_variant_value(buf, entry);
    }

    cfl_sds_cat_safe(buf, "]", 1);
}

static void append_bytes_value(cfl_sds_t *buf, char *bytes)
{
    size_t index;
    size_t length;
    char tmp[4];
    int len;

    length = cfl_sds_len(bytes);

    for (index = 0; index < length; index++) {
        len = snprintf(tmp, sizeof(tmp), "%02x", (unsigned char) bytes[index]);
        cfl_sds_cat_safe(buf, tmp, len);
    }
}

static void append_variant_value(cfl_sds_t *buf, struct cfl_variant *value)
{
    char tmp[128];
    int len;

    if (value == NULL) {
        cfl_sds_cat_safe(buf, "null", 4);
        return;
    }

    if (value->type == CFL_VARIANT_STRING || value->type == CFL_VARIANT_REFERENCE) {
        cfl_sds_cat_safe(buf, "\"", 1);
        cfl_sds_cat_safe(buf, value->data.as_string, cfl_sds_len(value->data.as_string));
        cfl_sds_cat_safe(buf, "\"", 1);
    }
    else if (value->type == CFL_VARIANT_BOOL) {
        cfl_sds_cat_safe(buf, value->data.as_bool ? "true" : "false",
                         value->data.as_bool ? 4 : 5);
    }
    else if (value->type == CFL_VARIANT_INT) {
        len = snprintf(tmp, sizeof(tmp), "%" PRId64, value->data.as_int64);
        cfl_sds_cat_safe(buf, tmp, len);
    }
    else if (value->type == CFL_VARIANT_UINT) {
        len = snprintf(tmp, sizeof(tmp), "%" PRIu64, value->data.as_uint64);
        cfl_sds_cat_safe(buf, tmp, len);
    }
    else if (value->type == CFL_VARIANT_DOUBLE) {
        len = snprintf(tmp, sizeof(tmp), "%.17g", value->data.as_double);
        cfl_sds_cat_safe(buf, tmp, len);
    }
    else if (value->type == CFL_VARIANT_BYTES) {
        append_bytes_value(buf, value->data.as_bytes);
    }
    else if (value->type == CFL_VARIANT_ARRAY) {
        append_array_value(buf, value->data.as_array);
    }
    else if (value->type == CFL_VARIANT_KVLIST) {
        append_kvlist_value(buf, value->data.as_kvlist);
    }
    else {
        cfl_sds_cat_safe(buf, "<unsupported>", 13);
    }
}

static struct cfl_kvlist *get_data_point_metadata_context(struct cmt *cmt,
                                                          struct cmt_map *map,
                                                          struct cmt_metric *metric)
{
    struct cfl_kvlist *otlp_root;
    struct cfl_kvlist *metrics_root;
    struct cfl_kvlist *type_root;
    struct cfl_kvlist *metric_context;
    struct cfl_kvlist *datapoints_context;
    const char *type_key;
    char key[128];

    type_key = map_type_to_otlp_key(map->type);
    if (type_key == NULL) {
        return NULL;
    }

    otlp_root = fetch_metadata_kvlist_key(cmt->external_metadata, "otlp");
    if (otlp_root == NULL) {
        return NULL;
    }

    metrics_root = fetch_metadata_kvlist_key(otlp_root, "metrics");
    if (metrics_root == NULL) {
        return NULL;
    }

    type_root = fetch_metadata_kvlist_key(metrics_root, type_key);
    if (type_root == NULL) {
        return NULL;
    }

    metric_context = fetch_metadata_kvlist_key(type_root, map->opts->fqname);
    if (metric_context == NULL) {
        return NULL;
    }

    datapoints_context = fetch_metadata_kvlist_key(metric_context, "datapoints");
    if (datapoints_context == NULL) {
        return NULL;
    }

    snprintf(key, sizeof(key) - 1, "%" PRIx64 ":%" PRIu64,
             metric != NULL ? metric->hash : 0,
             metric != NULL ? cmt_metric_get_timestamp(metric) : 0);

    return fetch_metadata_kvlist_key(datapoints_context, key);
}

static void append_metric_exemplars(struct cmt *cmt,
                                    cfl_sds_t *buf,
                                    struct cmt_map *map,
                                    struct cmt_metric *metric)
{
    struct cfl_kvlist *point_metadata;
    struct cfl_variant *exemplars_variant;
    struct cfl_array *exemplars;
    struct cfl_variant *entry;
    size_t index;

    point_metadata = get_data_point_metadata_context(cmt, map, metric);
    if (point_metadata == NULL) {
        return;
    }

    exemplars_variant = cfl_kvlist_fetch(point_metadata, "exemplars");
    if (exemplars_variant == NULL || exemplars_variant->type != CFL_VARIANT_ARRAY) {
        return;
    }

    exemplars = exemplars_variant->data.as_array;
    if (exemplars == NULL || exemplars->entry_count == 0) {
        return;
    }

    cfl_sds_cat_safe(buf, "  exemplars=[", 13);

    for (index = 0; index < exemplars->entry_count; index++) {
        entry = cfl_array_fetch_by_index(exemplars, index);

        if (entry == NULL || entry->type != CFL_VARIANT_KVLIST) {
            continue;
        }

        if (index > 0) {
            cfl_sds_cat_safe(buf, ", ", 2);
        }

        append_kvlist_value(buf, entry->data.as_kvlist);
    }

    cfl_sds_cat_safe(buf, "]\n", 2);
}

static void append_histogram_metric_value(cfl_sds_t *buf,
                                          struct cmt_map *map,
                                          struct cmt_metric *metric)
{
    char                         *bucket_value_format_string;
    size_t                        entry_buffer_length;
    size_t                        entry_buffer_index;
    char                          entry_buffer[256];
    struct cmt_histogram         *histogram;
    struct cmt_histogram_buckets *buckets;
    size_t                        index;

    histogram = (struct cmt_histogram *) map->parent;
    buckets = histogram->buckets;

    cfl_sds_cat_safe(buf, " = { buckets = { ", 17);

    for (index = 0 ; index <= buckets->count ; index++) {
        if (index < buckets->count) {
            entry_buffer_index = snprintf(entry_buffer,
                                           sizeof(entry_buffer) - 1,
                                           "%g",
                                           buckets->upper_bounds[index]);

            bucket_value_format_string = "=%" PRIu64 ", ";
        }
        else {
            entry_buffer_index = snprintf(entry_buffer,
                                           sizeof(entry_buffer) - 1,
                                           "+Inf");

            bucket_value_format_string = "=%" PRIu64 " ";
        }

        entry_buffer_length = entry_buffer_index;

        entry_buffer_length += snprintf(&entry_buffer[entry_buffer_index],
                                        sizeof(entry_buffer) - 1 -
                                        entry_buffer_index,
                                        bucket_value_format_string,
                                        cmt_metric_hist_get_value(metric,
                                                                  index));

        cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);
    }

    cfl_sds_cat_safe(buf, "}, ", 3);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "sum=%g, ",
                                   cmt_metric_hist_get_sum_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "count=%" PRIu64 ,
                                   cmt_metric_hist_get_count_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    cfl_sds_cat_safe(buf, " }\n", 3);
}

static void append_summary_metric_value(cfl_sds_t *buf,
                                        struct cmt_map *map,
                                        struct cmt_metric *metric)
{
    char               *quantile_pair_format_string;
    size_t              entry_buffer_length;
    char                entry_buffer[256];
    struct cmt_summary *summary;
    size_t              index;

    summary = (struct cmt_summary *) map->parent;

    cfl_sds_cat_safe(buf, " = { quantiles = { ", 19);

    for (index = 0 ; index < summary->quantiles_count ; index++) {
        if (index < summary->quantiles_count - 1) {
            quantile_pair_format_string = "%g=%g, ";
        }
        else {
            quantile_pair_format_string = "%g=%g ";
        }

        entry_buffer_length = snprintf(entry_buffer,
                                       sizeof(entry_buffer) - 1,
                                       quantile_pair_format_string,
                                       summary->quantiles[index],
                                       cmt_summary_quantile_get_value(metric,
                                                                      index));

        cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);
    }

    cfl_sds_cat_safe(buf, "}, ", 3);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "sum=%g, ",
                                   cmt_summary_get_sum_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1 ,
                                   "count=%" PRIu64,
                                   cmt_summary_get_count_value(metric));

    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    cfl_sds_cat_safe(buf, " }\n", 3);
}

static void append_exp_histogram_metric_value(cfl_sds_t *buf,
                                              struct cmt_metric *metric)
{
    size_t entry_buffer_length;
    char entry_buffer[256];
    size_t index;

    cfl_sds_cat_safe(buf, " = { ", 5);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1,
                                   "scale=%d, zero_count=%" PRIu64 ", zero_threshold=%.17g, ",
                                   metric->exp_hist_scale,
                                   metric->exp_hist_zero_count,
                                   metric->exp_hist_zero_threshold);
    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1,
                                   "positive={offset=%d, bucket_counts=[",
                                   metric->exp_hist_positive_offset);
    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    for (index = 0; index < metric->exp_hist_positive_count; index++) {
        entry_buffer_length = snprintf(entry_buffer,
                                       sizeof(entry_buffer) - 1,
                                       "%" PRIu64 "%s",
                                       metric->exp_hist_positive_buckets[index],
                                       (index + 1 < metric->exp_hist_positive_count) ? ", " : "");
        cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);
    }

    cfl_sds_cat_safe(buf, "]}, ", 4);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1,
                                   "negative={offset=%d, bucket_counts=[",
                                   metric->exp_hist_negative_offset);
    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    for (index = 0; index < metric->exp_hist_negative_count; index++) {
        entry_buffer_length = snprintf(entry_buffer,
                                       sizeof(entry_buffer) - 1,
                                       "%" PRIu64 "%s",
                                       metric->exp_hist_negative_buckets[index],
                                       (index + 1 < metric->exp_hist_negative_count) ? ", " : "");
        cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);
    }

    cfl_sds_cat_safe(buf, "]}, ", 4);

    entry_buffer_length = snprintf(entry_buffer,
                                   sizeof(entry_buffer) - 1,
                                   "count=%" PRIu64,
                                   metric->exp_hist_count);
    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    if (metric->exp_hist_sum_set) {
        entry_buffer_length = snprintf(entry_buffer,
                                       sizeof(entry_buffer) - 1,
                                       ", sum=%.17g",
                                       cmt_math_uint64_to_d64(metric->exp_hist_sum));
    }
    else {
        entry_buffer_length = snprintf(entry_buffer,
                                       sizeof(entry_buffer) - 1,
                                       ", sum=unset");
    }
    cfl_sds_cat_safe(buf, entry_buffer, entry_buffer_length);

    cfl_sds_cat_safe(buf, " }\n", 3);
}

static void append_metric_value(cfl_sds_t *buf, struct cmt_map *map,
                                struct cmt_metric *metric)
{
    int len;
    double val;
    char tmp[128];

    if (map->type == CMT_HISTOGRAM) {
        return append_histogram_metric_value(buf, map, metric);
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        return append_exp_histogram_metric_value(buf, metric);
    }
    else if (map->type == CMT_SUMMARY) {
        return append_summary_metric_value(buf, map, metric);
    }

    /* Retrieve metric value */
    val = cmt_metric_get_value(metric);

    len = snprintf(tmp, sizeof(tmp) - 1, " = %.17g\n", val);
    cfl_sds_cat_safe(buf, tmp, len);
}

static void format_metric(struct cmt *cmt, cfl_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric)
{
    int i;
    int n;
    int len;
    int count = 0;
    int static_labels = 0;
    char tmp[128];
    uint64_t ts;
    struct tm tm;
    struct timespec tms;
    struct cmt_map_label *label_k;
    struct cmt_map_label *label_v;
    struct cfl_list *head;
    struct cmt_opts *opts;
    struct cmt_label *slabel;

    opts = map->opts;

    /* timestamp (RFC3339Nano) */
    ts = cmt_metric_get_timestamp(metric);

    cmt_time_from_ns(&tms, ts);

    cmt_platform_gmtime_r(&tms.tv_sec, &tm);
    len = strftime(tmp, sizeof(tmp) - 1, "%Y-%m-%dT%H:%M:%S.", &tm);
    cfl_sds_cat_safe(buf, tmp, len);

    len = snprintf(tmp, sizeof(tmp) - 1, "%09luZ ", tms.tv_nsec);
    cfl_sds_cat_safe(buf, tmp, len);

    /* Metric info */
    cfl_sds_cat_safe(buf, opts->fqname, cfl_sds_len(opts->fqname));

    /* Static labels */
    static_labels = cmt_labels_count(cmt->static_labels);
    if (static_labels > 0) {
        cfl_sds_cat_safe(buf, "{", 1);
        cfl_list_foreach(head, &cmt->static_labels->list) {
            count++;
            slabel = cfl_list_entry(head, struct cmt_label, _head);
            cfl_sds_cat_safe(buf, slabel->key, cfl_sds_len(slabel->key));
            cfl_sds_cat_safe(buf, "=\"", 2);
            cfl_sds_cat_safe(buf, slabel->val, cfl_sds_len(slabel->val));
            cfl_sds_cat_safe(buf, "\"", 1);

            if (count < static_labels) {
                cfl_sds_cat_safe(buf, ",", 1);
            }
        }
    }

    n = cfl_list_size(&metric->labels);
    if (n > 0) {
        if (static_labels > 0) {
            cfl_sds_cat_safe(buf, ",", 1);
        }
        else {
            cfl_sds_cat_safe(buf, "{", 1);
        }

        label_k = cfl_list_entry_first(&map->label_keys, struct cmt_map_label, _head);

        i = 1;
        cfl_list_foreach(head, &metric->labels) {
            label_v = cfl_list_entry(head, struct cmt_map_label, _head);

            cfl_sds_cat_safe(buf, label_k->name, cfl_sds_len(label_k->name));
            cfl_sds_cat_safe(buf, "=\"", 2);
            cfl_sds_cat_safe(buf, label_v->name, cfl_sds_len(label_v->name));

            if (i < n) {
                cfl_sds_cat_safe(buf, "\",", 2);
            }
            else {
                cfl_sds_cat_safe(buf, "\"", 1);
            }
            i++;

            label_k = cfl_list_entry_next(&label_k->_head, struct cmt_map_label,
                                         _head, &map->label_keys);
        }
        cfl_sds_cat_safe(buf, "}", 1);

        append_metric_value(buf, map, metric);
        append_metric_exemplars(cmt, buf, map, metric);
    }
    else {
        if (static_labels > 0) {
            cfl_sds_cat_safe(buf, "}", 1);
        }
        append_metric_value(buf, map, metric);
        append_metric_exemplars(cmt, buf, map, metric);
    }
}

static void format_metrics(struct cmt *cmt, cfl_sds_t *buf, struct cmt_map *map)
{
    struct cfl_list *head;
    struct cmt_metric *metric;

    /* Simple metric, no labels */
    if (map->metric_static_set == 1) {
        format_metric(cmt, buf, map, &map->metric);
    }

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        format_metric(cmt, buf, map, metric);
    }
}

/* Format all the registered metrics in Prometheus Text format */
cfl_sds_t cmt_encode_text_create(struct cmt *cmt)
{
    cfl_sds_t buf;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;

    /* Allocate a 1KB of buffer */
    buf = cfl_sds_create_size(1024);
    if (!buf) {
        return NULL;
    }

    /* Counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        format_metrics(cmt, &buf, counter->map);
    }

    /* Gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        format_metrics(cmt, &buf, gauge->map);
    }

    /* Summaries */
    cfl_list_foreach(head, &cmt->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        format_metrics(cmt, &buf, summary->map);
    }

    /* Histograms */
    cfl_list_foreach(head, &cmt->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        format_metrics(cmt, &buf, histogram->map);
    }

    /* Exponential Histograms */
    cfl_list_foreach(head, &cmt->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        format_metrics(cmt, &buf, exp_histogram->map);
    }

    /* Untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        format_metrics(cmt, &buf, untyped->map);
    }

    return buf;
}

void cmt_encode_text_destroy(cfl_sds_t text)
{
    cfl_sds_destroy(text);
}
