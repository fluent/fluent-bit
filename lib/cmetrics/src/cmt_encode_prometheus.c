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

#include <stdbool.h>
#include <math.h>
#include <stdlib.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_atomic.h>

#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_compat.h>

#define PROM_FMT_VAL_FROM_VAL          0
#define PROM_FMT_VAL_FROM_BUCKET_ID    1
#define PROM_FMT_VAL_FROM_QUANTILE     2
#define PROM_FMT_VAL_FROM_SUM          3
#define PROM_FMT_VAL_FROM_COUNT        4

struct prom_fmt {
    int metric_name;   /* metric name already set ? */
    int brace_open;    /* first brace open ? */
    int labels_count;  /* number of labels aready added */
    int value_from;

    /*
     * For value_from 'PROM_FMT_VAL_FROM_BUCKET_ID', the 'id' belongs to a bucket
     * id position, if is 'PROM_FMT_VAL_FROM_QUANTILE' the value represents a
     * sum_quantiles position.
     */
    int id;
};

static void prom_fmt_init(struct prom_fmt *fmt)
{
    fmt->metric_name = CMT_FALSE;
    fmt->brace_open = CMT_FALSE;
    fmt->labels_count = 0;
    fmt->value_from = PROM_FMT_VAL_FROM_VAL;
    fmt->id = -1;
}

/*
 * Prometheus Exposition Format
 * ----------------------------
 * https://github.com/prometheus/docs/blob/master/content/docs/instrumenting/exposition_formats.md
 */

static void metric_escape(cfl_sds_t *buf, cfl_sds_t description, bool escape_quote)
{
    int i;
    size_t len;

    len = cfl_sds_len(description);

    for (i = 0; i < len; i++) {
        switch (description[i]) {
            case '\\':
                cfl_sds_cat_safe(buf, "\\\\", 2);
                break;
            case '\n':
                cfl_sds_cat_safe(buf, "\\n", 2);
                break;
            case '"':
                if (escape_quote) {
                    cfl_sds_cat_safe(buf, "\\\"", 2);
                    break;
                }
                /* FALLTHROUGH */
            default:
                cfl_sds_cat_safe(buf, description + i, 1);
                break;
        }
    }
}

/*
 * Metric and label names have no escape sequence in the exposition format: they
 * must match [a-zA-Z_:][a-zA-Z0-9_:]* (label names cannot contain ':'). Names
 * received from the network (OTLP, remote write, msgpack) are not constrained,
 * so replace every other byte with '_', otherwise a name containing a newline
 * or a space would inject new lines/tokens into the output.
 */
static char sanitize_name_char(char c, bool is_label)
{
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_' ||
          (c == ':' && !is_label))) {
        return '_';
    }

    return c;
}

static void metric_name_cat(cfl_sds_t *buf, cfl_sds_t name, bool is_label)
{
    size_t i;
    size_t len;
    char c;

    len = cfl_sds_len(name);

    for (i = 0; i < len; i++) {
        c = name[i];

        if (i == 0 && c >= '0' && c <= '9') {
            /* a leading digit is not allowed, prefix it */
            cfl_sds_cat_safe(buf, "_", 1);
        }

        c = sanitize_name_char(c, is_label);

        cfl_sds_cat_safe(buf, &c, 1);
    }
}

/*
 * Sanitizing is not injective ('a.b' and 'a_b' are both written as 'a_b'),
 * compare two names as they are written by metric_name_cat().
 */
static int sanitized_name_equal(cfl_sds_t a, cfl_sds_t b, bool is_label)
{
    size_t i;
    size_t a_len;
    size_t b_len;
    size_t a_prefix;
    size_t b_prefix;
    char   a_char;
    char   b_char;

    a_len = cfl_sds_len(a);
    b_len = cfl_sds_len(b);

    a_prefix = (a_len > 0 && a[0] >= '0' && a[0] <= '9') ? 1 : 0;
    b_prefix = (b_len > 0 && b[0] >= '0' && b[0] <= '9') ? 1 : 0;

    if (a_len + a_prefix != b_len + b_prefix) {
        return CMT_FALSE;
    }

    for (i = 0; i < a_len + a_prefix; i++) {
        a_char = (i < a_prefix) ? '_' : sanitize_name_char(a[i - a_prefix], is_label);
        b_char = (i < b_prefix) ? '_' : sanitize_name_char(b[i - b_prefix], is_label);

        if (a_char != b_char) {
            return CMT_FALSE;
        }
    }

    return CMT_TRUE;
}

static void metric_banner(cfl_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric)
{
    struct cmt_opts *opts;

    opts = map->opts;

    /* HELP */
    cfl_sds_cat_safe(buf, "# HELP ", 7);
    metric_name_cat(buf, opts->fqname, false);

    if (cfl_sds_len(opts->description) > 1 || opts->description[0] != ' ') {
        /* only append description if it is not empty. the parser uses a single whitespace
         * string to signal that no HELP was provided */
        cfl_sds_cat_safe(buf, " ", 1);
        metric_escape(buf, opts->description, false);
    }
    cfl_sds_cat_safe(buf, "\n", 1);

    /* TYPE */
    cfl_sds_cat_safe(buf, "# TYPE ", 7);
    metric_name_cat(buf, opts->fqname, false);

    if (map->type == CMT_COUNTER) {
        cfl_sds_cat_safe(buf, " counter\n", 9);
    }
    else if (map->type == CMT_GAUGE) {
        cfl_sds_cat_safe(buf, " gauge\n", 7);
    }
    else if (map->type == CMT_SUMMARY) {
        cfl_sds_cat_safe(buf, " summary\n", 9);
    }
    else if (map->type == CMT_HISTOGRAM) {
        cfl_sds_cat_safe(buf, " histogram\n", 11);
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        cfl_sds_cat_safe(buf, " histogram\n", 11);
    }
    else if (map->type == CMT_UNTYPED) {
        cfl_sds_cat_safe(buf, " untyped\n", 9);
    }
}

static void append_metric_value(cfl_sds_t *buf,
                                struct cmt_map *map,
                                struct cmt_metric *metric,
                                struct prom_fmt *fmt, int add_timestamp)
{
    int len;
    double val = 0.0;
    uint64_t ts;
    char tmp[128];

    /*
     * Retrieve metric value
     * ---------------------
     * the formatter 'fmt->value_from' specifies from 'where' the value must
     * be retrieved from, note the 'metric' structure contains one generic
     * value field plus others associated to histograms.
     */
    if (fmt->value_from == PROM_FMT_VAL_FROM_VAL) {
        /* get 'normal' metric value */
        val = cmt_metric_get_value(metric);
    }
    else if (fmt->value_from == PROM_FMT_VAL_FROM_BUCKET_ID) {
        /* retrieve the value from a bucket */
        val = cmt_metric_hist_get_value(metric, fmt->id);
    }
    else if (fmt->value_from == PROM_FMT_VAL_FROM_QUANTILE) {
        /* retrieve the value from a bucket */
        val = cmt_summary_quantile_get_value(metric, fmt->id);
    }
    else {
        if (map->type == CMT_HISTOGRAM) {
            if (fmt->value_from == PROM_FMT_VAL_FROM_SUM) {
                val = cmt_metric_hist_get_sum_value(metric);
            }
            else if (fmt->value_from == PROM_FMT_VAL_FROM_COUNT) {
                val = cmt_metric_hist_get_count_value(metric);
            }
        }
        else if (map->type == CMT_EXP_HISTOGRAM) {
            if (fmt->value_from == PROM_FMT_VAL_FROM_SUM) {
                val = cmt_math_uint64_to_d64(
                          cmt_atomic_load(&metric->exp_hist_sum));
            }
            else if (fmt->value_from == PROM_FMT_VAL_FROM_COUNT) {
                val = cmt_atomic_load(&metric->exp_hist_count);
            }
        }
        else if (map->type == CMT_SUMMARY) {
            if (fmt->value_from == PROM_FMT_VAL_FROM_SUM) {
                val = cmt_summary_get_sum_value(metric);
            }
            else if (fmt->value_from == PROM_FMT_VAL_FROM_COUNT) {
                val = cmt_summary_get_count_value(metric);
            }
        }
    }

    if (add_timestamp) {
        ts = cmt_metric_get_timestamp(metric);

        /* convert from nanoseconds to milliseconds */
        ts /= 1000000;

        len = snprintf(tmp, sizeof(tmp) - 1, " %.17g %" PRIu64 "\n", val, ts);
    }
    else {
        len = snprintf(tmp, sizeof(tmp) - 1, " %.17g\n", val);
    }
    cfl_sds_cat_safe(buf, tmp, len);
}

/*
 * Walks the labels of a sample in output order: static labels first, then
 * the api defined labels that have both a key and a value.
 */
struct prom_label_iter {
    struct cmt           *cmt;
    struct cmt_map       *map;
    struct cmt_metric    *metric;
    struct cfl_list      *static_head;
    struct cfl_list      *value_head;
    struct cmt_map_label *label_k;
    int                   label_index;
    int                   static_done;
};

static void prom_label_iter_init(struct prom_label_iter *iter, struct cmt *cmt,
                                 struct cmt_map *map, struct cmt_metric *metric)
{
    iter->cmt = cmt;
    iter->map = map;
    iter->metric = metric;
    iter->static_head = cmt->static_labels->list.next;
    iter->value_head = metric->labels.next;
    iter->label_k = NULL;
    iter->label_index = 0;
    iter->static_done = CMT_FALSE;

    if (map->label_count > 0) {
        iter->label_k = cfl_list_entry_first(&map->label_keys,
                                             struct cmt_map_label, _head);
    }
}

static int prom_label_iter_next(struct prom_label_iter *iter,
                                cfl_sds_t *key, cfl_sds_t *val)
{
    struct cmt_label *static_label;
    struct cmt_map_label *label_k;
    struct cmt_map_label *label_v;

    if (!iter->static_done) {
        if (iter->static_head != &iter->cmt->static_labels->list) {
            static_label = cfl_list_entry(iter->static_head, struct cmt_label, _head);
            iter->static_head = iter->static_head->next;
            *key = static_label->key;
            *val = static_label->val;
            return CMT_TRUE;
        }
        iter->static_done = CMT_TRUE;
    }

    while (iter->value_head != &iter->metric->labels &&
           iter->label_index < iter->map->label_count) {
        label_k = iter->label_k;
        label_v = cfl_list_entry(iter->value_head, struct cmt_map_label, _head);

        iter->value_head = iter->value_head->next;
        iter->label_index++;
        iter->label_k = cfl_list_entry_next(&label_k->_head, struct cmt_map_label,
                                            _head, &iter->map->label_keys);

        if (label_k->name != NULL && label_v->name != NULL) {
            *key = label_k->name;
            *val = label_v->name;
            return CMT_TRUE;
        }
    }

    return CMT_FALSE;
}

/*
 * Report if two label keys of the map samples are written under the same
 * name, computed once per map so samples without collisions take the plain
 * path in add_labels().
 */
static int label_keys_collide(struct cmt *cmt, struct cmt_map *map)
{
    struct cfl_list *head;
    struct cfl_list *other_head;
    struct cmt_label *static_label;
    struct cmt_label *other_static_label;
    struct cmt_map_label *label_k;
    struct cmt_map_label *other_label_k;

    cfl_list_foreach(head, &cmt->static_labels->list) {
        static_label = cfl_list_entry(head, struct cmt_label, _head);

        for (other_head = head->next;
             other_head != &cmt->static_labels->list;
             other_head = other_head->next) {
            other_static_label = cfl_list_entry(other_head, struct cmt_label, _head);
            if (sanitized_name_equal(static_label->key, other_static_label->key, true)) {
                return CMT_TRUE;
            }
        }

        cfl_list_foreach(other_head, &map->label_keys) {
            other_label_k = cfl_list_entry(other_head, struct cmt_map_label, _head);
            if (other_label_k->name != NULL &&
                sanitized_name_equal(static_label->key, other_label_k->name, true)) {
                return CMT_TRUE;
            }
        }
    }

    cfl_list_foreach(head, &map->label_keys) {
        label_k = cfl_list_entry(head, struct cmt_map_label, _head);
        if (label_k->name == NULL) {
            continue;
        }

        for (other_head = head->next;
             other_head != &map->label_keys;
             other_head = other_head->next) {
            other_label_k = cfl_list_entry(other_head, struct cmt_map_label, _head);
            if (other_label_k->name != NULL &&
                sanitized_name_equal(label_k->name, other_label_k->name, true)) {
                return CMT_TRUE;
            }
        }
    }

    return CMT_FALSE;
}

/*
 * Append the labels of a sample. Distinct keys can sanitize to the same
 * label name, which is invalid in the exposition format, so a colliding
 * label is written once with the values joined by ';'.
 */
static void add_labels(struct cmt *cmt, cfl_sds_t *buf, struct cmt_map *map,
                       struct cmt_metric *metric, int label_collisions,
                       struct prom_fmt *fmt)
{
    int i;
    int j;
    int duplicate;
    cfl_sds_t key;
    cfl_sds_t val;
    cfl_sds_t other_key;
    cfl_sds_t other_val;
    struct prom_label_iter iter;
    struct prom_label_iter other;

    prom_label_iter_init(&iter, cmt, map, metric);

    for (i = 0; prom_label_iter_next(&iter, &key, &val); i++) {
        if (!label_collisions) {
            if (fmt->labels_count > 0) {
                cfl_sds_cat_safe(buf, ",", 1);
            }

            metric_name_cat(buf, key, true);
            cfl_sds_cat_safe(buf, "=\"", 2);
            metric_escape(buf, val, true);
            cfl_sds_cat_safe(buf, "\"", 1);

            fmt->labels_count++;
            continue;
        }

        /* skip the label if an earlier one was written under the same name */
        duplicate = CMT_FALSE;
        prom_label_iter_init(&other, cmt, map, metric);

        for (j = 0; j < i && prom_label_iter_next(&other, &other_key, &other_val); j++) {
            if (sanitized_name_equal(other_key, key, true)) {
                duplicate = CMT_TRUE;
                break;
            }
        }

        if (duplicate) {
            continue;
        }

        if (fmt->labels_count > 0) {
            cfl_sds_cat_safe(buf, ",", 1);
        }

        metric_name_cat(buf, key, true);
        cfl_sds_cat_safe(buf, "=\"", 2);
        metric_escape(buf, val, true);

        /* join the values of the following labels with the same name */
        other = iter;
        while (prom_label_iter_next(&other, &other_key, &other_val)) {
            if (sanitized_name_equal(key, other_key, true)) {
                cfl_sds_cat_safe(buf, ";", 1);
                metric_escape(buf, other_val, true);
            }
        }

        cfl_sds_cat_safe(buf, "\"", 1);

        fmt->labels_count++;
    }
}

static void destroy_temporary_metric_labels(struct cmt_metric *metric)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cmt_map_label *label;

    cfl_list_foreach_safe(head, tmp, &metric->labels) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        cfl_list_del(&label->_head);
        cfl_sds_destroy(label->name);
        free(label);
    }
}

static int initialize_temporary_metric(struct cmt_metric *destination,
                                       struct cmt_metric *source)
{
    struct cfl_list *head;
    struct cmt_map_label *source_label;
    struct cmt_map_label *destination_label;

    memset(destination, 0, sizeof(struct cmt_metric));
    cfl_list_init(&destination->labels);

    cfl_list_foreach(head, &source->labels) {
        source_label = cfl_list_entry(head, struct cmt_map_label, _head);

        destination_label = calloc(1, sizeof(struct cmt_map_label));
        if (destination_label == NULL) {
            destroy_temporary_metric_labels(destination);
            return -1;
        }

        if (source_label->name == NULL) {
            destination_label->name = NULL;
        }
        else {
            destination_label->name = cfl_sds_create(source_label->name);
            if (destination_label->name == NULL) {
                free(destination_label);
                destroy_temporary_metric_labels(destination);
                return -1;
            }
        }

        cfl_list_add(&destination_label->_head, &destination->labels);
    }

    cmt_metric_set_timestamp(destination, cmt_metric_get_timestamp(source));

    return 0;
}

static void format_metric(struct cmt *cmt,
                          cfl_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric, int add_timestamp,
                          int label_collisions, struct prom_fmt *fmt)
{
    int static_labels = 0;
    int defined_labels = 0;
    int label_key_count;
    int label_index;
    struct cmt_map_label *label_k = NULL;
    struct cmt_map_label *label_v;
    struct cfl_list *head;
    struct cmt_opts *opts;

    opts = map->opts;

    /* Metric info */
    if (!fmt->metric_name) {
        metric_name_cat(buf, opts->fqname, false);
    }

    /* Static labels */
    static_labels = cmt_labels_count(cmt->static_labels);
    label_key_count = map->label_count;
    label_index = 0;
    if (label_key_count > 0) {
        label_k = cfl_list_entry_first(&map->label_keys, struct cmt_map_label, _head);
    }
    cfl_list_foreach(head, &metric->labels) {
        if (label_index >= label_key_count) {
            break;
        }

        label_v = cfl_list_entry(head, struct cmt_map_label, _head);
        if (label_k->name != NULL &&
            label_v->name != NULL) {
            defined_labels++;
        }

        label_index++;
        label_k = cfl_list_entry_next(&label_k->_head, struct cmt_map_label,
                                      _head, &map->label_keys);
    }

    if (!fmt->brace_open && (static_labels + defined_labels > 0)) {
        cfl_sds_cat_safe(buf, "{", 1);
    }

    /* Append static and api defined labels */
    add_labels(cmt, buf, map, metric, label_collisions, fmt);

    if (fmt->labels_count > 0) {
        cfl_sds_cat_safe(buf, "}", 1);
    }

    append_metric_value(buf, map, metric, fmt, add_timestamp);
}

static cfl_sds_t bucket_value_to_string(double val)
{
    int len;
    double parsed;
    cfl_sds_t str;

    str = cfl_sds_create_size(64);
    if (!str) {
        return NULL;
    }

    len = snprintf(str, 64, "%g", val);
    parsed = strtod(str, NULL);
    if (parsed != val || strchr(str, 'e') || strchr(str, 'E')) {
        len = snprintf(str, 64, "%.17g", val);
    }
    cfl_sds_len_set(str, len);

    /*
     * Append .0 only when there is no decimal point and the number
     * is finite and not in scientific notation.
     */
    if (isfinite(val) &&
        !strchr(str, '.') && !strchr(str, 'e') && !strchr(str, 'E')) {
        cfl_sds_cat_safe(&str, ".0", 2);
    }

    return str;
}

static void format_histogram_bucket(struct cmt *cmt,
                                    cfl_sds_t *buf, struct cmt_map *map,
                                    struct cmt_metric *metric, int add_timestamp,
                                    int label_collisions, int include_sum)
{
    int i;
    cfl_sds_t val;
    struct cmt_histogram *histogram;
    struct cmt_histogram_buckets *bucket;
    struct cmt_opts *opts;
    struct prom_fmt fmt = {0};

    histogram = (struct cmt_histogram *) map->parent;
    bucket = histogram->buckets;
    opts = map->opts;

    for (i = 0; i <= bucket->count; i++) {
        /* metric name */
        metric_name_cat(buf, opts->fqname, false);
        cfl_sds_cat_safe(buf, "_bucket", 7);

        /* upper bound */
        cfl_sds_cat_safe(buf, "{le=\"", 5);

        if (i < bucket->count) {
            val = bucket_value_to_string(bucket->upper_bounds[i]);
            cfl_sds_cat_safe(buf, val, cfl_sds_len(val));
            cfl_sds_destroy(val);
        }
        else {
            cfl_sds_cat_safe(buf, "+Inf", 4);
        }
        cfl_sds_cat_safe(buf, "\"", 1);

        /* configure formatter */
        fmt.metric_name  = CMT_TRUE;
        fmt.brace_open   = CMT_TRUE;
        fmt.labels_count = 1;
        fmt.value_from   = PROM_FMT_VAL_FROM_BUCKET_ID;
        fmt.id           = i;

        /* append metric labels, value and timestamp */
        format_metric(cmt, buf, map, metric, add_timestamp, label_collisions, &fmt);
    }

    if (include_sum) {
        /* sum */
        prom_fmt_init(&fmt);
        fmt.metric_name = CMT_TRUE;
        fmt.value_from = PROM_FMT_VAL_FROM_SUM;

        metric_name_cat(buf, opts->fqname, false);
        cfl_sds_cat_safe(buf, "_sum", 4);
        format_metric(cmt, buf, map, metric, add_timestamp, label_collisions, &fmt);
    }

    /* count */
    prom_fmt_init(&fmt);
    fmt.metric_name = CMT_TRUE;
    fmt.labels_count = 0;
    fmt.value_from = PROM_FMT_VAL_FROM_COUNT;

    metric_name_cat(buf, opts->fqname, false);
    cfl_sds_cat_safe(buf, "_count", 6);
    format_metric(cmt, buf, map, metric, add_timestamp, label_collisions, &fmt);
}

static void format_summary_quantiles(struct cmt *cmt,
                                     cfl_sds_t *buf, struct cmt_map *map,
                                     struct cmt_metric *metric, int add_timestamp,
                                     int label_collisions)
{
    int i;
    cfl_sds_t val;
    struct cmt_summary *summary;
    struct cmt_opts *opts;
    struct prom_fmt fmt = {0};

    summary = (struct cmt_summary *) map->parent;
    opts = map->opts;

    if (cmt_atomic_load(&metric->sum_quantiles_set)) {
        for (i = 0; i < summary->quantiles_count; i++) {
            /* metric name */
            metric_name_cat(buf, opts->fqname, false);

            /* quantiles */
            cfl_sds_cat_safe(buf, "{quantile=\"", 11);
            val = bucket_value_to_string(summary->quantiles[i]);
            cfl_sds_cat_safe(buf, val, cfl_sds_len(val));
            cfl_sds_destroy(val);
            cfl_sds_cat_safe(buf, "\"", 1);

            /* configure formatter */
            fmt.metric_name  = CMT_TRUE;
            fmt.brace_open   = CMT_TRUE;
            fmt.labels_count = 1;
            fmt.value_from   = PROM_FMT_VAL_FROM_QUANTILE;
            fmt.id           = i;

            /* append metric labels, value and timestamp */
            format_metric(cmt, buf, map, metric, add_timestamp, label_collisions, &fmt);
        }
    }

    /* sum */
    prom_fmt_init(&fmt);
    fmt.metric_name = CMT_TRUE;
    fmt.value_from = PROM_FMT_VAL_FROM_SUM;

    metric_name_cat(buf, opts->fqname, false);
    cfl_sds_cat_safe(buf, "_sum", 4);
    format_metric(cmt, buf, map, metric, add_timestamp, label_collisions, &fmt);

    /* count */
    fmt.labels_count = 0;
    fmt.value_from = PROM_FMT_VAL_FROM_COUNT;

    metric_name_cat(buf, opts->fqname, false);
    cfl_sds_cat_safe(buf, "_count", 6);
    format_metric(cmt, buf, map, metric, add_timestamp, label_collisions, &fmt);
}

static void format_metrics(struct cmt *cmt, cfl_sds_t *buf, struct cmt_map *map,
                           int add_timestamp)
{
    int banner_set = CMT_FALSE;
    int label_collisions;
    struct cfl_list *head;
    struct cmt_metric *metric;
    struct prom_fmt fmt = {0};

    label_collisions = label_keys_collide(cmt, map);

    /* Simple metric, no labels */
    if (map->metric_static_set) {
        metric_banner(buf, map, &map->metric);
        banner_set = CMT_TRUE;

        if (map->type == CMT_HISTOGRAM) {
            /* Histogram needs to format the buckets, one line per bucket */
            format_histogram_bucket(cmt, buf, map, &map->metric, add_timestamp,
                                    label_collisions, CMT_TRUE);
        }
        else if (map->type == CMT_EXP_HISTOGRAM) {
            struct cmt_map fake_map;
            struct cmt_metric fake_metric;
            struct cmt_histogram fake_histogram;
            struct cmt_histogram_buckets fake_buckets;
            size_t bucket_count;
            size_t upper_bounds_count;
            uint64_t *bucket_values;
            double *upper_bounds;

            if (cmt_exp_histogram_to_explicit(&map->metric,
                                              &upper_bounds,
                                              &upper_bounds_count,
                                              &bucket_values,
                                              &bucket_count) == 0) {
                memset(&fake_map, 0, sizeof(struct cmt_map));
                memset(&fake_histogram, 0, sizeof(struct cmt_histogram));
                memset(&fake_buckets, 0, sizeof(struct cmt_histogram_buckets));

                fake_buckets.count = upper_bounds_count;
                fake_buckets.upper_bounds = upper_bounds;
                fake_histogram.buckets = &fake_buckets;

                fake_map = *map;
                fake_map.type = CMT_HISTOGRAM;
                fake_map.parent = &fake_histogram;
                if (initialize_temporary_metric(&fake_metric, &map->metric) == 0) {
                    fake_metric.hist_buckets = bucket_values;
                    fake_metric.hist_count = bucket_values[bucket_count - 1];
                    fake_metric.hist_sum = cmt_atomic_load(&map->metric.exp_hist_sum);

                    format_histogram_bucket(cmt, buf, &fake_map, &fake_metric,
                                            add_timestamp, label_collisions,
                                            cmt_atomic_load(&map->metric.exp_hist_sum_set));

                    destroy_temporary_metric_labels(&fake_metric);
                }

                free(bucket_values);
                free(upper_bounds);
            }
        }
        else if (map->type == CMT_SUMMARY) {
            /* Histogram needs to format the buckets, one line per bucket */
            format_summary_quantiles(cmt, buf, map, &map->metric, add_timestamp,
                                     label_collisions);
        }
        else {
            prom_fmt_init(&fmt);
            format_metric(cmt, buf, map, &map->metric, add_timestamp,
                          label_collisions, &fmt);
        }
    }

    if (cfl_list_size(&map->metrics) > 0) {
        metric = cfl_list_entry_first(&map->metrics, struct cmt_metric, _head);
        if (!banner_set) {
            metric_banner(buf, map, metric);
        }
    }

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);

        /* Format the metric based on its type */
        if (map->type == CMT_HISTOGRAM) {
            /* Histogram needs to format the buckets, one line per bucket */
            format_histogram_bucket(cmt, buf, map, metric, add_timestamp,
                                    label_collisions, CMT_TRUE);
        }
        else if (map->type == CMT_EXP_HISTOGRAM) {
            struct cmt_map fake_map;
            struct cmt_metric fake_metric;
            struct cmt_histogram fake_histogram;
            struct cmt_histogram_buckets fake_buckets;
            size_t bucket_count;
            size_t upper_bounds_count;
            uint64_t *bucket_values;
            double *upper_bounds;

            if (cmt_exp_histogram_to_explicit(metric,
                                              &upper_bounds,
                                              &upper_bounds_count,
                                              &bucket_values,
                                              &bucket_count) == 0) {
                memset(&fake_map, 0, sizeof(struct cmt_map));
                memset(&fake_histogram, 0, sizeof(struct cmt_histogram));
                memset(&fake_buckets, 0, sizeof(struct cmt_histogram_buckets));

                fake_buckets.count = upper_bounds_count;
                fake_buckets.upper_bounds = upper_bounds;
                fake_histogram.buckets = &fake_buckets;

                fake_map = *map;
                fake_map.type = CMT_HISTOGRAM;
                fake_map.parent = &fake_histogram;
                if (initialize_temporary_metric(&fake_metric, metric) != 0) {
                    free(bucket_values);
                    free(upper_bounds);
                    continue;
                }

                fake_metric.hist_buckets = bucket_values;
                fake_metric.hist_count = bucket_values[bucket_count - 1];
                fake_metric.hist_sum = cmt_atomic_load(&metric->exp_hist_sum);

                format_histogram_bucket(cmt, buf, &fake_map, &fake_metric,
                                        add_timestamp, label_collisions,
                                        cmt_atomic_load(&metric->exp_hist_sum_set));

                destroy_temporary_metric_labels(&fake_metric);
                free(bucket_values);
                free(upper_bounds);
            }
        }
        else if (map->type == CMT_SUMMARY) {
            format_summary_quantiles(cmt, buf, map, metric, add_timestamp,
                                     label_collisions);
        }
        else {
            prom_fmt_init(&fmt);
            format_metric(cmt, buf, map, metric, add_timestamp, label_collisions, &fmt);
        }
    }
}

/*
 * Distinct metric names can sanitize to the same name, and a metric family
 * must be described once. Only the first name written under a sanitized name
 * is kept, maps sharing the exact same name (a family split across maps by
 * the decoders) are all written. Only a name changed by sanitizing can
 * collide with a different name, so the names are indexed only when such a
 * name exists.
 */
struct prom_name_entry {
    uint64_t  hash;
    cfl_sds_t name;
};

struct prom_encoder {
    struct cmt             *cmt;
    cfl_sds_t              *buf;
    int                     add_timestamp;
    size_t                  maps_count;   /* maps with samples */
    int                     sanitized;    /* a name is changed by sanitizing */
    struct prom_name_entry *names;        /* open addressing, NULL if unused */
    size_t                  names_size;   /* power of two */
};

/* FNV-1a of the name as written by metric_name_cat() */
static uint64_t sanitized_name_hash(cfl_sds_t name)
{
    size_t   i;
    size_t   len;
    uint64_t hash;

    hash = 14695981039346656037ULL;
    len = cfl_sds_len(name);

    if (len > 0 && name[0] >= '0' && name[0] <= '9') {
        hash ^= (unsigned char) '_';
        hash *= 1099511628211ULL;
    }

    for (i = 0; i < len; i++) {
        hash ^= (unsigned char) sanitize_name_char(name[i], false);
        hash *= 1099511628211ULL;
    }

    return hash;
}

/*
 * Return the name already written under the sanitized form of 'name', or
 * register 'name' and return it.
 */
static cfl_sds_t prom_names_claim(struct prom_encoder *encoder, cfl_sds_t name)
{
    size_t                  index;
    size_t                  mask;
    uint64_t                hash;
    struct prom_name_entry *entry;

    hash = sanitized_name_hash(name);
    mask = encoder->names_size - 1;
    index = (size_t) hash & mask;

    while (1) {
        entry = &encoder->names[index];

        if (entry->name == NULL) {
            entry->hash = hash;
            entry->name = name;
            return name;
        }

        if (entry->hash == hash &&
            sanitized_name_equal(entry->name, name, false)) {
            return entry->name;
        }

        index = (index + 1) & mask;
    }
}

static int metric_name_is_valid(cfl_sds_t name)
{
    size_t i;
    size_t len;

    len = cfl_sds_len(name);

    if (len > 0 && name[0] >= '0' && name[0] <= '9') {
        return CMT_FALSE;
    }

    for (i = 0; i < len; i++) {
        if (sanitize_name_char(name[i], false) != name[i]) {
            return CMT_FALSE;
        }
    }

    return CMT_TRUE;
}

static int map_has_samples(struct cmt_map *map)
{
    return map->metric_static_set || cfl_list_size(&map->metrics) > 0;
}

static int walk_maps(struct cmt *cmt,
                     int (*callback)(struct prom_encoder *, struct cmt_map *),
                     struct prom_encoder *encoder)
{
    int ret = 0;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_untyped *untyped;

    /* Counters */
    cfl_list_foreach(head, &cmt->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        if ((ret = callback(encoder, counter->map)) != 0) {
            return ret;
        }
    }

    /* Gauges */
    cfl_list_foreach(head, &cmt->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        if ((ret = callback(encoder, gauge->map)) != 0) {
            return ret;
        }
    }

    /* Summaries */
    cfl_list_foreach(head, &cmt->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        if ((ret = callback(encoder, summary->map)) != 0) {
            return ret;
        }
    }

    /* Histograms */
    cfl_list_foreach(head, &cmt->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        if ((ret = callback(encoder, histogram->map)) != 0) {
            return ret;
        }
    }

    /* Exponential Histograms */
    cfl_list_foreach(head, &cmt->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        if ((ret = callback(encoder, exp_histogram->map)) != 0) {
            return ret;
        }
    }

    /* Untyped */
    cfl_list_foreach(head, &cmt->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        if ((ret = callback(encoder, untyped->map)) != 0) {
            return ret;
        }
    }

    return ret;
}

static int inspect_map(struct prom_encoder *encoder, struct cmt_map *map)
{
    if (!map_has_samples(map)) {
        return 0;
    }

    encoder->maps_count++;

    if (!encoder->sanitized && !metric_name_is_valid(map->opts->fqname)) {
        encoder->sanitized = CMT_TRUE;
    }

    return 0;
}

static int format_map(struct prom_encoder *encoder, struct cmt_map *map)
{
    cfl_sds_t fqname;
    cfl_sds_t written;

    /* maps without samples do not write anything */
    if (!map_has_samples(map)) {
        return 0;
    }

    fqname = map->opts->fqname;

    if (encoder->names != NULL) {
        written = prom_names_claim(encoder, fqname);

        if (written != fqname &&
            (cfl_sds_len(written) != cfl_sds_len(fqname) ||
             memcmp(written, fqname, cfl_sds_len(fqname)) != 0)) {
            /* a different name was already written under this name */
            return 0;
        }
    }

    format_metrics(encoder->cmt, encoder->buf, map, encoder->add_timestamp);

    return 0;
}

/* Format all the registered metrics in Prometheus Text format */
cfl_sds_t cmt_encode_prometheus_create(struct cmt *cmt, int add_timestamp)
{
    int ret;
    cfl_sds_t buf;
    struct prom_encoder encoder = {0};

    /* Allocate a 1KB of buffer */
    buf = cfl_sds_create_size(1024);
    if (!buf) {
        return NULL;
    }

    encoder.cmt = cmt;
    encoder.buf = &buf;
    encoder.add_timestamp = add_timestamp;

    walk_maps(cmt, inspect_map, &encoder);

    if (encoder.sanitized) {
        /* keep the table at most half full */
        encoder.names_size = 16;
        while (encoder.names_size < encoder.maps_count * 2) {
            encoder.names_size *= 2;
        }

        encoder.names = calloc(encoder.names_size, sizeof(struct prom_name_entry));
        if (encoder.names == NULL) {
            cmt_errno();
            cfl_sds_destroy(buf);
            return NULL;
        }
    }

    ret = walk_maps(cmt, format_map, &encoder);

    free(encoder.names);

    if (ret != 0) {
        cfl_sds_destroy(buf);
        return NULL;
    }

    return buf;
}

void cmt_encode_prometheus_destroy(cfl_sds_t text)
{
    cfl_sds_destroy(text);
}
