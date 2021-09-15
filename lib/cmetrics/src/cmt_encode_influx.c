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
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_compat.h>

#include <ctype.h>

/*
 * Influx wire protocol
 * --------------------
 * https://docs.influxdata.com/influxdb/cloud/reference/syntax/line-protocol/
 */

static void append_metric_value(struct cmt_map *map,
                                cmt_sds_t *buf, struct cmt_metric *metric)
{
    int len;
    uint64_t ts;
    double val;
    char tmp[256];
    struct cmt_opts *opts;

    opts = map->opts;

    /* Retrieve metric value */
    val = cmt_metric_get_value(metric);

    ts = cmt_metric_get_timestamp(metric);
    len = snprintf(tmp, sizeof(tmp) - 1, "=%.17g %" PRIu64 "\n", val, ts);

    cmt_sds_cat_safe(buf, opts->name, cmt_sds_len(opts->name));
    cmt_sds_cat_safe(buf, tmp, len);

}

static int line_protocol_escape(const char *str_in, int size_in,
                                char *str_out, int quote)
{
    int i;
    int size_out = 0;
    char ch;

    for (i = 0; i < size_in; ++i) {
        ch = str_in[i];
        if (quote ? (ch == '"' || ch == '\\') : (isspace(ch) || ch == ',' || ch == '=')) {
            str_out[size_out++] = '\\';
        }
        else if (ch == '\\') {
            str_out[size_out++] = '\\';
        }
        str_out[size_out++] = ch;
    }

    return size_out;
}

static int append_string(cmt_sds_t *buf, cmt_sds_t str)
{
    int len;
    int size;
    char *esc_buf;

    len = cmt_sds_len(str);
    esc_buf = malloc(len * 2);
    if (!esc_buf) {
        cmt_errno();
        return -1;
    }

    size = line_protocol_escape(str, len, esc_buf, 0);
    cmt_sds_cat_safe(buf, esc_buf, size);

    free(esc_buf);
    return 0;
}

static void format_metric(struct cmt *cmt, cmt_sds_t *buf, struct cmt_map *map,
                          struct cmt_metric *metric)
{
    int i;
    int n;
    int count = 0;
    int static_labels = 0;
    struct cmt_map_label *label_k;
    struct cmt_map_label *label_v;
    struct mk_list *head;
    struct cmt_opts *opts;
    struct cmt_label *slabel;

    opts = map->opts;

    /* Measurement */
    cmt_sds_cat_safe(buf, opts->ns, cmt_sds_len(opts->ns));

    if (cmt_sds_len(opts->subsystem) > 0) {
        cmt_sds_cat_safe(buf, "_", 1);
        cmt_sds_cat_safe(buf, opts->subsystem, cmt_sds_len(opts->subsystem));
    }

    /* Static labels (tags) */
    static_labels = cmt_labels_count(cmt->static_labels);
    if (static_labels > 0) {
        cmt_sds_cat_safe(buf, ",", 1);
        mk_list_foreach(head, &cmt->static_labels->list) {
            count++;
            slabel = mk_list_entry(head, struct cmt_label, _head);

            /* key */
            append_string(buf, slabel->key);

            /* = */
            cmt_sds_cat_safe(buf, "=", 1);

            /* val */
            append_string(buf, slabel->val);

            if (count < static_labels) {
                cmt_sds_cat_safe(buf, ",", 1);
            }
        }
    }

    /* Labels / Tags */
    n = mk_list_size(&metric->labels);
    if (n > 0) {
        cmt_sds_cat_safe(buf, ",", 1);

        label_k = mk_list_entry_first(&map->label_keys, struct cmt_map_label, _head);

        i = 1;
        mk_list_foreach(head, &metric->labels) {
            label_v = mk_list_entry(head, struct cmt_map_label, _head);

            /* key */
            append_string(buf, label_k->name);
            cmt_sds_cat_safe(buf, "=", 1);
            append_string(buf, label_v->name);

            if (i < n) {
                cmt_sds_cat_safe(buf, ",", 1);
            }
            i++;

            label_k = mk_list_entry_next(&label_k->_head, struct cmt_map_label,
                                         _head, &map->label_keys);
        }
    }

    cmt_sds_cat_safe(buf, " ", 1);
    append_metric_value(map, buf, metric);
}

static void format_metrics(struct cmt *cmt,
                           cmt_sds_t *buf, struct cmt_map *map, int add_timestamp)
{
    struct mk_list *head;
    struct cmt_metric *metric;

    /* Simple metric, no labels */
    if (map->metric_static_set == 1) {
        format_metric(cmt, buf, map, &map->metric);
    }

    mk_list_foreach(head, &map->metrics) {
        metric = mk_list_entry(head, struct cmt_metric, _head);
        format_metric(cmt, buf, map, metric);
    }
}

/* Format all the registered metrics in Prometheus Text format */
cmt_sds_t cmt_encode_influx_create(struct cmt *cmt, int add_timestamp, ...)
{
    cmt_sds_t buf;
    struct mk_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;

    /* Allocate a 1KB of buffer */
    buf = cmt_sds_create_size(1024);
    if (!buf) {
        return NULL;
    }

    /* Counters */
    mk_list_foreach(head, &cmt->counters) {
        counter = mk_list_entry(head, struct cmt_counter, _head);
        format_metrics(cmt, &buf, counter->map, add_timestamp);
    }

    /* Gauges */
    mk_list_foreach(head, &cmt->gauges) {
        gauge = mk_list_entry(head, struct cmt_gauge, _head);
        format_metrics(cmt, &buf, gauge->map, add_timestamp);
    }

    /* Untyped */
    mk_list_foreach(head, &cmt->untypeds) {
        untyped = mk_list_entry(head, struct cmt_untyped, _head);
        format_metrics(cmt, &buf, untyped->map, add_timestamp);
    }

    return buf;
}

void cmt_encode_influx_destroy(cmt_sds_t text)
{
    cmt_sds_destroy(text);
}
