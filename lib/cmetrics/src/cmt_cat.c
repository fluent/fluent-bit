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
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>

static int copy_label_keys(struct cmt_map *map, char **out)
{
    int i;
    int s;
    char **labels = NULL;
    struct mk_list *head;
    struct cmt_map_label *label;

    /* labels array */
    s = map->label_count;
    if (s == 0) {
        *out = NULL;
        return 0;
    }

    if (s > 0) {
        labels = malloc(sizeof(char *) * s);
        if (!labels) {
            cmt_errno();
            return -1;
        }
    }

    /* label keys: by using the labels array, just point out the names */
    i = 0;
    mk_list_foreach(head, &map->label_keys) {
        label = mk_list_entry(head, struct cmt_map_label, _head);
        labels[i] = label->name;
        i++;
    }

    *out = (char *) labels;
    return i;
}

static int copy_label_values(struct cmt_metric *metric, char **out)
{
    int i;
    int s;
    char **labels = NULL;
    struct mk_list *head;
    struct cmt_map_label *label;

    /* labels array */
    s = mk_list_size(&metric->labels);
    if (s == 0) {
        *out = NULL;
        return 0;
    }

    if (s > 0) {
        labels = malloc(sizeof(char *) * s);
        if (!labels) {
            cmt_errno();
            return -1;
        }
    }

    /* label keys: by using the labels array, just point out the names */
    i = 0;
    mk_list_foreach(head, &metric->labels) {
        label = mk_list_entry(head, struct cmt_map_label, _head);
        labels[i] = label->name;
        i++;
    }

    *out = (char *) labels;
    return i;
}

static int copy_map(struct cmt_opts *opts, struct cmt_map *dst, struct cmt_map *src)
{
    int c;
    int ret;
    uint64_t ts;
    double val;
    char **labels = NULL;
    struct mk_list *head;
    struct cmt_metric *metric_dst;
    struct cmt_metric *metric_src;

    /* Handle static metric (no labels case) */
    if (src->metric_static_set) {
        dst->metric_static_set = CMT_TRUE;

        /* destination and source metric */
        metric_dst = &dst->metric;
        metric_src = &src->metric;

        ts  = cmt_metric_get_timestamp(metric_src);
        val = cmt_metric_get_value(metric_src);

        cmt_metric_set(metric_dst, ts, val);
    }

    /* Process map dynamic metrics */
    mk_list_foreach(head, &src->metrics) {
        metric_src = mk_list_entry(head, struct cmt_metric, _head);

        ret = copy_label_values(metric_src, (char **) &labels);
        if (ret == -1) {
            return -1;
        }

        c = mk_list_size(&metric_src->labels);
        metric_dst = cmt_map_metric_get(opts, dst, c, labels, CMT_TRUE);
        free(labels);

        if (!metric_dst) {
            return -1;
        }

        ts  = cmt_metric_get_timestamp(metric_src);
        val = cmt_metric_get_value(metric_src);

        cmt_metric_set(metric_dst, ts, val);
    }

    return 0;

}

static int copy_counter(struct cmt *cmt, struct cmt_counter *counter)
{
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_counter *c;

    map = counter->map;
    opts = map->opts;

    ret = copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    /* create counter */
    c = cmt_counter_create(cmt,
                           opts->ns, opts->subsystem,
                           opts->name, opts->description,
                           map->label_count, labels);

    free(labels);
    if (!c) {
        return -1;
    }

    ret = copy_map(&c->opts, c->map, map);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int copy_gauge(struct cmt *cmt, struct cmt_gauge *gauge)
{
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_gauge *g;

    map = gauge->map;
    opts = map->opts;

    ret = copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    /* create counter */
    g = cmt_gauge_create(cmt,
                         opts->ns, opts->subsystem,
                         opts->name, opts->description,
                         map->label_count, labels);
    free(labels);
    if (!g) {
        return -1;
    }

    ret = copy_map(&g->opts, g->map, map);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int copy_untyped(struct cmt *cmt, struct cmt_untyped *untyped)
{
    int ret;
    char **labels = NULL;
    struct cmt_map *map;
    struct cmt_opts *opts;
    struct cmt_untyped *u;

    map = untyped->map;
    opts = map->opts;

    ret = copy_label_keys(map, (char **) &labels);
    if (ret == -1) {
        return -1;
    }

    /* create counter */
    u = cmt_untyped_create(cmt,
                           opts->ns, opts->subsystem,
                           opts->name, opts->description,
                           map->label_count, labels);
    free(labels);
    if (!u) {
        return -1;
    }

    ret = copy_map(&u->opts, u->map, map);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

static int append_context(struct cmt *dst, struct cmt *src)
{
    int ret;
    struct mk_list *head;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;

     /* Counters */
    mk_list_foreach(head, &src->counters) {
        counter = mk_list_entry(head, struct cmt_counter, _head);
        ret = copy_counter(dst, counter);
        if (ret == -1) {
            return -1;
        }
    }

    /* Gauges */
    mk_list_foreach(head, &src->gauges) {
        gauge = mk_list_entry(head, struct cmt_gauge, _head);
        ret = copy_gauge(dst, gauge);
        if (ret == -1) {
            return -1;
        }
    }

    /* Untyped */
    mk_list_foreach(head, &src->untypeds) {
        untyped = mk_list_entry(head, struct cmt_untyped, _head);
        ret = copy_untyped(dst, untyped);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

int cmt_cat(struct cmt *dst, struct cmt *src)
{
    if (!dst) {
        return -1;
    }

    if (!src) {
        return -1;
    }

    return append_context(dst, src);
}
