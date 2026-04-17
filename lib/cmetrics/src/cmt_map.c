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
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_log.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_compat.h>

struct cmt_map *cmt_map_create(int type, struct cmt_opts *opts, int count, char **labels,
                               void *parent)
{
    int i;
    char *name;
    struct cmt_map *map;
    struct cmt_map_label *label;

    if (count < 0) {
        return NULL;
    }

    map = calloc(1, sizeof(struct cmt_map));
    if (!map) {
        cmt_errno();
        return NULL;
    }
    map->type = type;
    map->opts = opts;
    map->parent = parent;
    map->label_count = count;
    cfl_list_init(&map->label_keys);
    cfl_list_init(&map->metrics);
    cfl_list_init(&map->metric.labels);

    if (count == 0) {
        map->metric_static_set = 1;
    }

    for (i = 0; i < count; i++) {
        label = malloc(sizeof(struct cmt_map_label));
        if (!label) {
            cmt_errno();
            goto error;
        }

        name = labels[i];
        label->name = cfl_sds_create(name);
        if (!label->name) {
            cmt_errno();
            free(label);
            goto error;
        }
        cfl_list_add(&label->_head, &map->label_keys);
    }

    return map;

 error:
    cmt_map_destroy(map);
    return NULL;
}

static struct cmt_metric *metric_hash_lookup(struct cmt_map *map, uint64_t hash)
{
    struct cfl_list *head;
    struct cmt_metric *metric;

    if (hash == 0) {
        return &map->metric;
    }

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        if (metric->hash == hash) {
            return metric;
        }
    }

    return NULL;
}

static struct cmt_metric *map_metric_create(uint64_t hash,
                                            int labels_count, char **labels_val)
{
    int i;
    char *name;
    struct cmt_metric *metric;
    struct cmt_map_label *label;

    metric = calloc(1, sizeof(struct cmt_metric));
    if (!metric) {
        cmt_errno();
        return NULL;
    }
    cfl_list_init(&metric->labels);
    cmt_metric_set_double(metric, 0, 0.0);
    metric->hash = hash;

    for (i = 0; i < labels_count; i++) {
        label = malloc(sizeof(struct cmt_map_label));
        if (!label) {
            cmt_errno();
            goto error;
        }

        name = labels_val[i];
        label->name = cfl_sds_create(name);
        if (!label->name) {
            cmt_errno();
            free(label);
            goto error;
        }
        cfl_list_add(&label->_head, &metric->labels);
    }

    return metric;

 error:
    free(metric);
    return NULL;
}

void cmt_map_metric_destroy(struct cmt_metric *metric)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_map_label *label;

    cfl_list_foreach_safe(head, tmp, &metric->labels) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        cfl_sds_destroy(label->name);
        cfl_list_del(&label->_head);
        free(label);
    }

    if (metric->hist_buckets) {
        free(metric->hist_buckets);
    }
    if (metric->exp_hist_positive_buckets) {
        free(metric->exp_hist_positive_buckets);
    }
    if (metric->exp_hist_negative_buckets) {
        free(metric->exp_hist_negative_buckets);
    }
    if (metric->sum_quantiles) {
        free(metric->sum_quantiles);
    }

    cfl_list_del(&metric->_head);
    free(metric);
}

struct cmt_metric *cmt_map_metric_get(struct cmt_opts *opts, struct cmt_map *map,
                                      int labels_count, char **labels_val,
                                      int write_op)
{
    int i;
    int len;
    char *ptr;
    uint64_t hash;
    cfl_hash_state_t state;
    struct cmt_metric *metric = NULL;

    /* Enforce zero or exact labels */
    if (labels_count > 0 && labels_count != map->label_count) {
        return NULL;
    }

    /*
     * If the caller wants the no-labeled metric (metric_static_set) make sure
     * it was already pre-defined.
     */
    if (labels_count == 0) {
        /*
         * if an upcoming 'write operation' will be performed for a default
         * static metric, just initialize it and return it.
         */
        if (map->metric_static_set) {
            metric = &map->metric;
        }
        else if (write_op) {
            metric = &map->metric;
            if (!map->metric_static_set) {
                map->metric_static_set = 1;
            }
        }

        /* return the proper context or NULL */
        return metric;
    }

    /* Lookup the metric */
    cfl_hash_64bits_reset(&state);
    cfl_hash_64bits_update(&state, opts->fqname, cfl_sds_len(opts->fqname));
    for (i = 0; i < labels_count; i++) {
        ptr = labels_val[i];
        if (!ptr) {
            cfl_hash_64bits_update(&state, "_NULL_", 6);
        }
        else {
            len = strlen(ptr);
            cfl_hash_64bits_update(&state, ptr, len);
        }
    }

    hash = cfl_hash_64bits_digest(&state);
    metric = metric_hash_lookup(map, hash);

    if (metric) {
        return metric;
    }

    /*
     * If the metric was not found and the caller will not write a value, just
     * return NULL.
     */
    if (!write_op) {
        return NULL;
    }

    /* If the metric has not been found, just create it */
    metric = map_metric_create(hash, labels_count, labels_val);
    if (!metric) {
        return NULL;
    }
    cfl_list_add(&metric->_head, &map->metrics);
    return metric;
}

int cmt_map_metric_get_val(struct cmt_opts *opts, struct cmt_map *map,
                           int labels_count, char **labels_val,
                           double *out_val)
{
    double val = 0;
    struct cmt_metric *metric;

    metric = cmt_map_metric_get(opts, map, labels_count, labels_val, CMT_FALSE);
    if (!metric) {
        return -1;
    }

    val = cmt_metric_get_value(metric);
    *out_val = val;
    return 0;
}

void cmt_map_destroy(struct cmt_map *map)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_map_label *label;
    struct cmt_metric *metric;

    cfl_list_foreach_safe(head, tmp, &map->label_keys) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        cfl_sds_destroy(label->name);
        cfl_list_del(&label->_head);
        free(label);
    }

    cfl_list_foreach_safe(head, tmp, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        cmt_map_metric_destroy(metric);
    }

    /* histogram and quantile allocation for static metric */
    if (map->metric_static_set) {
        metric = &map->metric;

        if (map->type == CMT_HISTOGRAM) {
            if (metric->hist_buckets) {
                free(metric->hist_buckets);
            }
        }
        else if (map->type == CMT_EXP_HISTOGRAM) {
            if (metric->exp_hist_positive_buckets) {
                free(metric->exp_hist_positive_buckets);
            }
            if (metric->exp_hist_negative_buckets) {
                free(metric->exp_hist_negative_buckets);
            }
        }
        else if (map->type == CMT_SUMMARY) {
            if (metric->sum_quantiles) {
                free(metric->sum_quantiles);
            }
        }
    }

    if (map->unit != NULL) {
        cfl_sds_destroy(map->unit);
    }

    free(map);
}

/* I don't know if we should leave this or promote the label type so it has its own
 * header and source files with their own constructor / destructor and an agnostic name.
 * That last bit comes from the fact that we are using the cmt_map_label type both in the
 * dimension definition list held by the map structure and the dimension value list held
 * by the metric structure.
 */

void destroy_label_list(struct cfl_list *label_list)
{
    struct cfl_list       *tmp;
    struct cfl_list       *head;
    struct cmt_map_label *label;

    cfl_list_foreach_safe(head, tmp, label_list) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);

        cfl_sds_destroy(label->name);

        cfl_list_del(&label->_head);

        free(label);
    }
}
