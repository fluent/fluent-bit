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
#include <cmetrics/cmt_atomic.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_compat.h>

#define CMT_MAP_INITIAL_BUCKET_COUNT 64
#define CMT_MAP_BUCKET_LOAD_FACTOR   4

static void map_lock(struct cmt_map *map)
{
    while (cmt_atomic_compare_exchange(&map->metric_lock, 0, 1) == 0) {
    }
}

static void map_unlock(struct cmt_map *map)
{
    cmt_atomic_store(&map->metric_lock, 0);
}

static void metric_release_storage(struct cmt_metric *metric)
{
    free(metric->hist_buckets);
    free(metric->exp_hist_positive_buckets);
    free(metric->exp_hist_negative_buckets);
    free(metric->sum_quantiles);

    metric->hist_buckets = NULL;
    metric->exp_hist_positive_buckets = NULL;
    metric->exp_hist_negative_buckets = NULL;
    metric->sum_quantiles = NULL;
}

static int metric_index_resize(struct cmt_map *map, size_t bucket_count)
{
    size_t index;
    struct cfl_list *head;
    struct cfl_list *buckets;
    struct cmt_metric *metric;

    buckets = calloc(bucket_count, sizeof(struct cfl_list));
    if (buckets == NULL) {
        return -1;
    }
    for (index = 0; index < bucket_count; index++) {
        cfl_list_init(&buckets[index]);
    }

    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        if (metric->hash_indexed) {
            cfl_list_del(&metric->_hash_head);
            cfl_list_add(&metric->_hash_head,
                         &buckets[metric->hash % bucket_count]);
        }
    }

    free(map->metric_buckets);
    map->metric_buckets = buckets;
    map->metric_bucket_count = bucket_count;
    return 0;
}

static void metric_index_add(struct cmt_map *map, struct cmt_metric *metric)
{
    if (metric->hash_indexed) {
        return;
    }

    if (map->metric_buckets == NULL &&
        metric_index_resize(map, CMT_MAP_INITIAL_BUCKET_COUNT) != 0) {
        return;
    }

    if (map->indexed_metric_count >=
        map->metric_bucket_count * CMT_MAP_BUCKET_LOAD_FACTOR) {
        metric_index_resize(map, map->metric_bucket_count * 2);
    }

    cfl_list_add(&metric->_hash_head,
                 &map->metric_buckets[metric->hash % map->metric_bucket_count]);
    metric->hash_indexed = CMT_TRUE;
    metric->map = map;
    map->indexed_metric_count++;
}

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

    if (count > 0 &&
        metric_index_resize(map, CMT_MAP_INITIAL_BUCKET_COUNT) != 0) {
        cmt_errno();
        cmt_map_destroy(map);
        return NULL;
    }

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

static int metric_labels_match(struct cmt_metric *metric,
                               int labels_count, char **labels_val)
{
    int index = 0;
    struct cfl_list *head;
    struct cmt_map_label *label;

    cfl_list_foreach(head, &metric->labels) {
        if (index >= labels_count) {
            return CMT_FALSE;
        }

        label = cfl_list_entry(head, struct cmt_map_label, _head);
        if ((label->name == NULL) != (labels_val[index] == NULL)) {
            return CMT_FALSE;
        }
        if (label->name != NULL && strcmp(label->name, labels_val[index]) != 0) {
            return CMT_FALSE;
        }
        index++;
    }

    return index == labels_count;
}

static struct cmt_metric *metric_prepare_storage(struct cmt_map *map,
                                                 struct cmt_metric *metric,
                                                 int write_op)
{
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;

    if (metric == NULL || !write_op) {
        return metric;
    }

    if (map->type == CMT_HISTOGRAM && metric->hist_buckets == NULL) {
        histogram = map->parent;
        if (histogram == NULL || histogram->buckets == NULL) {
            return NULL;
        }
        metric->hist_buckets = calloc(histogram->buckets->count + 1,
                                      sizeof(uint64_t));
        if (metric->hist_buckets == NULL) {
            cmt_errno();
            return NULL;
        }
    }
    else if (map->type == CMT_SUMMARY && metric->sum_quantiles == NULL) {
        summary = map->parent;
        if (summary == NULL) {
            return NULL;
        }
        if (summary->quantiles_count > 0) {
            metric->sum_quantiles = calloc(summary->quantiles_count,
                                           sizeof(uint64_t));
            if (metric->sum_quantiles == NULL) {
                cmt_errno();
                return NULL;
            }
        }
        metric->sum_quantiles_count = summary->quantiles_count;
    }

    return metric;
}

static struct cmt_metric *metric_hash_lookup(struct cmt_map *map, uint64_t hash,
                                             int labels_count, char **labels_val)
{
    struct cfl_list *head;
    struct cmt_metric *metric;

    if (hash == 0) {
        return &map->metric;
    }

    metric = map->last_metric;
    if (metric != NULL && metric->hash == hash &&
        metric_labels_match(metric, labels_count, labels_val)) {
        return metric;
    }

    if (map->metric_buckets != NULL) {
        cfl_list_foreach(head,
                         &map->metric_buckets[hash % map->metric_bucket_count]) {
            metric = cfl_list_entry(head, struct cmt_metric, _hash_head);
            if (metric->hash == hash &&
                metric_labels_match(metric, labels_count, labels_val)) {
                return metric;
            }
        }
    }

    /* Decoders can populate the public metric list directly. Search only
     * entries that have not yet been indexed, then index a successful match. */
    cfl_list_foreach(head, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        if (!metric->hash_indexed && metric->hash == hash &&
            metric_labels_match(metric, labels_count, labels_val)) {
            metric_index_add(map, metric);
            return metric;
        }
    }

    return NULL;
}

static struct cmt_metric *map_metric_create(struct cmt_map *map, uint64_t hash,
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
    cfl_list_init(&metric->_hash_head);
    cmt_metric_set_double(metric, 0, 0.0);
    metric->hash = hash;
    metric->map = map;

    for (i = 0; i < labels_count; i++) {
        label = malloc(sizeof(struct cmt_map_label));
        if (!label) {
            cmt_errno();
            goto error;
        }

        name = labels_val[i];
        if (name == NULL) {
            label->name = NULL;
        }
        else {
            label->name = cfl_sds_create(name);
            if (!label->name) {
                cmt_errno();
                free(label);
                goto error;
            }
        }
        cfl_list_add(&label->_head, &metric->labels);
    }

    return metric;

 error:
    destroy_label_list(&metric->labels);
    free(metric);
    return NULL;
}

static void map_metric_destroy_unlocked(struct cmt_metric *metric)
{
    struct cmt_map *map;
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_map_label *label;

    map = metric->map;

    cfl_list_foreach_safe(head, tmp, &metric->labels) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        cfl_sds_destroy(label->name);
        cfl_list_del(&label->_head);
        free(label);
    }

    metric_release_storage(metric);

    if (map != NULL && map->last_metric == metric) {
        map->last_metric = NULL;
    }

    if (metric->hash_indexed) {
        if (map != NULL) {
            if (map->indexed_metric_count > 0) {
                map->indexed_metric_count--;
            }
        }
        cfl_list_del(&metric->_hash_head);
    }

    cfl_list_del(&metric->_head);
    free(metric);
}

void cmt_map_metric_destroy(struct cmt_metric *metric)
{
    struct cmt_map *map;

    map = metric->map;
    if (map != NULL) {
        map_lock(map);
    }

    map_metric_destroy_unlocked(metric);

    if (map != NULL) {
        map_unlock(map);
    }
}

static struct cmt_metric *map_metric_get_unlocked(struct cmt_opts *opts,
                                                  struct cmt_map *map,
                                                  int labels_count,
                                                  char **labels_val,
                                                  int write_op)
{
    int i;
    size_t len;
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
        return metric_prepare_storage(map, metric, write_op);
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
    metric = metric_hash_lookup(map, hash, labels_count, labels_val);

    if (metric) {
        return metric_prepare_storage(map, metric, write_op);
    }

    /*
     * If the metric was not found and the caller will not write a value, just
     * return NULL.
     */
    if (!write_op) {
        return NULL;
    }

    /* If the metric has not been found, just create it */
    metric = map_metric_create(map, hash, labels_count, labels_val);
    if (!metric) {
        return NULL;
    }
    cfl_list_add(&metric->_head, &map->metrics);
    metric_index_add(map, metric);
    map->last_metric = metric;
    return metric_prepare_storage(map, metric, write_op);
}

struct cmt_metric *cmt_map_metric_get(struct cmt_opts *opts, struct cmt_map *map,
                                      int labels_count, char **labels_val,
                                      int write_op)
{
    struct cmt_metric *metric;

    map_lock(map);
    metric = map_metric_get_unlocked(opts, map, labels_count, labels_val,
                                     write_op);
    map_unlock(map);

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

        metric_release_storage(metric);
    }

    if (map->unit != NULL) {
        cfl_sds_destroy(map->unit);
    }

    free(map->metric_buckets);

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

/* This function can be used to expire untouched metrics.
 */
void cmt_map_metrics_expire(struct cmt_map *map, uint64_t expiration)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_metric *metric;

    map_lock(map);

    if (map->metric_static_set && map->metric.timestamp < expiration) {
        metric_release_storage(&map->metric);
        memset(&map->metric, 0, sizeof(struct cmt_metric));
        cfl_list_init(&map->metric.labels);
        map->metric_static_set = CMT_FALSE;
    }

    cfl_list_foreach_safe(head, tmp, &map->metrics) {
        metric = cfl_list_entry(head, struct cmt_metric, _head);
        if (metric->timestamp < expiration) {
            map_metric_destroy_unlocked(metric);
        }
    }
    map_unlock(map);
}
