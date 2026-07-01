/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <cfl/cfl.h>
#include <cfl/cfl_hash.h>
#include <cfl/cfl_time.h>

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_hash_table.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_map.h>

#include "cumulative_to_delta.h"

#define FLB_C2D_KEEP 0
#define FLB_C2D_DROP 1
#define FLB_C2D_SERIES_TABLE_SIZE 1024
#define FLB_C2D_MAX_SERIES 65536
#define FLB_C2D_SERIES_TTL_SECONDS 3600
#define FLB_C2D_GC_INTERVAL_SECONDS 30
#define FLB_C2D_CONTEXT_HASH_MAX_DEPTH 16

struct flb_cumulative_to_delta_series {
    int type;
    uint64_t last_timestamp;
    uint64_t last_update_timestamp;
    double last_counter_value;
    uint64_t last_hist_count;
    double last_hist_sum;
    size_t last_hist_bucket_count;
    uint64_t *last_hist_buckets;
    int32_t last_exp_hist_scale;
    uint64_t last_exp_hist_zero_count;
    double last_exp_hist_zero_threshold;
    int32_t last_exp_hist_positive_offset;
    size_t last_exp_hist_positive_count;
    uint64_t *last_exp_hist_positive_buckets;
    int32_t last_exp_hist_negative_offset;
    size_t last_exp_hist_negative_count;
    uint64_t *last_exp_hist_negative_buckets;
    uint64_t last_exp_hist_count;
    int last_exp_hist_sum_set;
    double last_exp_hist_sum;
    flb_sds_t key;
    struct cfl_list _head;
};

struct flb_cumulative_to_delta_ctx {
    int initial_value_mode;
    int drop_on_reset;
    uint64_t processor_start_timestamp;
    uint64_t gc_interval;
    uint64_t next_gc_timestamp;
    uint64_t series_ttl;
    size_t max_series;
    struct flb_hash_table *series_table;
    struct cfl_list series_list;
};

static int should_drop_initial_sample(struct flb_cumulative_to_delta_ctx *context,
                                      struct cmt_metric *sample)
{
    uint64_t sample_timestamp;

    if (context->initial_value_mode == FLB_C2D_INITIAL_VALUE_DROP) {
        return FLB_TRUE;
    }
    else if (context->initial_value_mode == FLB_C2D_INITIAL_VALUE_KEEP) {
        return FLB_FALSE;
    }

    if (cmt_metric_has_start_timestamp(sample)) {
        sample_timestamp = cmt_metric_get_start_timestamp(sample);
    }
    else {
        sample_timestamp = cmt_metric_get_timestamp(sample);
    }

    if (sample_timestamp >= context->processor_start_timestamp) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static void hash_variant(cfl_hash_state_t *state,
                         struct cfl_variant *variant,
                         size_t depth);

static int compare_uint64_values(const void *left, const void *right)
{
    uint64_t left_value;
    uint64_t right_value;

    left_value = *(const uint64_t *) left;
    right_value = *(const uint64_t *) right;

    if (left_value < right_value) {
        return -1;
    }
    else if (left_value > right_value) {
        return 1;
    }

    return 0;
}

static void hash_array(cfl_hash_state_t *state,
                       struct cfl_array *array,
                       size_t depth)
{
    size_t index;
    size_t count;

    if (array == NULL || depth >= FLB_C2D_CONTEXT_HASH_MAX_DEPTH) {
        count = 0;
        cfl_hash_64bits_update(state, &count, sizeof(count));
        return;
    }

    count = cfl_array_size(array);
    cfl_hash_64bits_update(state, &count, sizeof(count));

    for (index = 0; index < count; index++) {
        hash_variant(state,
                     cfl_array_fetch_by_index(array, index),
                     depth + 1);
    }
}

static void hash_kvlist(cfl_hash_state_t *state,
                        struct cfl_kvlist *kvlist,
                        size_t depth)
{
    int entry_count;
    size_t count;
    size_t index;
    size_t key_length;
    uint64_t *entry_hashes;
    uint64_t value_hash;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    cfl_hash_state_t entry_state;

    if (kvlist == NULL || depth >= FLB_C2D_CONTEXT_HASH_MAX_DEPTH) {
        count = 0;
        cfl_hash_64bits_update(state, &count, sizeof(count));
        return;
    }

    entry_count = cfl_kvlist_count(kvlist);
    if (entry_count < 0) {
        count = 0;
    }
    else {
        count = (size_t) entry_count;
    }

    cfl_hash_64bits_update(state, &count, sizeof(count));

    if (count == 0) {
        return;
    }

    entry_hashes = flb_calloc(count, sizeof(uint64_t));
    if (entry_hashes == NULL) {
        entry_hashes = NULL;
    }

    index = 0;
    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);

        cfl_hash_64bits_reset(&entry_state);

        if (pair->key == NULL) {
            key_length = 0;
            cfl_hash_64bits_update(&entry_state, &key_length, sizeof(key_length));
        }
        else {
            key_length = cfl_sds_len(pair->key);
            cfl_hash_64bits_update(&entry_state, &key_length, sizeof(key_length));
            cfl_hash_64bits_update(&entry_state, pair->key, key_length);
        }

        hash_variant(&entry_state, pair->val, depth + 1);
        value_hash = cfl_hash_64bits_digest(&entry_state);

        if (entry_hashes != NULL) {
            entry_hashes[index] = value_hash;
        }
        else {
            cfl_hash_64bits_update(state, &value_hash, sizeof(value_hash));
        }

        index++;
    }

    if (entry_hashes != NULL) {
        qsort(entry_hashes, count, sizeof(uint64_t), compare_uint64_values);

        for (index = 0; index < count; index++) {
            cfl_hash_64bits_update(state,
                                   &entry_hashes[index],
                                   sizeof(entry_hashes[index]));
        }

        flb_free(entry_hashes);
    }
}

static void hash_variant(cfl_hash_state_t *state,
                         struct cfl_variant *variant,
                         size_t depth)
{
    int type;
    size_t data_length;

    if (variant == NULL) {
        type = CFL_VARIANT_NULL;
        cfl_hash_64bits_update(state, &type, sizeof(type));
        return;
    }

    type = variant->type;
    cfl_hash_64bits_update(state, &type, sizeof(type));

    switch (variant->type) {
    case CFL_VARIANT_BOOL:
        cfl_hash_64bits_update(state,
                               &variant->data.as_bool,
                               sizeof(variant->data.as_bool));
        break;
    case CFL_VARIANT_INT:
        cfl_hash_64bits_update(state,
                               &variant->data.as_int64,
                               sizeof(variant->data.as_int64));
        break;
    case CFL_VARIANT_UINT:
        cfl_hash_64bits_update(state,
                               &variant->data.as_uint64,
                               sizeof(variant->data.as_uint64));
        break;
    case CFL_VARIANT_DOUBLE:
        cfl_hash_64bits_update(state,
                               &variant->data.as_double,
                               sizeof(variant->data.as_double));
        break;
    case CFL_VARIANT_STRING:
    case CFL_VARIANT_BYTES:
        if (variant->data.as_string != NULL) {
            data_length = cfl_sds_len(variant->data.as_string);
            cfl_hash_64bits_update(state, &data_length, sizeof(data_length));
            cfl_hash_64bits_update(state, variant->data.as_string, data_length);
        }
        else {
            data_length = 0;
            cfl_hash_64bits_update(state, &data_length, sizeof(data_length));
        }
        break;
    case CFL_VARIANT_ARRAY:
        hash_array(state, variant->data.as_array, depth + 1);
        break;
    case CFL_VARIANT_KVLIST:
        hash_kvlist(state, variant->data.as_kvlist, depth + 1);
        break;
    case CFL_VARIANT_NULL:
    case CFL_VARIANT_REFERENCE:
    default:
        break;
    }
}

static uint64_t compute_context_identity(struct cmt *metrics_context)
{
    cfl_hash_state_t hash_state;
    struct cfl_variant *resource_context;
    struct cfl_variant *scope_context;
    struct cfl_variant *resource_metrics_context;
    struct cfl_variant *scope_metrics_context;

    if (metrics_context == NULL || metrics_context->external_metadata == NULL) {
        return 0;
    }

    cfl_hash_64bits_reset(&hash_state);

    resource_context = cfl_kvlist_fetch(metrics_context->external_metadata,
                                        "resource");
    scope_context = cfl_kvlist_fetch(metrics_context->external_metadata, "scope");
    resource_metrics_context = cfl_kvlist_fetch(metrics_context->external_metadata,
                                                "resource_metrics");
    scope_metrics_context = cfl_kvlist_fetch(metrics_context->external_metadata,
                                             "scope_metrics");

    hash_variant(&hash_state, resource_context, 0);
    hash_variant(&hash_state, scope_context, 0);
    hash_variant(&hash_state, resource_metrics_context, 0);
    hash_variant(&hash_state, scope_metrics_context, 0);

    return cfl_hash_64bits_digest(&hash_state);
}

static int series_state_update_counter(
    struct flb_cumulative_to_delta_series *state,
    uint64_t timestamp,
    double value)
{
    state->last_timestamp = timestamp;
    state->last_update_timestamp = cfl_time_now();
    state->last_counter_value = value;

    return 0;
}

static void series_state_mark_recent(struct flb_cumulative_to_delta_ctx *context,
                                     struct flb_cumulative_to_delta_series *state)
{
    if (context == NULL || state == NULL) {
        return;
    }

    if (state->_head.next == NULL || state->_head.prev == NULL) {
        return;
    }

    if (context->series_list.prev == &state->_head) {
        return;
    }

    cfl_list_del(&state->_head);
    cfl_list_add(&state->_head, &context->series_list);
}

static int series_state_update_histogram(
    struct flb_cumulative_to_delta_series *state,
    uint64_t timestamp,
    uint64_t count,
    double sum,
    size_t bucket_count,
    uint64_t *buckets)
{
    int resize_buckets;
    uint64_t *new_buckets;

    resize_buckets =
        (state->last_hist_bucket_count != bucket_count ||
         (bucket_count > 0 && state->last_hist_buckets == NULL));

    new_buckets = NULL;

    if (resize_buckets == FLB_TRUE && bucket_count > 0) {
        new_buckets = flb_calloc(bucket_count, sizeof(uint64_t));
        if (new_buckets == NULL) {
            return -1;
        }
    }

    if (resize_buckets == FLB_TRUE) {
        if (state->last_hist_buckets != NULL) {
            flb_free(state->last_hist_buckets);
        }

        state->last_hist_buckets = new_buckets;
        state->last_hist_bucket_count = bucket_count;
    }

    if (bucket_count > 0) {
        memcpy(state->last_hist_buckets, buckets, sizeof(uint64_t) * bucket_count);
    }

    state->last_hist_count = count;
    state->last_hist_sum = sum;
    state->last_timestamp = timestamp;
    state->last_update_timestamp = cfl_time_now();

    return 0;
}

static int series_state_update_exp_histogram(
    struct flb_cumulative_to_delta_series *state,
    uint64_t timestamp,
    int32_t scale,
    uint64_t zero_count,
    double zero_threshold,
    int32_t positive_offset,
    size_t positive_count,
    uint64_t *positive_buckets,
    int32_t negative_offset,
    size_t negative_count,
    uint64_t *negative_buckets,
    uint64_t count,
    int sum_set,
    double sum)
{
    int resize_positive;
    int resize_negative;
    uint64_t *new_positive_buckets;
    uint64_t *new_negative_buckets;

    resize_positive =
        (state->last_exp_hist_positive_count != positive_count ||
         (positive_count > 0 && state->last_exp_hist_positive_buckets == NULL));

    resize_negative =
        (state->last_exp_hist_negative_count != negative_count ||
         (negative_count > 0 && state->last_exp_hist_negative_buckets == NULL));

    new_positive_buckets = NULL;
    new_negative_buckets = NULL;

    if (resize_positive == FLB_TRUE && positive_count > 0) {
        new_positive_buckets = flb_calloc(positive_count, sizeof(uint64_t));
        if (new_positive_buckets == NULL) {
            return -1;
        }
    }

    if (resize_negative == FLB_TRUE && negative_count > 0) {
        new_negative_buckets = flb_calloc(negative_count, sizeof(uint64_t));
        if (new_negative_buckets == NULL) {
            if (new_positive_buckets != NULL) {
                flb_free(new_positive_buckets);
            }
            return -1;
        }
    }

    if (resize_positive == FLB_TRUE) {
        if (state->last_exp_hist_positive_buckets != NULL) {
            flb_free(state->last_exp_hist_positive_buckets);
        }

        state->last_exp_hist_positive_buckets = new_positive_buckets;
        state->last_exp_hist_positive_count = positive_count;
    }

    if (resize_negative == FLB_TRUE) {
        if (state->last_exp_hist_negative_buckets != NULL) {
            flb_free(state->last_exp_hist_negative_buckets);
        }

        state->last_exp_hist_negative_buckets = new_negative_buckets;
        state->last_exp_hist_negative_count = negative_count;
    }

    if (positive_count > 0) {
        memcpy(state->last_exp_hist_positive_buckets,
               positive_buckets,
               sizeof(uint64_t) * positive_count);
    }

    if (negative_count > 0) {
        memcpy(state->last_exp_hist_negative_buckets,
               negative_buckets,
               sizeof(uint64_t) * negative_count);
    }

    state->last_exp_hist_scale = scale;
    state->last_exp_hist_zero_count = zero_count;
    state->last_exp_hist_zero_threshold = zero_threshold;
    state->last_exp_hist_positive_offset = positive_offset;
    state->last_exp_hist_negative_offset = negative_offset;
    state->last_exp_hist_count = count;
    state->last_exp_hist_sum_set = sum_set;
    state->last_exp_hist_sum = sum;
    state->last_timestamp = timestamp;
    state->last_update_timestamp = cfl_time_now();

    return 0;
}

static flb_sds_t build_series_key(struct cmt_map *map,
                                  struct cmt_metric *sample,
                                  uint64_t context_identity)
{
    flb_sds_t key;

    key = flb_sds_create_size(cfl_sds_len(map->opts->fqname) + 96);
    if (key == NULL) {
        return NULL;
    }

    if (flb_sds_printf(&key, "%d|%s|%d|%016" PRIx64 "|%" PRIu64,
                       map->type,
                       map->opts->fqname,
                       map->opts->resource_index,
                       context_identity,
                       sample->hash) == NULL) {
        flb_sds_destroy(key);
        return NULL;
    }

    return key;
}

static struct flb_cumulative_to_delta_series *series_state_create()
{
    struct flb_cumulative_to_delta_series *state;

    state = flb_calloc(1, sizeof(struct flb_cumulative_to_delta_series));
    if (state == NULL) {
        return NULL;
    }

    cfl_list_init(&state->_head);

    return state;
}

static int series_state_table_del(struct flb_cumulative_to_delta_ctx *context,
                                  struct flb_cumulative_to_delta_series *state)
{
    if (state->key == NULL) {
        return 0;
    }

    return flb_hash_table_del_ptr(context->series_table,
                                  state->key,
                                  cfl_sds_len(state->key),
                                  state);
}

static void series_state_destroy(struct flb_cumulative_to_delta_series *state)
{
    if (state == NULL) {
        return;
    }

    if (state->last_hist_buckets != NULL) {
        flb_free(state->last_hist_buckets);
    }
    if (state->last_exp_hist_positive_buckets != NULL) {
        flb_free(state->last_exp_hist_positive_buckets);
    }
    if (state->last_exp_hist_negative_buckets != NULL) {
        flb_free(state->last_exp_hist_negative_buckets);
    }

    if (state->key != NULL) {
        flb_sds_destroy(state->key);
    }

    if (state->_head.next != NULL && state->_head.prev != NULL) {
        cfl_list_del(&state->_head);
    }
    flb_free(state);
}

static struct flb_cumulative_to_delta_series *series_state_get(
    struct flb_cumulative_to_delta_ctx *context,
    struct cmt_map *map,
    struct cmt_metric *sample,
    uint64_t context_identity,
    int create_if_missing)
{
    int ret;
    flb_sds_t key;
    struct flb_cumulative_to_delta_series *state;

    key = build_series_key(map, sample, context_identity);
    if (key == NULL) {
        return NULL;
    }

    state = flb_hash_table_get_ptr(context->series_table, key, cfl_sds_len(key));
    if (state != NULL || create_if_missing == FLB_FALSE) {
        flb_sds_destroy(key);

        if (state != NULL) {
            series_state_mark_recent(context, state);
        }

        return state;
    }

    state = series_state_create();
    if (state == NULL) {
        flb_sds_destroy(key);
        return NULL;
    }

    state->type = map->type;
    cfl_list_add(&state->_head, &context->series_list);

    ret = flb_hash_table_add(context->series_table, key, cfl_sds_len(key),
                             state, 0);
    if (ret == -1) {
        flb_sds_destroy(key);
        series_state_destroy(state);
        return NULL;
    }

    state->key = key;

    return state;
}

static void series_state_gc(struct flb_cumulative_to_delta_ctx *context,
                            uint64_t now)
{
    uint64_t age;
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct flb_cumulative_to_delta_series *state;

    cfl_list_foreach_safe(head, tmp, &context->series_list) {
        state = cfl_list_entry(head, struct flb_cumulative_to_delta_series, _head);

        if (now >= state->last_update_timestamp) {
            age = now - state->last_update_timestamp;
        }
        else {
            continue;
        }

        if (age > context->series_ttl) {
            series_state_table_del(context, state);
            series_state_destroy(state);
        }
    }
}

static void series_state_evict_if_needed(struct flb_cumulative_to_delta_ctx *context)
{
    struct flb_cumulative_to_delta_series *state;

    while (cfl_list_size(&context->series_list) > context->max_series) {
        if (cfl_list_is_empty(&context->series_list)) {
            break;
        }

        state = cfl_list_entry_first(&context->series_list,
                                     struct flb_cumulative_to_delta_series,
                                     _head);

        series_state_table_del(context, state);
        series_state_destroy(state);
    }
}

static int process_counter_sample(struct flb_cumulative_to_delta_ctx *context,
                                  struct cmt_counter *counter,
                                  struct cmt_metric *sample,
                                  uint64_t context_identity)
{
    int reset_detected;
    double delta;
    double current_value;
    uint64_t timestamp;
    struct flb_cumulative_to_delta_series *state;

    timestamp = cmt_metric_get_timestamp(sample);
    current_value = cmt_metric_get_value(sample);

    state = series_state_get(context,
                             counter->map,
                             sample,
                             context_identity,
                             FLB_FALSE);
    if (state == NULL) {
        state = series_state_get(context,
                                 counter->map,
                                 sample,
                                 context_identity,
                                 FLB_TRUE);
        if (state == NULL) {
            return -1;
        }

        if (series_state_update_counter(state, timestamp, current_value) != 0) {
            series_state_table_del(context, state);
            series_state_destroy(state);
            return -1;
        }

        if (should_drop_initial_sample(context, sample) == FLB_TRUE) {
            return FLB_C2D_DROP;
        }

        return FLB_C2D_KEEP;
    }

    if (timestamp <= state->last_timestamp) {
        return FLB_C2D_DROP;
    }

    reset_detected = FLB_FALSE;

    if (counter->allow_reset == FLB_FALSE &&
        current_value < state->last_counter_value) {
        reset_detected = FLB_TRUE;
    }

    if (reset_detected == FLB_TRUE) {
        if (series_state_update_counter(state, timestamp, current_value) != 0) {
            return -1;
        }

        if (context->drop_on_reset == FLB_TRUE) {
            return FLB_C2D_DROP;
        }
    }

    if (reset_detected == FLB_TRUE) {
        delta = current_value;
    }
    else {
        delta = current_value - state->last_counter_value;
    }

    if (reset_detected == FLB_TRUE) {
        if (cmt_metric_has_start_timestamp(sample) == FLB_FALSE) {
            cmt_metric_set_start_timestamp(sample, timestamp);
        }
    }
    else {
        cmt_metric_set_start_timestamp(sample, state->last_timestamp);
    }

    cmt_metric_set(sample, timestamp, delta);

    if (series_state_update_counter(state, timestamp, current_value) != 0) {
        return -1;
    }

    return FLB_C2D_KEEP;
}

static uint64_t exp_hist_bucket_get_value(int32_t offset,
                                          size_t bucket_count,
                                          uint64_t *buckets,
                                          int64_t target_index)
{
    int64_t index;

    if (bucket_count == 0 || buckets == NULL) {
        return 0;
    }

    index = (int64_t) target_index - (int64_t) offset;
    if (index < 0 || (size_t) index >= bucket_count) {
        return 0;
    }

    return buckets[index];
}

static int exp_hist_bucket_index_from_offset(int32_t offset,
                                             size_t position,
                                             int64_t *bucket_index)
{
    int64_t signed_offset;
    int64_t signed_position;

    if (bucket_index == NULL) {
        return -1;
    }

    if (position > (size_t) INT64_MAX) {
        return -1;
    }

    signed_offset = (int64_t) offset;
    signed_position = (int64_t) position;

    if (signed_offset > (INT64_MAX - signed_position)) {
        return -1;
    }

    *bucket_index = signed_offset + signed_position;

    return 0;
}

struct flb_c2d_exp_hist_bucket_layout {
    int32_t offset;
    size_t count;
    uint64_t *buckets;
    int owns_buckets;
};

struct flb_c2d_exp_hist_layout {
    int32_t scale;
    struct flb_c2d_exp_hist_bucket_layout positive;
    struct flb_c2d_exp_hist_bucket_layout negative;
};

static void exp_hist_bucket_layout_destroy(
    struct flb_c2d_exp_hist_bucket_layout *layout)
{
    if (layout == NULL) {
        return;
    }

    if (layout->owns_buckets == FLB_TRUE &&
        layout->buckets != NULL) {
        flb_free(layout->buckets);
    }

    memset(layout, 0, sizeof(struct flb_c2d_exp_hist_bucket_layout));
}

static void exp_hist_layout_destroy(struct flb_c2d_exp_hist_layout *layout)
{
    if (layout == NULL) {
        return;
    }

    exp_hist_bucket_layout_destroy(&layout->positive);
    exp_hist_bucket_layout_destroy(&layout->negative);
    memset(layout, 0, sizeof(struct flb_c2d_exp_hist_layout));
}

static int exp_hist_floor_div(int64_t value,
                              int64_t divisor,
                              int64_t *result)
{
    int64_t quotient;
    int64_t remainder;

    if (result == NULL || divisor <= 0) {
        return -1;
    }

    quotient = value / divisor;
    remainder = value % divisor;

    if (remainder != 0 && value < 0) {
        quotient--;
    }

    *result = quotient;

    return 0;
}

static int exp_hist_bucket_layout_downscale(
    struct flb_c2d_exp_hist_bucket_layout *source,
    int32_t scale_delta,
    struct flb_c2d_exp_hist_bucket_layout *destination)
{
    int64_t first_index;
    int64_t group_index;
    int64_t last_index;
    int64_t new_first_index;
    int64_t new_last_index;
    int64_t signed_position;
    int64_t width;
    size_t index;

    if (source == NULL || destination == NULL) {
        return -1;
    }

    memset(destination, 0, sizeof(struct flb_c2d_exp_hist_bucket_layout));

    if (source->count == 0) {
        return 0;
    }

    if (source->buckets == NULL || scale_delta < 0 || scale_delta > 62) {
        return -1;
    }

    if (scale_delta == 0) {
        destination->offset = source->offset;
        destination->count = source->count;
        destination->buckets = source->buckets;
        destination->owns_buckets = FLB_FALSE;

        return 0;
    }

    width = ((int64_t) 1) << scale_delta;
    signed_position = (int64_t) source->count - 1;
    first_index = (int64_t) source->offset;
    last_index = first_index + signed_position;

    if (last_index < first_index) {
        return -1;
    }

    if (exp_hist_floor_div(first_index, width, &new_first_index) != 0 ||
        exp_hist_floor_div(last_index, width, &new_last_index) != 0) {
        return -1;
    }

    if (new_first_index < INT32_MIN || new_first_index > INT32_MAX ||
        new_last_index < INT32_MIN || new_last_index > INT32_MAX ||
        new_last_index < new_first_index) {
        return -1;
    }

    destination->count = (size_t) (new_last_index - new_first_index + 1);
    destination->offset = (int32_t) new_first_index;
    destination->owns_buckets = FLB_TRUE;
    destination->buckets = flb_calloc(destination->count, sizeof(uint64_t));
    if (destination->buckets == NULL) {
        return -1;
    }

    for (index = 0; index < source->count; index++) {
        signed_position = (int64_t) index;
        group_index = first_index + signed_position;

        if (exp_hist_floor_div(group_index, width, &group_index) != 0) {
            exp_hist_bucket_layout_destroy(destination);
            return -1;
        }

        destination->buckets[(size_t) (group_index - new_first_index)] +=
            source->buckets[index];
    }

    return 0;
}

static int exp_hist_layout_downscale(struct flb_c2d_exp_hist_layout *source,
                                     int32_t target_scale,
                                     struct flb_c2d_exp_hist_layout *destination)
{
    int32_t scale_delta;

    if (source == NULL || destination == NULL || target_scale > source->scale) {
        return -1;
    }

    memset(destination, 0, sizeof(struct flb_c2d_exp_hist_layout));
    destination->scale = target_scale;
    scale_delta = source->scale - target_scale;

    if (exp_hist_bucket_layout_downscale(&source->positive,
                                         scale_delta,
                                         &destination->positive) != 0) {
        return -1;
    }

    if (exp_hist_bucket_layout_downscale(&source->negative,
                                         scale_delta,
                                         &destination->negative) != 0) {
        exp_hist_layout_destroy(destination);
        return -1;
    }

    return 0;
}

static int exp_hist_layout_init_from_sample(struct flb_c2d_exp_hist_layout *layout,
                                            struct cmt_metric *sample)
{
    if (layout == NULL || sample == NULL) {
        return -1;
    }

    memset(layout, 0, sizeof(struct flb_c2d_exp_hist_layout));
    layout->scale = sample->exp_hist_scale;

    layout->positive.offset = sample->exp_hist_positive_offset;
    layout->positive.count = sample->exp_hist_positive_count;
    layout->positive.buckets = sample->exp_hist_positive_buckets;
    layout->positive.owns_buckets = FLB_FALSE;

    layout->negative.offset = sample->exp_hist_negative_offset;
    layout->negative.count = sample->exp_hist_negative_count;
    layout->negative.buckets = sample->exp_hist_negative_buckets;
    layout->negative.owns_buckets = FLB_FALSE;

    return 0;
}

static int exp_hist_layout_init_from_state(struct flb_c2d_exp_hist_layout *layout,
                                           struct flb_cumulative_to_delta_series *state)
{
    if (layout == NULL || state == NULL) {
        return -1;
    }

    memset(layout, 0, sizeof(struct flb_c2d_exp_hist_layout));
    layout->scale = state->last_exp_hist_scale;

    layout->positive.offset = state->last_exp_hist_positive_offset;
    layout->positive.count = state->last_exp_hist_positive_count;
    layout->positive.buckets = state->last_exp_hist_positive_buckets;
    layout->positive.owns_buckets = FLB_FALSE;

    layout->negative.offset = state->last_exp_hist_negative_offset;
    layout->negative.count = state->last_exp_hist_negative_count;
    layout->negative.buckets = state->last_exp_hist_negative_buckets;
    layout->negative.owns_buckets = FLB_FALSE;

    return 0;
}

static int exp_hist_bucket_layout_is_monotonic(
    struct flb_c2d_exp_hist_bucket_layout *current,
    struct flb_c2d_exp_hist_bucket_layout *previous)
{
    int64_t bucket_index;
    int64_t current_end;
    int64_t current_start;
    int64_t previous_end;
    int64_t previous_start;
    uint64_t current_value;
    uint64_t previous_value;

    if (current == NULL || previous == NULL) {
        return FLB_FALSE;
    }

    current_start = (int64_t) current->offset;
    previous_start = (int64_t) previous->offset;
    current_end = current_start + (int64_t) current->count - 1;
    previous_end = previous_start + (int64_t) previous->count - 1;

    if (current->count == 0) {
        current_end = current_start - 1;
    }
    if (previous->count == 0) {
        previous_end = previous_start - 1;
    }

    for (bucket_index = current_start; bucket_index <= current_end; bucket_index++) {
        current_value = exp_hist_bucket_get_value(current->offset,
                                                  current->count,
                                                  current->buckets,
                                                  bucket_index);
        previous_value = exp_hist_bucket_get_value(previous->offset,
                                                   previous->count,
                                                   previous->buckets,
                                                   bucket_index);

        if (current_value < previous_value) {
            return FLB_FALSE;
        }
    }

    for (bucket_index = previous_start; bucket_index <= previous_end; bucket_index++) {
        current_value = exp_hist_bucket_get_value(current->offset,
                                                  current->count,
                                                  current->buckets,
                                                  bucket_index);
        previous_value = exp_hist_bucket_get_value(previous->offset,
                                                   previous->count,
                                                   previous->buckets,
                                                   bucket_index);

        if (current_value < previous_value) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static void exp_hist_bucket_layout_subtract(
    struct flb_c2d_exp_hist_bucket_layout *current,
    struct flb_c2d_exp_hist_bucket_layout *previous)
{
    int64_t bucket_index;
    size_t index;
    uint64_t previous_value;

    if (current == NULL || previous == NULL) {
        return;
    }

    for (index = 0; index < current->count; index++) {
        if (exp_hist_bucket_index_from_offset(current->offset,
                                              index,
                                              &bucket_index) != 0) {
            continue;
        }

        previous_value = exp_hist_bucket_get_value(previous->offset,
                                                   previous->count,
                                                   previous->buckets,
                                                   bucket_index);
        current->buckets[index] -= previous_value;
    }
}

static void exp_hist_sample_apply_layout(struct cmt_metric *sample,
                                         struct flb_c2d_exp_hist_layout *layout)
{
    uint64_t *old_negative;
    uint64_t *old_positive;

    if (sample == NULL || layout == NULL) {
        return;
    }

    old_positive = sample->exp_hist_positive_buckets;
    old_negative = sample->exp_hist_negative_buckets;

    sample->exp_hist_scale = layout->scale;
    sample->exp_hist_positive_offset = layout->positive.offset;
    sample->exp_hist_positive_count = layout->positive.count;
    sample->exp_hist_positive_buckets = layout->positive.buckets;
    sample->exp_hist_negative_offset = layout->negative.offset;
    sample->exp_hist_negative_count = layout->negative.count;
    sample->exp_hist_negative_buckets = layout->negative.buckets;

    if (layout->positive.owns_buckets == FLB_TRUE &&
        old_positive != NULL &&
        old_positive != sample->exp_hist_positive_buckets) {
        flb_free(old_positive);
    }

    if (layout->negative.owns_buckets == FLB_TRUE &&
        old_negative != NULL &&
        old_negative != sample->exp_hist_negative_buckets) {
        flb_free(old_negative);
    }

    layout->positive.owns_buckets = FLB_FALSE;
    layout->negative.owns_buckets = FLB_FALSE;
}

static int process_histogram_sample(struct flb_cumulative_to_delta_ctx *context,
                                    struct cmt_histogram *histogram,
                                    struct cmt_metric *sample,
                                    uint64_t context_identity)
{
    size_t bucket_index;
    int reset_detected;
    uint64_t bucket_delta;
    uint64_t count_delta;
    uint64_t current_count;
    uint64_t timestamp;
    double sum_delta;
    double current_sum;
    size_t bucket_count;
    uint64_t *cumulative_buckets_snapshot;
    struct flb_cumulative_to_delta_series *state;

    if (sample->hist_buckets == NULL) {
        return FLB_C2D_DROP;
    }

    timestamp = cmt_metric_get_timestamp(sample);
    current_count = cmt_metric_hist_get_count_value(sample);
    current_sum = cmt_metric_hist_get_sum_value(sample);
    bucket_count = histogram->buckets->count + 1;

    if (bucket_count > (size_t) INT_MAX) {
        return FLB_C2D_DROP;
    }

    state = series_state_get(context,
                             histogram->map,
                             sample,
                             context_identity,
                             FLB_FALSE);
    if (state == NULL) {
        state = series_state_get(context,
                                 histogram->map,
                                 sample,
                                 context_identity,
                                 FLB_TRUE);
        if (state == NULL) {
            return -1;
        }

        if (series_state_update_histogram(state,
                                          timestamp,
                                          current_count,
                                          current_sum,
                                          bucket_count,
                                          sample->hist_buckets) != 0) {
            series_state_table_del(context, state);
            series_state_destroy(state);
            return -1;
        }

        if (should_drop_initial_sample(context, sample) == FLB_TRUE) {
            return FLB_C2D_DROP;
        }

        return FLB_C2D_KEEP;
    }

    if (timestamp <= state->last_timestamp) {
        return FLB_C2D_DROP;
    }

    reset_detected = FLB_FALSE;

    if (bucket_count != state->last_hist_bucket_count) {
        reset_detected = FLB_TRUE;
    }

    if (current_count < state->last_hist_count) {
        reset_detected = FLB_TRUE;
    }

    if (reset_detected == FLB_FALSE) {
        for (bucket_index = 0; bucket_index < bucket_count; bucket_index++) {
            if (sample->hist_buckets[bucket_index] <
                state->last_hist_buckets[bucket_index]) {
                reset_detected = FLB_TRUE;
                break;
            }
        }
    }

    if (reset_detected == FLB_TRUE && context->drop_on_reset == FLB_TRUE) {
        if (series_state_update_histogram(state,
                                          timestamp,
                                          current_count,
                                          current_sum,
                                          bucket_count,
                                          sample->hist_buckets) != 0) {
            return -1;
        }

        return FLB_C2D_DROP;
    }

    cumulative_buckets_snapshot = NULL;

    if (bucket_count > 0) {
        cumulative_buckets_snapshot = flb_calloc(bucket_count, sizeof(uint64_t));
        if (cumulative_buckets_snapshot == NULL) {
            return -1;
        }

        memcpy(cumulative_buckets_snapshot,
               sample->hist_buckets,
               sizeof(uint64_t) * bucket_count);
    }

    for (bucket_index = 0; bucket_index < bucket_count; bucket_index++) {
        if (reset_detected == FLB_TRUE) {
            bucket_delta = sample->hist_buckets[bucket_index];
        }
        else {
            bucket_delta = sample->hist_buckets[bucket_index] -
                           state->last_hist_buckets[bucket_index];
        }

        cmt_metric_hist_set(sample, timestamp, bucket_index, bucket_delta);
    }

    if (reset_detected == FLB_TRUE) {
        count_delta = current_count;
        sum_delta = current_sum;
    }
    else {
        count_delta = current_count - state->last_hist_count;
        sum_delta = current_sum - state->last_hist_sum;
    }

    if (reset_detected == FLB_TRUE) {
        if (cmt_metric_has_start_timestamp(sample) == FLB_FALSE) {
            cmt_metric_set_start_timestamp(sample, timestamp);
        }
    }
    else {
        cmt_metric_set_start_timestamp(sample, state->last_timestamp);
    }

    cmt_metric_hist_count_set(sample, timestamp, count_delta);
    cmt_metric_hist_sum_set(sample, timestamp, sum_delta);

    if (series_state_update_histogram(state,
                                      timestamp,
                                      current_count,
                                      current_sum,
                                      bucket_count,
                                      cumulative_buckets_snapshot) != 0) {
        if (cumulative_buckets_snapshot != NULL) {
            flb_free(cumulative_buckets_snapshot);
        }
        return -1;
    }

    if (cumulative_buckets_snapshot != NULL) {
        flb_free(cumulative_buckets_snapshot);
    }

    return FLB_C2D_KEEP;
}

static int process_exp_histogram_sample(struct flb_cumulative_to_delta_ctx *context,
                                        struct cmt_exp_histogram *exp_histogram,
                                        struct cmt_metric *sample,
                                        uint64_t context_identity)
{
    int32_t original_negative_offset;
    int32_t original_positive_offset;
    int32_t original_scale;
    int32_t output_scale;
    int reset_detected;
    int current_sum_set;
    uint64_t current_count;
    uint64_t current_zero_count;
    uint64_t count_delta;
    uint64_t zero_count_delta;
    uint64_t timestamp;
    double current_sum;
    double sum_delta;
    double original_zero_threshold;
    uint64_t *cumulative_positive_snapshot;
    uint64_t *cumulative_negative_snapshot;
    struct flb_c2d_exp_hist_layout current_layout;
    struct flb_c2d_exp_hist_layout normalized_current_layout;
    struct flb_c2d_exp_hist_layout normalized_previous_layout;
    struct flb_cumulative_to_delta_series *state;
    size_t original_negative_count;
    size_t original_positive_count;

    if (sample->exp_hist_positive_count > 0 &&
        sample->exp_hist_positive_buckets == NULL) {
        return FLB_C2D_DROP;
    }

    if (sample->exp_hist_negative_count > 0 &&
        sample->exp_hist_negative_buckets == NULL) {
        return FLB_C2D_DROP;
    }

    timestamp = cmt_metric_get_timestamp(sample);
    current_count = sample->exp_hist_count;
    current_zero_count = sample->exp_hist_zero_count;
    current_sum_set = sample->exp_hist_sum_set;
    current_sum = 0.0;
    sum_delta = 0.0;
    original_scale = sample->exp_hist_scale;
    original_zero_threshold = sample->exp_hist_zero_threshold;
    original_positive_offset = sample->exp_hist_positive_offset;
    original_positive_count = sample->exp_hist_positive_count;
    original_negative_offset = sample->exp_hist_negative_offset;
    original_negative_count = sample->exp_hist_negative_count;

    memset(&current_layout, 0, sizeof(struct flb_c2d_exp_hist_layout));
    memset(&normalized_current_layout, 0, sizeof(struct flb_c2d_exp_hist_layout));
    memset(&normalized_previous_layout, 0, sizeof(struct flb_c2d_exp_hist_layout));

    if (current_sum_set == CMT_TRUE) {
        current_sum = cmt_math_uint64_to_d64(sample->exp_hist_sum);
    }

    state = series_state_get(context,
                             exp_histogram->map,
                             sample,
                             context_identity,
                             FLB_FALSE);
    if (state == NULL) {
        state = series_state_get(context,
                                 exp_histogram->map,
                                 sample,
                                 context_identity,
                                 FLB_TRUE);
        if (state == NULL) {
            return -1;
        }

        if (series_state_update_exp_histogram(state,
                                              timestamp,
                                              sample->exp_hist_scale,
                                              current_zero_count,
                                              sample->exp_hist_zero_threshold,
                                              sample->exp_hist_positive_offset,
                                              sample->exp_hist_positive_count,
                                              sample->exp_hist_positive_buckets,
                                              sample->exp_hist_negative_offset,
                                              sample->exp_hist_negative_count,
                                              sample->exp_hist_negative_buckets,
                                              current_count,
                                              current_sum_set,
                                              current_sum) != 0) {
            series_state_table_del(context, state);
            series_state_destroy(state);
            return -1;
        }

        if (should_drop_initial_sample(context, sample) == FLB_TRUE) {
            return FLB_C2D_DROP;
        }

        return FLB_C2D_KEEP;
    }

    if (timestamp <= state->last_timestamp) {
        return FLB_C2D_DROP;
    }

    reset_detected = FLB_FALSE;

    if (sample->exp_hist_zero_threshold != state->last_exp_hist_zero_threshold ||
        current_sum_set != state->last_exp_hist_sum_set) {
        reset_detected = FLB_TRUE;
    }

    if (current_count < state->last_exp_hist_count ||
        current_zero_count < state->last_exp_hist_zero_count) {
        reset_detected = FLB_TRUE;
    }

    output_scale = sample->exp_hist_scale;
    if (state->last_exp_hist_scale < output_scale) {
        output_scale = state->last_exp_hist_scale;
    }

    if (reset_detected == FLB_FALSE) {
        if (exp_hist_layout_init_from_sample(&current_layout, sample) != 0 ||
            exp_hist_layout_downscale(&current_layout,
                                      output_scale,
                                      &normalized_current_layout) != 0) {
            return -1;
        }

        if (exp_hist_layout_init_from_state(&current_layout, state) != 0 ||
            exp_hist_layout_downscale(&current_layout,
                                      output_scale,
                                      &normalized_previous_layout) != 0) {
            exp_hist_layout_destroy(&normalized_current_layout);
            return -1;
        }

        if (exp_hist_bucket_layout_is_monotonic(&normalized_current_layout.positive,
                                                &normalized_previous_layout.positive) ==
                FLB_FALSE ||
            exp_hist_bucket_layout_is_monotonic(&normalized_current_layout.negative,
                                                &normalized_previous_layout.negative) ==
                FLB_FALSE) {
            reset_detected = FLB_TRUE;
        }
    }

    if (reset_detected == FLB_TRUE && context->drop_on_reset == FLB_TRUE) {
        exp_hist_layout_destroy(&normalized_current_layout);
        exp_hist_layout_destroy(&normalized_previous_layout);

        if (series_state_update_exp_histogram(state,
                                              timestamp,
                                              original_scale,
                                              current_zero_count,
                                              original_zero_threshold,
                                              original_positive_offset,
                                              original_positive_count,
                                              sample->exp_hist_positive_buckets,
                                              original_negative_offset,
                                              original_negative_count,
                                              sample->exp_hist_negative_buckets,
                                              current_count,
                                              current_sum_set,
                                              current_sum) != 0) {
            return -1;
        }

        return FLB_C2D_DROP;
    }

    cumulative_positive_snapshot = NULL;
    cumulative_negative_snapshot = NULL;

    if (sample->exp_hist_positive_count > 0) {
        cumulative_positive_snapshot = flb_calloc(sample->exp_hist_positive_count,
                                                  sizeof(uint64_t));
        if (cumulative_positive_snapshot == NULL) {
            return -1;
        }

        memcpy(cumulative_positive_snapshot,
               sample->exp_hist_positive_buckets,
               sizeof(uint64_t) * sample->exp_hist_positive_count);
    }

    if (sample->exp_hist_negative_count > 0) {
        cumulative_negative_snapshot = flb_calloc(sample->exp_hist_negative_count,
                                                  sizeof(uint64_t));
        if (cumulative_negative_snapshot == NULL) {
            if (cumulative_positive_snapshot != NULL) {
                flb_free(cumulative_positive_snapshot);
            }
            exp_hist_layout_destroy(&normalized_current_layout);
            exp_hist_layout_destroy(&normalized_previous_layout);
            return -1;
        }

        memcpy(cumulative_negative_snapshot,
               sample->exp_hist_negative_buckets,
               sizeof(uint64_t) * sample->exp_hist_negative_count);
    }

    if (reset_detected == FLB_FALSE) {
        exp_hist_sample_apply_layout(sample, &normalized_current_layout);

        exp_hist_bucket_layout_subtract(&normalized_current_layout.positive,
                                        &normalized_previous_layout.positive);
        exp_hist_bucket_layout_subtract(&normalized_current_layout.negative,
                                        &normalized_previous_layout.negative);
    }

    if (reset_detected == FLB_TRUE) {
        count_delta = current_count;
        zero_count_delta = current_zero_count;
        sum_delta = current_sum;
    }
    else {
        count_delta = current_count - state->last_exp_hist_count;
        zero_count_delta = current_zero_count - state->last_exp_hist_zero_count;

        if (current_sum_set == CMT_TRUE) {
            sum_delta = current_sum - state->last_exp_hist_sum;
        }
    }

    if (reset_detected == FLB_TRUE) {
        if (cmt_metric_has_start_timestamp(sample) == FLB_FALSE) {
            cmt_metric_set_start_timestamp(sample, timestamp);
        }
    }
    else {
        cmt_metric_set_start_timestamp(sample, state->last_timestamp);
    }

    sample->exp_hist_count = count_delta;
    sample->exp_hist_zero_count = zero_count_delta;

    if (current_sum_set == CMT_TRUE) {
        sample->exp_hist_sum_set = CMT_TRUE;
        sample->exp_hist_sum = cmt_math_d64_to_uint64(sum_delta);
    }
    else {
        sample->exp_hist_sum_set = CMT_FALSE;
        sample->exp_hist_sum = 0;
    }

    exp_hist_layout_destroy(&normalized_current_layout);
    exp_hist_layout_destroy(&normalized_previous_layout);

    if (series_state_update_exp_histogram(state,
                                          timestamp,
                                          original_scale,
                                          current_zero_count,
                                          original_zero_threshold,
                                          original_positive_offset,
                                          original_positive_count,
                                          cumulative_positive_snapshot,
                                          original_negative_offset,
                                          original_negative_count,
                                          cumulative_negative_snapshot,
                                          current_count,
                                          current_sum_set,
                                          current_sum) != 0) {
        if (cumulative_positive_snapshot != NULL) {
            flb_free(cumulative_positive_snapshot);
        }
        if (cumulative_negative_snapshot != NULL) {
            flb_free(cumulative_negative_snapshot);
        }
        return -1;
    }

    if (cumulative_positive_snapshot != NULL) {
        flb_free(cumulative_positive_snapshot);
    }
    if (cumulative_negative_snapshot != NULL) {
        flb_free(cumulative_negative_snapshot);
    }

    return FLB_C2D_KEEP;
}

static int process_counter_map(struct flb_cumulative_to_delta_ctx *context,
                               struct cmt_counter *counter,
                               uint64_t context_identity)
{
    int result;
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_metric *sample;
    struct cmt_map *map;

    map = counter->map;

    if (counter->aggregation_type != CMT_AGGREGATION_TYPE_CUMULATIVE) {
        return 0;
    }

    /*
     * OTLP non-monotonic sums are decoded as counters with allow_reset=true.
     * This processor only converts monotonic cumulative sums to delta.
     */
    if (counter->allow_reset == FLB_TRUE) {
        return 0;
    }

    if (map->metric_static_set == FLB_TRUE) {
        result = process_counter_sample(context,
                                        counter,
                                        &map->metric,
                                        context_identity);
        if (result == -1) {
            return -1;
        }
        if (result == FLB_C2D_DROP) {
            map->metric_static_set = FLB_FALSE;
        }
    }

    cfl_list_foreach_safe(head, tmp, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);

        result = process_counter_sample(context,
                                        counter,
                                        sample,
                                        context_identity);
        if (result == -1) {
            return -1;
        }
        if (result == FLB_C2D_DROP) {
            cmt_map_metric_destroy(sample);
        }
    }

    counter->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;

    return 0;
}

static int process_histogram_map(struct flb_cumulative_to_delta_ctx *context,
                                 struct cmt_histogram *histogram,
                                 uint64_t context_identity)
{
    int result;
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_metric *sample;
    struct cmt_map *map;

    map = histogram->map;

    if (histogram->aggregation_type != CMT_AGGREGATION_TYPE_CUMULATIVE) {
        return 0;
    }

    if (map->metric_static_set == FLB_TRUE) {
        result = process_histogram_sample(context,
                                          histogram,
                                          &map->metric,
                                          context_identity);
        if (result == -1) {
            return -1;
        }
        if (result == FLB_C2D_DROP) {
            if (map->metric.hist_buckets != NULL) {
                flb_free(map->metric.hist_buckets);
                map->metric.hist_buckets = NULL;
            }
            map->metric_static_set = FLB_FALSE;
        }
    }

    cfl_list_foreach_safe(head, tmp, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);

        result = process_histogram_sample(context,
                                          histogram,
                                          sample,
                                          context_identity);
        if (result == -1) {
            return -1;
        }
        if (result == FLB_C2D_DROP) {
            cmt_map_metric_destroy(sample);
        }
    }

    histogram->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;

    return 0;
}

static int process_exp_histogram_map(struct flb_cumulative_to_delta_ctx *context,
                                     struct cmt_exp_histogram *exp_histogram,
                                     uint64_t context_identity)
{
    int result;
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct cmt_metric *sample;
    struct cmt_map *map;

    map = exp_histogram->map;

    if (exp_histogram->aggregation_type != CMT_AGGREGATION_TYPE_CUMULATIVE) {
        return 0;
    }

    if (map->metric_static_set == FLB_TRUE) {
        result = process_exp_histogram_sample(context,
                                              exp_histogram,
                                              &map->metric,
                                              context_identity);
        if (result == -1) {
            return -1;
        }
        if (result == FLB_C2D_DROP) {
            if (map->metric.exp_hist_positive_buckets != NULL) {
                flb_free(map->metric.exp_hist_positive_buckets);
                map->metric.exp_hist_positive_buckets = NULL;
            }
            if (map->metric.exp_hist_negative_buckets != NULL) {
                flb_free(map->metric.exp_hist_negative_buckets);
                map->metric.exp_hist_negative_buckets = NULL;
            }
            map->metric_static_set = FLB_FALSE;
        }
    }

    cfl_list_foreach_safe(head, tmp, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);

        result = process_exp_histogram_sample(context,
                                              exp_histogram,
                                              sample,
                                              context_identity);
        if (result == -1) {
            return -1;
        }
        if (result == FLB_C2D_DROP) {
            cmt_map_metric_destroy(sample);
        }
    }

    exp_histogram->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;

    return 0;
}

struct flb_cumulative_to_delta_ctx *flb_cumulative_to_delta_ctx_create(
    int initial_value_mode,
    int drop_on_reset,
    uint64_t processor_start_timestamp)
{
    struct flb_cumulative_to_delta_ctx *context;

    context = flb_calloc(1, sizeof(struct flb_cumulative_to_delta_ctx));
    if (context == NULL) {
        return NULL;
    }

    context->series_table = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE,
                                                  FLB_C2D_SERIES_TABLE_SIZE,
                                                  0);
    if (context->series_table == NULL) {
        flb_free(context);
        return NULL;
    }

    cfl_list_init(&context->series_list);
    context->initial_value_mode = initial_value_mode;
    context->drop_on_reset = drop_on_reset;
    context->processor_start_timestamp = processor_start_timestamp;
    context->gc_interval = (uint64_t) FLB_C2D_GC_INTERVAL_SECONDS * 1000000000ULL;
    context->series_ttl = (uint64_t) FLB_C2D_SERIES_TTL_SECONDS * 1000000000ULL;
    context->max_series = FLB_C2D_MAX_SERIES;
    context->next_gc_timestamp = cfl_time_now() + context->gc_interval;

    return context;
}

void flb_cumulative_to_delta_ctx_destroy(
    struct flb_cumulative_to_delta_ctx *context)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct flb_cumulative_to_delta_series *state;

    if (context == NULL) {
        return;
    }

    cfl_list_foreach_safe(head, tmp, &context->series_list) {
        state = cfl_list_entry(head, struct flb_cumulative_to_delta_series, _head);
        series_state_table_del(context, state);
        series_state_destroy(state);
    }

    if (context->series_table != NULL) {
        flb_hash_table_destroy(context->series_table);
    }

    flb_free(context);
}

int flb_cumulative_to_delta_ctx_process(struct flb_cumulative_to_delta_ctx *context,
                                        struct cmt *metrics_context)
{
    int result;
    uint64_t now;
    uint64_t context_identity;
    struct cfl_list *head;
    struct cmt_counter *counter;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;

    now = cfl_time_now();
    context_identity = compute_context_identity(metrics_context);

    if (now >= context->next_gc_timestamp) {
        series_state_gc(context, now);
        context->next_gc_timestamp = now + context->gc_interval;
    }

    cfl_list_foreach(head, &metrics_context->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);

        result = process_counter_map(context, counter, context_identity);
        if (result != 0) {
            return -1;
        }
    }

    cfl_list_foreach(head, &metrics_context->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);

        result = process_histogram_map(context, histogram, context_identity);
        if (result != 0) {
            return -1;
        }
    }

    cfl_list_foreach(head, &metrics_context->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);

        result = process_exp_histogram_map(context,
                                           exp_histogram,
                                           context_identity);
        if (result != 0) {
            return -1;
        }
    }

    series_state_evict_if_needed(context);

    return 0;
}

int flb_cumulative_to_delta_ctx_configure(
    struct flb_cumulative_to_delta_ctx *context,
    int max_staleness_seconds,
    int max_series)
{
    uint64_t default_gc_interval;

    if (context == NULL) {
        return -1;
    }

    if (max_staleness_seconds < 0 || max_series < 0) {
        return -1;
    }

    if (max_staleness_seconds == 0) {
        context->series_ttl = UINT64_MAX;
        context->gc_interval =
            (uint64_t) FLB_C2D_GC_INTERVAL_SECONDS * 1000000000ULL;
    }
    else {
        context->series_ttl = (uint64_t) max_staleness_seconds * 1000000000ULL;
        default_gc_interval =
            (uint64_t) FLB_C2D_GC_INTERVAL_SECONDS * 1000000000ULL;

        if (context->series_ttl < default_gc_interval) {
            context->gc_interval = context->series_ttl;
        }
        else {
            context->gc_interval = default_gc_interval;
        }
    }

    if (max_series == 0) {
        context->max_series = SIZE_MAX;
    }
    else {
        context->max_series = (size_t) max_series;
    }

    context->next_gc_timestamp = cfl_time_now() + context->gc_interval;

    return 0;
}
