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

#include <cmetrics/cmt_otlp_metadata.h>
#include <cmetrics/cmt_variant_utils.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>

#include <string.h>

#define METADATA_KEY "__cmetrics_native_metadata_v1"
/* Written only by unreleased builds; ignored on input, never emitted. */
#define HISTOGRAM_MARKER_KEY "__cmetrics_histogram_buckets"

struct cfl_kvlist *cmt_otlp_metadata_clone(struct cfl_kvlist *source)
{
    mpack_writer_t writer;
    mpack_reader_t reader;
    struct cfl_kvlist *copy = NULL;
    char *buffer = NULL;
    size_t size = 0;
    int result;

    if (source == NULL) {
        return NULL;
    }
    mpack_writer_init_growable(&writer, &buffer, &size);
    result = pack_cfl_variant_kvlist(&writer, source);
    if (mpack_writer_destroy(&writer) != mpack_ok || result != 0) {
        free(buffer);
        return NULL;
    }
    mpack_reader_init_data(&reader, buffer, size);
    result = unpack_cfl_kvlist(&reader, &copy);
    if (mpack_reader_destroy(&reader) != mpack_ok || result != 0) {
        cfl_kvlist_destroy(copy);
        copy = NULL;
    }
    free(buffer);
    return copy;
}

static int visit_maps(struct cmt *context,
                       int (*callback)(struct cmt_map *, void *), void *data)
{
    struct cfl_list *head;
    int result;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_summary *summary;
    struct cmt_histogram *histogram;
    struct cmt_exp_histogram *exp_histogram;


    cfl_list_foreach(head, &context->counters) {
        counter = cfl_list_entry(head, struct cmt_counter, _head);
        result = callback(counter->map, data);
        if (result != 0) {
            return result;
        }
    }
    cfl_list_foreach(head, &context->gauges) {
        gauge = cfl_list_entry(head, struct cmt_gauge, _head);
        result = callback(gauge->map, data);
        if (result != 0) {
            return result;
        }
    }
    cfl_list_foreach(head, &context->untypeds) {
        untyped = cfl_list_entry(head, struct cmt_untyped, _head);
        result = callback(untyped->map, data);
        if (result != 0) {
            return result;
        }
    }
    cfl_list_foreach(head, &context->summaries) {
        summary = cfl_list_entry(head, struct cmt_summary, _head);
        result = callback(summary->map, data);
        if (result != 0) {
            return result;
        }
    }
    cfl_list_foreach(head, &context->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        result = callback(histogram->map, data);
        if (result != 0) {
            return result;
        }
    }
    cfl_list_foreach(head, &context->exp_histograms) {
        exp_histogram = cfl_list_entry(head, struct cmt_exp_histogram, _head);
        result = callback(exp_histogram->map, data);
        if (result != 0) {
            return result;
        }
    }
    return 0;
}

static int count_maps(struct cmt_map *map, void *data)
{
    (*(size_t *) data)++;
    return 0;
}

static int has_metadata(struct cmt_map *map, void *data)
{
    struct cfl_list *head;
    struct cmt_metric *sample;

    if (map->otlp_metadata || map->metric.otlp_metadata ||
        (map->type == CMT_COUNTER && ((struct cmt_counter *) map->parent)->allow_reset)) {
        return 1;
    }
    cfl_list_foreach(head, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);
        if (sample->otlp_metadata) {
            return 1;
        }
    }
    return 0;
}

static int pack_optional_map(mpack_writer_t *writer, struct cfl_kvlist *map)
{
    mpack_writer_t metadata_writer;
    char *buffer = NULL;
    size_t size = 0;
    int result;

    if (map == NULL) {
        mpack_write_nil(writer);
        return 0;
    }
    /* A binary sidecar does not add nesting to the established wire metadata
     * tree. Older readers can retain/ignore it even for deeply nested values. */
    mpack_writer_init_growable(&metadata_writer, &buffer, &size);
    result = pack_cfl_variant_kvlist(&metadata_writer, map);
    if (mpack_writer_destroy(&metadata_writer) != mpack_ok || result || size > UINT32_MAX) {
        free(buffer);
        return -1;
    }
    mpack_write_bin(writer, buffer, size);
    free(buffer);
    return 0;
}

static int pack_map_metadata(struct cmt_map *map, void *data)
{
    mpack_writer_t *writer = data;
    struct cfl_list *head;
    struct cmt_metric *sample;

    mpack_start_map(writer, 5);
    mpack_write_cstr(writer, "type");
    mpack_write_int(writer, map->type);
    mpack_write_cstr(writer, "name");
    mpack_write_cstr(writer, map->opts->fqname);
    mpack_write_cstr(writer, "family");
    if (pack_optional_map(writer, map->otlp_metadata) != 0) {
        return -1;
    }
    mpack_write_cstr(writer, "allow_reset");
    mpack_write_bool(writer, map->type == CMT_COUNTER &&
                     ((struct cmt_counter *) map->parent)->allow_reset);
    mpack_write_cstr(writer, "points");
    mpack_start_array(writer, cfl_list_size(&map->metrics) + !!map->metric_static_set);
    if (map->metric_static_set && pack_optional_map(writer, map->metric.otlp_metadata) != 0) {
        return -1;
    }
    cfl_list_foreach(head, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);
        if (pack_optional_map(writer, sample->otlp_metadata) != 0) {
            return -1;
        }
    }
    mpack_finish_array(writer);
    mpack_finish_map(writer);
    return 0;
}

/* The established internal metadata map accepts arbitrary typed keys. No new
 * metric/map wire fields are emitted, so old decoders still consume the chunk.
 * Histogram buckets are never re-shaped here: they stay cumulative on the wire,
 * exactly as released readers and writers expect. */
int cmt_otlp_metadata_pack(mpack_writer_t *writer, struct cmt *context)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    size_t count = 0;
    size_t entries;
    int has_sidecar;
    int has_marker;

    has_sidecar = visit_maps(context, has_metadata, NULL) != 0;
    has_marker = cfl_kvlist_fetch(context->internal_metadata,
                                  HISTOGRAM_MARKER_KEY) != NULL;
    if (!has_sidecar && !has_marker) {
        return pack_cfl_variant_kvlist(writer, context->internal_metadata);
    }
    if (has_sidecar && cfl_kvlist_fetch(context->internal_metadata, METADATA_KEY)) {
        return -1;
    }

    /* A stale bucket marker is never forwarded. */
    entries = has_sidecar;
    cfl_list_foreach(head, &context->internal_metadata->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (strcmp(pair->key, HISTOGRAM_MARKER_KEY) != 0) {
            entries++;
        }
    }

    mpack_start_map(writer, entries);
    cfl_list_foreach(head, &context->internal_metadata->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (strcmp(pair->key, HISTOGRAM_MARKER_KEY) == 0) {
            continue;
        }
        mpack_write_str(writer, pair->key, cfl_sds_len(pair->key));
        if (pack_cfl_variant(writer, pair->val) != 0) {
            return -1;
        }
    }

    if (!has_sidecar) {
        mpack_finish_map(writer);
        return 0;
    }

    mpack_write_cstr(writer, METADATA_KEY);
    visit_maps(context, count_maps, &count);
    mpack_start_array(writer, count);
    if (visit_maps(context, pack_map_metadata, writer) != 0) {
        return -1;
    }
    mpack_finish_array(writer);
    mpack_finish_map(writer);
    return 0;
}

struct staged_family_metadata {
    struct cmt_map *map;
    struct cfl_kvlist *family;
    struct cfl_kvlist **points;
    size_t point_count;
    int allow_reset;
    int restore_points;
};

struct restore_state {
    struct cfl_array *families;
    size_t index;
    struct staged_family_metadata *staged;
};

static int restore_optional_map(struct cfl_kvlist **target, struct cfl_variant *value)
{
    struct cfl_kvlist *copy = NULL;
    mpack_reader_t reader;
    size_t remaining;
    int result;

    if (value == NULL || value->type == CFL_VARIANT_NULL) {
        return 0;
    }
    if (value->type == CFL_VARIANT_BYTES) {
        mpack_reader_init_data(&reader, value->data.as_bytes, cfl_sds_len(value->data.as_bytes));
        result = unpack_cfl_kvlist(&reader, &copy);
        remaining = result == 0 ? mpack_reader_remaining(&reader, NULL) : 0;
        if (mpack_reader_destroy(&reader) != mpack_ok || result || remaining) {
            cfl_kvlist_destroy(copy);
            return -1;
        }
    }
    else {
        return -1;
    }
    if (!copy) {
        return -1;
    }
    cfl_kvlist_destroy(*target);
    *target = copy;
    return 0;
}

static int stage_map_metadata(struct cmt_map *map, void *data)
{
    struct restore_state *state = data;
    struct staged_family_metadata *staged;
    struct cfl_variant *family;
    struct cfl_variant *points;
    struct cfl_variant *reset;
    size_t index;

    staged = &state->staged[state->index];
    family = state->families->entries[state->index++];
    staged->map = map;
    points = cfl_kvlist_fetch(family->data.as_kvlist, "points");
    reset = cfl_kvlist_fetch(family->data.as_kvlist, "allow_reset");
    if (!reset || reset->type != CFL_VARIANT_BOOL ||
        restore_optional_map(&staged->family, cfl_kvlist_fetch(family->data.as_kvlist, "family"))) {
        return -1;
    }
    staged->allow_reset = reset->data.as_bool;

    /* Label-less entries fold into the static metric on decode, so the point
     * list of that family may no longer line up: keep the family metadata
     * but skip its point metadata rather than misattributing it. */
    staged->restore_points = points->data.as_array->entry_count ==
                             cfl_list_size(&map->metrics) + !!map->metric_static_set;
    if (!staged->restore_points) {
        return 0;
    }

    staged->point_count = points->data.as_array->entry_count;
    if (staged->point_count > 0) {
        staged->points = calloc(staged->point_count, sizeof(*staged->points));
        if (!staged->points) {
            return -1;
        }
    }
    for (index = 0; index < staged->point_count; index++) {
        if (restore_optional_map(&staged->points[index], points->data.as_array->entries[index])) {
            return -1;
        }
    }
    return 0;
}

static void commit_map_metadata(struct staged_family_metadata *staged)
{
    struct cmt_map *map = staged->map;
    struct cfl_list *head;
    struct cmt_metric *sample;
    size_t index = 0;

    cfl_kvlist_destroy(map->otlp_metadata);
    map->otlp_metadata = staged->family;
    staged->family = NULL;
    if (map->type == CMT_COUNTER) {
        ((struct cmt_counter *) map->parent)->allow_reset = staged->allow_reset;
    }
    if (!staged->restore_points) {
        return;
    }
    if (map->metric_static_set) {
        cfl_kvlist_destroy(map->metric.otlp_metadata);
        map->metric.otlp_metadata = staged->points[index];
        staged->points[index++] = NULL;
    }
    cfl_list_foreach(head, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);
        cfl_kvlist_destroy(sample->otlp_metadata);
        sample->otlp_metadata = staged->points[index];
        staged->points[index++] = NULL;
    }
}

static int check_map_metadata_shape(struct cmt_map *map, void *data)
{
    struct restore_state *state = data;
    struct cfl_variant *family;
    struct cfl_variant *points;
    struct cfl_variant *name;
    struct cfl_variant *type;

    if (state->index >= state->families->entry_count) {
        return -1;
    }
    family = state->families->entries[state->index++];
    if (family->type != CFL_VARIANT_KVLIST) {
        return -1;
    }
    points = cfl_kvlist_fetch(family->data.as_kvlist, "points");
    name = cfl_kvlist_fetch(family->data.as_kvlist, "name");
    type = cfl_kvlist_fetch(family->data.as_kvlist, "type");
    if (points == NULL || points->type != CFL_VARIANT_ARRAY) {
        return -1;
    }
    if (name != NULL && (name->type != CFL_VARIANT_STRING ||
                        cfl_sds_len(name->data.as_string) != cfl_sds_len(map->opts->fqname) ||
                        memcmp(name->data.as_string, map->opts->fqname,
                               cfl_sds_len(map->opts->fqname)) != 0)) {
        return -1;
    }
    if (type != NULL && !((type->type == CFL_VARIANT_INT && type->data.as_int64 == map->type) ||
                          (type->type == CFL_VARIANT_UINT && type->data.as_uint64 == map->type))) {
        return -1;
    }
    return 0;
}

int cmt_otlp_metadata_restore(struct cmt *context)
{
    struct cfl_variant *value;
    struct restore_state state;
    int result;
    size_t family_index;
    size_t point_index;

    value = cfl_kvlist_fetch(context->internal_metadata, METADATA_KEY);
    if (value == NULL) {
        return 0;
    }
    if (value->type != CFL_VARIANT_ARRAY) {
        cfl_kvlist_remove(context->internal_metadata, METADATA_KEY);
        return 0;
    }
    state.families = value->data.as_array;
    state.index = 0;
    result = visit_maps(context, check_map_metadata_shape, &state);
    if (result != 0 || state.index != state.families->entry_count) {
        /* Optional metadata must not invalidate an otherwise usable chunk. */
        cfl_kvlist_remove(context->internal_metadata, METADATA_KEY);
        return 0;
    }
    state.staged = calloc(state.families->entry_count, sizeof(*state.staged));
    if (!state.staged && state.families->entry_count > 0) {
        cfl_kvlist_remove(context->internal_metadata, METADATA_KEY);
        return 0;
    }
    state.index = 0;
    result = visit_maps(context, stage_map_metadata, &state);
    if (result == 0) {
        for (family_index = 0; family_index < state.families->entry_count; family_index++) {
            commit_map_metadata(&state.staged[family_index]);
        }
    }
    for (family_index = 0; family_index < state.families->entry_count; family_index++) {
        cfl_kvlist_destroy(state.staged[family_index].family);
        if (state.staged[family_index].points != NULL) {
            for (point_index = 0; point_index < state.staged[family_index].point_count; point_index++) {
                cfl_kvlist_destroy(state.staged[family_index].points[point_index]);
            }
        }
        free(state.staged[family_index].points);
    }
    free(state.staged);
    cfl_kvlist_remove(context->internal_metadata, METADATA_KEY);
    /* Malformed optional metadata never invalidates the native metric payload. */
    return 0;
}

int cmt_otlp_capture_labels(struct cmt_map *map, struct cmt_metric *sample)
{
    struct cfl_list *key_head;
    struct cfl_list *value_head;
    struct cmt_map_label *key;
    struct cmt_map_label *value;
    struct cfl_kvlist *projection;

    if (!sample->otlp_metadata) {
        return -1;
    }
    projection = cfl_kvlist_create();
    if (!projection) {
        return -1;
    }
    key_head = map->label_keys.next;
    value_head = sample->labels.next;
    while (key_head != &map->label_keys && value_head != &sample->labels) {
        key = cfl_list_entry(key_head, struct cmt_map_label, _head);
        value = cfl_list_entry(value_head, struct cmt_map_label, _head);
        if (key->name && value->name && cfl_kvlist_insert_string(projection, key->name, value->name)) {
            cfl_kvlist_destroy(projection);
            return -1;
        }
        key_head = key_head->next;
        value_head = value_head->next;
    }
    cfl_kvlist_remove(sample->otlp_metadata, "label_projection");
    if (cfl_kvlist_insert_kvlist(sample->otlp_metadata, "label_projection", projection)) {
        cfl_kvlist_destroy(projection);
        return -1;
    }
    return 0;
}

int cmt_otlp_attributes_match_labels(struct cmt_map *map, struct cmt_metric *sample)
{
    struct cfl_variant *projection;
    struct cfl_list *key_head;
    struct cfl_list *value_head;
    struct cfl_list *original_head;
    struct cfl_kvpair *original;
    struct cmt_map_label *key;
    struct cmt_map_label *value;

    if (!sample->otlp_metadata) {
        return CMT_FALSE;
    }
    projection = cfl_kvlist_fetch(sample->otlp_metadata, "label_projection");
    if (!projection || projection->type != CFL_VARIANT_KVLIST) {
        return CMT_FALSE;
    }
    key_head = map->label_keys.next;
    value_head = sample->labels.next;
    original_head = projection->data.as_kvlist->list.next;
    while (key_head != &map->label_keys && value_head != &sample->labels) {
        key = cfl_list_entry(key_head, struct cmt_map_label, _head);
        value = cfl_list_entry(value_head, struct cmt_map_label, _head);
        if (key->name && value->name) {
            if (original_head == &projection->data.as_kvlist->list) {
                return CMT_FALSE;
            }
            original = cfl_list_entry(original_head, struct cfl_kvpair, _head);
            if (original->val->type != CFL_VARIANT_STRING ||
                strcmp(original->key, key->name) || strcmp(original->val->data.as_string, value->name)) {
                return CMT_FALSE;
            }
            original_head = original_head->next;
        }
        key_head = key_head->next;
        value_head = value_head->next;
    }
    return original_head == &projection->data.as_kvlist->list && value_head == &sample->labels;
}

/*
 * CMetrics stores classic histogram buckets cumulatively (including +Inf) and
 * the msgpack wire format carries them exactly like that. Fluent Bit v5.1.0
 * and older, however, stored OTLP-decoded histograms with independent bucket
 * counts in the same fields, so chunks written by those releases (forward
 * peers, filesystem backlog) can contain either shape without any marker.
 *
 * Detect the shape from the sample itself instead of trusting a marker:
 *
 * - monotonic buckets whose last (+Inf) value equals count: cumulative.
 * - otherwise, buckets whose sum equals count: independent counts.
 * - anything else is left untouched (cumulative by default).
 *
 * Both rules can only match at once when every bucket but +Inf is zero, in
 * which case both interpretations are identical, so the check is unambiguous
 * for consistent data.
 */
static int histogram_sample_is_independent(struct cmt_metric *sample, size_t count)
{
    uint64_t total;
    uint64_t value;
    uint64_t previous;
    uint64_t sample_count;
    size_t index;
    int monotonic;

    if (sample->hist_buckets == NULL || count == 0) {
        return CMT_FALSE;
    }

    sample_count = cmt_metric_hist_get_count_value(sample);
    total = 0;
    previous = 0;
    monotonic = CMT_TRUE;

    for (index = 0; index < count; index++) {
        value = sample->hist_buckets[index];
        if (value < previous) {
            monotonic = CMT_FALSE;
        }
        previous = value;

        if (value > UINT64_MAX - total) {
            /* An overflowing sum cannot match any count. */
            return CMT_FALSE;
        }
        total += value;
    }

    if (monotonic && sample->hist_buckets[count - 1] == sample_count) {
        return CMT_FALSE;
    }

    return total == sample_count;
}

static void normalize_histogram_sample(struct cmt_metric *sample, size_t count)
{
    uint64_t total;
    size_t index;

    if (!histogram_sample_is_independent(sample, count)) {
        return;
    }

    total = 0;
    for (index = 0; index < count; index++) {
        /* No overflow: the sum was validated against count. */
        total += sample->hist_buckets[index];
        sample->hist_buckets[index] = total;
    }
}

int cmt_otlp_histogram_restore(struct cmt *context)
{
    struct cfl_list *head;
    struct cfl_list *sample_head;
    struct cmt_histogram *histogram;
    struct cmt_metric *sample;

    /* A bucket marker is advisory at most: drop it whatever its value. */
    if (cfl_kvlist_fetch(context->internal_metadata, HISTOGRAM_MARKER_KEY) != NULL) {
        cfl_kvlist_remove(context->internal_metadata, HISTOGRAM_MARKER_KEY);
    }

    cfl_list_foreach(head, &context->histograms) {
        histogram = cfl_list_entry(head, struct cmt_histogram, _head);
        if (histogram->buckets == NULL) {
            continue;
        }

        if (histogram->map->metric_static_set) {
            normalize_histogram_sample(&histogram->map->metric,
                                       histogram->buckets->count + 1);
        }

        cfl_list_foreach(sample_head, &histogram->map->metrics) {
            sample = cfl_list_entry(sample_head, struct cmt_metric, _head);
            normalize_histogram_sample(sample, histogram->buckets->count + 1);
        }
    }

    return 0;
}
