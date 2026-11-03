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
#include <cmetrics/cmt_atomic.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>

#define METADATA_KEY "__cmetrics_native_metadata_v1"
/* Written only by unreleased builds; ignored on input, never emitted. */
#define HISTOGRAM_MARKER_KEY "__cmetrics_histogram_buckets"

static struct cfl_kvlist *clone_kvlist(struct cfl_kvlist *source);

static struct cfl_variant *clone_variant(struct cfl_variant *source)
{
    size_t index;
    struct cfl_array *array;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *entry;
    struct cfl_variant *copy;

    switch (source->type) {
    case CFL_VARIANT_STRING:
        return cfl_variant_create_from_string_s(source->data.as_string,
                                                cfl_variant_size_get(source), CFL_FALSE);
    case CFL_VARIANT_REFERENCE:
        return cfl_variant_create_from_string(source->data.as_reference);
    case CFL_VARIANT_BYTES:
        return cfl_variant_create_from_bytes(source->data.as_bytes,
                                             cfl_variant_size_get(source), CFL_FALSE);
    case CFL_VARIANT_BOOL:
        return cfl_variant_create_from_bool(source->data.as_bool);
    case CFL_VARIANT_INT:
        return cfl_variant_create_from_int64(source->data.as_int64);
    case CFL_VARIANT_UINT:
        return cfl_variant_create_from_uint64(source->data.as_uint64);
    case CFL_VARIANT_DOUBLE:
        return cfl_variant_create_from_double(source->data.as_double);
    case CFL_VARIANT_NULL:
        return cfl_variant_create_from_null();
    case CFL_VARIANT_ARRAY:
        array = cfl_array_create(source->data.as_array->entry_count);
        if (array == NULL) {
            return NULL;
        }
        for (index = 0; index < source->data.as_array->entry_count; index++) {
            entry = clone_variant(source->data.as_array->entries[index]);
            if (entry == NULL || cfl_array_append(array, entry) != 0) {
                cfl_variant_destroy(entry);
                cfl_array_destroy(array);
                return NULL;
            }
        }
        copy = cfl_variant_create_from_array(array);
        if (copy == NULL) {
            cfl_array_destroy(array);
        }
        return copy;
    case CFL_VARIANT_KVLIST:
        kvlist = clone_kvlist(source->data.as_kvlist);
        if (kvlist == NULL) {
            return NULL;
        }
        copy = cfl_variant_create_from_kvlist(kvlist);
        if (copy == NULL) {
            cfl_kvlist_destroy(kvlist);
        }
        return copy;
    default:
        return NULL;
    }
}

static struct cfl_kvlist *clone_kvlist(struct cfl_kvlist *source)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_kvlist *copy;
    struct cfl_variant *value;

    copy = cfl_kvlist_create();
    if (copy == NULL) {
        return NULL;
    }
    cfl_list_foreach(head, &source->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        value = clone_variant(pair->val);
        if (value == NULL ||
            cfl_kvlist_insert_s(copy, pair->key, cfl_sds_len(pair->key), value) != 0) {
            cfl_variant_destroy(value);
            cfl_kvlist_destroy(copy);
            return NULL;
        }
    }
    return copy;
}

/*
 * Deep copy, preserving key order and duplicate keys. Unlike a msgpack round
 * trip it has no nesting limit, so metadata accepted by a decoder can always
 * be copied.
 */
struct cfl_kvlist *cmt_otlp_metadata_clone(struct cfl_kvlist *source)
{
    if (source == NULL) {
        return NULL;
    }
    return clone_kvlist(source);
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

static void fingerprint_u64(cfl_hash_state_t *state, uint64_t value)
{
    unsigned char bytes[8];
    int index;

    /* byte order independent: writer and reader may differ */
    for (index = 0; index < 8; index++) {
        bytes[index] = (unsigned char) (value >> (index * 8));
    }
    cfl_hash_64bits_update(state, bytes, sizeof(bytes));
}

static uint64_t double_bits(double value)
{
    uint64_t bits;

    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

/*
 * Fingerprint of the complete value a point carries through the MessagePack
 * codec, read as pack_metric() reads it, distributions included. Points of
 * one series and time window that differ only in what the labels cannot
 * hold, such as attribute types, usually differ in value too.
 */
static int point_fingerprint(struct cmt_map *map, struct cmt_metric *sample,
                             uint64_t *fingerprint)
{
    struct cmt_exp_histogram_snapshot snapshot;
    struct cmt_histogram *histogram;
    struct cmt_summary *summary;
    cfl_hash_state_t state;
    int64_t int64_value;
    uint64_t uint64_value;
    size_t index;
    int type;

    cfl_hash_64bits_reset(&state);
    fingerprint_u64(&state, map->type);
    if (map->type == CMT_HISTOGRAM) {
        histogram = (struct cmt_histogram *) map->parent;
        for (index = 0; index <= histogram->buckets->count; index++) {
            fingerprint_u64(&state, cmt_metric_hist_get_value(sample, index));
        }
        fingerprint_u64(&state, cmt_metric_hist_get_count_value(sample));
        fingerprint_u64(&state, double_bits(cmt_metric_hist_get_sum_value(sample)));
    }
    else if (map->type == CMT_SUMMARY) {
        summary = (struct cmt_summary *) map->parent;
        fingerprint_u64(&state, cmt_atomic_load(&sample->sum_quantiles_set));
        for (index = 0; sample->sum_quantiles != NULL &&
                        index < summary->quantiles_count; index++) {
            fingerprint_u64(&state, cmt_atomic_load(&sample->sum_quantiles[index]));
        }
        fingerprint_u64(&state, cmt_summary_get_count_value(sample));
        fingerprint_u64(&state, double_bits(cmt_summary_get_sum_value(sample)));
    }
    else if (map->type == CMT_EXP_HISTOGRAM) {
        if (cmt_metric_exp_hist_get_snapshot(sample, &snapshot) != 0) {
            return -1;
        }
        fingerprint_u64(&state, (uint64_t) (int64_t) snapshot.scale);
        fingerprint_u64(&state, snapshot.zero_count);
        fingerprint_u64(&state, double_bits(snapshot.zero_threshold));
        fingerprint_u64(&state, (uint64_t) (int64_t) snapshot.positive_offset);
        fingerprint_u64(&state, snapshot.positive_count);
        for (index = 0; index < snapshot.positive_count; index++) {
            fingerprint_u64(&state, snapshot.positive_buckets[index]);
        }
        fingerprint_u64(&state, (uint64_t) (int64_t) snapshot.negative_offset);
        fingerprint_u64(&state, snapshot.negative_count);
        for (index = 0; index < snapshot.negative_count; index++) {
            fingerprint_u64(&state, snapshot.negative_buckets[index]);
        }
        fingerprint_u64(&state, snapshot.count);
        fingerprint_u64(&state, snapshot.sum_set);
        fingerprint_u64(&state, snapshot.sum);
        cmt_metric_exp_hist_snapshot_destroy(&snapshot);
    }
    else {
        cmt_metric_get_value_snapshot(sample, &type, &int64_value, &uint64_value);
        fingerprint_u64(&state, type);
        if (type == CMT_METRIC_VALUE_INT64) {
            fingerprint_u64(&state, (uint64_t) int64_value);
        }
        else if (type == CMT_METRIC_VALUE_UINT64) {
            fingerprint_u64(&state, uint64_value);
        }
        else {
            fingerprint_u64(&state, double_bits(cmt_metric_get_value(sample)));
        }
    }
    *fingerprint = cfl_hash_64bits_digest(&state);
    return 0;
}

/*
 * A point is identified as in cmt_cat() by label values, time and start
 * time, plus a fingerprint of its values. The series hash concatenates label
 * values without boundaries, so distinct label sets can share it: it only
 * accelerates the comparison. Values are written as pack_metric() writes
 * labels, so they compare against the labels a reader decodes. The start
 * time is appended only when set, so its absence stays distinct. A point
 * whose fingerprint cannot be computed records zero and is unlikely to bind.
 */
static void pack_point_id(mpack_writer_t *writer, struct cmt_map *map,
                          struct cmt_metric *sample)
{
    int has_start;
    uint64_t fingerprint;
    struct cfl_list *head;
    struct cmt_map_label *label;

    if (point_fingerprint(map, sample, &fingerprint) != 0) {
        fingerprint = 0;
    }
    has_start = cmt_metric_has_start_timestamp(sample);
    mpack_start_array(writer, has_start ? 5 : 4);
    mpack_write_uint(writer, sample->hash);
    mpack_write_uint(writer, cmt_metric_get_timestamp(sample));
    mpack_start_array(writer, cfl_list_size(&sample->labels));
    cfl_list_foreach(head, &sample->labels) {
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        if (label->name == NULL) {
            mpack_write_nil(writer);
        }
        else {
            mpack_write_cstr(writer, label->name);
        }
    }
    mpack_finish_array(writer);
    mpack_write_uint(writer, fingerprint);
    if (has_start) {
        mpack_write_uint(writer, cmt_metric_get_start_timestamp(sample));
    }
    mpack_finish_array(writer);
}

static int pack_map_metadata(struct cmt_map *map, void *data)
{
    mpack_writer_t *writer = data;
    struct cfl_list *head;
    struct cmt_metric *sample;

    mpack_start_map(writer, 6);
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

    /* Identity of each entry in "points". An intermediary
     * that edits points without updating the sidecar (any released reader)
     * changes them, so readers bind by identity instead of by position.
     * Readers of v2.3.0 ignore this key. */
    mpack_write_cstr(writer, "point_ids");
    mpack_start_array(writer, cfl_list_size(&map->metrics) + !!map->metric_static_set);
    if (map->metric_static_set) {
        pack_point_id(writer, map, &map->metric);
    }
    cfl_list_foreach(head, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);
        pack_point_id(writer, map, sample);
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

/*
 * Fluent Bit 5.1 and older keep OTLP point metadata in the external metadata
 * tree: otlp -> metrics -> <type> -> <name> -> {metadata, datapoints}, where a
 * point is keyed by "<series hash>:<timestamp>". They do not read the binary
 * sidecar, so the encoder also writes that tree for families with metadata,
 * with the keys those readers use. The tree is built on a copy: the context
 * itself is not modified.
 */
static const char *legacy_point_keys[] = {
    "start_time_unix_nano", "flags", "number_value_case", "has_sum", "has_min",
    "min", "has_max", "max", "exemplars", NULL
};

static const char *legacy_type_key(int map_type)
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
        return "unknown";
    }
}

static struct cfl_kvlist *legacy_child(struct cfl_kvlist *parent, const char *key)
{
    struct cfl_variant *value;
    struct cfl_kvlist *child;

    value = cfl_kvlist_fetch(parent, (char *) key);
    if (value != NULL && value->type == CFL_VARIANT_KVLIST) {
        return value->data.as_kvlist;
    }
    if (value != NULL) {
        cfl_kvlist_remove(parent, (char *) key);
    }
    child = cfl_kvlist_create();
    if (child == NULL) {
        return NULL;
    }
    if (cfl_kvlist_insert_kvlist(parent, (char *) key, child) != 0) {
        cfl_kvlist_destroy(child);
        return NULL;
    }
    return child;
}

static int legacy_add_point(struct cfl_kvlist *datapoints, struct cmt_metric *sample)
{
    char key[64];
    size_t index;
    struct cfl_variant *value;
    struct cfl_variant *copy;
    struct cfl_kvlist *point;

    if (sample->otlp_metadata == NULL) {
        return 0;
    }

    snprintf(key, sizeof(key), "%" PRIx64 ":%" PRIu64,
             sample->hash, cmt_metric_get_timestamp(sample));
    cfl_kvlist_remove(datapoints, key);
    point = legacy_child(datapoints, key);
    if (point == NULL) {
        return -1;
    }

    for (index = 0; legacy_point_keys[index] != NULL; index++) {
        value = cfl_kvlist_fetch(sample->otlp_metadata, (char *) legacy_point_keys[index]);
        if (value == NULL) {
            continue;
        }
        copy = clone_variant(value);
        if (copy == NULL ||
            cfl_kvlist_insert(point, (char *) legacy_point_keys[index], copy) != 0) {
            cfl_variant_destroy(copy);
            return -1;
        }
    }
    return 0;
}

static int legacy_add_map(struct cmt_map *map, void *data)
{
    struct cfl_kvlist *metrics = data;
    struct cfl_kvlist *type_root;
    struct cfl_kvlist *family;
    struct cfl_kvlist *datapoints;
    struct cfl_kvlist *copy;
    struct cfl_variant *metadata;
    struct cfl_list *head;
    struct cmt_metric *sample;
    int points;

    metadata = map->otlp_metadata ? cfl_kvlist_fetch(map->otlp_metadata, "metadata") : NULL;
    points = map->metric_static_set && map->metric.otlp_metadata != NULL;
    cfl_list_foreach(head, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);
        points |= sample->otlp_metadata != NULL;
    }
    if (!points && (metadata == NULL || metadata->type != CFL_VARIANT_KVLIST)) {
        return 0;
    }

    type_root = legacy_child(metrics, legacy_type_key(map->type));
    if (type_root == NULL) {
        return -1;
    }
    family = legacy_child(type_root, map->opts->fqname);
    if (family == NULL) {
        return -1;
    }

    if (metadata != NULL && metadata->type == CFL_VARIANT_KVLIST) {
        copy = clone_kvlist(metadata->data.as_kvlist);
        cfl_kvlist_remove(family, "metadata");
        if (copy == NULL || cfl_kvlist_insert_kvlist(family, "metadata", copy) != 0) {
            cfl_kvlist_destroy(copy);
            return -1;
        }
    }

    if (!points) {
        return 0;
    }
    datapoints = legacy_child(family, "datapoints");
    if (datapoints == NULL) {
        return -1;
    }
    if (map->metric_static_set && legacy_add_point(datapoints, &map->metric) != 0) {
        return -1;
    }
    cfl_list_foreach(head, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);
        if (legacy_add_point(datapoints, sample) != 0) {
            return -1;
        }
    }
    return 0;
}

static int has_legacy_metadata(struct cmt_map *map, void *data)
{
    struct cfl_list *head;
    struct cmt_metric *sample;

    if ((map->otlp_metadata && cfl_kvlist_fetch(map->otlp_metadata, "metadata")) ||
        (map->metric_static_set && map->metric.otlp_metadata)) {
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

int cmt_otlp_metadata_pack_external(mpack_writer_t *writer, struct cmt *context)
{
    int result;
    struct cfl_kvlist *external;
    struct cfl_kvlist *otlp;
    struct cfl_kvlist *metrics;

    if (visit_maps(context, has_legacy_metadata, NULL) == 0) {
        return pack_cfl_variant_kvlist(writer, context->external_metadata);
    }

    external = clone_kvlist(context->external_metadata);
    if (external == NULL) {
        return -1;
    }
    otlp = legacy_child(external, "otlp");
    metrics = otlp ? legacy_child(otlp, "metrics") : NULL;
    if (metrics == NULL || visit_maps(context, legacy_add_map, metrics) != 0) {
        cfl_kvlist_destroy(external);
        return -1;
    }

    result = pack_cfl_variant_kvlist(writer, external);
    cfl_kvlist_destroy(external);
    return result;
}

struct staged_family_metadata {
    struct cmt_map *map;
    struct cfl_kvlist *family;
    struct cfl_kvlist **points;
    struct cfl_array *point_ids;
    size_t *order;
    unsigned char *point_flags;
    size_t point_count;
    int allow_reset;
    int restore_points;
};

/* point_flags bits, per staged point: identity recorded more than once,
 * native metadata read back, bound to a decoded sample */
#define POINT_AMBIGUOUS     1
#define POINT_HAS_METADATA  2
#define POINT_MATCHED       4

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
        if (result != 0) {
            /* A rejected value can leave containers open without setting an
             * MPack error (for example, at the nesting limit). Cancel tracking
             * before destroying this reader for optional metadata. */
            mpack_reader_flag_error(&reader, mpack_error_data);
        }
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

/* Unsigned values are read back as CFL_VARIANT_INT with the same bits. */
static int is_integer(struct cfl_variant *value)
{
    return value->type == CFL_VARIANT_INT || value->type == CFL_VARIANT_UINT;
}

static uint64_t integer_bits(struct cfl_variant *value)
{
    if (value->type == CFL_VARIANT_INT) {
        return (uint64_t) value->data.as_int64;
    }
    return value->data.as_uint64;
}

static int label_values_valid(struct cfl_variant *values)
{
    struct cfl_array *array;
    size_t index;

    if (values->type != CFL_VARIANT_ARRAY) {
        return CMT_FALSE;
    }
    array = values->data.as_array;
    for (index = 0; index < array->entry_count; index++) {
        if (array->entries[index]->type != CFL_VARIANT_STRING &&
            array->entries[index]->type != CFL_VARIANT_NULL) {
            return CMT_FALSE;
        }
    }
    return CMT_TRUE;
}

/* Each identifier is [series hash, timestamp, label values, fingerprint]
 * with the start timestamp appended when set, one per "points" entry. */
static int point_ids_valid(struct cfl_variant *ids, size_t count)
{
    struct cfl_array *id;
    size_t index;

    if (ids->type != CFL_VARIANT_ARRAY || ids->data.as_array->entry_count != count) {
        return CMT_FALSE;
    }
    for (index = 0; index < count; index++) {
        if (ids->data.as_array->entries[index]->type != CFL_VARIANT_ARRAY) {
            return CMT_FALSE;
        }
        id = ids->data.as_array->entries[index]->data.as_array;
        if (id->entry_count < 4 || id->entry_count > 5 ||
            !is_integer(id->entries[0]) || !is_integer(id->entries[1]) ||
            !label_values_valid(id->entries[2]) || !is_integer(id->entries[3]) ||
            (id->entry_count == 5 && !is_integer(id->entries[4]))) {
            return CMT_FALSE;
        }
    }
    return CMT_TRUE;
}

static int compare_u64(uint64_t left, uint64_t right)
{
    return left < right ? -1 : left > right;
}

/* Order a label value against one read back from an identifier: nil first,
 * then by length and bytes, so values keep their boundaries. */
static int compare_label_value(struct cfl_variant *value, cfl_sds_t label)
{
    size_t length;
    int result;

    if (value->type == CFL_VARIANT_NULL || label == NULL) {
        return (value->type != CFL_VARIANT_NULL) - (label != NULL);
    }
    length = cfl_sds_len(value->data.as_string);
    if (length != cfl_sds_len(label)) {
        return length < cfl_sds_len(label) ? -1 : 1;
    }
    result = memcmp(value->data.as_string, label, length);
    return (result > 0) - (result < 0);
}

static int compare_id_header(struct cfl_array *id, uint64_t hash, uint64_t timestamp,
                             uint64_t fingerprint, int has_start, uint64_t start,
                             size_t label_count)
{
    int result;

    result = compare_u64(integer_bits(id->entries[0]), hash);
    if (result == 0) {
        result = compare_u64(integer_bits(id->entries[1]), timestamp);
    }
    if (result == 0) {
        result = compare_u64(integer_bits(id->entries[3]), fingerprint);
    }
    if (result == 0) {
        result = (id->entry_count == 5) - (has_start != 0);
    }
    if (result == 0 && has_start) {
        result = compare_u64(integer_bits(id->entries[4]), start);
    }
    if (result == 0) {
        result = compare_u64(id->entries[2]->data.as_array->entry_count, label_count);
    }
    return result;
}

/* Order an identifier against a decoded sample with its fingerprint. */
static int compare_id_sample(struct cfl_array *id, struct cmt_metric *sample,
                             uint64_t fingerprint)
{
    struct cfl_array *values;
    struct cfl_list *head;
    struct cmt_map_label *label;
    size_t index = 0;
    int has_start;
    int result;

    has_start = cmt_metric_has_start_timestamp(sample);
    result = compare_id_header(id, sample->hash, cmt_metric_get_timestamp(sample),
                               fingerprint, has_start,
                               has_start ? cmt_metric_get_start_timestamp(sample) : 0,
                               cfl_list_size(&sample->labels));
    values = id->entries[2]->data.as_array;
    cfl_list_foreach(head, &sample->labels) {
        if (result != 0) {
            break;
        }
        label = cfl_list_entry(head, struct cmt_map_label, _head);
        result = compare_label_value(values->entries[index++], label->name);
    }
    return result;
}

/* Order two identifiers. */
static int compare_ids(struct cfl_array *left, struct cfl_array *right)
{
    struct cfl_array *left_values;
    struct cfl_array *right_values;
    struct cfl_variant *value;
    size_t index;
    int has_start;
    int result;

    has_start = right->entry_count == 5;
    right_values = right->entries[2]->data.as_array;
    result = compare_id_header(left, integer_bits(right->entries[0]),
                               integer_bits(right->entries[1]),
                               integer_bits(right->entries[3]), has_start,
                               has_start ? integer_bits(right->entries[4]) : 0,
                               right_values->entry_count);
    left_values = left->entries[2]->data.as_array;
    for (index = 0; result == 0 && index < left_values->entry_count; index++) {
        value = right_values->entries[index];
        result = compare_label_value(left_values->entries[index],
                                     value->type == CFL_VARIANT_NULL ?
                                     NULL : value->data.as_string);
    }
    return result;
}

static int compare_staged(struct cfl_array *ids, size_t left, size_t right)
{
    return compare_ids(ids->entries[left]->data.as_array,
                       ids->entries[right]->data.as_array);
}

static void sift_down(struct cfl_array *ids, size_t *order, size_t root, size_t count)
{
    size_t child;
    size_t swap;

    while ((child = root * 2 + 1) < count) {
        if (child + 1 < count && compare_staged(ids, order[child], order[child + 1]) < 0) {
            child++;
        }
        if (compare_staged(ids, order[root], order[child]) >= 0) {
            return;
        }
        swap = order[root];
        order[root] = order[child];
        order[child] = swap;
        root = child;
    }
}

/* Sort identifier positions in place. The comparison needs the identifiers,
 * which qsort() cannot receive without shared state. */
static void sort_point_ids(struct cfl_array *ids, size_t *order, size_t count)
{
    size_t index;
    size_t swap;

    for (index = count / 2; index-- > 0;) {
        sift_down(ids, order, index, count);
    }
    for (index = count; index-- > 1;) {
        swap = order[0];
        order[0] = order[index];
        order[index] = swap;
        sift_down(ids, order, 0, index);
    }
}

/* Find the staged entry recorded for this sample, or point_count. */
static size_t find_point_id(struct staged_family_metadata *staged, struct cmt_metric *sample,
                            uint64_t fingerprint)
{
    size_t low = 0;
    size_t high = staged->point_count;
    size_t middle;

    while (low < high) {
        middle = low + (high - low) / 2;
        if (compare_id_sample(staged->point_ids->entries[staged->order[middle]]
                              ->data.as_array, sample, fingerprint) < 0) {
            low = middle + 1;
        }
        else {
            high = middle;
        }
    }
    if (low >= staged->point_count ||
        compare_id_sample(staged->point_ids->entries[staged->order[low]]->data.as_array,
                          sample, fingerprint) != 0) {
        return staged->point_count;
    }
    return staged->order[low];
}

/*
 * Take the staged metadata recorded for this sample. Without identifiers
 * (v2.3.0) points bind by position. Otherwise each sample is looked up by
 * identity through the sorted identifiers, wherever it now sits. A sample
 * whose identity is not recorded gets no metadata, and neither does one
 * whose identity was recorded more than once: nothing tells those points
 * apart, so whichever binding was chosen could be another point's.
 */
static struct cfl_kvlist *take_point_metadata(struct staged_family_metadata *staged,
                                              struct cmt_metric *sample, size_t position)
{
    struct cfl_kvlist *metadata;
    uint64_t fingerprint;
    size_t index;

    if (staged->point_ids == NULL) {
        index = position;
    }
    else {
        if (point_fingerprint(staged->map, sample, &fingerprint) != 0) {
            return NULL;
        }
        index = find_point_id(staged, sample, fingerprint);
        if (index >= staged->point_count ||
            (staged->point_flags[index] & POINT_AMBIGUOUS)) {
            return NULL;
        }
        staged->point_flags[index] |= POINT_MATCHED;
    }
    metadata = staged->points[index];
    staged->points[index] = NULL;
    return metadata;
}

static int stage_map_metadata(struct cmt_map *map, void *data)
{
    struct restore_state *state = data;
    struct staged_family_metadata *staged;
    struct cfl_variant *family;
    struct cfl_variant *points;
    struct cfl_variant *reset;
    struct cfl_variant *ids;
    size_t index;

    staged = &state->staged[state->index];
    family = state->families->entries[state->index++];
    staged->map = map;
    points = cfl_kvlist_fetch(family->data.as_kvlist, "points");
    reset = cfl_kvlist_fetch(family->data.as_kvlist, "allow_reset");
    if (!reset || reset->type != CFL_VARIANT_BOOL) {
        return -1;
    }
    staged->allow_reset = reset->data.as_bool;

    /* metadata that cannot be read back is skipped for this family only */
    if (restore_optional_map(&staged->family,
                             cfl_kvlist_fetch(family->data.as_kvlist, "family")) != 0) {
        staged->family = NULL;
    }

    ids = cfl_kvlist_fetch(family->data.as_kvlist, "point_ids");
    if (ids != NULL) {
        /* Points are bound by labels, time and start time. Identifiers that
         * cannot be read back leave the family without point metadata. */
        staged->restore_points = point_ids_valid(ids, points->data.as_array->entry_count);
        staged->point_ids = staged->restore_points ? ids->data.as_array : NULL;
    }
    else {
        /* v2.3.0 sidecars carry no identifiers and bind by position. Label-less
         * entries fold into the static metric on decode, so the point list of
         * that family may no longer line up: keep the family metadata but skip
         * its point metadata rather than misattributing it. */
        staged->restore_points = points->data.as_array->entry_count ==
                                 cfl_list_size(&map->metrics) + !!map->metric_static_set;
    }
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
    if (staged->point_ids != NULL && staged->point_count > 0) {
        staged->point_flags = calloc(staged->point_count, sizeof(*staged->point_flags));
        if (!staged->point_flags) {
            return -1;
        }
    }
    for (index = 0; index < staged->point_count; index++) {
        /* a point whose metadata cannot be read back keeps none here, and
         * keeps its legacy entry: only metadata read back supersedes it */
        if (restore_optional_map(&staged->points[index],
                                 points->data.as_array->entries[index]) != 0) {
            staged->points[index] = NULL;
        }
        if (staged->point_flags != NULL && staged->points[index] != NULL) {
            staged->point_flags[index] |= POINT_HAS_METADATA;
        }
    }
    if (staged->point_ids != NULL && staged->point_count > 0) {
        staged->order = malloc(staged->point_count * sizeof(*staged->order));
        if (!staged->order) {
            return -1;
        }
        for (index = 0; index < staged->point_count; index++) {
            staged->order[index] = index;
        }
        sort_point_ids(staged->point_ids, staged->order, staged->point_count);

        for (index = 1; index < staged->point_count; index++) {
            if (compare_staged(staged->point_ids, staged->order[index - 1],
                               staged->order[index]) == 0) {
                staged->point_flags[staged->order[index - 1]] |= POINT_AMBIGUOUS;
                staged->point_flags[staged->order[index]] |= POINT_AMBIGUOUS;
            }
        }
    }
    return 0;
}

static struct cfl_kvlist *legacy_type_root(struct cmt *context, struct cmt_map *map)
{
    struct cfl_variant *value;

    value = cfl_kvlist_fetch(context->external_metadata, "otlp");
    if (value == NULL || value->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }
    value = cfl_kvlist_fetch(value->data.as_kvlist, "metrics");
    if (value == NULL || value->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }
    value = cfl_kvlist_fetch(value->data.as_kvlist, (char *) legacy_type_key(map->type));
    if (value == NULL || value->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }
    return value->data.as_kvlist;
}

static struct cfl_kvlist *legacy_family(struct cmt *context, struct cmt_map *map)
{
    struct cfl_kvlist *type_root;
    struct cfl_variant *value;

    type_root = legacy_type_root(context, map);
    if (type_root == NULL) {
        return NULL;
    }
    value = cfl_kvlist_fetch(type_root, map->opts->fqname);
    if (value == NULL || value->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }
    return value->data.as_kvlist;
}

/* Remove legacy containers left empty once native metadata replaced them. */
static void prune_legacy_family(struct cmt *context, struct cmt_map *map)
{
    struct cfl_kvlist *family;
    struct cfl_variant *datapoints;

    family = legacy_family(context, map);
    if (family == NULL) {
        return;
    }
    datapoints = cfl_kvlist_fetch(family, "datapoints");
    if (datapoints != NULL && datapoints->type == CFL_VARIANT_KVLIST &&
        cfl_kvlist_count(datapoints->data.as_kvlist) == 0) {
        cfl_kvlist_remove(family, "datapoints");
    }
    if (cfl_kvlist_count(family) == 0) {
        cfl_kvlist_remove(legacy_type_root(context, map), map->opts->fqname);
    }
}

struct legacy_point_key {
    uint64_t hash;
    uint64_t timestamp;
};

static int compare_legacy_point_keys(const void *left, const void *right)
{
    const struct legacy_point_key *a = left;
    const struct legacy_point_key *b = right;

    if (a->hash != b->hash) {
        return a->hash < b->hash ? -1 : 1;
    }
    return (a->timestamp > b->timestamp) - (a->timestamp < b->timestamp);
}

static void add_sample_key(struct legacy_point_key *keys, size_t *count,
                           struct cmt_metric *sample)
{
    keys[*count].hash = sample->hash;
    keys[*count].timestamp = cmt_metric_get_timestamp(sample);
    (*count)++;
}

/*
 * Append the keys two or more decoded samples share. Distinct series can share
 * a series hash, and windows of one series a time, so such a legacy entry may
 * be any of their points': it is no sample's fallback. Returns -1 when the
 * samples cannot be gathered.
 */
static int add_shared_sample_keys(struct legacy_point_key *keys, size_t *count,
                                  struct cmt_map *map)
{
    struct legacy_point_key *samples;
    struct cfl_list *head;
    size_t total = 0;
    size_t index;

    samples = malloc((cfl_list_size(&map->metrics) + 1) * sizeof(*samples));
    if (samples == NULL) {
        return -1;
    }
    if (map->metric_static_set) {
        add_sample_key(samples, &total, &map->metric);
    }
    cfl_list_foreach(head, &map->metrics) {
        add_sample_key(samples, &total, cfl_list_entry(head, struct cmt_metric, _head));
    }
    qsort(samples, total, sizeof(*samples), compare_legacy_point_keys);
    for (index = 1; index < total; index++) {
        if (compare_legacy_point_keys(&samples[index - 1], &samples[index]) == 0 &&
            (*count == 0 ||
             compare_legacy_point_keys(&keys[*count - 1], &samples[index]) != 0)) {
            keys[(*count)++] = samples[index];
        }
    }
    free(samples);
    return 0;
}

static void add_restored_key(struct legacy_point_key *keys, size_t *count,
                             struct cmt_metric *sample)
{
    if (sample->otlp_metadata != NULL) {
        keys[*count].hash = sample->hash;
        keys[*count].timestamp = cmt_metric_get_timestamp(sample);
        (*count)++;
    }
}

/* A legacy "hash:timestamp" key names a restored point when it reads back
 * as one of the restored keys in its canonical form, ignoring case as
 * cfl_kvlist_remove() did. */
static int legacy_key_listed(cfl_sds_t name, struct legacy_point_key *keys, size_t count)
{
    struct legacy_point_key key;
    char canonical[64];
    char *end;
    size_t length;
    size_t index;

    key.hash = strtoull(name, &end, 16);
    if (*end != ':') {
        return CMT_FALSE;
    }
    key.timestamp = strtoull(end + 1, NULL, 10);
    snprintf(canonical, sizeof(canonical), "%" PRIx64 ":%" PRIu64,
             key.hash, key.timestamp);
    length = strlen(canonical);
    if (cfl_sds_len(name) != length) {
        return CMT_FALSE;
    }
    for (index = 0; index < length; index++) {
        if (tolower((unsigned char) name[index]) != canonical[index]) {
            return CMT_FALSE;
        }
    }
    return bsearch(&key, keys, count, sizeof(*keys), compare_legacy_point_keys) != NULL;
}

/*
 * Drop legacy copies the native metadata supersedes, in one pass over the
 * legacy entries: removing them one by one would rescan the list for every
 * point.
 *
 * With identifiers, a legacy entry, keyed by series hash and time only, stays
 * only when every point recorded under its key was bound to a decoded sample
 * by a unique identity and has no native metadata to read back: the entry is
 * then that sample's own, as in released readers. It is dropped when native
 * metadata replaced it, and when a recorded point was not bound (removed,
 * changed by an intermediary, or ambiguous): the entry describes another or
 * an older point. Legacy entries of points never recorded stay.
 * Without identifiers (v2.3.0), only the copies of restored points are
 * dropped, so points an intermediary left unbound keep what released readers
 * keep.
 */
static void drop_legacy_points(struct cfl_kvlist *family,
                               struct staged_family_metadata *staged)
{
    struct cmt_map *map = staged->map;
    struct cfl_array *id;
    size_t index;
    struct legacy_point_key *keys;
    struct cfl_variant *datapoints;
    struct cfl_kvpair *pair;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cmt_metric *sample;
    size_t count = 0;

    if (family == NULL) {
        return;
    }
    datapoints = cfl_kvlist_fetch(family, "datapoints");
    if (datapoints == NULL || datapoints->type != CFL_VARIANT_KVLIST) {
        return;
    }
    keys = malloc(((staged->point_ids != NULL ? staged->point_count : 0) +
                   cfl_list_size(&map->metrics) + 1) * sizeof(*keys));
    if (keys == NULL) {
        /* no entry can be shown to be a safe fallback */
        cfl_kvlist_remove(family, "datapoints");
        return;
    }
    if (staged->point_ids != NULL) {
        for (index = 0; index < staged->point_count; index++) {
            if ((staged->point_flags[index] & POINT_MATCHED) &&
                !(staged->point_flags[index] & POINT_HAS_METADATA)) {
                continue;
            }
            id = staged->point_ids->entries[index]->data.as_array;
            keys[count].hash = integer_bits(id->entries[0]);
            keys[count].timestamp = integer_bits(id->entries[1]);
            count++;
        }
    }
    else {
        if (map->metric_static_set) {
            add_restored_key(keys, &count, &map->metric);
        }
        cfl_list_foreach(head, &map->metrics) {
            sample = cfl_list_entry(head, struct cmt_metric, _head);
            add_restored_key(keys, &count, sample);
        }
    }
    qsort(keys, count, sizeof(*keys), compare_legacy_point_keys);
    cfl_list_foreach_safe(head, tmp, &datapoints->data.as_kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (count > 0 && legacy_key_listed(pair->key, keys, count)) {
            cfl_kvpair_destroy(pair);
        }
    }
    free(keys);
}

static void commit_map_metadata(struct cmt *context,
                                struct staged_family_metadata *staged)
{
    struct cmt_map *map = staged->map;
    struct cfl_kvlist *legacy;
    struct cfl_list *head;
    struct cmt_metric *sample;
    size_t index = 0;

    legacy = legacy_family(context, map);
    if (legacy != NULL && staged->family != NULL) {
        cfl_kvlist_remove(legacy, "metadata");
    }
    cfl_kvlist_destroy(map->otlp_metadata);
    map->otlp_metadata = staged->family;
    staged->family = NULL;
    if (map->type == CMT_COUNTER) {
        ((struct cmt_counter *) map->parent)->allow_reset = staged->allow_reset;
    }
    if (!staged->restore_points) {
        prune_legacy_family(context, map);
        return;
    }
    if (map->metric_static_set) {
        cfl_kvlist_destroy(map->metric.otlp_metadata);
        map->metric.otlp_metadata = take_point_metadata(staged, &map->metric, index++);
    }
    cfl_list_foreach(head, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);
        cfl_kvlist_destroy(sample->otlp_metadata);
        sample->otlp_metadata = take_point_metadata(staged, sample, index++);
    }
    drop_legacy_points(legacy, staged);
    prune_legacy_family(context, map);
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

/*
 * Drop legacy entries whose key two or more decoded samples share. Distinct
 * series can share a series hash, and windows of one series a time, so such
 * an entry may be any of their points': it is no sample's fallback. This
 * holds whether native metadata was restored, skipped or absent, so it runs
 * for every family. Entries one sample owns stay.
 */
static int drop_shared_legacy_keys(struct cmt_map *map, void *data)
{
    struct cmt *context = data;
    struct legacy_point_key *keys;
    struct cfl_kvlist *family;
    struct cfl_variant *datapoints;
    struct cfl_kvpair *pair;
    struct cfl_list *head;
    struct cfl_list *tmp;
    size_t count = 0;

    family = legacy_family(context, map);
    if (family == NULL) {
        return 0;
    }
    datapoints = cfl_kvlist_fetch(family, "datapoints");
    if (datapoints == NULL || datapoints->type != CFL_VARIANT_KVLIST) {
        return 0;
    }
    keys = malloc((cfl_list_size(&map->metrics) + 1) * sizeof(*keys));
    if (keys == NULL || add_shared_sample_keys(keys, &count, map) != 0) {
        /* no entry can be shown to be a safe fallback */
        cfl_kvlist_remove(family, "datapoints");
    }
    else if (count > 0) {
        cfl_list_foreach_safe(head, tmp, &datapoints->data.as_kvlist->list) {
            pair = cfl_list_entry(head, struct cfl_kvpair, _head);
            if (legacy_key_listed(pair->key, keys, count)) {
                cfl_kvpair_destroy(pair);
            }
        }
    }
    free(keys);
    prune_legacy_family(context, map);
    return 0;
}

static void restore_native_metadata(struct cmt *context);

int cmt_otlp_metadata_restore(struct cmt *context)
{
    restore_native_metadata(context);
    visit_maps(context, drop_shared_legacy_keys, context);
    /* Malformed optional metadata never invalidates the native metric payload. */
    return 0;
}

static void restore_native_metadata(struct cmt *context)
{
    struct cfl_variant *value;
    struct restore_state state;
    int result;
    size_t family_index;
    size_t point_index;

    value = cfl_kvlist_fetch(context->internal_metadata, METADATA_KEY);
    if (value == NULL) {
        return;
    }
    if (value->type != CFL_VARIANT_ARRAY) {
        cfl_kvlist_remove(context->internal_metadata, METADATA_KEY);
        return;
    }
    state.families = value->data.as_array;
    state.index = 0;
    result = visit_maps(context, check_map_metadata_shape, &state);
    if (result != 0 || state.index != state.families->entry_count) {
        /* Optional metadata must not invalidate an otherwise usable chunk. */
        cfl_kvlist_remove(context->internal_metadata, METADATA_KEY);
        return;
    }
    state.staged = calloc(state.families->entry_count, sizeof(*state.staged));
    if (!state.staged && state.families->entry_count > 0) {
        cfl_kvlist_remove(context->internal_metadata, METADATA_KEY);
        return;
    }
    state.index = 0;
    result = visit_maps(context, stage_map_metadata, &state);
    if (result == 0) {
        for (family_index = 0; family_index < state.families->entry_count; family_index++) {
            commit_map_metadata(context, &state.staged[family_index]);
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
        free(state.staged[family_index].order);
        free(state.staged[family_index].point_flags);
    }
    free(state.staged);
    cfl_kvlist_remove(context->internal_metadata, METADATA_KEY);
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
