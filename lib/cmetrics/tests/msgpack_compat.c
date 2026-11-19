/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2026 The CMetrics Authors
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

/*
 * Compatibility of the MessagePack format between Fluent Bit releases. Agents
 * exchange it over forward and keep it in filesystem chunks across upgrades
 * and rollbacks, and released readers reject any key they do not know.
 *
 * Fixtures under tests/data/all-types-*.msgpack were written by the CMetrics
 * bundled with each Fluent Bit release (see tests/data/all-types-release.c).
 */

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_cat.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_label.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <mpack/mpack.h>

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "cmt_tests.h"

static const char *release_fixtures[] = {
    "all-types-v5.0.0.msgpack",
    "all-types-v5.0.11.msgpack",
    "all-types-v5.1.5.msgpack",
};

/* Fluent Bit v5.0.0 (CMetrics 2.0.5) does not know "unit", and Fluent Bit 5.0
 * releases write the aggregation type of counters only: their histograms and
 * exponential histograms arrive without temporality. */
#define RELEASE_FIXTURE_HAS_UNIT(index) ((index) > 0)
#define RELEASE_FIXTURE_HAS_HISTOGRAM_TEMPORALITY(index) ((index) > 1)

static cfl_sds_t read_fixture(const char *name)
{
    char path[1024];

    snprintf(path, sizeof(path), "%s/%s", CMT_TESTS_DATA_PATH, name);
    return read_file(path);
}

static struct cmt_map *find_map(struct cmt *ctx, int type, const char *name)
{
    struct cfl_list *list;
    struct cfl_list *head;
    struct cmt_map *map;

    switch (type) {
    case CMT_COUNTER:
        list = &ctx->counters;
        break;
    case CMT_GAUGE:
        list = &ctx->gauges;
        break;
    case CMT_UNTYPED:
        list = &ctx->untypeds;
        break;
    case CMT_SUMMARY:
        list = &ctx->summaries;
        break;
    case CMT_HISTOGRAM:
        list = &ctx->histograms;
        break;
    default:
        list = &ctx->exp_histograms;
        break;
    }

    cfl_list_foreach(head, list) {
        /* Every family struct starts with its opts and map pointers in the
         * same order after a type-specific header; use the typed entries. */
        switch (type) {
        case CMT_COUNTER:
            map = cfl_list_entry(head, struct cmt_counter, _head)->map;
            break;
        case CMT_GAUGE:
            map = cfl_list_entry(head, struct cmt_gauge, _head)->map;
            break;
        case CMT_UNTYPED:
            map = cfl_list_entry(head, struct cmt_untyped, _head)->map;
            break;
        case CMT_SUMMARY:
            map = cfl_list_entry(head, struct cmt_summary, _head)->map;
            break;
        case CMT_HISTOGRAM:
            map = cfl_list_entry(head, struct cmt_histogram, _head)->map;
            break;
        default:
            map = cfl_list_entry(head, struct cmt_exp_histogram, _head)->map;
            break;
        }
        if (strcmp(map->opts->fqname, name) == 0) {
            return map;
        }
    }
    return NULL;
}

static struct cmt_metric *find_sample(struct cmt_map *map, const char *label_value)
{
    struct cfl_list *head;
    struct cmt_metric *sample;
    struct cmt_map_label *label;

    if (label_value == NULL) {
        return map->metric_static_set ? &map->metric : NULL;
    }
    cfl_list_foreach(head, &map->metrics) {
        sample = cfl_list_entry(head, struct cmt_metric, _head);
        label = cfl_list_entry_first(&sample->labels, struct cmt_map_label, _head);
        if (label != NULL && label->name != NULL && strcmp(label->name, label_value) == 0) {
            return sample;
        }
    }
    return NULL;
}

static int has_static_label(struct cmt *ctx, const char *key, const char *value)
{
    struct cfl_list *head;
    struct cmt_label *label;

    cfl_list_foreach(head, &ctx->static_labels->list) {
        label = cfl_list_entry(head, struct cmt_label, _head);
        if (strcmp(label->key, key) == 0 && strcmp(label->val, value) == 0) {
            return CMT_TRUE;
        }
    }
    return CMT_FALSE;
}

/* The content written by tests/data/all-types-release.c. */
static void check_release_content(struct cmt *ctx, int has_unit, int has_temporality,
                                  const char *source)
{
    struct cmt_map *map;
    struct cmt_metric *sample;
    struct cmt_histogram *histogram;
    struct cmt_summary *summary;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_exp_histogram_snapshot snapshot;

    TEST_CASE(source);
    TEST_CHECK(has_static_label(ctx, "cluster", "prod"));

    map = find_map(ctx, CMT_COUNTER, "fixture_http_requests_total");
    TEST_ASSERT(map != NULL);
    TEST_CHECK(map->label_count == 1);
    sample = find_sample(map, "GET");
    TEST_ASSERT(sample != NULL);
    TEST_CHECK(cmt_metric_get_value(sample) == 10);
    TEST_CHECK(cmt_metric_get_timestamp(sample) == 1000);
    TEST_CHECK(cmt_metric_has_start_timestamp(sample));
    TEST_CHECK(cmt_metric_get_start_timestamp(sample) == 500);
    sample = find_sample(map, "POST");
    TEST_ASSERT(sample != NULL);
    TEST_CHECK(cmt_metric_get_value(sample) == 4);
    TEST_CHECK(!cmt_metric_has_start_timestamp(sample));

    map = find_map(ctx, CMT_COUNTER, "fixture_delta_total");
    TEST_ASSERT(map != NULL);
    TEST_CHECK(((struct cmt_counter *) map->parent)->aggregation_type ==
               CMT_AGGREGATION_TYPE_DELTA);
    TEST_CHECK(cmt_metric_get_value(&map->metric) == 3);

    map = find_map(ctx, CMT_GAUGE, "fixture_temperature");
    TEST_ASSERT(map != NULL);
    sample = find_sample(map, "lab");
    TEST_ASSERT(sample != NULL);
    TEST_CHECK(cmt_metric_get_value(sample) == -12.5);
    sample = find_sample(map, "");
    TEST_ASSERT(sample != NULL);
    TEST_CHECK(cmt_metric_get_value(sample) == 21);

    map = find_map(ctx, CMT_GAUGE, "fixture_signed");
    TEST_ASSERT(map != NULL);
    TEST_CHECK(cmt_metric_get_value_type(&map->metric) == CMT_METRIC_VALUE_INT64);
    TEST_CHECK(cmt_metric_get_int64_value(&map->metric) == -9007199254740993LL);

    map = find_map(ctx, CMT_GAUGE, "fixture_unsigned");
    TEST_ASSERT(map != NULL);
    TEST_CHECK(cmt_metric_get_value_type(&map->metric) == CMT_METRIC_VALUE_UINT64);
    TEST_CHECK(cmt_metric_get_uint64_value(&map->metric) == UINT64_MAX);

    map = find_map(ctx, CMT_UNTYPED, "fixture_untyped");
    TEST_ASSERT(map != NULL);
    sample = find_sample(map, "v");
    TEST_ASSERT(sample != NULL);
    TEST_CHECK(cmt_metric_get_value(sample) == 1.5);

    map = find_map(ctx, CMT_HISTOGRAM, "fixture_latency_seconds");
    TEST_ASSERT(map != NULL);
    histogram = map->parent;
    TEST_CHECK(histogram->aggregation_type == (has_temporality ?
                                               CMT_AGGREGATION_TYPE_CUMULATIVE :
                                               CMT_AGGREGATION_TYPE_UNSPECIFIED));
    TEST_ASSERT(histogram->buckets != NULL && histogram->buckets->count == 3);
    TEST_CHECK(histogram->buckets->upper_bounds[0] == 0.1);
    TEST_CHECK(histogram->buckets->upper_bounds[2] == 10.0);
    if (has_unit) {
        TEST_CHECK(map->unit != NULL && strcmp(map->unit, "s") == 0);
    }
    sample = find_sample(map, "/");
    TEST_ASSERT(sample != NULL);
    TEST_CHECK(cmt_metric_hist_get_value(sample, 0) == 1);
    TEST_CHECK(cmt_metric_hist_get_value(sample, 1) == 3);
    TEST_CHECK(cmt_metric_hist_get_value(sample, 2) == 4);
    TEST_CHECK(cmt_metric_hist_get_value(sample, 3) == 5);
    TEST_CHECK(cmt_metric_hist_get_count_value(sample) == 5);
    TEST_CHECK(cmt_metric_hist_get_sum_value(sample) == 6.5);

    map = find_map(ctx, CMT_SUMMARY, "fixture_rpc_seconds");
    TEST_ASSERT(map != NULL);
    summary = map->parent;
    TEST_ASSERT(summary->quantiles_count == 2);
    TEST_CHECK(summary->quantiles[0] == 0.5 && summary->quantiles[1] == 0.9);
    sample = find_sample(map, "api");
    TEST_ASSERT(sample != NULL);
    TEST_CHECK(cmt_summary_quantile_get_value(sample, 0) == 0.2);
    TEST_CHECK(cmt_summary_quantile_get_value(sample, 1) == 0.8);
    TEST_CHECK(cmt_summary_get_sum_value(sample) == 10);
    TEST_CHECK(cmt_summary_get_count_value(sample) == 20);

    map = find_map(ctx, CMT_EXP_HISTOGRAM, "fixture_exp");
    TEST_ASSERT(map != NULL);
    exp_histogram = map->parent;
    TEST_CHECK(exp_histogram->aggregation_type == (has_temporality ?
                                                   CMT_AGGREGATION_TYPE_DELTA :
                                                   CMT_AGGREGATION_TYPE_UNSPECIFIED));
    sample = find_sample(map, "read");
    TEST_ASSERT(sample != NULL);
    TEST_ASSERT(cmt_metric_exp_hist_get_snapshot(sample, &snapshot) == 0);
    TEST_CHECK(snapshot.scale == 2);
    TEST_CHECK(snapshot.zero_count == 1);
    TEST_CHECK(snapshot.zero_threshold == 0.001);
    TEST_CHECK(snapshot.positive_offset == -1 && snapshot.positive_count == 2);
    TEST_CHECK(snapshot.positive_count == 2 &&
               snapshot.positive_buckets[0] == 1 && snapshot.positive_buckets[1] == 2);
    TEST_CHECK(snapshot.negative_offset == 0 && snapshot.negative_count == 1);
    TEST_CHECK(snapshot.negative_count == 1 && snapshot.negative_buckets[0] == 3);
    TEST_CHECK(snapshot.count == 7);
    TEST_CHECK(snapshot.sum_set);
    cmt_metric_exp_hist_snapshot_destroy(&snapshot);
}

static struct cmt *decode_all(char *buffer, size_t size, size_t *offset)
{
    struct cmt *decoded = NULL;
    int result;

    result = cmt_decode_msgpack_create(&decoded, buffer, size, offset);
    TEST_CHECK_(result == CMT_DECODE_MSGPACK_SUCCESS, "decode result %d", result);
    return result == CMT_DECODE_MSGPACK_SUCCESS ? decoded : NULL;
}

/* Chunks written by released agents decode completely in this release, keep
 * their content through a re-encode (forward relay) and through cmt_cat. */
static void test_release_fixtures(void)
{
    size_t index;
    size_t offset;
    size_t size;
    cfl_sds_t fixture;
    struct cmt *decoded;
    struct cmt *again;
    struct cmt *merged;
    char *buffer;
    char label[128];

    for (index = 0; index < sizeof(release_fixtures) / sizeof(*release_fixtures); index++) {
        fixture = read_fixture(release_fixtures[index]);
        TEST_ASSERT(fixture != NULL);

        offset = 0;
        decoded = decode_all(fixture, cfl_sds_len(fixture), &offset);
        TEST_ASSERT(decoded != NULL);
        TEST_CHECK(offset == cfl_sds_len(fixture));
        snprintf(label, sizeof(label), "%s decoded", release_fixtures[index]);
        check_release_content(decoded, RELEASE_FIXTURE_HAS_UNIT(index),
                              RELEASE_FIXTURE_HAS_HISTOGRAM_TEMPORALITY(index), label);

        TEST_ASSERT(cmt_encode_msgpack_create(decoded, &buffer, &size) == 0);
        offset = 0;
        again = decode_all(buffer, size, &offset);
        TEST_ASSERT(again != NULL);
        snprintf(label, sizeof(label), "%s re-encoded", release_fixtures[index]);
        check_release_content(again, RELEASE_FIXTURE_HAS_UNIT(index),
                              RELEASE_FIXTURE_HAS_HISTOGRAM_TEMPORALITY(index), label);

        merged = cmt_create();
        TEST_ASSERT(merged != NULL);
        TEST_CHECK(cmt_cat(merged, again) == 0);
        snprintf(label, sizeof(label), "%s concatenated", release_fixtures[index]);
        check_release_content(merged, RELEASE_FIXTURE_HAS_UNIT(index),
                              RELEASE_FIXTURE_HAS_HISTOGRAM_TEMPORALITY(index), label);

        cmt_destroy(merged);
        cmt_decode_msgpack_destroy(again);
        cmt_encode_msgpack_destroy(buffer);
        cmt_decode_msgpack_destroy(decoded);
        cfl_sds_destroy(fixture);
    }
}

/* A forward chunk can hold contexts from agents of different releases. */
static void test_mixed_release_batch(void)
{
    size_t index;
    size_t offset;
    size_t count;
    size_t size;
    cfl_sds_t batch;
    cfl_sds_t fixture;
    struct cmt *decoded;
    char *buffer;

    batch = cfl_sds_create_size(0);
    TEST_ASSERT(batch != NULL);
    for (index = 0; index < sizeof(release_fixtures) / sizeof(*release_fixtures); index++) {
        fixture = read_fixture(release_fixtures[index]);
        TEST_ASSERT(fixture != NULL);
        batch = cfl_sds_cat(batch, fixture, cfl_sds_len(fixture));
        cfl_sds_destroy(fixture);
    }

    /* The current encoder's output for the newest fixture closes the batch. */
    fixture = read_fixture(release_fixtures[2]);
    offset = 0;
    decoded = decode_all(fixture, cfl_sds_len(fixture), &offset);
    TEST_ASSERT(decoded != NULL);
    TEST_ASSERT(cmt_encode_msgpack_create(decoded, &buffer, &size) == 0);
    batch = cfl_sds_cat(batch, buffer, size);
    cmt_encode_msgpack_destroy(buffer);
    cmt_decode_msgpack_destroy(decoded);
    cfl_sds_destroy(fixture);

    offset = 0;
    count = 0;
    while (offset < cfl_sds_len(batch)) {
        decoded = decode_all(batch, cfl_sds_len(batch), &offset);
        TEST_ASSERT(decoded != NULL);
        check_release_content(decoded, RELEASE_FIXTURE_HAS_UNIT(count),
                              RELEASE_FIXTURE_HAS_HISTOGRAM_TEMPORALITY(count), "batch entry");
        cmt_decode_msgpack_destroy(decoded);
        count++;
    }
    TEST_CHECK(count == 4);
    TEST_CHECK(offset == cfl_sds_len(batch));
    cfl_sds_destroy(batch);
}

/* Every metric type with labels, static samples, typed values, start
 * timestamps, units, OTLP metadata and the native metadata sidecar. */
static struct cmt *create_full_context(void)
{
    struct cmt *ctx;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_histogram *histogram;
    struct cmt_summary *summary;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_metric *sample;
    struct cfl_kvlist *metadata;
    double quantiles[] = {0.5, 0.99};
    double quantile_values[] = {1, 2};
    uint64_t buckets[] = {1, 2, 3};
    uint64_t positive[] = {4, 5};

    ctx = cmt_create();
    TEST_ASSERT(ctx != NULL);
    TEST_ASSERT(cmt_label_add(ctx, "dc", "eu-1") == 0);

    counter = cmt_counter_create(ctx, "ns", "sub", "events_total", "events", 2,
                                 (char *[]) {"a", "b"});
    TEST_ASSERT(counter != NULL);
    cmt_counter_allow_reset(counter);
    counter->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;
    TEST_ASSERT(cmt_counter_set(counter, 10, 5, 2, (char *[]) {"x", "y"}) == 0);
    sample = cmt_map_metric_get(&counter->opts, counter->map, 2, (char *[]) {"x", "y"}, CMT_FALSE);
    TEST_ASSERT(sample != NULL);
    cmt_metric_set_start_timestamp(sample, 5);
    sample->otlp_metadata = cfl_kvlist_create();
    TEST_ASSERT(sample->otlp_metadata != NULL);
    TEST_ASSERT(cfl_kvlist_insert_uint64(sample->otlp_metadata, "flags", 1) == 0);
    counter->map->unit = cfl_sds_create("{event}");

    gauge = cmt_gauge_create(ctx, "", "", "level", "level", 0, NULL);
    TEST_ASSERT(gauge != NULL);
    TEST_ASSERT(cmt_gauge_set(gauge, 10, 0, 0, NULL) == 0);
    cmt_metric_set_int64(&gauge->map->metric, 10, INT64_MIN);
    gauge->map->otlp_metadata = cfl_kvlist_create();
    metadata = cfl_kvlist_create();
    TEST_ASSERT(gauge->map->otlp_metadata != NULL && metadata != NULL);
    TEST_ASSERT(cfl_kvlist_insert_string(metadata, "k", "v") == 0);
    TEST_ASSERT(cfl_kvlist_insert_kvlist(gauge->map->otlp_metadata, "metadata", metadata) == 0);

    untyped = cmt_untyped_create(ctx, "", "", "raw", "raw", 1, (char *[]) {"k"});
    TEST_ASSERT(untyped != NULL);
    TEST_ASSERT(cmt_untyped_set(untyped, 10, NAN, 1, (char *[]) {"nan"}) == 0);

    histogram = cmt_histogram_create(ctx, "", "", "latency", "latency",
                                     cmt_histogram_buckets_create(2, 1.0, 2.0),
                                     1, (char *[]) {"r"});
    TEST_ASSERT(histogram != NULL);
    TEST_ASSERT(cmt_histogram_set_default(histogram, 10, buckets, 4.5, 3, 1,
                                          (char *[]) {"/"}) == 0);

    summary = cmt_summary_create(ctx, "", "", "rpc", "rpc", 2, quantiles, 0, NULL);
    TEST_ASSERT(summary != NULL);
    TEST_ASSERT(cmt_summary_set_default(summary, 10, quantile_values, 3, 2, 0, NULL) == 0);

    exp_histogram = cmt_exp_histogram_create(ctx, "", "", "exp", "exp", 0, NULL);
    TEST_ASSERT(exp_histogram != NULL);
    TEST_ASSERT(cmt_exp_histogram_set_default(exp_histogram, 10, -2, 0, 0, 3, 2, positive,
                                              0, 0, NULL, 0, 0, 9, 0, NULL) == 0);
    return ctx;
}

/* Released decoders (Fluent Bit 5.0.11, 5.1.x) accept exactly these keys;
 * Fluent Bit 5.0.0 accepts all of them except "unit". */
static const char *released_keys[] = {
    "aggregation_type", "buckets", "cmetrics", "count", "desc", "exp_histogram",
    "external", "hash", "histogram", "labels", "meta", "metrics", "name",
    "negative_buckets", "negative_offset", "ns", "opts", "positive_buckets",
    "positive_offset", "processing", "quantiles", "quantiles_set", "scale", "ss",
    "start_ts", "static_labels", "sum", "summary", "sum_set", "ts", "type", "unit",
    "value", "values", "value_type", "value_int64", "value_uint64", "ver",
    "zero_count", "zero_threshold", NULL
};

static int is_released_key(const char *key, size_t length)
{
    size_t index;

    for (index = 0; released_keys[index] != NULL; index++) {
        if (strlen(released_keys[index]) == length &&
            memcmp(released_keys[index], key, length) == 0) {
            return CMT_TRUE;
        }
    }
    return CMT_FALSE;
}

/* Walk a value; map keys are schema keys except inside the schemaless
 * internal ("cmetrics") and external metadata maps, which are skipped. */
static int walk_keys(mpack_reader_t *reader, int depth)
{
    mpack_tag_t tag;
    uint32_t index;
    uint32_t count;
    char key[64];
    uint32_t length;
    int unknown = 0;

    tag = mpack_read_tag(reader);
    if (mpack_reader_error(reader) != mpack_ok) {
        return -1;
    }
    switch (mpack_tag_type(&tag)) {
    case mpack_type_map:
        count = mpack_tag_map_count(&tag);
        for (index = 0; index < count; index++) {
            tag = mpack_read_tag(reader);
            if (mpack_tag_type(&tag) != mpack_type_str) {
                return -1;
            }
            length = mpack_tag_str_length(&tag);
            if (length >= sizeof(key)) {
                return -1;
            }
            mpack_read_bytes(reader, key, length);
            mpack_done_str(reader);
            if (!is_released_key(key, length)) {
                TEST_MSG("key not known to released readers: %.*s", (int) length, key);
                unknown++;
            }
            if ((length == 8 && memcmp(key, "cmetrics", 8) == 0) ||
                (length == 8 && memcmp(key, "external", 8) == 0)) {
                mpack_discard(reader);
            }
            else {
                unknown += walk_keys(reader, depth + 1);
            }
        }
        mpack_done_map(reader);
        break;
    case mpack_type_array:
        count = mpack_tag_array_count(&tag);
        for (index = 0; index < count; index++) {
            unknown += walk_keys(reader, depth + 1);
        }
        mpack_done_array(reader);
        break;
    case mpack_type_str:
        mpack_skip_bytes(reader, mpack_tag_str_length(&tag));
        mpack_done_str(reader);
        break;
    case mpack_type_bin:
        mpack_skip_bytes(reader, mpack_tag_bin_length(&tag));
        mpack_done_bin(reader);
        break;
    default:
        break;
    }
    return unknown;
}

/* New information must travel in the schemaless metadata maps: a new schema
 * key makes every released reader reject the whole chunk. */
static void test_encoder_uses_released_keys_only(void)
{
    struct cmt *ctx;
    mpack_reader_t reader;
    char *buffer;
    size_t size;
    int unknown;

    ctx = create_full_context();
    TEST_ASSERT(cmt_encode_msgpack_create(ctx, &buffer, &size) == 0);
    mpack_reader_init_data(&reader, buffer, size);
    unknown = walk_keys(&reader, 0);
    TEST_CHECK(mpack_reader_destroy(&reader) == mpack_ok);
    TEST_CHECK_(unknown == 0, "%d keys unknown to released readers", unknown);
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
}

static uint64_t double_bits(double value)
{
    uint64_t bits;

    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

/* Exact values of every scalar type for counters, gauges and untyped. */
static void test_scalar_extremes(void)
{
    static const uint64_t double_patterns[] = {
        0x7ff8000000000000ULL, /* quiet NaN */
        0x7ff0000000000002ULL, /* Prometheus staleness marker */
        0x7ff0000000000000ULL, /* +Inf */
        0xfff0000000000000ULL, /* -Inf */
        0x8000000000000000ULL, /* -0.0 */
        0x0000000000000001ULL, /* smallest denormal */
        0x7fefffffffffffffULL, /* DBL_MAX */
    };
    static const int64_t signed_values[] = {INT64_MIN, INT64_MAX, -1, 0};
    static const uint64_t unsigned_values[] = {UINT64_MAX, (uint64_t) INT64_MAX + 1, 0};
    struct cmt *ctx;
    struct cmt *decoded;
    struct cmt_counter *counter;
    struct cmt_gauge *gauge;
    struct cmt_untyped *untyped;
    struct cmt_metric *sample;
    struct cmt_map *maps[3];
    char value_label[32];
    char *labels[] = {value_label};
    char *buffer;
    size_t size;
    size_t offset;
    size_t index;
    size_t type;
    double value;

    ctx = cmt_create();
    TEST_ASSERT(ctx != NULL);
    counter = cmt_counter_create(ctx, "", "", "c", "c", 1, (char *[]) {"v"});
    gauge = cmt_gauge_create(ctx, "", "", "g", "g", 1, (char *[]) {"v"});
    untyped = cmt_untyped_create(ctx, "", "", "u", "u", 1, (char *[]) {"v"});
    TEST_ASSERT(counter != NULL && gauge != NULL && untyped != NULL);
    maps[0] = counter->map;
    maps[1] = gauge->map;
    maps[2] = untyped->map;

    for (type = 0; type < 3; type++) {
        for (index = 0; index < sizeof(double_patterns) / sizeof(*double_patterns); index++) {
            snprintf(value_label, sizeof(value_label), "d%zu", index);
            sample = cmt_map_metric_get(&counter->opts, maps[type], 1, labels, CMT_TRUE);
            TEST_ASSERT(sample != NULL);
            memcpy(&value, &double_patterns[index], sizeof(value));
            cmt_metric_set_double(sample, 1, value);
        }
        for (index = 0; index < sizeof(signed_values) / sizeof(*signed_values); index++) {
            snprintf(value_label, sizeof(value_label), "i%zu", index);
            sample = cmt_map_metric_get(&counter->opts, maps[type], 1, labels, CMT_TRUE);
            TEST_ASSERT(sample != NULL);
            cmt_metric_set_int64(sample, 1, signed_values[index]);
        }
        for (index = 0; index < sizeof(unsigned_values) / sizeof(*unsigned_values); index++) {
            snprintf(value_label, sizeof(value_label), "u%zu", index);
            sample = cmt_map_metric_get(&counter->opts, maps[type], 1, labels, CMT_TRUE);
            TEST_ASSERT(sample != NULL);
            cmt_metric_set_uint64(sample, 1, unsigned_values[index]);
        }
    }

    TEST_ASSERT(cmt_encode_msgpack_create(ctx, &buffer, &size) == 0);
    offset = 0;
    decoded = decode_all(buffer, size, &offset);
    TEST_ASSERT(decoded != NULL);
    maps[0] = find_map(decoded, CMT_COUNTER, "c");
    maps[1] = find_map(decoded, CMT_GAUGE, "g");
    maps[2] = find_map(decoded, CMT_UNTYPED, "u");
    for (type = 0; type < 3; type++) {
        TEST_ASSERT(maps[type] != NULL);
        for (index = 0; index < sizeof(double_patterns) / sizeof(*double_patterns); index++) {
            snprintf(value_label, sizeof(value_label), "d%zu", index);
            sample = find_sample(maps[type], value_label);
            TEST_ASSERT(sample != NULL);
            TEST_CHECK(cmt_metric_get_value_type(sample) == CMT_METRIC_VALUE_DOUBLE);
            TEST_CHECK_(double_bits(cmt_metric_get_value(sample)) == double_patterns[index],
                        "type %zu double %016" PRIx64, type, double_patterns[index]);
        }
        for (index = 0; index < sizeof(signed_values) / sizeof(*signed_values); index++) {
            snprintf(value_label, sizeof(value_label), "i%zu", index);
            sample = find_sample(maps[type], value_label);
            TEST_ASSERT(sample != NULL);
            TEST_CHECK(cmt_metric_get_value_type(sample) == CMT_METRIC_VALUE_INT64);
            TEST_CHECK_(cmt_metric_get_int64_value(sample) == signed_values[index],
                        "type %zu int64 %" PRId64, type, signed_values[index]);
        }
        for (index = 0; index < sizeof(unsigned_values) / sizeof(*unsigned_values); index++) {
            snprintf(value_label, sizeof(value_label), "u%zu", index);
            sample = find_sample(maps[type], value_label);
            TEST_ASSERT(sample != NULL);
            TEST_CHECK(cmt_metric_get_value_type(sample) == CMT_METRIC_VALUE_UINT64);
            TEST_CHECK_(cmt_metric_get_uint64_value(sample) == unsigned_values[index],
                        "type %zu uint64 %" PRIu64, type, unsigned_values[index]);
        }
    }
    cmt_decode_msgpack_destroy(decoded);
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
}

/* Storage corruption or a broken peer: every prefix and every single byte
 * corruption of a full chunk is rejected or decoded, never crashes, and a
 * decoded context can be encoded again. Run under Valgrind or ASan. */
static void test_corrupted_chunks(void)
{
    struct cmt *ctx;
    struct cmt *decoded;
    char *buffer;
    char *copy;
    char *again;
    size_t size;
    size_t again_size;
    size_t length;
    size_t index;
    size_t offset;
    int result;

    ctx = create_full_context();
    TEST_ASSERT(cmt_encode_msgpack_create(ctx, &buffer, &size) == 0);
    copy = malloc(size);
    TEST_ASSERT(copy != NULL);

    for (length = 0; length < size; length++) {
        offset = 0;
        decoded = NULL;
        result = cmt_decode_msgpack_create(&decoded, buffer, length, &offset);
        if (result == CMT_DECODE_MSGPACK_SUCCESS) {
            cmt_decode_msgpack_destroy(decoded);
        }
    }

    for (index = 0; index < size; index++) {
        memcpy(copy, buffer, size);
        copy[index] ^= 0xa5;
        offset = 0;
        decoded = NULL;
        result = cmt_decode_msgpack_create(&decoded, copy, size, &offset);
        if (result == CMT_DECODE_MSGPACK_SUCCESS) {
            TEST_CHECK(offset <= size);
            if (cmt_encode_msgpack_create(decoded, &again, &again_size) == 0) {
                cmt_encode_msgpack_destroy(again);
            }
            cmt_decode_msgpack_destroy(decoded);
        }
    }

    free(copy);
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
}

/* Replace the array header that follows the nth occurrence of a key. */
static char *replace_array_header(char *buffer, size_t size, const char *key,
                                  const char *header, size_t header_size, size_t *out_size)
{
    size_t index;
    size_t key_length;
    char *patched;
    char encoded_key[32];

    key_length = strlen(key);
    encoded_key[0] = (char) (0xa0 | key_length);
    memcpy(&encoded_key[1], key, key_length);
    for (index = 0; index + key_length + 2 <= size; index++) {
        if (memcmp(&buffer[index], encoded_key, key_length + 1) != 0) {
            continue;
        }
        index += key_length + 1;
        /* fixarray headers only: the fixture arrays are small */
        if (((unsigned char) buffer[index] & 0xf0) != 0x90) {
            return NULL;
        }
        patched = malloc(size + header_size);
        TEST_ASSERT(patched != NULL);
        memcpy(patched, buffer, index);
        memcpy(&patched[index], header, header_size);
        memcpy(&patched[index + header_size], &buffer[index + 1], size - index - 1);
        *out_size = size + header_size - 1;
        return patched;
    }
    return NULL;
}

/* A declared element count far beyond the remaining input must be rejected
 * before any allocation sized from it. */
static void test_oversized_declared_counts(void)
{
    static const char *keys[] = {"values", "labels", "buckets", "quantiles"};
    static const char huge_array[] = {(char) 0xdd, (char) 0xff, (char) 0xff,
                                      (char) 0xff, (char) 0xff};
    struct cmt *ctx;
    struct cmt *decoded;
    char *buffer;
    char *patched;
    size_t size;
    size_t patched_size;
    size_t offset;
    size_t index;
    int result;

    ctx = create_full_context();
    TEST_ASSERT(cmt_encode_msgpack_create(ctx, &buffer, &size) == 0);
    for (index = 0; index < sizeof(keys) / sizeof(*keys); index++) {
        patched = replace_array_header(buffer, size, keys[index], huge_array,
                                       sizeof(huge_array), &patched_size);
        TEST_ASSERT_(patched != NULL, "array key %s found", keys[index]);
        offset = 0;
        decoded = NULL;
        result = cmt_decode_msgpack_create(&decoded, patched, patched_size, &offset);
        TEST_CHECK_(result != CMT_DECODE_MSGPACK_SUCCESS, "%s count rejected", keys[index]);
        if (result == CMT_DECODE_MSGPACK_SUCCESS) {
            cmt_decode_msgpack_destroy(decoded);
        }
        free(patched);
    }
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
}

/* Released readers reject any other format version, so the version cannot
 * be raised to signal new content; this release must behave the same. */
static void test_format_version_is_strict(void)
{
    static const char version_key[] = {(char) 0xa3, 'v', 'e', 'r', 0x02};
    struct cmt *ctx;
    struct cmt *decoded;
    char *buffer;
    size_t size;
    size_t index;
    size_t offset;
    int found = CMT_FALSE;

    ctx = create_full_context();
    TEST_ASSERT(cmt_encode_msgpack_create(ctx, &buffer, &size) == 0);
    for (index = 0; index + sizeof(version_key) <= size; index++) {
        if (memcmp(&buffer[index], version_key, sizeof(version_key)) == 0) {
            buffer[index + sizeof(version_key) - 1] = 0x03;
            found = CMT_TRUE;
            break;
        }
    }
    TEST_ASSERT(found);
    offset = 0;
    decoded = NULL;
    TEST_CHECK(cmt_decode_msgpack_create(&decoded, buffer, size, &offset) !=
               CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(decoded == NULL);
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
}

TEST_LIST = {
    {"release_fixtures", test_release_fixtures},
    {"mixed_release_batch", test_mixed_release_batch},
    {"encoder_uses_released_keys_only", test_encoder_uses_released_keys_only},
    {"scalar_extremes", test_scalar_extremes},
    {"corrupted_chunks", test_corrupted_chunks},
    {"oversized_declared_counts", test_oversized_declared_counts},
    {"format_version_is_strict", test_format_version_is_strict},
    {0}
};
