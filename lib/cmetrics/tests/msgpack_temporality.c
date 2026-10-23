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
 * Regression test: histogram and exp_histogram aggregation_type (delta vs
 * cumulative temporality) must survive a cmt_encode_msgpack /
 * cmt_decode_msgpack round trip.
 *
 * Before this fix, pack_header() in cmt_encode_msgpack.c only wrote the
 * "aggregation_type" meta field for CMT_COUNTER, so histograms and
 * exp_histograms always decoded back with CMT_AGGREGATION_TYPE_UNSPECIFIED
 * regardless of what temporality they were created with. This is the path
 * Fluent Bit's in_opentelemetry -> (internal msgpack buffer) ->
 * out_opentelemetry pipeline uses, so any OTLP histogram passing through
 * Fluent Bit lost its temporality and Prometheus's OTLP receiver rejected it
 * with "invalid temporality and type combination".
 */

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_exp_histogram.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_msgpack.h>

#include "cmt_tests.h"

static void test_histogram_temporality_survives_msgpack_roundtrip()
{
    int result;
    char *encoded_buffer;
    size_t encoded_size;
    size_t offset;
    struct cmt *cmt;
    struct cmt *decoded_cmt;
    struct cmt_histogram *histogram;
    struct cmt_histogram *decoded_histogram;
    struct cmt_histogram_buckets *buckets;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    buckets = cmt_histogram_buckets_default_create();
    TEST_CHECK(buckets != NULL);

    histogram = cmt_histogram_create(cmt, "k6", "http", "req_duration",
                                     "request duration", buckets, 0, NULL);
    TEST_CHECK(histogram != NULL);

    result = cmt_histogram_observe(histogram, 12345, 1.5, 0, NULL);
    TEST_CHECK(result == 0);

    /* Simulate what an OTLP delta-temporality histogram looks like once
     * decoded from OTLP into a cmt_histogram (cmt_decode_opentelemetry.c
     * already sets this correctly; the bug is losing it in the internal
     * msgpack buffer that sits between Fluent Bit's OTLP input and output
     * plugins).
     */
    histogram->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;

    offset = 0;
    result = cmt_encode_msgpack_create(cmt, &encoded_buffer, &encoded_size);
    TEST_CHECK(result == 0);

    result = cmt_decode_msgpack_create(&decoded_cmt, encoded_buffer,
                                       encoded_size, &offset);
    TEST_CHECK(result == CMT_DECODE_MSGPACK_SUCCESS);

    if (result == CMT_DECODE_MSGPACK_SUCCESS) {
        TEST_CHECK(cfl_list_size(&decoded_cmt->histograms) == 1);

        decoded_histogram = cfl_list_entry_first(&decoded_cmt->histograms,
                                                 struct cmt_histogram, _head);
        TEST_CHECK(decoded_histogram != NULL);

        if (decoded_histogram != NULL) {
            TEST_CHECK(decoded_histogram->aggregation_type ==
                      CMT_AGGREGATION_TYPE_DELTA);
        }

        cmt_decode_msgpack_destroy(decoded_cmt);
    }

    cmt_encode_msgpack_destroy(encoded_buffer);
    cmt_destroy(cmt);
}

static void test_exp_histogram_temporality_survives_msgpack_roundtrip()
{
    int result;
    char *encoded_buffer;
    size_t encoded_size;
    size_t offset;
    struct cmt *cmt;
    struct cmt *decoded_cmt;
    struct cmt_exp_histogram *exp_histogram;
    struct cmt_exp_histogram *decoded_exp_histogram;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    exp_histogram = cmt_exp_histogram_create(cmt, "k6", "http", "req_duration",
                                             "request duration", 0, NULL);
    TEST_CHECK(exp_histogram != NULL);

    exp_histogram->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;

    offset = 0;
    result = cmt_encode_msgpack_create(cmt, &encoded_buffer, &encoded_size);
    TEST_CHECK(result == 0);

    result = cmt_decode_msgpack_create(&decoded_cmt, encoded_buffer,
                                       encoded_size, &offset);
    TEST_CHECK(result == CMT_DECODE_MSGPACK_SUCCESS);

    if (result == CMT_DECODE_MSGPACK_SUCCESS) {
        TEST_CHECK(cfl_list_size(&decoded_cmt->exp_histograms) == 1);

        decoded_exp_histogram = cfl_list_entry_first(&decoded_cmt->exp_histograms,
                                                      struct cmt_exp_histogram,
                                                      _head);
        TEST_CHECK(decoded_exp_histogram != NULL);

        if (decoded_exp_histogram != NULL) {
            TEST_CHECK(decoded_exp_histogram->aggregation_type ==
                      CMT_AGGREGATION_TYPE_DELTA);
        }

        cmt_decode_msgpack_destroy(decoded_cmt);
    }

    cmt_encode_msgpack_destroy(encoded_buffer);
    cmt_destroy(cmt);
}

static void test_counter_temporality_still_survives_msgpack_roundtrip()
{
    int result;
    char *encoded_buffer;
    size_t encoded_size;
    size_t offset;
    struct cmt *cmt;
    struct cmt *decoded_cmt;
    struct cmt_counter *counter;
    struct cmt_counter *decoded_counter;

    cmt_initialize();

    cmt = cmt_create();
    TEST_CHECK(cmt != NULL);

    counter = cmt_counter_create(cmt, "k6", "http", "reqs", "requests", 0, NULL);
    TEST_CHECK(counter != NULL);

    counter->aggregation_type = CMT_AGGREGATION_TYPE_DELTA;
    counter->allow_reset = CMT_TRUE;

    offset = 0;
    result = cmt_encode_msgpack_create(cmt, &encoded_buffer, &encoded_size);
    TEST_CHECK(result == 0);

    result = cmt_decode_msgpack_create(&decoded_cmt, encoded_buffer,
                                       encoded_size, &offset);
    TEST_CHECK(result == CMT_DECODE_MSGPACK_SUCCESS);

    if (result == CMT_DECODE_MSGPACK_SUCCESS) {
        TEST_CHECK(cfl_list_size(&decoded_cmt->counters) == 1);

        decoded_counter = cfl_list_entry_first(&decoded_cmt->counters,
                                               struct cmt_counter, _head);
        TEST_CHECK(decoded_counter != NULL);

        if (decoded_counter != NULL) {
            TEST_CHECK(decoded_counter->allow_reset == CMT_TRUE);
            TEST_CHECK(decoded_counter->aggregation_type ==
                      CMT_AGGREGATION_TYPE_DELTA);
        }

        cmt_decode_msgpack_destroy(decoded_cmt);
    }

    cmt_encode_msgpack_destroy(encoded_buffer);
    cmt_destroy(cmt);
}

static void test_legacy_histogram_bucket_semantics()
{
    cfl_sds_t fixture;
    struct cmt *decoded;
    struct cmt_histogram *histogram;
    size_t offset = 0;

    fixture = read_file(CMT_TESTS_DATA_PATH "/histogram-v5.1.0.msgpack");
    TEST_ASSERT(fixture != NULL);
    TEST_ASSERT(cmt_decode_msgpack_create(&decoded, fixture,
                                          cfl_sds_len(fixture), &offset) == 0);
    histogram = cfl_list_entry_first(&decoded->histograms, struct cmt_histogram, _head);
    /* Legacy OTLP chunks contain independent bucket counts [5,1,3]. */
    TEST_CHECK(cmt_metric_hist_get_value(&histogram->map->metric, 0) == 5);
    TEST_CHECK(cmt_metric_hist_get_value(&histogram->map->metric, 1) == 6);
    TEST_CHECK(cmt_metric_hist_get_value(&histogram->map->metric, 2) == 9);
    TEST_CHECK(offset == cfl_sds_len(fixture));
    cmt_destroy(decoded);
    cfl_sds_destroy(fixture);
}

static int buffer_contains(char *buffer, size_t size, const void *needle, size_t length)
{
    size_t index;

    for (index = 0; index + length <= size; index++) {
        if (memcmp(buffer + index, needle, length) == 0) {
            return CMT_TRUE;
        }
    }

    return CMT_FALSE;
}

static void check_histogram_sample(struct cmt_metric *sample, uint64_t *expected,
                                   size_t count)
{
    size_t index;

    for (index = 0; index < count; index++) {
        TEST_CHECK(cmt_metric_hist_get_value(sample, index) == expected[index]);
        TEST_MSG("bucket %zu: expected %" PRIu64 ", got %" PRIu64, index,
                 expected[index], cmt_metric_hist_get_value(sample, index));
    }
}

/* Fluent Bit v5.1.0 natively writes cumulative (Prometheus-style) buckets. */
static void test_legacy_cumulative_histogram_fixture()
{
    cfl_sds_t fixture;
    struct cmt *decoded;
    struct cmt_histogram *histogram;
    struct cmt_metric *sample;
    size_t offset = 0;
    uint64_t cumulative[] = {1, 3, 5, 6};
    uint64_t independent[] = {1, 2, 2, 1};
    size_t index;

    fixture = read_file(CMT_TESTS_DATA_PATH "/histogram-cumulative-v5.1.0.msgpack");
    TEST_ASSERT(fixture != NULL);
    TEST_ASSERT(cmt_decode_msgpack_create(&decoded, fixture,
                                          cfl_sds_len(fixture), &offset) == 0);
    TEST_CHECK(offset == cfl_sds_len(fixture));

    histogram = cfl_list_entry_first(&decoded->histograms, struct cmt_histogram, _head);
    TEST_ASSERT(histogram != NULL);
    TEST_CHECK(histogram->map->metric_static_set == CMT_TRUE);
    check_histogram_sample(&histogram->map->metric, cumulative, 4);

    TEST_ASSERT(cfl_list_size(&histogram->map->metrics) == 1);
    sample = cfl_list_entry_first(&histogram->map->metrics, struct cmt_metric, _head);
    check_histogram_sample(sample, cumulative, 4);
    TEST_CHECK(cmt_metric_hist_get_count_value(sample) == 6);

    for (index = 0; index < 4; index++) {
        TEST_CHECK(cmt_metric_hist_get_bucket_count(sample, index) == independent[index]);
    }

    cmt_destroy(decoded);
    cfl_sds_destroy(fixture);
}

/* The wire must stay byte-compatible with v5.1.0 readers: cumulative and
 * unmarked, with or without the OTLP metadata sidecar. */
static void test_histogram_wire_stays_cumulative()
{
    struct cmt *ctx;
    struct cmt *decoded;
    struct cmt_histogram *histogram;
    char *buffer;
    size_t size;
    size_t offset;
    int pass;
    uint64_t counts[] = {5, 6, 9};
    const unsigned char expected[] = {0xa7, 'b','u','c','k','e','t','s',0x93,5,6,9};
    const char marker[] = "__cmetrics_histogram_buckets";

    for (pass = 0; pass < 2; pass++) {
        ctx = cmt_create();
        TEST_ASSERT(ctx != NULL);
        histogram = cmt_histogram_create(ctx, "", "", "hist", "hist",
                                         cmt_histogram_buckets_create(2, 1.0, 2.0), 0, NULL);
        TEST_ASSERT(histogram != NULL);
        TEST_ASSERT(cmt_histogram_set_default(histogram, 100, counts, 12.0, 9, 0, NULL) == 0);

        if (pass == 1) {
            /* Force the OTLP metadata sidecar path. */
            histogram->map->metric.otlp_metadata = cfl_kvlist_create();
            TEST_ASSERT(histogram->map->metric.otlp_metadata != NULL);
            TEST_ASSERT(cfl_kvlist_insert_uint64(histogram->map->metric.otlp_metadata,
                                                 "flags", 1) == 0);
        }

        TEST_ASSERT(cmt_encode_msgpack_create(ctx, &buffer, &size) == 0);
        TEST_CHECK(buffer_contains(buffer, size, expected, sizeof(expected)));
        TEST_CHECK(!buffer_contains(buffer, size, marker, sizeof(marker) - 1));

        offset = 0;
        TEST_ASSERT(cmt_decode_msgpack_create(&decoded, buffer, size, &offset) == 0);
        histogram = cfl_list_entry_first(&decoded->histograms, struct cmt_histogram, _head);
        check_histogram_sample(&histogram->map->metric, counts, 3);
        if (pass == 1) {
            TEST_CHECK(histogram->map->metric.otlp_metadata != NULL);
        }

        cmt_destroy(decoded);
        cmt_encode_msgpack_destroy(buffer);
        cmt_destroy(ctx);
    }
}

/* Encode a histogram and splice a bucket marker into the internal metadata
 * map, as unreleased writers did; the current encoder never emits it. */
static int encode_with_marker(uint64_t *counts, uint64_t total,
                              const char *marker, size_t marker_length,
                              char **buffer, size_t *size)
{
    struct cmt *ctx;
    struct cmt_histogram *histogram;
    char *encoded;
    char *spliced;
    size_t encoded_size;
    size_t index;
    size_t position;
    size_t key_length;
    const char header[] = "\xa8" "cmetrics" "\x80";
    const char key[] = "__cmetrics_histogram_buckets";

    ctx = cmt_create();
    if (ctx == NULL) {
        return -1;
    }

    histogram = cmt_histogram_create(ctx, "", "", "hist", "hist",
                                     cmt_histogram_buckets_create(2, 1.0, 2.0), 0, NULL);
    if (histogram == NULL ||
        cmt_histogram_set_default(histogram, 100, counts, 12.0, total, 0, NULL) != 0 ||
        cmt_encode_msgpack_create(ctx, &encoded, &encoded_size) != 0) {
        cmt_destroy(ctx);
        return -1;
    }
    cmt_destroy(ctx);

    position = encoded_size;
    for (index = 0; index + sizeof(header) - 1 <= encoded_size; index++) {
        if (memcmp(encoded + index, header, sizeof(header) - 1) == 0) {
            position = index + sizeof(header) - 2;
            break;
        }
    }
    if (position == encoded_size) {
        cmt_encode_msgpack_destroy(encoded);
        return -1;
    }

    key_length = sizeof(key) - 1;
    spliced = malloc(encoded_size + 2 + key_length + marker_length);
    if (spliced == NULL) {
        cmt_encode_msgpack_destroy(encoded);
        return -1;
    }

    /* fixmap(1) { fixstr(key): marker } replaces the empty fixmap. */
    memcpy(spliced, encoded, position);
    index = position;
    spliced[index++] = (char) 0x81;
    spliced[index++] = (char) (0xa0 | key_length);
    memcpy(spliced + index, key, key_length);
    index += key_length;
    memcpy(spliced + index, marker, marker_length);
    index += marker_length;
    memcpy(spliced + index, encoded + position + 1, encoded_size - position - 1);
    index += encoded_size - position - 1;

    cmt_encode_msgpack_destroy(encoded);
    *buffer = spliced;
    *size = index;

    return 0;
}

/* Bucket markers written by unreleased builds are advisory: unknown or
 * mistyped values must not drop the chunk, and a marker can not force a
 * wrong interpretation of the buckets. */
static void test_histogram_marker_is_ignored()
{
    struct cmt *decoded;
    struct cmt_histogram *histogram;
    char *buffer;
    size_t size;
    size_t offset;
    size_t index;
    int ret;
    uint64_t cumulative[] = {5, 6, 9};
    uint64_t independent[] = {5, 1, 3};
    struct {
        const char *marker;
        size_t length;
        uint64_t *counts;
    } cases[] = {
        {"\xa5" "bogus", 6, cumulative},
        {"\x07", 1, cumulative},
        {"\xc0", 1, cumulative},
        {"\xaa" "per_bucket", 11, cumulative},
        /* spoofed: "cumulative" claimed on independent counts */
        {"\xaa" "cumulative", 11, independent},
        {"\xaa" "cumulative", 11, cumulative},
        {"\xaa" "per_bucket", 11, independent},
    };

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        buffer = NULL;
        size = 0;
        ret = encode_with_marker(cases[index].counts, 9, cases[index].marker,
                                 cases[index].length, &buffer, &size);
        TEST_ASSERT(ret == 0);

        offset = 0;
        decoded = NULL;
        ret = cmt_decode_msgpack_create(&decoded, buffer, size, &offset);
        TEST_CHECK(ret == CMT_DECODE_MSGPACK_SUCCESS);
        TEST_MSG("case %zu: decode returned %d", index, ret);
        TEST_CHECK(offset == size);

        if (decoded != NULL) {
            histogram = cfl_list_entry_first(&decoded->histograms,
                                             struct cmt_histogram, _head);
            check_histogram_sample(&histogram->map->metric, cumulative, 3);
            TEST_CHECK(cfl_kvlist_fetch(decoded->internal_metadata,
                                        "__cmetrics_histogram_buckets") == NULL);
            cmt_destroy(decoded);
        }

        free(buffer);
    }
}

/* Samples whose shape is not consistent with either layout are untouched. */
static void test_histogram_inconsistent_buckets_untouched()
{
    struct cmt *ctx;
    struct cmt *decoded;
    struct cmt_histogram *histogram;
    char *buffer;
    size_t size;
    size_t offset = 0;
    uint64_t counts[] = {4, 2, 8};

    ctx = cmt_create();
    TEST_ASSERT(ctx != NULL);
    histogram = cmt_histogram_create(ctx, "", "", "hist", "hist",
                                     cmt_histogram_buckets_create(2, 1.0, 2.0), 0, NULL);
    TEST_ASSERT(histogram != NULL);
    TEST_ASSERT(cmt_histogram_set_default(histogram, 100, counts, 1.0, 11, 0, NULL) == 0);
    TEST_ASSERT(cmt_encode_msgpack_create(ctx, &buffer, &size) == 0);
    TEST_ASSERT(cmt_decode_msgpack_create(&decoded, buffer, size, &offset) == 0);
    histogram = cfl_list_entry_first(&decoded->histograms, struct cmt_histogram, _head);
    check_histogram_sample(&histogram->map->metric, counts, 3);
    cmt_destroy(decoded);
    cmt_encode_msgpack_destroy(buffer);
    cmt_destroy(ctx);
}

TEST_LIST = {
    {"legacy_histogram_bucket_semantics", test_legacy_histogram_bucket_semantics},
    {"legacy_cumulative_histogram_fixture", test_legacy_cumulative_histogram_fixture},
    {"histogram_wire_stays_cumulative", test_histogram_wire_stays_cumulative},
    {"histogram_marker_is_ignored", test_histogram_marker_is_ignored},
    {"histogram_inconsistent_buckets_untouched", test_histogram_inconsistent_buckets_untouched},
    {"histogram_temporality_survives_msgpack_roundtrip",
     test_histogram_temporality_survives_msgpack_roundtrip},
    {"exp_histogram_temporality_survives_msgpack_roundtrip",
     test_exp_histogram_temporality_survives_msgpack_roundtrip},
    {"counter_temporality_still_survives_msgpack_roundtrip",
     test_counter_temporality_still_survives_msgpack_roundtrip},
    {NULL, NULL}
};
