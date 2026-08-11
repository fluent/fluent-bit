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
            TEST_CHECK(decoded_counter->aggregation_type ==
                      CMT_AGGREGATION_TYPE_DELTA);
        }

        cmt_decode_msgpack_destroy(decoded_cmt);
    }

    cmt_encode_msgpack_destroy(encoded_buffer);
    cmt_destroy(cmt);
}

TEST_LIST = {
    {"histogram_temporality_survives_msgpack_roundtrip",
     test_histogram_temporality_survives_msgpack_roundtrip},
    {"exp_histogram_temporality_survives_msgpack_roundtrip",
     test_exp_histogram_temporality_survives_msgpack_roundtrip},
    {"counter_temporality_still_survives_msgpack_roundtrip",
     test_counter_temporality_still_survives_msgpack_roundtrip},
    {NULL, NULL}
};
