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


#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_opts.h>
#include <cmetrics/cmt_cat.h>
#include <mpack/mpack.h>
#include "cmt_tests.h"

static void write_meta(mpack_writer_t *writer, int type, const char *duplicate)
{
    const char *fields[] = {"ns", "ss", "name", "desc", "unit"};
    size_t index;
    int repeated;
    int duplicate_layout;

    mpack_write_cstr(writer, "meta");
    duplicate_layout = duplicate != NULL && strcmp(duplicate, "layout") == 0;
    mpack_start_map(writer, 4 + duplicate_layout);
    mpack_write_cstr(writer, "ver");
    mpack_write_uint(writer, 2);
    mpack_write_cstr(writer, "type");
    mpack_write_uint(writer, type);
    mpack_write_cstr(writer, "opts");
    repeated = duplicate != NULL && !duplicate_layout;
    mpack_start_map(writer, 5 + repeated);
    for (index = 0; index < 5; index++) {
        mpack_write_cstr(writer, fields[index]);
        mpack_write_cstr(writer, "test");
        if (duplicate != NULL && strcmp(duplicate, fields[index]) == 0) {
            mpack_write_cstr(writer, fields[index]);
            mpack_write_cstr(writer, "replacement");
        }
    }
    mpack_finish_map(writer);
    mpack_write_cstr(writer, type == CMT_SUMMARY ? "quantiles" : "buckets");
    mpack_start_array(writer, 1);
    mpack_write_double(writer, 0.5);
    mpack_finish_array(writer);
    if (duplicate_layout) {
        mpack_write_cstr(writer, type == CMT_SUMMARY ? "quantiles" : "buckets");
        mpack_start_array(writer, 0);
        mpack_finish_array(writer);
    }
    mpack_finish_map(writer);
}


/* section: 0 = none, 1 = histogram, 2 = summary */
static void write_sample(mpack_writer_t *writer, int section)
{
    mpack_start_map(writer, section == 0 ? 1 : 2);
    mpack_write_cstr(writer, "ts");
    mpack_write_uint(writer, 1);
    if (section == 1) {
        mpack_write_cstr(writer, "histogram");
        mpack_start_map(writer, 3);
        mpack_write_cstr(writer, "buckets");
        mpack_start_array(writer, 2);
        mpack_write_uint(writer, 1);
        mpack_write_uint(writer, 2);
        mpack_finish_array(writer);
        mpack_write_cstr(writer, "sum");
        mpack_write_double(writer, 1.0);
        mpack_write_cstr(writer, "count");
        mpack_write_uint(writer, 3);
        mpack_finish_map(writer);
    }
    else if (section == 2) {
        mpack_write_cstr(writer, "summary");
        mpack_start_map(writer, 4);
        mpack_write_cstr(writer, "quantiles_set");
        mpack_write_uint(writer, 1);
        mpack_write_cstr(writer, "quantiles");
        mpack_start_array(writer, 1);
        mpack_write_uint(writer, 1);
        mpack_finish_array(writer);
        mpack_write_cstr(writer, "count");
        mpack_write_uint(writer, 1);
        mpack_write_cstr(writer, "sum");
        mpack_write_uint(writer, 1);
        mpack_finish_map(writer);
    }
    mpack_finish_map(writer);
}

static void write_values(mpack_writer_t *writer, int type)
{
    mpack_write_cstr(writer, "values");
    mpack_start_array(writer, 1);
    write_sample(writer, type == CMT_HISTOGRAM ? 1 : 2);
    mpack_finish_array(writer);
}

static void check_document(int type, int mode, const char *duplicate)
{
    mpack_writer_t writer;
    char *data;
    size_t size;
    size_t offset;
    size_t consumed;
    struct cmt *context;
    char *encoded;
    size_t encoded_size;
    int result;

    data = NULL;
    size = 0;
    offset = 0;
    context = NULL;
    mpack_writer_init_growable(&writer, &data, &size);
    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "metrics");
    mpack_start_array(&writer, 1);
    mpack_start_map(&writer, mode == 1 ? 3 : 2);
    if (mode == 2) {
        write_values(&writer, type);
    }
    write_meta(&writer, type, duplicate);
    if (mode != 2) {
        write_values(&writer, type);
    }
    if (mode == 1) {
        mpack_write_cstr(&writer, "meta");
        mpack_start_map(&writer, 1);
        mpack_write_cstr(&writer, type == CMT_SUMMARY ? "quantiles" : "buckets");
        mpack_start_array(&writer, 2);
        mpack_write_double(&writer, 0.9);
        mpack_write_double(&writer, 1.0);
        mpack_finish_array(&writer);
        mpack_finish_map(&writer);
    }
    mpack_finish_map(&writer);
    mpack_finish_array(&writer);
    mpack_finish_map(&writer);
    TEST_ASSERT(mpack_writer_destroy(&writer) == mpack_ok);
    result = cmt_decode_msgpack_create(&context, data, size, &offset);
    if (mode == 0 && duplicate == NULL) {
        TEST_CHECK(result == CMT_DECODE_MSGPACK_SUCCESS);
        if (result == CMT_DECODE_MSGPACK_SUCCESS) {
            TEST_CHECK(cmt_encode_msgpack_create(context, &encoded, &encoded_size) == 0);
            cmt_encode_msgpack_destroy(encoded);
        }
    }
    else {
        TEST_CHECK(result != CMT_DECODE_MSGPACK_SUCCESS);
    }
    if (context != NULL) {
        cmt_decode_msgpack_destroy(context);
    }
    for (offset = 0; offset < size; offset++) {
        consumed = 0;
        context = NULL;
        result = cmt_decode_msgpack_create(&context, data, offset, &consumed);
        TEST_CHECK(result != CMT_DECODE_MSGPACK_SUCCESS);
        if (context != NULL) {
            cmt_decode_msgpack_destroy(context);
        }
    }
    free(data);
}

static void test_controls(void)
{
    check_document(CMT_SUMMARY, 0, NULL);
    check_document(CMT_HISTOGRAM, 0, NULL);
}

static void test_duplicate_meta(void)
{
    check_document(CMT_SUMMARY, 1, NULL);
    check_document(CMT_HISTOGRAM, 1, NULL);
}

static void test_values_before_meta(void)
{
    check_document(CMT_SUMMARY, 2, NULL);
    check_document(CMT_HISTOGRAM, 2, NULL);
}

static void test_duplicate_layout(void)
{
    check_document(CMT_SUMMARY, 0, "layout");
    check_document(CMT_HISTOGRAM, 0, "layout");
}

static void test_duplicate_options(void)
{
    const char *fields[] = {"ns", "ss", "name", "desc", "unit"};
    size_t index;

    for (index = 0; index < 5; index++) {
        check_document(CMT_SUMMARY, 0, fields[index]);
    }
}

static int decode_metadata_document(const char *data, size_t size)
{
    int         result;
    size_t      offset;
    struct cmt *context;

    offset = 0;
    context = NULL;
    result = cmt_decode_msgpack_create(&context, (char *) data, size, &offset);
    if (context != NULL) {
        cmt_decode_msgpack_destroy(context);
    }

    return result;
}

static void test_truncated_metadata_string(void)
{
    /* {"meta": {"cmetrics": {"k": <value>}}} */
    const char prefix[] = "\x81\xa4meta\x81\xa8" "cmetrics\x81\xa1k";
    const char *values[] = {
        "\xdb\xff\xff\xff\xff",          /* str32, 4 GiB, no data */
        "\xc6\xff\xff\xff\xff",          /* bin32, 4 GiB, no data */
        "\xdb\x00\x00\x10\x00" "abc",    /* str32, 4 KiB, 3 bytes */
        "\xc6\x00\x00\x10\x00" "abc",    /* bin32, 4 KiB, 3 bytes */
        NULL
    };
    const size_t sizes[] = {5, 5, 8, 8};
    char   document[64];
    size_t index;

    for (index = 0; values[index] != NULL; index++) {
        memcpy(document, prefix, sizeof(prefix) - 1);
        memcpy(&document[sizeof(prefix) - 1], values[index], sizes[index]);
        TEST_CHECK(decode_metadata_document(document,
                                            sizeof(prefix) - 1 + sizes[index]) !=
                   CMT_DECODE_MSGPACK_SUCCESS);
        TEST_MSG("value %zu", index);
    }
}

static void test_metadata_string_control(void)
{
    const char document[] = "\x82\xa4meta\x81\xa8" "cmetrics\x82\xa1k\xa1v"
                            "\xa1" "b\xc4\x02\x00\x01"
                            "\xa7metrics\x90";

    TEST_CHECK(decode_metadata_document(document, sizeof(document) - 1) ==
               CMT_DECODE_MSGPACK_SUCCESS);
}

/* one metric of 'type' whose 'values' holds 'count' label-less samples
 * carrying 'section'
 */
static int decode_samples_document(int type, int section, int count)
{
    mpack_writer_t writer;
    char          *data;
    char          *encoded;
    size_t         encoded_size;
    size_t         size;
    size_t         offset;
    int            index;
    int            result;
    struct cmt    *context;

    data = NULL;
    size = 0;
    offset = 0;
    context = NULL;
    mpack_writer_init_growable(&writer, &data, &size);
    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "metrics");
    mpack_start_array(&writer, 1);
    mpack_start_map(&writer, 2);
    write_meta(&writer, type, NULL);
    mpack_write_cstr(&writer, "values");
    mpack_start_array(&writer, count);
    for (index = 0; index < count; index++) {
        write_sample(&writer, section);
    }
    mpack_finish_array(&writer);
    mpack_finish_map(&writer);
    mpack_finish_array(&writer);
    mpack_finish_map(&writer);
    TEST_ASSERT(mpack_writer_destroy(&writer) == mpack_ok);

    result = cmt_decode_msgpack_create(&context, data, size, &offset);
    if (result == CMT_DECODE_MSGPACK_SUCCESS) {
        TEST_CHECK(cmt_encode_msgpack_create(context, &encoded, &encoded_size) == 0);
        cmt_encode_msgpack_destroy(encoded);
        cmt_decode_msgpack_destroy(context);
    }
    free(data);

    return result;
}

static void test_repeated_static_samples(void)
{
    TEST_CHECK(decode_samples_document(CMT_HISTOGRAM, 1, 3) ==
               CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(decode_samples_document(CMT_SUMMARY, 2, 3) ==
               CMT_DECODE_MSGPACK_SUCCESS);
}

static void test_missing_sample_section(void)
{
    /* histogram and summary samples must carry their own data */
    TEST_CHECK(decode_samples_document(CMT_HISTOGRAM, 0, 1) !=
               CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(decode_samples_document(CMT_SUMMARY, 0, 1) !=
               CMT_DECODE_MSGPACK_SUCCESS);

    /* and the section must match the metric type */
    TEST_CHECK(decode_samples_document(CMT_HISTOGRAM, 2, 1) !=
               CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(decode_samples_document(CMT_SUMMARY, 1, 1) !=
               CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(decode_samples_document(CMT_COUNTER, 1, 1) !=
               CMT_DECODE_MSGPACK_SUCCESS);
    TEST_CHECK(decode_samples_document(CMT_GAUGE, 2, 1) !=
               CMT_DECODE_MSGPACK_SUCCESS);
}

/* a histogram without buckets decoded from msgpack must not crash cmt_cat() */
static void test_cat_histogram_without_buckets(void)
{
    mpack_writer_t writer;
    char          *data;
    size_t         size;
    size_t         offset;
    int            result;
    struct cmt    *context;
    struct cmt    *target;

    data = NULL;
    size = 0;
    offset = 0;
    context = NULL;
    mpack_writer_init_growable(&writer, &data, &size);
    mpack_start_map(&writer, 1);
    mpack_write_cstr(&writer, "metrics");
    mpack_start_array(&writer, 1);
    mpack_start_map(&writer, 2);
    mpack_write_cstr(&writer, "meta");
    mpack_start_map(&writer, 3);
    mpack_write_cstr(&writer, "ver");
    mpack_write_uint(&writer, 2);
    mpack_write_cstr(&writer, "type");
    mpack_write_uint(&writer, CMT_HISTOGRAM);
    mpack_write_cstr(&writer, "opts");
    mpack_start_map(&writer, 2);
    mpack_write_cstr(&writer, "name");
    mpack_write_cstr(&writer, "test");
    mpack_write_cstr(&writer, "desc");
    mpack_write_cstr(&writer, "test");
    mpack_finish_map(&writer);
    mpack_finish_map(&writer);
    mpack_write_cstr(&writer, "values");
    mpack_start_array(&writer, 0);
    mpack_finish_array(&writer);
    mpack_finish_map(&writer);
    mpack_finish_array(&writer);
    mpack_finish_map(&writer);
    TEST_ASSERT(mpack_writer_destroy(&writer) == mpack_ok);

    result = cmt_decode_msgpack_create(&context, data, size, &offset);
    if (result == CMT_DECODE_MSGPACK_SUCCESS) {
        target = cmt_create();
        TEST_ASSERT(target != NULL);
        TEST_CHECK(cmt_cat(target, context) != 0);
        cmt_destroy(target);
        cmt_decode_msgpack_destroy(context);
    }
    free(data);
}

TEST_LIST = {
    {"controls", test_controls},
    {"duplicate_meta", test_duplicate_meta},
    {"values_before_meta", test_values_before_meta},
    {"duplicate_options", test_duplicate_options},
    {"duplicate_layout", test_duplicate_layout},
    {"truncated_metadata_string", test_truncated_metadata_string},
    {"metadata_string_control", test_metadata_string_control},
    {"repeated_static_samples", test_repeated_static_samples},
    {"missing_sample_section", test_missing_sample_section},
    {"cat_histogram_without_buckets", test_cat_histogram_without_buckets},
    {NULL, NULL}
};
