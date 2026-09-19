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

static void write_values(mpack_writer_t *writer)
{
    mpack_write_cstr(writer, "values");
    mpack_start_array(writer, 1);
    mpack_start_map(writer, 2);
    mpack_write_cstr(writer, "ts");
    mpack_write_uint(writer, 1);
    mpack_write_cstr(writer, "value");
    mpack_write_double(writer, 1.0);
    mpack_finish_map(writer);
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
        write_values(&writer);
    }
    write_meta(&writer, type, duplicate);
    if (mode != 2) {
        write_values(&writer);
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

TEST_LIST = {
    {"controls", test_controls},
    {"duplicate_meta", test_duplicate_meta},
    {"values_before_meta", test_values_before_meta},
    {"duplicate_options", test_duplicate_options},
    {"duplicate_layout", test_duplicate_layout},
    {NULL, NULL}
};
