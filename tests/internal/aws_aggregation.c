/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/aws/flb_aws_aggregation.h>
#include "flb_tests_internal.h"

#include <string.h>

#define MAX_RECORD_SIZE 1024000

/* Test: Initialize and destroy aggregation buffer */
void test_aws_aggregation_init_destroy()
{
    struct flb_aws_agg_buffer buf;
    int ret;

    /* Test successful initialization */
    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(buf.agg_buf != NULL);
    TEST_CHECK(buf.agg_buf_size == MAX_RECORD_SIZE);
    TEST_CHECK(buf.agg_buf_offset == 0);

    /* Test destroy */
    flb_aws_aggregation_destroy(&buf);
    TEST_CHECK(buf.agg_buf == NULL);
    TEST_CHECK(buf.agg_buf_size == 0);
    TEST_CHECK(buf.agg_buf_offset == 0);
}

/* Test: Add single record to buffer */
void test_aws_aggregation_add_single()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    const char *data = "{\"message\":\"test\"}\n";
    size_t data_len = strlen(data);

    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    /* Add single record */
    ret = flb_aws_aggregation_add(&buf, data, data_len, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(buf.agg_buf_offset == data_len);

    /* Verify content */
    TEST_CHECK(memcmp(buf.agg_buf, data, data_len) == 0);

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Add multiple records to buffer */
void test_aws_aggregation_add_multiple()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    const char *data1 = "{\"message\":\"test1\"}\n";
    const char *data2 = "{\"message\":\"test2\"}\n";
    const char *data3 = "{\"message\":\"test3\"}\n";
    size_t len1 = strlen(data1);
    size_t len2 = strlen(data2);
    size_t len3 = strlen(data3);

    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    /* Add first record */
    ret = flb_aws_aggregation_add(&buf, data1, len1, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(buf.agg_buf_offset == len1);

    /* Add second record */
    ret = flb_aws_aggregation_add(&buf, data2, len2, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(buf.agg_buf_offset == len1 + len2);

    /* Add third record */
    ret = flb_aws_aggregation_add(&buf, data3, len3, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(buf.agg_buf_offset == len1 + len2 + len3);

    /* Verify all content is concatenated */
    TEST_CHECK(memcmp(buf.agg_buf, data1, len1) == 0);
    TEST_CHECK(memcmp(buf.agg_buf + len1, data2, len2) == 0);
    TEST_CHECK(memcmp(buf.agg_buf + len1 + len2, data3, len3) == 0);

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Buffer full detection */
void test_aws_aggregation_buffer_full()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    size_t small_size = 100;
    char data[150];

    /* Initialize with small buffer */
    ret = flb_aws_aggregation_init(&buf, small_size);
    TEST_CHECK(ret == 0);

    /* Create data larger than buffer */
    memset(data, 'A', sizeof(data) - 1);
    data[sizeof(data) - 1] = '\0';

    /* Try to add data that exceeds buffer size */
    ret = flb_aws_aggregation_add(&buf, data, sizeof(data) - 1, small_size);
    TEST_CHECK(ret == 1); /* Should return 1 (buffer full) */

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Buffer full with multiple adds */
void test_aws_aggregation_buffer_full_multiple()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    size_t small_size = 100;
    const char *data = "0123456789"; /* 10 bytes */
    size_t data_len = strlen(data);
    int i;

    ret = flb_aws_aggregation_init(&buf, small_size);
    TEST_CHECK(ret == 0);

    /* Add records until buffer is full */
    for (i = 0; i < 9; i++) {
        ret = flb_aws_aggregation_add(&buf, data, data_len, small_size);
        TEST_CHECK(ret == 0); /* Should succeed */
    }

    /* This should fill the buffer (90 bytes used) */
    TEST_CHECK(buf.agg_buf_offset == 90);

    /* Try to add one more (would be 100 bytes, at limit) */
    ret = flb_aws_aggregation_add(&buf, data, data_len, small_size);
    TEST_CHECK(ret == 0); /* Should succeed, exactly at limit */

    /* Now buffer is full, next add should fail */
    ret = flb_aws_aggregation_add(&buf, data, data_len, small_size);
    TEST_CHECK(ret == 1); /* Should return 1 (buffer full) */

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Finalize with both modes (with and without newline) */
void test_aws_aggregation_finalize()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    const char *data = "{\"message\":\"test\"}\n";
    size_t data_len = strlen(data);
    size_t out_size;

    /* Test without newline (Kinesis Streams mode) */
    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    ret = flb_aws_aggregation_add(&buf, data, data_len, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    ret = flb_aws_aggregation_finalize(&buf, 0, &out_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out_size == data_len);

    flb_aws_aggregation_destroy(&buf);

    /* Test with newline (Firehose mode) */
    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    ret = flb_aws_aggregation_add(&buf, data, data_len, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    ret = flb_aws_aggregation_finalize(&buf, 1, &out_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out_size == data_len + 1);
    TEST_CHECK(buf.agg_buf[data_len] == '\n');

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Finalize empty buffer */
void test_aws_aggregation_finalize_empty()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    size_t out_size;

    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    /* Try to finalize empty buffer */
    ret = flb_aws_aggregation_finalize(&buf, 1, &out_size);
    TEST_CHECK(ret == -1); /* Should fail */

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Reset and reuse buffer (complete cycle) */
void test_aws_aggregation_reset_reuse()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    const char *data1 = "{\"message\":\"test1\"}\n";
    const char *data2 = "{\"message\":\"test2\"}\n";
    size_t len1 = strlen(data1);
    size_t len2 = strlen(data2);
    size_t out_size;

    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    /* First batch */
    ret = flb_aws_aggregation_add(&buf, data1, len1, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    ret = flb_aws_aggregation_finalize(&buf, 1, &out_size);
    TEST_CHECK(ret == 0);

    /* Reset for reuse */
    flb_aws_aggregation_reset(&buf);
    TEST_CHECK(buf.agg_buf_offset == 0);

    /* Second batch */
    ret = flb_aws_aggregation_add(&buf, data2, len2, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(buf.agg_buf_offset == len2);

    ret = flb_aws_aggregation_finalize(&buf, 1, &out_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out_size == len2 + 1);

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Large aggregation (many small records) */
void test_aws_aggregation_large()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    const char *data = "{\"msg\":\"x\"}\n"; /* 12 bytes */
    size_t data_len = strlen(data);
    int i;
    int count = 1000;

    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    /* Add 1000 small records */
    for (i = 0; i < count; i++) {
        ret = flb_aws_aggregation_add(&buf, data, data_len, MAX_RECORD_SIZE);
        TEST_CHECK(ret == 0);
    }

    TEST_CHECK(buf.agg_buf_offset == data_len * count);

    flb_aws_aggregation_destroy(&buf);
}

/* Test: NULL parameter handling */
void test_aws_aggregation_null_params()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    size_t out_size;

    /* Test init with NULL */
    ret = flb_aws_aggregation_init(NULL, MAX_RECORD_SIZE);
    TEST_CHECK(ret == -1);

    /* Initialize properly for other tests */
    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    /* Test add with NULL buffer */
    ret = flb_aws_aggregation_add(NULL, "data", 4, MAX_RECORD_SIZE);
    TEST_CHECK(ret == -1);

    /* Test add with NULL data */
    ret = flb_aws_aggregation_add(&buf, NULL, 4, MAX_RECORD_SIZE);
    TEST_CHECK(ret == -1);

    /* Test add with zero length */
    ret = flb_aws_aggregation_add(&buf, "data", 0, MAX_RECORD_SIZE);
    TEST_CHECK(ret == -1);

    /* Test finalize with NULL buffer */
    ret = flb_aws_aggregation_finalize(NULL, 1, &out_size);
    TEST_CHECK(ret == -1);

    /* Test finalize with NULL out_size */
    ret = flb_aws_aggregation_finalize(&buf, 1, NULL);
    TEST_CHECK(ret == -1);

    /* Test destroy with NULL (should not crash) */
    flb_aws_aggregation_destroy(NULL);

    /* Test reset with NULL (should not crash) */
    flb_aws_aggregation_reset(NULL);

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Exact boundary conditions */
void test_aws_aggregation_boundary()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    size_t exact_size = 50;
    char data[50];
    size_t out_size;

    /* Initialize with exact size */
    ret = flb_aws_aggregation_init(&buf, exact_size);
    TEST_CHECK(ret == 0);

    /* Fill exactly to the boundary */
    memset(data, 'X', exact_size);
    ret = flb_aws_aggregation_add(&buf, data, exact_size, exact_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(buf.agg_buf_offset == exact_size);

    /* Try to add one more byte - should fail */
    ret = flb_aws_aggregation_add(&buf, "Y", 1, exact_size);
    TEST_CHECK(ret == 1);

    /* Finalize without newline should work */
    ret = flb_aws_aggregation_finalize(&buf, 0, &out_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out_size == exact_size);

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Finalize with newline at boundary */
void test_aws_aggregation_finalize_boundary()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    size_t size = 100;
    char data[99];
    size_t out_size;

    ret = flb_aws_aggregation_init(&buf, size);
    TEST_CHECK(ret == 0);

    /* Fill to size-1 to leave room for newline */
    memset(data, 'A', 99);
    ret = flb_aws_aggregation_add(&buf, data, 99, size);
    TEST_CHECK(ret == 0);

    /* Finalize with newline should work */
    ret = flb_aws_aggregation_finalize(&buf, 1, &out_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out_size == 100);
    TEST_CHECK(buf.agg_buf[99] == '\n');

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Multiple reset cycles */
void test_aws_aggregation_multiple_resets()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    const char *data = "test_data\n";
    size_t data_len = strlen(data);
    int i;

    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    /* Perform multiple add/reset cycles */
    for (i = 0; i < 10; i++) {
        ret = flb_aws_aggregation_add(&buf, data, data_len, MAX_RECORD_SIZE);
        TEST_CHECK(ret == 0);
        TEST_CHECK(buf.agg_buf_offset == data_len);
        
        flb_aws_aggregation_reset(&buf);
        TEST_CHECK(buf.agg_buf_offset == 0);
    }

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Very small buffer size */
void test_aws_aggregation_tiny_buffer()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    const char *data = "AB";
    size_t out_size;

    /* Initialize with very small buffer */
    ret = flb_aws_aggregation_init(&buf, 10);
    TEST_CHECK(ret == 0);

    /* Add small data */
    ret = flb_aws_aggregation_add(&buf, data, 2, 10);
    TEST_CHECK(ret == 0);

    /* Add more small data */
    ret = flb_aws_aggregation_add(&buf, data, 2, 10);
    TEST_CHECK(ret == 0);

    /* Should have 4 bytes */
    TEST_CHECK(buf.agg_buf_offset == 4);

    /* Finalize */
    ret = flb_aws_aggregation_finalize(&buf, 0, &out_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out_size == 4);

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Sequential finalize without reset */
void test_aws_aggregation_double_finalize()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    const char *data = "test\n";
    size_t data_len = strlen(data);
    size_t out_size1, out_size2;

    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    ret = flb_aws_aggregation_add(&buf, data, data_len, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    /* First finalize */
    ret = flb_aws_aggregation_finalize(&buf, 0, &out_size1);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out_size1 == data_len);

    /* Second finalize without reset - should still work */
    ret = flb_aws_aggregation_finalize(&buf, 0, &out_size2);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out_size2 == out_size1);

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Add after finalize without reset */
void test_aws_aggregation_add_after_finalize()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    const char *data1 = "first\n";
    const char *data2 = "second\n";
    size_t len1 = strlen(data1);
    size_t len2 = strlen(data2);
    size_t out_size;

    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    /* Add first data */
    ret = flb_aws_aggregation_add(&buf, data1, len1, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    /* Finalize */
    ret = flb_aws_aggregation_finalize(&buf, 0, &out_size);
    TEST_CHECK(ret == 0);

    /* Add more data without reset - should append */
    ret = flb_aws_aggregation_add(&buf, data2, len2, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);
    TEST_CHECK(buf.agg_buf_offset == len1 + len2);

    flb_aws_aggregation_destroy(&buf);
}

/* Test: Alternating add and finalize patterns */
void test_aws_aggregation_alternating_pattern()
{
    struct flb_aws_agg_buffer buf;
    int ret;
    const char *data = "X";
    size_t out_size;
    int i;

    ret = flb_aws_aggregation_init(&buf, MAX_RECORD_SIZE);
    TEST_CHECK(ret == 0);

    /* Add one byte, finalize, reset - repeat */
    for (i = 0; i < 5; i++) {
        ret = flb_aws_aggregation_add(&buf, data, 1, MAX_RECORD_SIZE);
        TEST_CHECK(ret == 0);
        TEST_CHECK(buf.agg_buf_offset == 1);

        ret = flb_aws_aggregation_finalize(&buf, 0, &out_size);
        TEST_CHECK(ret == 0);
        TEST_CHECK(out_size == 1);

        flb_aws_aggregation_reset(&buf);
        TEST_CHECK(buf.agg_buf_offset == 0);
    }

    flb_aws_aggregation_destroy(&buf);
}

/* Test list */
TEST_LIST = {
    {"aws_aggregation_init_destroy",           test_aws_aggregation_init_destroy},
    {"aws_aggregation_add_single",             test_aws_aggregation_add_single},
    {"aws_aggregation_add_multiple",           test_aws_aggregation_add_multiple},
    {"aws_aggregation_buffer_full",            test_aws_aggregation_buffer_full},
    {"aws_aggregation_buffer_full_multiple",   test_aws_aggregation_buffer_full_multiple},
    {"aws_aggregation_finalize",               test_aws_aggregation_finalize},
    {"aws_aggregation_finalize_empty",         test_aws_aggregation_finalize_empty},
    {"aws_aggregation_reset_reuse",            test_aws_aggregation_reset_reuse},
    {"aws_aggregation_large",                  test_aws_aggregation_large},
    {"aws_aggregation_null_params",            test_aws_aggregation_null_params},
    {"aws_aggregation_boundary",               test_aws_aggregation_boundary},
    {"aws_aggregation_finalize_boundary",      test_aws_aggregation_finalize_boundary},
    {"aws_aggregation_multiple_resets",        test_aws_aggregation_multiple_resets},
    {"aws_aggregation_tiny_buffer",            test_aws_aggregation_tiny_buffer},
    {"aws_aggregation_double_finalize",        test_aws_aggregation_double_finalize},
    {"aws_aggregation_add_after_finalize",     test_aws_aggregation_add_after_finalize},
    {"aws_aggregation_alternating_pattern",    test_aws_aggregation_alternating_pattern},
    {NULL, NULL}
};
