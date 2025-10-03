/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2025 The Fluent Bit Authors
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

#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#ifdef FLB_HAVE_METRICS
#include <fluent-bit/flb_metrics.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <io.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <float.h>
#include <inttypes.h>
#include "flb_tests_runtime.h"

#define TMP_CSV_PATH "lookup_test.csv"

struct test_ctx {
    flb_ctx_t *flb;
    int i_ffd;
    int f_ffd;
    int o_ffd;
};

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int o_ffd;
    int f_ffd;
    struct test_ctx *ctx = NULL;

    ctx = flb_malloc(sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("malloc failed");
        flb_errno();
        return NULL;
    }

    /* Service config */
    ctx->flb = flb_create();
    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(i_ffd >= 0);
    flb_input_set(ctx->flb, i_ffd, "tag", "test", NULL);
    ctx->i_ffd = i_ffd;

    /* Filter */
    f_ffd = flb_filter(ctx->flb, (char *) "lookup", NULL);
    TEST_CHECK(f_ffd >= 0);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test",
                   NULL);

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    TEST_CHECK(ctx != NULL);

    flb_time_msleep(1000);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void delete_csv_file()
{
#ifdef _WIN32
    _unlink(TMP_CSV_PATH);
#else
    unlink(TMP_CSV_PATH);
#endif
}

int create_csv_file(char *csv_content)
{
    FILE *fp = NULL;
    fp = fopen(TMP_CSV_PATH, "w");
    if (fp == NULL) {
        TEST_MSG("fopen error\n");
        return -1;
    }
    fprintf(fp, "%s", csv_content);
    fflush(fp);
    fclose(fp);
    return 0;
}

/* Callback to check expected results */
static int cb_check_result_json(void *record, size_t size, void *data)
{
    char *p;
    char *expected;
    char *result;
    char *scratch_buffer;

    expected = (char *) data;
    result = (char *) record;

    /* Create null-terminated scratch buffer to safely use strstr() */
    scratch_buffer = flb_malloc(size + 1);
    if (!scratch_buffer) {
        flb_error("Failed to allocate scratch buffer for string comparison");
        flb_free(record);
        return -1;
    }
    
    memcpy(scratch_buffer, result, size);
    scratch_buffer[size] = '\0';

    p = strstr(scratch_buffer, expected);
    TEST_CHECK(p != NULL);

    if (p == NULL) {
        flb_error("Expected to find: '%s' in result '%s'",
                  expected, scratch_buffer);
    }

    flb_free(scratch_buffer);
    flb_free(record);
    return 0;
}

/* Callback to check expected results and ensure specific field is absent */
static int cb_check_result_and_absence(void *record, size_t size, void *data)
{
    char *p;
    char *expected;
    char *absent_field;
    char *result;
    char *scratch_buffer;
    char **test_data = (char **) data; /* Array: [0] = expected, [1] = absent_field */

    expected = test_data[0];
    absent_field = test_data[1];
    result = (char *) record;

    /* Create null-terminated scratch buffer to safely use strstr() */
    scratch_buffer = flb_malloc(size + 1);
    if (!scratch_buffer) {
        flb_error("Failed to allocate scratch buffer for string comparison");
        flb_free(record);
        return -1;
    }
    
    memcpy(scratch_buffer, result, size);
    scratch_buffer[size] = '\0';

    /* Check that expected field exists */
    p = strstr(scratch_buffer, expected);
    TEST_CHECK(p != NULL);
    if (p == NULL) {
        flb_error("Expected to find: '%s' in result '%s'",
                  expected, scratch_buffer);
    }

    /* Check that absent field does NOT exist */
    p = strstr(scratch_buffer, absent_field);
    TEST_CHECK(p == NULL);
    if (p != NULL) {
        flb_error("Expected field '%s' to be absent, but found it in result '%s'",
                  absent_field, scratch_buffer);
    }

    flb_free(scratch_buffer);
    flb_free(record);
    return 0;
}

/* Test basic lookup functionality */
void flb_test_lookup_basic(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *csv_content = 
        "key,value\n"
        "user1,John Doe\n"
        "user2,Jane Smith\n"
        "user3,Bob Wilson\n";
    char *input = "[0, {\"user_id\": \"user1\"}]";

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"user_name\":\"John Doe\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "user_id",
                         "result_key", "user_name",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500);

    delete_csv_file();
    test_ctx_destroy(ctx);
}

/* Test lookup with ignore_case option */
void flb_test_lookup_ignore_case(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *csv_content = 
        "key,value\n"
        "USER1,John Doe\n"
        "user2,Jane Smith\n";
    char *input = "[0, {\"user_id\": \"user1\"}]";

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"user_name\":\"John Doe\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "user_id",
                         "result_key", "user_name",
                         "ignore_case", "true",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500);

    delete_csv_file();
    test_ctx_destroy(ctx);
}

/* Test lookup with CSV containing quotes and special characters */
void flb_test_lookup_csv_quotes(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *csv_content = 
        "key,value\n"
        "\"quoted,key\",\"Value with \"\"quotes\"\" and, commas\"\n"
        "simple_key,Simple Value\n";
    char *input = "[0, {\"lookup_field\": \"quoted,key\"}]";

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result_field\":\"Value with \\\"quotes\\\" and, commas\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "lookup_field",
                         "result_key", "result_field",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500);

    delete_csv_file();
    test_ctx_destroy(ctx);
}

/* Test lookup with numeric values */
void flb_test_lookup_numeric_values(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *csv_content = 
        "key,value\n"
        "123,Numeric Key\n"
        "456,Another Number\n";
    char *input = "[0, {\"numeric_field\": 123}]";

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"description\":\"Numeric Key\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "numeric_field",
                         "result_key", "description",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500);

    delete_csv_file();
    test_ctx_destroy(ctx);
}

/* Test lookup with very large numbers (testing the two-pass snprintf fix) */
void flb_test_lookup_large_numbers(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char large_number_str[64];
    snprintf(large_number_str, sizeof(large_number_str), "%lld", (long long)LLONG_MAX);
    
    char csv_content[256];
    snprintf(csv_content, sizeof(csv_content),
        "key,value\n"
        "%s,Very Large Number\n"
        "456,Small Number\n", large_number_str);
    
    char input[128];
    snprintf(input, sizeof(input), "[0, {\"big_number\": %lld}]", (long long)LLONG_MAX);

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"number_desc\":\"Very Large Number\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "big_number",
                         "result_key", "number_desc",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500);

    delete_csv_file();
    test_ctx_destroy(ctx);
}

/* Test lookup with boolean values */
void flb_test_lookup_boolean_values(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *csv_content = 
        "key,value\n"
        "true,Boolean True\n"
        "false,Boolean False\n";
    char *input = "[0, {\"bool_field\": true}]";

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"bool_desc\":\"Boolean True\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "bool_field",
                         "result_key", "bool_desc",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500);

    delete_csv_file();
    test_ctx_destroy(ctx);
}

/* Test lookup with no match (should emit original record) */
void flb_test_lookup_no_match(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *csv_content = 
        "key,value\n"
        "user1,John Doe\n"
        "user2,Jane Smith\n";
    char *input = "[0, {\"user_id\": \"user999\", \"other_field\": \"test\"}]";
    
    /* Test data: [0] = expected field, [1] = field that should be absent */
    char *test_data[2];
    test_data[0] = "\"other_field\":\"test\"";     /* Should exist */
    test_data[1] = "\"user_name\"";                /* Should NOT exist */

    cb_data.cb = cb_check_result_and_absence;
    cb_data.data = test_data;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "user_id",
                         "result_key", "user_name",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500);

    delete_csv_file();
    test_ctx_destroy(ctx);
}

/* Test dynamic line reading with very long CSV lines */
void flb_test_lookup_long_csv_lines(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *input = "[0, {\"key_field\": \"long_key\"}]";
    
    /* Test that long CSV values (>4096 chars) can be read correctly.
     * Just verify that the lookup worked by checking for value_field key. */
    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"value_field\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    /* Create CSV file with very long lines */
    FILE *fp = fopen(TMP_CSV_PATH, "w");
    TEST_CHECK(fp != NULL);
    
    fprintf(fp, "key,value\n");
    fprintf(fp, "long_key,");
    
    /* Write a very long value (> 4096 chars) */
    {
        int i;
        for (i = 0; i < 100; i++) {
            fprintf(fp, "This is a very long value that exceeds the original 4096 character buffer limit to test dynamic line reading functionality. ");
        }
    }
    fprintf(fp, "\n");
    fprintf(fp, "short_key,Short Value\n");
    fclose(fp);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "key_field",
                         "result_key", "value_field",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500);

    delete_csv_file();
    test_ctx_destroy(ctx);
}

/* Test with whitespace trimming */
void flb_test_lookup_whitespace_trim(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *csv_content = 
        "key,value\n"
        "  trimmed_key  ,  Trimmed Value  \n"
        "normal_key,Normal Value\n";
    char *input = "[0, {\"lookup_field\": \"  trimmed_key  \"}]";

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"result_field\":\"Trimmed Value\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "lookup_field",
                         "result_key", "result_field",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500);

    delete_csv_file();
    test_ctx_destroy(ctx);
}

/* Mock the dynamic buffer functions and structure for testing */
struct dynamic_buffer {
    char *data;
    size_t len;
    size_t capacity;
};

static int dynbuf_init(struct dynamic_buffer *buf, size_t initial_capacity) {
    buf->data = malloc(initial_capacity);
    if (!buf->data) return -1;
    buf->len = 0;
    buf->capacity = initial_capacity;
    buf->data[0] = '\0';
    return 0;
}

static int dynbuf_append_char(struct dynamic_buffer *buf, char c) {
    if (buf->len + 1 >= buf->capacity) {
        size_t new_capacity = buf->capacity * 2;
        char *new_data = realloc(buf->data, new_capacity);
        if (!new_data) return -1;
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    buf->data[buf->len++] = c;
    buf->data[buf->len] = '\0';
    return 0;
}

static void dynbuf_destroy(struct dynamic_buffer *buf) {
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
        buf->capacity = 0;
    }
}

/* Test dynamic buffer functionality */
void flb_test_dynamic_buffer(void)
{
    /* This is an internal unit test that doesn't require Fluent Bit setup */

    struct dynamic_buffer buf;
    
    /* Test initialization */
    int ret = dynbuf_init(&buf, 4);
    TEST_CHECK(ret == 0);
    TEST_CHECK(buf.capacity == 4);
    TEST_CHECK(buf.len == 0);
    
    /* Test appending characters that will cause growth */
    const char *test_str = "This is a test string that is longer than the initial capacity";
    {
        size_t i;
        for (i = 0; test_str[i]; i++) {
            ret = dynbuf_append_char(&buf, test_str[i]);
            TEST_CHECK(ret == 0);
        }
    }
    
    TEST_CHECK(strcmp(buf.data, test_str) == 0);
    TEST_CHECK(buf.len == strlen(test_str));
    TEST_CHECK(buf.capacity >= buf.len + 1);
    
    dynbuf_destroy(&buf);
}

/* Test nested record accessor patterns ($a.b.c) */
void flb_test_lookup_nested_keys(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *csv_content = 
        "key,value\n"
        "user123,John Doe\n"
        "admin456,Jane Smith\n";
    char *input = "[0, {\"user\": {\"profile\": {\"id\": \"user123\"}}, \"other_field\": \"test\"}]";

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"user_name\":\"John Doe\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "$user['profile']['id']",
                         "result_key", "user_name",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500);

    delete_csv_file();
    test_ctx_destroy(ctx);
}

/* Test with large CSV file (performance/load testing) */
void flb_test_lookup_large_csv(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *input = "[0, {\"user_id\": \"user5000\"}]";

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"user_name\":\"User 5000\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    /* Create CSV file with 10,000 entries for performance testing */
    FILE *fp = fopen(TMP_CSV_PATH, "w");
    TEST_CHECK(fp != NULL);
    
    fprintf(fp, "key,value\n");
    
    /* Write 10,000 test entries */
    {
        int i;
        for (i = 1; i <= 10000; i++) {
            fprintf(fp, "user%d,User %d\n", i, i);
        }
    }
    fclose(fp);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "user_id",
                         "result_key", "user_name",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Test lookup performance with large dataset */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(2000); /* Give more time for large CSV processing */

    delete_csv_file();
    test_ctx_destroy(ctx);
}

/* Test nested record accessor with array indexing ($users[0].id) */
void flb_test_lookup_nested_array_keys(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *csv_content = 
        "key,value\n"
        "array_user1,First User\n"
        "array_user2,Second User\n";
    char *input = "[0, {\"users\": [{\"id\": \"array_user1\"}, {\"id\": \"array_user2\"}], \"metadata\": \"test\"}]";

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"user_desc\":\"First User\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "$users[0]['id']",
                         "result_key", "user_desc",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
    TEST_CHECK(bytes == strlen(input));
    flb_time_msleep(1500);

    delete_csv_file();
    test_ctx_destroy(ctx);
}

#ifdef FLB_HAVE_METRICS
/* Custom callback to capture metrics and verify counts */
static int cb_check_metrics(void *record, size_t size, void *data)
{
    /* Just free the record - we'll check metrics through the filter instance */
    flb_free(record);
    return 0;
}

/* Helper function to get metric value from filter instance */
static uint64_t get_filter_metric(struct test_ctx *ctx, int metric_id)
{
    struct flb_filter_instance *f_ins;
    struct mk_list *head;
    struct flb_metric *metric;
    
    mk_list_foreach(head, &ctx->flb->config->filters) {
        f_ins = mk_list_entry(head, struct flb_filter_instance, _head);
        if (f_ins->id == ctx->f_ffd && f_ins->metrics) {
            metric = flb_metrics_get_id(metric_id, f_ins->metrics);
            if (metric) {
                return metric->val;
            }
        }
    }
    return 0;
}
#endif

#ifdef FLB_HAVE_METRICS
/* Test metrics with matched records */
void flb_test_lookup_metrics_matched(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *csv_content = 
        "key,value\n"
        "user1,John Doe\n"
        "user2,Jane Smith\n"
        "user3,Bob Wilson\n";
    char *input1 = "[0, {\"user_id\": \"user1\"}]";
    char *input2 = "[0, {\"user_id\": \"user2\"}]";
    char *input3 = "[0, {\"user_id\": \"unknown\"}]"; /* No match */

    cb_data.cb = cb_check_metrics;
    cb_data.data = NULL;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "user_id",
                         "result_key", "user_name",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Process three records: 2 matches + 1 no-match */
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input1, strlen(input1));
    TEST_CHECK(bytes == strlen(input1));
    
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input2, strlen(input2));
    TEST_CHECK(bytes == strlen(input2));
    
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input3, strlen(input3));
    TEST_CHECK(bytes == strlen(input3));
    
    flb_time_msleep(2000);

    /* Check metrics: should have 3 processed, 2 matched, 0 skipped */
    uint64_t processed = get_filter_metric(ctx, 200); /* FLB_LOOKUP_METRIC_PROCESSED */
    uint64_t matched = get_filter_metric(ctx, 201);   /* FLB_LOOKUP_METRIC_MATCHED */
    uint64_t skipped = get_filter_metric(ctx, 202);   /* FLB_LOOKUP_METRIC_SKIPPED */
    
    TEST_CHECK(processed == 3);
    TEST_CHECK(matched == 2);
    TEST_CHECK(skipped == 0);
    
    if (processed != 3) {
        TEST_MSG("Expected processed=3, got %llu", (unsigned long long)processed);
    }
    if (matched != 2) {
        TEST_MSG("Expected matched=2, got %llu", (unsigned long long)matched);
    }
    if (skipped != 0) {
        TEST_MSG("Expected skipped=0, got %llu", (unsigned long long)skipped);
    }

    delete_csv_file();
    test_ctx_destroy(ctx);
}
#endif

#ifdef FLB_HAVE_METRICS
/* Test metrics with large volume to verify counter accuracy */
void flb_test_lookup_metrics_processed(void)
{
    int ret;
    int bytes;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;
    char *csv_content = 
        "key,value\n"
        "match_key,Matched Value\n";

    cb_data.cb = cb_check_metrics;
    cb_data.data = NULL;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = create_csv_file(csv_content);
    TEST_CHECK(ret == 0);

    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "Match", "*",
                         "file", TMP_CSV_PATH,
                         "lookup_key", "test_key",
                         "result_key", "test_result",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Send 20 matching records and 10 non-matching records */
    const int matching_count = 20;
    const int non_matching_count = 10;
    {
        int i;
        for (i = 0; i < matching_count; i++) {
            char input[256];
            snprintf(input, sizeof(input), "[0, {\"test_key\": \"match_key\", \"seq\": %d}]", i);
            bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
            TEST_CHECK(bytes == strlen(input));
        }
    }
    
    {
        int i;
        for (i = 0; i < non_matching_count; i++) {
            char input[256];
            snprintf(input, sizeof(input), "[0, {\"test_key\": \"no_match_%d\", \"seq\": %d}]", i, i);
            bytes = flb_lib_push(ctx->flb, ctx->i_ffd, input, strlen(input));
            TEST_CHECK(bytes == strlen(input));
        }
    }
    
    flb_time_msleep(3000); /* Give more time for processing large volume */

    /* Verify metrics accuracy */
    uint64_t processed = get_filter_metric(ctx, 200);
    uint64_t matched = get_filter_metric(ctx, 201);
    uint64_t skipped = get_filter_metric(ctx, 202);
    
    TEST_CHECK(processed == matching_count + non_matching_count);
    TEST_CHECK(matched == matching_count);
    TEST_CHECK(skipped == 0);
    
    if (processed != matching_count + non_matching_count) {
        TEST_MSG("Expected processed=%d, got %llu", matching_count + non_matching_count, (unsigned long long)processed);
    }
    if (matched != matching_count) {
        TEST_MSG("Expected matched=%d, got %llu", matching_count, (unsigned long long)matched);
    }
    if (skipped != 0) {
        TEST_MSG("Expected skipped=0, got %llu", (unsigned long long)skipped);
    }

    delete_csv_file();
    test_ctx_destroy(ctx);
}
#endif

TEST_LIST = {
    {"basic_lookup", flb_test_lookup_basic},
    {"ignore_case", flb_test_lookup_ignore_case},
    {"csv_quotes", flb_test_lookup_csv_quotes},
    {"numeric_values", flb_test_lookup_numeric_values},
    {"large_numbers", flb_test_lookup_large_numbers},
    {"boolean_values", flb_test_lookup_boolean_values},
    {"no_match", flb_test_lookup_no_match},
    {"long_csv_lines", flb_test_lookup_long_csv_lines},
    {"whitespace_trim", flb_test_lookup_whitespace_trim},
    {"dynamic_buffer", flb_test_dynamic_buffer},
    {"nested_keys", flb_test_lookup_nested_keys},
    {"large_csv", flb_test_lookup_large_csv},
    {"nested_array_keys", flb_test_lookup_nested_array_keys},
#ifdef FLB_HAVE_METRICS
    {"metrics_matched", flb_test_lookup_metrics_matched},
    {"metrics_processed", flb_test_lookup_metrics_processed},
#endif
    {NULL, NULL}
};
