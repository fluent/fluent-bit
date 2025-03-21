/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include "flb_tests_runtime.h"

#define JSON_TEST_DATA "[12345678, {\"numstr\":\"123.456\", \"int\":123, \"float\":123.456, \"hexstr\":\"0xff\"}]"
#define JSON_NEST_DATA "[12345678, {\"nest\":{\"numstr\":\"123.456\", \"float\":123.456}}]"

struct filter_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
};

/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    char *expected;
    char *result;

    expected = (char *) data;
    result = (char *) record;

    p = strstr(result, expected);
    TEST_CHECK(p != NULL);

    if (p==NULL) {
        flb_error("Expected to find: '%s' in result '%s'",
                  expected, result);
    }
    /*
     * If you want to debug your test
     *
     * printf("Expect: '%s' in result '%s'", expected, result);
     */
    flb_free(record);
    return 0;
}

static struct filter_test *filter_test_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int f_ffd;
    int o_ffd;
    struct filter_test *ctx;

    ctx = flb_malloc(sizeof(struct filter_test));
    if (!ctx) {
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

    /* Filter configuration */
    f_ffd = flb_filter(ctx->flb, (char *) "type_converter", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "*", NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test",
                   "format", "json",
                   NULL);

    return ctx;
}

static void filter_test_destroy(struct filter_test *ctx)
{
    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void flb_test_str_to_int()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int len;
    int ret;
    int bytes;
    char *p = JSON_TEST_DATA;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"new\":123";

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create context");
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "str_key", "numstr new int",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

void flb_test_str_to_hex()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int len;
    int ret;
    int bytes;
    char *p = JSON_TEST_DATA;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"new\":255";

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create context");
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "str_key", "hexstr new hex",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

void flb_test_str_to_float()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int len;
    int ret;
    int bytes;
    char *p = JSON_TEST_DATA;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"new\":123.456";

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create context");
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "str_key", "numstr new float",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

void flb_test_int_to_str()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int len;
    int ret;
    int bytes;
    char *p = JSON_TEST_DATA;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"new\":\"123\"";

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create context");
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "int_key", "int new str",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

void flb_test_int_to_float()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int len;
    int ret;
    int bytes;
    char *p = JSON_TEST_DATA;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"new\":123.";

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create context");
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "int_key", "int new float",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

void flb_test_str_to_int_and_int_to_str()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int len;
    int ret;
    int bytes;
    char *p = JSON_TEST_DATA;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"new1\":123,\"new2\":\"123\"";

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create context");
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "str_key", "numstr new1 int",
                         "int_key", "int new2 str",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

void flb_test_nest_key()
{
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    int len;
    int ret;
    int bytes;
    char *p = JSON_NEST_DATA;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = "\"new\":123";

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("failed to create context");
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "str_key", "$nest['numstr'] new int",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"str_to_int"        , flb_test_str_to_int },
    {"str_to_float"      , flb_test_str_to_float },
    {"str_to_hex"        , flb_test_str_to_hex },
    {"int_to_str"        , flb_test_int_to_str },
    {"int_to_float"      , flb_test_int_to_float },
    {"str<->int"         , flb_test_str_to_int_and_int_to_str },
    {"nest_key"          , flb_test_nest_key},
    {NULL, NULL}
};
