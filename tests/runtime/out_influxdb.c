/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_sds.h>
#include "flb_tests_runtime.h"

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_output = 0;
static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void set_output_num(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_output = num;
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_num()
{
    set_output_num(0);
}

#define JSON_BASIC "[12345678, {\"key\":\"value\"}]"
static void cb_check_basic(void *ctx, int ffd,
                           int res_ret, void *res_data, size_t res_size,
                           void *data)
{
    char *p;
    flb_sds_t out = res_data;
    char *index_line = "key=\"value\"";

    set_output_num(1);

    p = strstr(out, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out);
    }

    flb_free(out);
}

#define JSON_FLOAT "[12345678, {\"float\":1.3}]"
static void cb_check_float_value(void *ctx, int ffd,
                                 int res_ret, void *res_data, size_t res_size,
                                 void *data)
{
    char *p;
    flb_sds_t out = res_data;
    char *index_line = "float=1.3";

    set_output_num(1);

    p = strstr(out, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out);
    }

    flb_free(out);
}

#define JSON_INTEGER "[12345678, {\"int\":100}]"
static void cb_check_int_value(void *ctx, int ffd,
                               int res_ret, void *res_data, size_t res_size,
                               void *data)
{
    char *p;
    flb_sds_t out = res_data;
    char *index_line = "int=100i";

    set_output_num(1);

    p = strstr(out, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out);
    }

    flb_free(out);
}


#define JSON_NEGATIVE_INTEGER "[12345678, {\"int\":-200}]"
static void cb_check_negative_int_value(void *ctx, int ffd,
                                        int res_ret, void *res_data, size_t res_size,
                                        void *data)
{
    char *p;
    flb_sds_t out = res_data;
    char *index_line = "int=-200i";

    set_output_num(1);

    p = strstr(out, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out);
    }

    flb_free(out);
}

static void cb_check_int_as_float_value(void *ctx, int ffd,
                                        int res_ret, void *res_data, size_t res_size,
                                        void *data)
{
    char *p;
    flb_sds_t out = res_data;
    char *missing_index_line = "int=100i";
    char *index_line = "int=100";

    set_output_num(1);

    p = strstr(out, missing_index_line);
    if (!TEST_CHECK(p == NULL)) {
      TEST_MSG("Given:%s", out);
    }
    p = strstr(out, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out);
    }

    flb_free(out);
}

static void cb_check_negative_int_as_float_value(
    void *ctx, int ffd,
    int res_ret, void *res_data, size_t res_size,
    void *data)
{
    char *p;
    flb_sds_t out = res_data;
    char *missing_index_line = "int=-200i";
    char *index_line = "int=-200";

    set_output_num(1);

    p = strstr(out, missing_index_line);
    if (!TEST_CHECK(p == NULL)) {
      TEST_MSG("Given:%s", out);
    }
    p = strstr(out, index_line);
    if (!TEST_CHECK(p != NULL)) {
      TEST_MSG("Given:%s", out);
    }

    flb_free(out);
}

void flb_test_basic()
{
    int ret;
    int size = sizeof(JSON_BASIC) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_output_num();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "influxdb", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_basic,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_BASIC, size);
    TEST_CHECK(ret >= 0);

    sleep(2);

    ret = get_output_num();
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("no output");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_float_value()
{
    int ret;
    int size = sizeof(JSON_FLOAT) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_output_num();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "influxdb", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_float_value,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_FLOAT, size);
    TEST_CHECK(ret >= 0);

    sleep(2);
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Using integer type */
void flb_test_integer_value()
{
    int ret;
    int size = sizeof(JSON_INTEGER) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_output_num();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "influxdb", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "add_integer_suffix", "true",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_int_value,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_INTEGER, size);
    TEST_CHECK(ret >= 0);

    sleep(2);

    ret = get_output_num();
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("no output");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_negative_integer_value()
{
    int ret;
    int size = sizeof(JSON_NEGATIVE_INTEGER) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_output_num();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "influxdb", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "add_integer_suffix", "true",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_negative_int_value,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_NEGATIVE_INTEGER, size);
    TEST_CHECK(ret >= 0);

    sleep(2);

    ret = get_output_num();
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("no output");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Not using integer type of line protocol */
void flb_test_integer_as_float_value()
{
    int ret;
    int size = sizeof(JSON_INTEGER) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_output_num();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "influxdb", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "add_integer_suffix", "false",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_int_as_float_value,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_INTEGER, size);
    TEST_CHECK(ret >= 0);

    sleep(2);

    ret = get_output_num();
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("no output");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_negative_integer_as_float_value()
{
    int ret;
    int size = sizeof(JSON_NEGATIVE_INTEGER) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    clear_output_num();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Elasticsearch output */
    out_ffd = flb_output(ctx, (char *) "influxdb", NULL);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   "add_integer_suffix", "false",
                   NULL);

    /* Enable test mode */
    ret = flb_output_set_test(ctx, out_ffd, "formatter",
                              cb_check_negative_int_as_float_value,
                              NULL, NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx, in_ffd, (char *) JSON_NEGATIVE_INTEGER, size);
    TEST_CHECK(ret >= 0);

    sleep(2);

    ret = get_output_num();
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("no output");
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"basic"                  , flb_test_basic },
    {"float"                  , flb_test_float_value },
    {"int_integer"            , flb_test_integer_value },
    {"int_negative_integer"   , flb_test_negative_integer_value },
    {"int_integer_as_float"   , flb_test_integer_as_float_value },
    {"int_negative_integer_as_float" , flb_test_negative_integer_as_float_value },
    {NULL, NULL}
};
