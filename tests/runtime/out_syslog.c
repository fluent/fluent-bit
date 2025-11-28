/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "flb_tests_runtime.h"

struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd (unused) */
    int o_ffd;         /* Output fd */
};


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

struct str_list {
    size_t size;
    char **lists;
};

/* Callback to check expected results */
static void cb_check_str_list(void *ctx, int ffd, int res_ret, 
                              void *res_data, size_t res_size, void *data)
{
    char *p;
    flb_sds_t out_line = res_data;
    int num = get_output_num();
    size_t i;
    struct str_list *l = (struct str_list *)data;

    if (!TEST_CHECK(res_data != NULL)) {
        TEST_MSG("res_data is NULL");
        return;
    }

    if (!TEST_CHECK(l != NULL)) {
        TEST_MSG("l is NULL");
        flb_sds_destroy(out_line);
        return;
    }

    if(!TEST_CHECK(res_ret == 0)) {
        TEST_MSG("callback ret=%d", res_ret);
    }
    if (!TEST_CHECK(res_data != NULL)) {
        TEST_MSG("res_data is NULL");
        flb_sds_destroy(out_line);
        return;
    }

    for (i=0; i<l->size; i++) {
        p = strstr(out_line, l->lists[i]);
        if (!TEST_CHECK(p != NULL)) {
            TEST_MSG("  Got   :%s\n  expect:%s", out_line, l->lists[i]);
        }
    }
    set_output_num(num+1);

    flb_sds_destroy(out_line);
}

static struct test_ctx *test_ctx_create()
{
    int i_ffd;
    int o_ffd;
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
    ctx->i_ffd = i_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "syslog", NULL);
    ctx->o_ffd = o_ffd;

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    TEST_CHECK(ctx != NULL);

    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void flb_test_syslog_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_severity_key_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"s_key\":\"5\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "<13>" /* 1(user-level messages) * 8 + 5(severity) */,
                             "<13>1 1970-01-01T00:00:01.000000Z - - - - - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_severity_key", "s_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}


void flb_test_severity_preset_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"s_key\":\"5\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "<13>" /* 1(user-level messages) * 8 + 5(severity) */,
                             "<13>1 1970-01-01T00:00:01.000000Z - - - - - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_severity_preset", "5",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_severity_key_rfc3164()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"s_key\":\"5\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "Jan  1 00:00:01", "<13>" /* 1(user-level messages) * 8 + 5(severity) */,
                             "<13>Jan  1 00:00:01 hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc3164",
                         "syslog_message_key", "msg",
                         "syslog_severity_key", "s_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_severity_preset_rfc3164()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"s_key\":\"5\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "Jan  1 00:00:01", "<13>" /* 1(user-level messages) * 8 + 5(severity) */,
                             "<13>Jan  1 00:00:01 hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc3164",
                         "syslog_message_key", "msg",
                         "syslog_severity_preset", "5",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_facility_key_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"f_key\":\"13\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "<110>" /* 13(log audit) * 8 + 6(default severity) */,
                             "<110>1 1970-01-01T00:00:01.000000Z - - - - - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_facility_key", "f_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_facility_preset_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"f_key\":\"13\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "<110>" /* 13(log audit) * 8 + 6(default severity) */,
                             "<110>1 1970-01-01T00:00:01.000000Z - - - - - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_facility_preset", "13",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_facility_key_rfc3164()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"f_key\":\"13\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "Jan  1 00:00:01", "<110>" /* 13(log audit) * 8 + 6(default severity) */,
                             "<110>Jan  1 00:00:01 hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc3164",
                         "syslog_message_key", "msg",
                         "syslog_facility_key", "f_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_facility_preset_rfc3164()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"f_key\":\"13\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "Jan  1 00:00:01", "<110>" /* 13(log audit) * 8 + 6(default severity) */,
                             "<110>Jan  1 00:00:01 hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc3164",
                         "syslog_message_key", "msg",
                         "syslog_facility_preset", "13",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_severity_facility_key_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"f_key\":\"13\", \"s_key\":\"5\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "<109>" /* 13(log audit) * 8 + 5(severity) */,
                             "<109>1 1970-01-01T00:00:01.000000Z - - - - - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_severity_key", "s_key",
                         "syslog_facility_key", "f_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_severity_facility_key_rfc3164()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"f_key\":\"13\", \"s_key\":\"5\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "Jan  1 00:00:01", "<109>" /* 13(log audit) * 8 + 5(severity) */,
                             "<109>Jan  1 00:00:01 hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc3164",
                         "syslog_message_key", "msg",
                         "syslog_severity_key", "s_key",
                         "syslog_facility_key", "f_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_hostname_key_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"h_key\":\"localhost\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "localhost",
                             "<14>1 1970-01-01T00:00:01.000000Z localhost - - - - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_hostname_key", "h_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_hostname_preset_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"h_key\":\"localhost\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "localhost",
                             "<14>1 1970-01-01T00:00:01.000000Z localhost - - - - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_hostname_preset", "localhost",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_hostname_key_rfc3164()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"h_key\":\"localhost\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "Jan  1 00:00:01", "localhost",
                             "<14>Jan  1 00:00:01 localhost hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc3164",
                         "syslog_message_key", "msg",
                         "syslog_hostname_key", "h_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_hostname_preset_rfc3164()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"h_key\":\"localhost\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "Jan  1 00:00:01", "localhost",
                             "<14>Jan  1 00:00:01 localhost hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc3164",
                         "syslog_message_key", "msg",
                         "syslog_hostname_preset", "localhost",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_appname_key_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"a_key\":\"fluent-bit\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "fluent-bit",
                             "<14>1 1970-01-01T00:00:01.000000Z - fluent-bit - - - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_appname_key", "a_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_appname_preset_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"a_key\":\"fluent-bit\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "fluent-bit",
                             "<14>1 1970-01-01T00:00:01.000000Z - fluent-bit - - - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_appname_preset", "fluent-bit",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_appname_key_rfc3164()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"a_key\":\"fluent-bit\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "Jan  1 00:00:01", "fluent-bit",
                             "<14>Jan  1 00:00:01 fluent-bit: hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc3164",
                         "syslog_message_key", "msg",
                         "syslog_appname_key", "a_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_appname_preset_rfc3164()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"a_key\":\"fluent-bit\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "Jan  1 00:00:01", "fluent-bit",
                             "<14>Jan  1 00:00:01 fluent-bit: hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc3164",
                         "syslog_message_key", "msg",
                         "syslog_appname_preset", "fluent-bit",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_procid_key_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"p_key\":\"1234\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "1234",
                             "<14>1 1970-01-01T00:00:01.000000Z - - 1234 - - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_procid_key", "p_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_procid_preset_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"p_key\":\"1234\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "1234",
                             "<14>1 1970-01-01T00:00:01.000000Z - - 1234 - - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_procid_preset", "1234",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_msgid_key_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"m_key\":\"TCPIN\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "TCPIN",
                             "<14>1 1970-01-01T00:00:01.000000Z - - - TCPIN - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_msgid_key", "m_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_msgid_preset_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"m_key\":\"TCPIN\"}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z", "TCPIN",
                             "<14>1 1970-01-01T00:00:01.000000Z - - - TCPIN - ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_msgid_preset", "TCPIN",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_sd_key_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"sd_key\": {\"logtype\": \"access\",\"clustername\": \"mycluster\",\"namespace\": \"mynamespace\"}}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z",
                             "<14>1 1970-01-01T00:00:01.000000Z - - - - [sd_key logtype=\"access\" clustername=\"mycluster\" namespace=\"mynamespace\"] ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_sd_key", "sd_key",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_allow_longer_sd_id_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"sd_key_that_is_longer_than_32_characters\": {\"logtype_that_is_longer_than_32_characters\": \"access\",\"clustername\": \"mycluster\",\"namespace\": \"mynamespace\"}}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z",
                             "<14>1 1970-01-01T00:00:01.000000Z - - - - [sd_key_that_is_longer_than_32_characters logtype_that_is_longer_than_32_characters=\"access\" clustername=\"mycluster\" namespace=\"mynamespace\"] ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_sd_key", "sd_key_that_is_longer_than_32_characters",
                         "allow_longer_sd_id", "true",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_malformed_longer_sd_id_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"msg\":\"hello world\", \"sd_key_that_is_longer_than_32_characters\": {\"logtype_that_is_longer_than_32_characters\": \"access\",\"clustername\": \"mycluster\",\"namespace\": \"mynamespace\"}}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z",
                             "<14>1 1970-01-01T00:00:01.000000Z - - - - [sd_key_that_is_longer_than_32_ch logtype_that_is_longer_than_32_c=\"access\" clustername=\"mycluster\" namespace=\"mynamespace\"] ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "msg",
                         "syslog_sd_key", "sd_key_that_is_longer_than_32_characters",
                         "allow_longer_sd_id", "false",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_nested_keys_rfc5424()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf = "[1, {\"log.appname\":\"fluent-bit\", \"p_key\":\"1234\", \"nested_values\": {\"msg\":\"hello world\", \"hostname.key\":\"localhost\", \"sd_key\": {\"logtype\": \"access\",\"clustername\": \"mycluster\",\"namespace\": \"mynamespace\"}}}]";
    size_t size = strlen(buf);

    char *expected_strs[] = {"hello world", "1970-01-01T00:00:01.000000Z",
                             "<14>1 1970-01-01T00:00:01.000000Z localhost fluent-bit 1234 - [nested_values.sd_key logtype=\"access\" clustername=\"mycluster\" namespace=\"mynamespace\"] ﻿hello world"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "syslog_format", "rfc5424",
                         "syslog_message_key", "$nested_values['msg']",
                         "syslog_sd_key", "$nested_values['sd_key']",
                         "syslog_appname_key", "log.appname",
                         "syslog_procid_key", "$p_key",
                         "syslog_hostname_key", "$nested_values['hostname.key']",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_str_list,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

TEST_LIST = {
    /* rfc3164 */
    /* procid_key, msgid_key, sd_key are not supported */
    {"format_severity_key_rfc3164", flb_test_severity_key_rfc3164},
    {"format_facility_key_rfc3164", flb_test_facility_key_rfc3164},
    {"format_severity_facility_key_rfc3164", flb_test_severity_facility_key_rfc3164},
    {"format_hostname_key_rfc3164", flb_test_hostname_key_rfc3164},
    {"format_appname_key_rfc3164", flb_test_appname_key_rfc3164},
    {"format_severity_preset_rfc3164", flb_test_severity_preset_rfc3164},
    {"format_facility_preset_rfc3164", flb_test_facility_preset_rfc5424},
    {"format_hostname_preset_rfc3164", flb_test_hostname_preset_rfc5424},
    {"format_appname_preset_rfc3164", flb_test_appname_preset_rfc3164},

    /* rfc5424 (Default) */
    {"format_syslog_rfc5424", flb_test_syslog_rfc5424},
    {"format_severity_key_rfc5424", flb_test_severity_key_rfc5424},
    {"format_facility_key_rfc5424", flb_test_facility_key_rfc5424},
    {"format_severity_facility_key_rfc5424", flb_test_severity_facility_key_rfc5424},
    {"format_hostname_key_rfc5424", flb_test_hostname_key_rfc5424},
    {"format_appname_key_rfc5424", flb_test_appname_key_rfc5424},
    {"format_procid_key_rfc5424", flb_test_procid_key_rfc5424},
    {"format_msgid_key_rfc5424", flb_test_msgid_key_rfc5424},
    {"format_sd_key_rfc5424", flb_test_sd_key_rfc5424},
    {"format_severity_preset_rfc5424", flb_test_severity_preset_rfc5424},
    {"format_facility_preset_rfc5424", flb_test_facility_preset_rfc5424},
    {"format_hostname_preset_rfc5424", flb_test_hostname_preset_rfc5424},
    {"format_appname_preset_rfc5424", flb_test_appname_preset_rfc5424},
    {"format_procid_preset_rfc5424", flb_test_procid_preset_rfc5424},
    {"format_msgid_preset_rfc5424", flb_test_msgid_preset_rfc5424},
    {"allow_longer_sd_id_rfc5424", flb_test_allow_longer_sd_id_rfc5424},
    {"malformed_longer_sd_id_rfc5424", flb_test_malformed_longer_sd_id_rfc5424},
    {"nested_values_rfc5424", flb_test_nested_keys_rfc5424},
    {NULL, NULL}
};

