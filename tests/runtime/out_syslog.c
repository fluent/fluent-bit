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
#ifdef FLB_HAVE_TLS
#include <fluent-bit/tls/flb_tls.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "flb_tests_runtime.h"

#define UTF8_BOM "\xEF\xBB\xBF"

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

struct exact_result {
    const char *expected;
    size_t expected_size;
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

static void cb_check_exact(void *ctx, int ffd, int res_ret,
                           void *res_data, size_t res_size, void *data)
{
    int num;
    struct exact_result *result = data;

    num = get_output_num();

    if (!TEST_CHECK(res_ret == 0)) {
        TEST_MSG("callback ret=%d", res_ret);
    }
    if (!TEST_CHECK(res_data != NULL)) {
        TEST_MSG("res_data is NULL");
        return;
    }
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("expected result is NULL");
        flb_sds_destroy(res_data);
        return;
    }

    if (!TEST_CHECK(res_size == result->expected_size)) {
        TEST_MSG("output size is %zu, expected %zu", res_size,
                 result->expected_size);
    }
    else if (!TEST_CHECK(memcmp(res_data, result->expected, res_size) == 0)) {
        TEST_MSG("output does not match expected wire representation");
    }

    set_output_num(num + 1);
    flb_sds_destroy(res_data);
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

static void run_exact_formatter_test(const char *input,
                                     const char *mode,
                                     const char *format,
                                     const char *framing,
                                     const char *maxsize,
                                     const char *sd_key,
                                     const char *sd_preset,
                                     const char *allow_longer_sd_id,
                                     const char *expected,
                                     size_t expected_size)
{
    int ret;
    int num;
    struct test_ctx *ctx;
    struct exact_result result;

    result.expected = expected;
    result.expected_size = expected_size;
    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "mode", mode,
                         "syslog_format", format,
                         "syslog_message_key", "msg",
                         NULL);
    TEST_CHECK(ret == 0);

    if (framing != NULL) {
        ret = flb_output_set(ctx->flb, ctx->o_ffd,
                             "syslog_framing", framing,
                             NULL);
        TEST_CHECK(ret == 0);
    }
    if (maxsize != NULL) {
        ret = flb_output_set(ctx->flb, ctx->o_ffd,
                             "syslog_maxsize", maxsize,
                             NULL);
        TEST_CHECK(ret == 0);
    }
    if (sd_key != NULL) {
        ret = flb_output_set(ctx->flb, ctx->o_ffd,
                             "syslog_sd_key", sd_key,
                             NULL);
        TEST_CHECK(ret == 0);
    }
    if (sd_preset != NULL) {
        ret = flb_output_set(ctx->flb, ctx->o_ffd,
                             "syslog_sd_preset", sd_preset,
                             NULL);
        TEST_CHECK(ret == 0);
    }
    if (allow_longer_sd_id != NULL) {
        ret = flb_output_set(ctx->flb, ctx->o_ffd,
                             "allow_longer_sd_id", allow_longer_sd_id,
                             NULL);
        TEST_CHECK(ret == 0);
    }

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                              "formatter", cb_check_exact,
                              &result, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx->flb, ctx->i_ffd,
                       (char *) input, strlen(input));
    TEST_CHECK(ret >= 0);

    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0)) {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

static void run_invalid_configuration_test(const char *mode,
                                           const char *framing)
{
    int ret;
    struct test_ctx *ctx;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "mode", mode,
                         "syslog_framing", framing,
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("expected startup failure for mode=%s, syslog_framing=%s",
                 mode, framing);
    }

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
                             "<13>1 1970-01-01T00:00:01.000000Z - - - - - " UTF8_BOM "hello world"};
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
                             "<13>1 1970-01-01T00:00:01.000000Z - - - - - " UTF8_BOM "hello world"};
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
                             "<110>1 1970-01-01T00:00:01.000000Z - - - - - " UTF8_BOM "hello world"};
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
                             "<110>1 1970-01-01T00:00:01.000000Z - - - - - " UTF8_BOM "hello world"};
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
                             "<109>1 1970-01-01T00:00:01.000000Z - - - - - " UTF8_BOM "hello world"};
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
                             "<14>1 1970-01-01T00:00:01.000000Z localhost - - - - " UTF8_BOM "hello world"};
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
                             "<14>1 1970-01-01T00:00:01.000000Z localhost - - - - " UTF8_BOM "hello world"};
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
                             "<14>1 1970-01-01T00:00:01.000000Z - fluent-bit - - - " UTF8_BOM "hello world"};
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
                             "<14>1 1970-01-01T00:00:01.000000Z - fluent-bit - - - " UTF8_BOM "hello world"};
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
                             "<14>1 1970-01-01T00:00:01.000000Z - - 1234 - - " UTF8_BOM "hello world"};
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
                             "<14>1 1970-01-01T00:00:01.000000Z - - 1234 - - " UTF8_BOM "hello world"};
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
                             "<14>1 1970-01-01T00:00:01.000000Z - - - TCPIN - " UTF8_BOM "hello world"};
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
                             "<14>1 1970-01-01T00:00:01.000000Z - - - TCPIN - " UTF8_BOM "hello world"};
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
                             "<14>1 1970-01-01T00:00:01.000000Z - - - - [sd_key logtype=\"access\" clustername=\"mycluster\" namespace=\"mynamespace\"] " UTF8_BOM "hello world"};
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
                             "<14>1 1970-01-01T00:00:01.000000Z - - - - [sd_key_that_is_longer_than_32_characters logtype_that_is_longer_than_32_characters=\"access\" clustername=\"mycluster\" namespace=\"mynamespace\"] " UTF8_BOM "hello world"};
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
                             "<14>1 1970-01-01T00:00:01.000000Z - - - - [sd_key_that_is_longer_than_32_ch logtype_that_is_longer_than_32_c=\"access\" clustername=\"mycluster\" namespace=\"mynamespace\"] " UTF8_BOM "hello world"};
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

void flb_test_octet_counting_rfc5424_multiline_utf8()
{
    static const char input[] =
        "[1, {\"msg\":\"first\\n\xE4\xB8\x96\xE7\x95\x8C\"}]";
    static const char expected[] =
        "59 <14>1 1970-01-01T00:00:01.000000Z - - - - - "
        UTF8_BOM "first\n\xE4\xB8\x96\xE7\x95\x8C";

    run_exact_formatter_test(input, "tcp", "rfc5424", "octet_counting",
                             NULL, NULL, NULL, NULL,
                             expected, sizeof(expected) - 1);
}

void flb_test_octet_counting_rfc3164_multiline_utf8()
{
    static const char input[] =
        "[1, {\"msg\":\"first\\n\xE4\xB8\x96\xE7\x95\x8C\"}]";
    static const char expected[] =
        "32 <14>Jan  1 00:00:01 first\n\xE4\xB8\x96\xE7\x95\x8C";

    run_exact_formatter_test(input, "tcp", "rfc3164", "octet_counting",
                             NULL, NULL, NULL, NULL,
                             expected, sizeof(expected) - 1);
}

void flb_test_octet_counting_after_maxsize_truncation()
{
    static const char input[] =
        "[1, {\"msg\":\"abcdefghijklmnopqrstuvwxyz\"}]";
    static const char expected[] =
        "60 <14>1 1970-01-01T00:00:01.000000Z - - - - - "
        UTF8_BOM "abcdefghijklm";

    run_exact_formatter_test(input, "tcp", "rfc5424", "octet_counting",
                             "60", NULL, NULL, NULL,
                             expected, sizeof(expected) - 1);
}

void flb_test_default_newline_framing_tcp()
{
    static const char input[] = "[1, {\"msg\":\"hello world\"}]";
    static const char expected[] =
        "<14>1 1970-01-01T00:00:01.000000Z - - - - - "
        UTF8_BOM "hello world\n";

    run_exact_formatter_test(input, "tcp", "rfc5424", NULL, NULL,
                             NULL, NULL, NULL, expected, sizeof(expected) - 1);
}

void flb_test_explicit_newline_framing_tcp()
{
    static const char input[] = "[1, {\"msg\":\"hello world\"}]";
    static const char expected[] =
        "<14>1 1970-01-01T00:00:01.000000Z - - - - - "
        UTF8_BOM "hello world\n";

    run_exact_formatter_test(input, "tcp", "rfc5424", "newline", NULL,
                             NULL, NULL, NULL, expected, sizeof(expected) - 1);
}

void flb_test_newline_framing_udp_preserves_datagram()
{
    static const char input[] = "[1, {\"msg\":\"hello world\"}]";
    static const char expected[] =
        "<14>1 1970-01-01T00:00:01.000000Z - - - - - "
        UTF8_BOM "hello world";

    run_exact_formatter_test(input, "udp", "rfc5424", "newline", NULL,
                             NULL, NULL, NULL, expected, sizeof(expected) - 1);
}

void flb_test_invalid_syslog_framing_rejected()
{
    run_invalid_configuration_test("tcp", "invalid");
}

void flb_test_octet_counting_datagram_modes_rejected()
{
    run_invalid_configuration_test("udp", "octet_counting");
    run_invalid_configuration_test("dtls", "octet_counting");
}

void flb_test_sd_preset_rfc5424_fallback()
{
    static const char input[] = "[1, {\"msg\":\"hello\"}]";
    static const char expected[] =
        "<14>1 1970-01-01T00:00:01.000000Z - - - - "
        "[preset@1 source=\"preset\"] " UTF8_BOM "hello";

    run_exact_formatter_test(input, "udp", "rfc5424", NULL, NULL, NULL,
                             "[preset@1 source=\"preset\"]",
                             NULL,
                             expected, sizeof(expected) - 1);
}

void flb_test_sd_record_precedes_preset_rfc5424()
{
    static const char input[] =
        "[1, {\"msg\":\"hello\", \"sd_key\": {\"source\":\"record\"}}]";
    static const char expected[] =
        "<14>1 1970-01-01T00:00:01.000000Z - - - - "
        "[sd_key source=\"record\"] " UTF8_BOM "hello";

    run_exact_formatter_test(input, "udp", "rfc5424", NULL, NULL, "sd_key",
                             "[preset@1 source=\"preset\"]",
                             NULL,
                             expected, sizeof(expected) - 1);
}

void flb_test_sd_preset_ignored_rfc3164()
{
    static const char input[] = "[1, {\"msg\":\"hello\"}]";
    static const char expected[] = "<14>Jan  1 00:00:01 hello";

    run_exact_formatter_test(input, "udp", "rfc3164", NULL, NULL, NULL,
                             "[meta bad=\"unescaped]value\"]",
                             NULL,
                             expected, sizeof(expected) - 1);
}

void flb_test_sd_preset_allow_longer_id_rfc5424()
{
    static const char input[] = "[1, {\"msg\":\"hello\"}]";
    static const char expected[] =
        "<14>1 1970-01-01T00:00:01.000000Z - - - - "
        "[abcdefghijklmnopqrstuvwxyz1234567 source=\"preset\"] "
        UTF8_BOM "hello";

    run_exact_formatter_test(
        input, "udp", "rfc5424", NULL, NULL, NULL,
        "[abcdefghijklmnopqrstuvwxyz1234567 source=\"preset\"]", "true",
        expected, sizeof(expected) - 1);
}

void flb_test_malformed_sd_preset_rfc5424_rejected()
{
    int ret;
    size_t index;
    struct test_ctx *ctx;
    static const char *presets[] = {
        "[meta",
        "[meta bad=\"value]",
        "[meta bad=\"value\\",
        "[meta bad=\"value\\q\"]",
        "[meta bad=\"unescaped]value\"]",
        "[abcdefghijklmnopqrstuvwxyz1234567]"
    };

    for (index = 0; index < sizeof(presets) / sizeof(presets[0]); index++) {
        ctx = test_ctx_create();
        if (!TEST_CHECK(ctx != NULL)) {
            TEST_MSG("test_ctx_create failed");
            exit(EXIT_FAILURE);
        }

        ret = flb_output_set(ctx->flb, ctx->o_ffd,
                             "match", "*",
                             "syslog_format", "rfc5424",
                             "syslog_sd_preset", presets[index],
                             NULL);
        TEST_CHECK(ret == 0);

        ret = flb_start(ctx->flb);
        if (!TEST_CHECK(ret != 0)) {
            TEST_MSG("expected startup failure for malformed syslog_sd_preset: %s",
                     presets[index]);
        }

        flb_destroy(ctx->flb);
        flb_free(ctx);
    }
}

void flb_test_valid_sd_preset_boundaries_rfc5424()
{
    static const char input[] = "[1, {\"msg\":\"hello\"}]";
    static const char unset_expected[] =
        "<14>1 1970-01-01T00:00:01.000000Z - - - - - " UTF8_BOM "hello";
    static const char elements[] =
        "[meta a=\"quote\\\" slash\\\\ bracket\\]\"][next x=\"y\"]";
    static const char elements_expected[] =
        "<14>1 1970-01-01T00:00:01.000000Z - - - - "
        "[meta a=\"quote\\\" slash\\\\ bracket\\]\"][next x=\"y\"] "
        UTF8_BOM "hello";

    run_exact_formatter_test(input, "udp", "rfc5424", NULL, NULL, NULL,
                             "", NULL,
                             unset_expected, sizeof(unset_expected) - 1);
    run_exact_formatter_test(input, "udp", "rfc5424", NULL, NULL, NULL,
                             "-", NULL,
                             unset_expected, sizeof(unset_expected) - 1);
    run_exact_formatter_test(input, "udp", "rfc5424", NULL, NULL, NULL,
                             elements, NULL,
                             elements_expected, sizeof(elements_expected) - 1);
}

void flb_test_udp_mode_rejects_tls()
{
    struct test_ctx *ctx;
    int ret;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "mode", "udp",
                         "tls", "on",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("expected startup failure for mode=udp with tls=on");
    }

    /* flb_start failed, so there is no running engine to stop. */
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

#ifdef FLB_HAVE_TLS
static void test_secure_mode_enables_tls(const char *mode, int tls_mode)
{
    struct test_ctx *ctx;
    struct flb_output_instance *ins;
    int ret;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "mode", mode,
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    if (!TEST_CHECK(ret == 0)) {
        flb_destroy(ctx->flb);
        flb_free(ctx);
        return;
    }

    ins = flb_output_get_instance(ctx->flb->config, ctx->o_ffd);
    TEST_CHECK(ins != NULL);
    if (ins != NULL) {
        TEST_CHECK(ins->use_tls == FLB_TRUE);
        TEST_CHECK(ins->tls != NULL);
        if (ins->tls != NULL) {
            TEST_CHECK(ins->tls->mode == tls_mode);
        }
    }

    test_ctx_destroy(ctx);
}

void flb_test_tls_mode_enables_tls()
{
    test_secure_mode_enables_tls("tls", FLB_TLS_CLIENT_MODE);
}

void flb_test_dtls_mode_enables_tls()
{
    test_secure_mode_enables_tls("dtls", FLB_TLS_CLIENT_MODE_DGRAM);
}
#endif

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
    {"octet_counting_rfc5424_multiline_utf8",
     flb_test_octet_counting_rfc5424_multiline_utf8},
    {"octet_counting_rfc3164_multiline_utf8",
     flb_test_octet_counting_rfc3164_multiline_utf8},
    {"octet_counting_after_maxsize_truncation",
     flb_test_octet_counting_after_maxsize_truncation},
    {"default_newline_framing_tcp", flb_test_default_newline_framing_tcp},
    {"explicit_newline_framing_tcp", flb_test_explicit_newline_framing_tcp},
    {"newline_framing_udp_preserves_datagram",
     flb_test_newline_framing_udp_preserves_datagram},
    {"invalid_syslog_framing_rejected", flb_test_invalid_syslog_framing_rejected},
    {"octet_counting_datagram_modes_rejected",
     flb_test_octet_counting_datagram_modes_rejected},
    {"sd_preset_rfc5424_fallback", flb_test_sd_preset_rfc5424_fallback},
    {"sd_record_precedes_preset_rfc5424",
     flb_test_sd_record_precedes_preset_rfc5424},
    {"sd_preset_ignored_rfc3164", flb_test_sd_preset_ignored_rfc3164},
    {"sd_preset_allow_longer_id_rfc5424",
     flb_test_sd_preset_allow_longer_id_rfc5424},
    {"malformed_sd_preset_rfc5424_rejected",
     flb_test_malformed_sd_preset_rfc5424_rejected},
    {"valid_sd_preset_boundaries_rfc5424",
     flb_test_valid_sd_preset_boundaries_rfc5424},
    {"udp_mode_rejects_tls", flb_test_udp_mode_rejects_tls},
#ifdef FLB_HAVE_TLS
    {"tls_mode_enables_tls", flb_test_tls_mode_enables_tls},
    {"dtls_mode_enables_tls", flb_test_dtls_mode_enables_tls},
#endif
    {NULL, NULL}
};
