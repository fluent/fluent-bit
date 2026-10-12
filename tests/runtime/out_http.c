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

#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <fluent-bit.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_network.h>
#include <float.h>
#include <math.h>
#include <msgpack.h>
#include "flb_tests_runtime.h"

struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd (unused) */
    int o_ffd;         /* Output fd */
};


pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_output = 0;
static const char *callback_error = NULL;

static int get_output_num()
{
    int ret;

    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static void increment_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output++;
    pthread_mutex_unlock(&result_mutex);
}

static void add_output_num(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_output += num;
    pthread_mutex_unlock(&result_mutex);
}

static void set_callback_error(const char *message)
{
    pthread_mutex_lock(&result_mutex);
    if (callback_error == NULL) {
        callback_error = message;
    }
    pthread_mutex_unlock(&result_mutex);
}

static void clear_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output = 0;
    callback_error = NULL;
    pthread_mutex_unlock(&result_mutex);
}

static void check_callback_error()
{
    const char *message;

    pthread_mutex_lock(&result_mutex);
    message = callback_error;
    pthread_mutex_unlock(&result_mutex);

    if (!TEST_CHECK(message == NULL)) {
        TEST_MSG("%s", message);
    }
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
    size_t i;
    struct str_list *l = (struct str_list *)data;

    if (res_data == NULL) {
        set_callback_error("formatter returned no output");
        return;
    }

    if (l == NULL) {
        set_callback_error("formatter callback data is NULL");
        flb_sds_destroy(out_line);
        return;
    }

    if (res_ret != 0) {
        set_callback_error("formatter returned an error");
    }

    for (i = 0; i < l->size; i++) {
        p = strstr(out_line, l->lists[i]);
        if (p == NULL) {
            set_callback_error("formatter output did not contain an expected string");
        }
    }

    increment_output_num();
    flb_sds_destroy(out_line);
}

static int msgpack_strncmp(char* str, size_t str_len, msgpack_object obj)
{
    int ret = -1;

    if (str == NULL) {
        flb_error("str is NULL");
        return -1;
    }

    switch (obj.type)  {
    case MSGPACK_OBJECT_STR:
        if (obj.via.str.size != str_len) {
            return -1;
        }
        ret = strncmp(str, obj.via.str.ptr, str_len);
        break;
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        {
            unsigned long val = strtoul(str, NULL, 10);
            if (val == (unsigned long)obj.via.u64) {
                ret = 0;
            }
        }
        break;
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        {
            long long val = strtoll(str, NULL, 10);
            if (val == obj.via.i64) {
                ret = 0;
            }
        }
        break;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        {
            double val = strtod(str, NULL);
            if (fabs(val - obj.via.f64) < DBL_EPSILON) {
                ret = 0;
            }
        }
        break;
    case MSGPACK_OBJECT_BOOLEAN:
        if (obj.via.boolean) {
            if (str_len != 4 /*true*/) {
                return -1;
            }
            ret = strncasecmp(str, "true", 4);
        }
        else {
            if (str_len != 5 /*false*/) {
                return -1;
            }
            ret = strncasecmp(str, "false", 5);
        }
        break;
    default:
        flb_error("not supported");
    }

    return ret;
}

/* Callback to check expected results */
static void cb_check_msgpack_kv(void *ctx, int ffd, int res_ret,
                                void *res_data, size_t res_size, void *data)
{
    msgpack_unpacked result;
    msgpack_object obj;
    size_t off = 0;
    struct str_list *l = (struct str_list *)data;
    int i_map;
    int map_size;
    int i_list;
    int matches = 0;
    msgpack_unpack_return unpack_result = MSGPACK_UNPACK_CONTINUE;

    if (res_data == NULL) {
        set_callback_error("formatter returned no output");
        return;
    }

    if (data == NULL) {
        set_callback_error("formatter callback data is NULL");
        return;
    }

    if (res_ret != 0) {
        set_callback_error("formatter returned an error");
    }

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (off < res_size) {
        unpack_result = msgpack_unpack_next(&result, res_data, res_size, &off);
        if (unpack_result != MSGPACK_UNPACK_SUCCESS) {
            break;
        }

        obj = result.data;
        /*
        msgpack_object_print(stdout, obj);
        */
        if (obj.type != MSGPACK_OBJECT_ARRAY || obj.via.array.size != 2) {
            set_callback_error("formatter output contained an invalid record");
            continue;
        }
        obj = obj.via.array.ptr[1];
        if (obj.type != MSGPACK_OBJECT_MAP) {
            set_callback_error("formatter output record was not a map");
            continue;
        }
        map_size = obj.via.map.size;
        for (i_map=0; i_map<map_size; i_map++) {
            if (obj.via.map.ptr[i_map].key.type != MSGPACK_OBJECT_STR) {
                set_callback_error("formatter output map key was not a string");
                continue;
            }
            for (i_list=0; i_list< l->size/2; i_list++)  {
                if (msgpack_strncmp(l->lists[i_list*2], strlen(l->lists[i_list*2]),
                                    obj.via.map.ptr[i_map].key) == 0 &&
                    msgpack_strncmp(l->lists[i_list*2+1], strlen(l->lists[i_list*2+1]),
                                    obj.via.map.ptr[i_map].val) == 0) {
                    matches++;
                }
            }
        }
    }

    if (unpack_result == MSGPACK_UNPACK_PARSE_ERROR) {
        set_callback_error("formatter output contained invalid MessagePack");
    }
    else if (unpack_result == MSGPACK_UNPACK_NOMEM_ERROR) {
        set_callback_error("could not unpack formatter output");
    }
    else if (unpack_result == MSGPACK_UNPACK_CONTINUE && res_size != 0) {
        set_callback_error("formatter output contained incomplete MessagePack");
    }
    else if (unpack_result != MSGPACK_UNPACK_SUCCESS &&
             unpack_result != MSGPACK_UNPACK_CONTINUE) {
        set_callback_error("formatter output returned an unexpected unpack result");
    }
    else {
        add_output_num(matches);
    }

    msgpack_unpacked_destroy(&result);
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
    o_ffd = flb_output(ctx->flb, (char *) "http", NULL);
    ctx->o_ffd = o_ffd;

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    TEST_CHECK(ctx != NULL);

    sleep(1);
    flb_stop(ctx->flb);
    check_callback_error();
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void flb_test_format_msgpack()
{
    int attempts;
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf1 = "[1, {\"msg\":\"hello world\", \"val\":1000, \"nval\":-10000, \"bool\":true, \"float\":1.234}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"msg", "hello world", "val", "1000", "nval", "-10000", "bool", "true", "float", "1.234"};
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
                         "format", "msgpack",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set_test(ctx->flb, ctx->o_ffd,
                         "formatter", cb_check_msgpack_kv,
                          &expected, NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    for (attempts = 0; attempts < 50; attempts++) {
        if (get_output_num() == expected.size / 2) {
            break;
        }
        flb_time_msleep(100);
    }

    num = get_output_num();
    if (!TEST_CHECK(num == expected.size / 2))  {
        TEST_MSG("got %d, expected %lu", num, expected.size/2);
    }

    test_ctx_destroy(ctx);
}

void flb_test_format_json()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    /*
     * Both records in one push: in_lib appends them together, so a flush
     * cannot split them across formatter calls.
     */
    char *buf1 = "[1, {\"msg\":\"hello world\"}]"
                 "[2, {\"msg\":\"hello world\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"[{\"date\":1.0,\"msg\":\"hello world\"},{\"date\":2.0,\"msg\":\"hello world\"}]"};
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
                         "format", "json",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_format_json_stream()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    /*
     * Both records in one push: in_lib appends them together, so a flush
     * cannot split them across formatter calls.
     */
    char *buf1 = "[1, {\"msg\":\"hello world\"}]"
                 "[2, {\"msg\":\"hello world\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"{\"date\":1.0,\"msg\":\"hello world\"}{\"date\":2.0,\"msg\":\"hello world\"}"};
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
                         "format", "json_stream",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_format_json_lines()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    /*
     * Both records in one push: in_lib appends them together, so a flush
     * cannot split them across formatter calls.
     */
    char *buf1 = "[1, {\"msg\":\"hello world\"}]"
                 "[2, {\"msg\":\"hello world\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"{\"date\":1.0,\"msg\":\"hello world\"}\n{\"date\":2.0,\"msg\":\"hello world\"}"};
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
                         "format", "json_lines",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_format_gelf()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf1 = "[1, {\"msg\":\"hello world\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"\"short_message\":\"hello world\"", "\"timestamp\":1.000"};
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
                         "format", "gelf",
                         "gelf_short_message_key", "msg",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}


void flb_test_format_gelf_host_key()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf1 = "[1, {\"msg\":\"hello world\", \"h_key\":\"localhost\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"\"short_message\":\"hello world\"", "\"timestamp\":1.000", "\"host\":\"localhost\""};
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
                         "format", "gelf",
                         "gelf_short_message_key", "msg",
                         "gelf_host_key", "h_key",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_format_gelf_timestamp_key()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf1 = "[1, {\"msg\":\"hello world\", \"t_key\":\"2018-05-30T09:39:52.000681Z\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"\"short_message\":\"hello world\"", "\"timestamp\":\"2018-05-30T09:39:52.000681Z\""};
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
                         "format", "gelf",
                         "gelf_short_message_key", "msg",
                         "gelf_timestamp_key", "t_key",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_format_gelf_full_message_key()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf1 = "[1, {\"msg\":\"hello world\", \"f_msg\":\"full message\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"\"short_message\":\"hello world\"", "\"timestamp\":1.000","\"full_message\":\"full message\""};
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
                         "format", "gelf",
                         "gelf_short_message_key", "msg",
                         "gelf_full_message_key", "f_msg",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_format_gelf_level_key()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf1 = "[1, {\"msg\":\"hello world\", \"l_msg\":6\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"\"short_message\":\"hello world\"", "\"timestamp\":1.000","\"level\":6"};
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
                         "format", "gelf",
                         "gelf_short_message_key", "msg",
                         "gelf_level_key", "l_msg",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_set_json_date_key()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf1 = "[1, {\"msg\":\"hello world\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"{\"timestamp\":1.0,\"msg\":\"hello world\"}"};
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
                         "format", "json",
                         "json_date_key", "timestamp",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_disable_json_date_key()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf1 = "[1, {\"msg\":\"hello world\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"{\"msg\":\"hello world\"}"};
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
                         "format", "json",
                         "json_date_key", "false",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_json_date_format_epoch()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf1 = "[1, {\"msg\":\"hello world\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"{\"date\":1,\"msg\":\"hello world\"}"};
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
                         "format", "json",
                         "json_date_format", "epoch",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_json_date_format_iso8601()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf1 = "[1, {\"msg\":\"hello world\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"\"msg\":\"hello world\"", "\"date\":\"1970-01-01T00:00:01.000000Z\""};
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
                         "format", "json",
                         "json_date_format", "iso8601",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

void flb_test_json_date_format_java_sql_timestamp()
{
    struct test_ctx *ctx;
    int ret;
    int num;

    char *buf1 = "[1, {\"msg\":\"hello world\"}]";
    size_t size1 = strlen(buf1);

    char *expected_strs[] = {"\"msg\":\"hello world\"", "\"date\":\"1970-01-01 00:00:01.000000\""};
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
                         "format", "json",
                         "json_date_format", "java_sql_timestamp",
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
    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf1, size1);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    flb_time_msleep(500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

int callback_test(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        increment_output_num();
    }
    return 0;
}

/* test to make sure out_http is always able to work with in_http by default. */
void flb_test_in_http()
{
    struct test_ctx *ctx;
    int ret;
    int num;
    int i_ffd;
    int o_ffd;
    int trys;
    struct flb_lib_out_cb cb;
    char *buf = "[1, {\"msg\":\"hello world\"}]";
    size_t size = strlen(buf);
    const char *port;

    port = getenv("FLB_TEST_HTTP_PORT");
    if (!port) {
        port = "8888";
    }

    cb.cb   = callback_test;
    cb.data = NULL;
    clear_output_num();


    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb,
                        ctx->i_ffd,
                        "tag", "lib",
                        NULL);
    TEST_CHECK(ret == 0);

    /* Input */
    i_ffd = flb_input(ctx->flb, (char *) "http", NULL);
    TEST_CHECK(i_ffd >= 0);

    ret = flb_input_set(ctx->flb,
                        i_ffd,
                        "port", port,
                        "tag", "http",
                        "host", "127.0.0.1",
                        NULL);
    TEST_CHECK(ret == 0);

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", &cb);
    TEST_CHECK(o_ffd >= 0);
    ret = flb_output_set(ctx->flb,
                         o_ffd,
                         "match", "http",
                         NULL);
    TEST_CHECK(ret == 0);

    /* explicitly do not set anything beyond match, port and localhost
     * to be sure the default options work with in_http.
     */
    ret = flb_output_set(ctx->flb,
                         ctx->o_ffd,
                         "match", "lib",
                         "host", "127.0.0.1",
                         "port", port,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engines */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    ret = flb_lib_push(ctx->flb,
                       ctx->i_ffd,
                       (char *) buf,
                       size);
    TEST_CHECK(ret >= 0);

    /* try several times to detect the record being flushed. */
    for (trys = 0, num = 0; trys < 20 && num <= 0; trys++) {
        num = get_output_num();
        if (num <= 0) {
            flb_time_msleep(500);
        }
    }

    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

#ifndef _WIN32
struct patch_method_mock_server {
    flb_sockfd_t listen_fd;
    int port;
    int stop;
    pthread_t thread;
    char request_method[16];
};

static void *patch_method_mock_server_thread(void *data)
{
    struct patch_method_mock_server *server;
    flb_sockfd_t conn_fd;
    ssize_t bytes;
    char request[4096];
    const char response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n";

    server = data;

    while (!server->stop) {
        conn_fd = accept(server->listen_fd, NULL, NULL);
        if (conn_fd < 0) {
            if (server->stop) {
                break;
            }
            flb_time_msleep(10);
            continue;
        }

        bytes = recv(conn_fd, request, sizeof(request) - 1, 0);
        if (bytes > 0) {
            request[bytes] = '\0';
            if (strncmp(request, "PATCH ", 6) == 0) {
                strncpy(server->request_method, "PATCH",
                        sizeof(server->request_method) - 1);
            }
            else if (strncmp(request, "POST ", 5) == 0) {
                strncpy(server->request_method, "POST",
                        sizeof(server->request_method) - 1);
            }
            else if (strncmp(request, "PUT ", 4) == 0) {
                strncpy(server->request_method, "PUT",
                        sizeof(server->request_method) - 1);
            }
        }

        send(conn_fd, response, strlen(response), 0);
        flb_socket_close(conn_fd);
        break;
    }

    return NULL;
}

static int patch_method_mock_server_start(struct patch_method_mock_server *server)
{
    int on = 1;
    struct sockaddr_in addr;
    socklen_t len;

    memset(server, 0, sizeof(struct patch_method_mock_server));
    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listen_fd < 0) {
        return -1;
    }

    setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &on,
               sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(server->listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        flb_socket_close(server->listen_fd);
        return -1;
    }

    len = sizeof(addr);
    if (getsockname(server->listen_fd, (struct sockaddr *) &addr, &len) < 0) {
        flb_socket_close(server->listen_fd);
        return -1;
    }

    server->port = ntohs(addr.sin_port);

    if (listen(server->listen_fd, 4) < 0) {
        flb_socket_close(server->listen_fd);
        return -1;
    }

    server->stop = 0;
    if (pthread_create(&server->thread, NULL, patch_method_mock_server_thread,
                       server) != 0) {
        flb_socket_close(server->listen_fd);
        return -1;
    }

    return 0;
}

static void patch_method_mock_server_stop(struct patch_method_mock_server *server)
{
    if (server->listen_fd < 0) {
        return;
    }

    server->stop = 1;
    pthread_join(server->thread, NULL);
    flb_socket_close(server->listen_fd);
    server->listen_fd = -1;
}

void flb_test_http_method_patch(void)
{
    struct patch_method_mock_server server;
    struct test_ctx *ctx;
    int ret;
    int attempts;
    char port[16];
    char *buf = "[1, {\"msg\":\"hello world\"}]";
    size_t size = strlen(buf);

    memset(&server, 0, sizeof(server));
    server.listen_fd = -1;

    if (!TEST_CHECK(patch_method_mock_server_start(&server) == 0)) {
        TEST_MSG("failed to start mock HTTP server");
        return;
    }

    snprintf(port, sizeof(port), "%d", server.port);

    clear_output_num();

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        patch_method_mock_server_stop(&server);
        TEST_MSG("test_ctx_create failed");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         "host", "127.0.0.1",
                         "port", port,
                         "http_method", "patch",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx->flb, ctx->i_ffd, (char *) buf, size);
    TEST_CHECK(ret >= 0);

    for (attempts = 0; attempts < 50; attempts++) {
        if (server.request_method[0] != '\0') {
            break;
        }
        flb_time_msleep(100);
    }

    if (!TEST_CHECK(strcmp(server.request_method, "PATCH") == 0)) {
        TEST_MSG("expected PATCH request, got '%s'", server.request_method);
    }

    patch_method_mock_server_stop(&server);
    test_ctx_destroy(ctx);
}

void flb_test_http_method_invalid(void)
{
    struct test_ctx *ctx;
    int ret;

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        return;
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         "http_method", "DELETE",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret != 0);

    flb_destroy(ctx->flb);
    flb_free(ctx);
}
#endif

/* Test list */
TEST_LIST = {
    {"format_msgpack" , flb_test_format_msgpack},
    {"format_json" , flb_test_format_json},
    {"format_json_stream" , flb_test_format_json_stream},
    {"format_json_lines" , flb_test_format_json_lines},
    {"format_gelf" , flb_test_format_gelf},
    {"format_gelf_host_key" , flb_test_format_gelf_host_key},
    {"format_gelf_timestamp_key" , flb_test_format_gelf_timestamp_key},
    {"format_gelf_full_message_key" , flb_test_format_gelf_full_message_key},
    {"format_gelf_level_key" , flb_test_format_gelf_level_key},
    {"set_json_date_key" , flb_test_set_json_date_key},
    {"disable_json_date_key" , flb_test_disable_json_date_key},
    {"json_date_format_epoch" , flb_test_json_date_format_epoch},
    {"json_date_format_iso8601" , flb_test_json_date_format_iso8601},
    {"json_date_format_java_sql_timestamp" , flb_test_json_date_format_java_sql_timestamp},
    {"in_http", flb_test_in_http},
#ifndef _WIN32
    {"http_method_patch", flb_test_http_method_patch},
    {"http_method_invalid", flb_test_http_method_invalid},
#endif
    {NULL, NULL}
};
