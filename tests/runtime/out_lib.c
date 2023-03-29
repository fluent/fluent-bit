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
#include <float.h>
#include <math.h>
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

void wait_with_timeout(uint32_t timeout_ms, int *output_num)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb = 0;

    flb_time_get(&start_time);

    while (true) {
        *output_num = get_output_num();

        if (*output_num > 0) {
            break;
        }

        flb_time_msleep(100);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;

        if (elapsed_time_flb > timeout_ms) {
            flb_warn("[timeout] elapsed_time: %ld", elapsed_time_flb);
            // Reached timeout.
            break;
        }
    }
}

struct str_list {
    size_t size;
    char **lists;
};

/* Callback to check expected results */
static int cb_check_json_str_list(void *record, size_t size, void *data)
{
    char *p;
    char *result;
    int num = get_output_num();
    size_t i;
    struct str_list *l = (struct str_list*)data;

    if (!TEST_CHECK(l != NULL)) {
        TEST_MSG("Data is NULL");
        flb_free(record);
        return 0;
    }

    set_output_num(num+1);

    result = (char *) record;

    for (i=0; i<l->size; i++) {
        p = strstr(result, l->lists[i]);
        if(!TEST_CHECK(p != NULL)) {
            TEST_MSG("Expected to find: '%s' in result '%s'",
                     l->lists[i], result);
        }
    }

    /*
     * If you want to debug your test
     *
     * printf("Expect: '%s' in result '%s'", expected, result);
     */
    flb_free(record);
    return 0;
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
            if (val == (unsigned long)obj.via.i64) {
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
static int cb_check_msgpack_kv(void *record, size_t size, void *data)

                                /*void *ctx, int ffd, int res_ret, 
                                  void *res_data, size_t res_size, void *data)*/
{
    msgpack_unpacked result;
    msgpack_object obj;
    size_t off = 0;
    struct str_list *l = (struct str_list *)data;
    int i_map;
    int map_size;
    int i_list;
    int num = get_output_num();

    if (!TEST_CHECK(record != NULL)) {
        TEST_MSG("record is NULL");
        return -1;
    }

    if (!TEST_CHECK(data != NULL)) {
        TEST_MSG("data is NULL");
        flb_free(record);
        return -1;
    }

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        obj = result.data;
        /*
        msgpack_object_print(stdout, obj);
        */
        if (obj.type != MSGPACK_OBJECT_ARRAY || obj.via.array.size != 2) {
            flb_error("array error. type = %d", obj.type);
            continue;
        }
        obj = obj.via.array.ptr[1];
        if (obj.type != MSGPACK_OBJECT_MAP) {
            flb_error("map error. type = %d", obj.type);
            continue;
        }
        map_size = obj.via.map.size;
        for (i_map=0; i_map<map_size; i_map++) {
            if (obj.via.map.ptr[i_map].key.type != MSGPACK_OBJECT_STR) {
                flb_error("key is not string. type =%d", obj.via.map.ptr[i_map].key.type);
                continue;
            }
            for (i_list=0; i_list< l->size/2; i_list++)  {
                if (msgpack_strncmp(l->lists[i_list*2], strlen(l->lists[i_list*2]),
                                    obj.via.map.ptr[i_map].key) == 0 &&
                    msgpack_strncmp(l->lists[i_list*2+1], strlen(l->lists[i_list*2+1]),
                                    obj.via.map.ptr[i_map].val) == 0) {
                    num++;
                }
            }
        }
    }
    set_output_num(num);

    msgpack_unpacked_destroy(&result);
    flb_free(record);

    return 0;
}


static int cb_count_msgpack(void *record, size_t size, void *data)
{
    msgpack_unpacked result;
    size_t off = 0;

    if (!TEST_CHECK(data != NULL)) {
        TEST_MSG("data is NULL");
    }

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        pthread_mutex_lock(&result_mutex);
        num_output++;
        /*
           msgpack_object_print(stdout, result.data);
        */
        pthread_mutex_unlock(&result_mutex);
    }
    msgpack_unpacked_destroy(&result);

    flb_free(record);
    return 0;
}

static int cb_count(void *record, size_t size, void *data)
{
    if (!TEST_CHECK(data != NULL)) {
        TEST_MSG("data is NULL");
    }
    pthread_mutex_lock(&result_mutex);
    num_output++;
    pthread_mutex_unlock(&result_mutex);

    flb_free(record);
    return 0;
}

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
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

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
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

static void test_format_json(void)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    char *input_json = "[1,{\"hoge\":\"moge\", \"bool\":true, \"int\":100, \"float\":-2.0}]";
    int size = strlen(input_json);
    int ret;
    int num;

    char *expected_strs[] = {"\"hoge\"", "\"moge\"", "\"bool\"", "true", "\"int\"", "100", "\"float\"", "-2."};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_json_str_list;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }
    /* Input */
    ctx->i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(ctx->i_ffd >= 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx->flb, ctx->i_ffd, input_json,size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    wait_with_timeout(2000, &num);

    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

static void test_format_msgpack(void)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    char *input_json = "[1,{\"hoge\":\"moge\", \"bool\":true, \"int\":100, \"float\":-2.0}]";
    int size = strlen(input_json);

    char *expected_strs[] = {"hoge", "moge", "bool", "true", "int", "100", "float", "-2.0"};
    struct str_list expected = {
                                .size = sizeof(expected_strs)/sizeof(char*),
                                .lists = &expected_strs[0],
    };

    clear_output_num();

    cb_data.cb = cb_check_msgpack_kv;
    cb_data.data = &expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }
    /* Input */
    ctx->i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(ctx->i_ffd >= 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "msgpack",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ret = flb_lib_push(ctx->flb, ctx->i_ffd, input_json,size);
    TEST_CHECK(ret >= 0);

    /* waiting to flush */
    wait_with_timeout(2000, &num);

    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

static void test_max_records(void)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    char *input_json = "[1,{\"hoge\":\"moge\", \"bool\":true, \"int\":100, \"float\":-2.0}]";
    int size = strlen(input_json);
    int i;
    int unused;
    int expected = 5 /* max_records */;

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }
    /* Input */
    ctx->i_ffd = flb_input(ctx->flb, (char *) "lib", NULL);
    TEST_CHECK(ctx->i_ffd >= 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "msgpack",
                         "max_records", "5",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    for (i=0; i<100; i++) {
        ret = flb_lib_push(ctx->flb, ctx->i_ffd, input_json,size);
        TEST_CHECK(ret >= 0);
    }

    /* waiting to flush */
    wait_with_timeout(1000, &num);

    if (!TEST_CHECK(num == expected /* max_records */))  {
        TEST_MSG("max_records error. got=%d, expected=%d", num, expected);
    }

    test_ctx_destroy(ctx);
}
#ifdef FLB_HAVE_METRICS
static void test_metrics_msgpack(void)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    int unused;

    clear_output_num();

    cb_data.cb = cb_count_msgpack;
    cb_data.data = &unused;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }
    /* Input */
    ctx->i_ffd = flb_input(ctx->flb, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(ctx->i_ffd >= 0);
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "scrape_interval", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "msgpack",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* waiting to flush */
    wait_with_timeout(5000, &num);

    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}

static void test_metrics_json(void)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    int ret;
    int num;
    int unused;

    clear_output_num();

    cb_data.cb = cb_count;
    cb_data.data = &unused;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }
    /* Input */
    ctx->i_ffd = flb_input(ctx->flb, (char *) "fluentbit_metrics", NULL);
    TEST_CHECK(ctx->i_ffd >= 0);
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "scrape_interval", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* waiting to flush */
    wait_with_timeout(5000, &num);

    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }

    test_ctx_destroy(ctx);
}
#endif

TEST_LIST = {
#ifdef FLB_HAVE_METRICS
    {"metrics_msgpack", test_metrics_msgpack},
    {"metrics_json", test_metrics_json},
#endif
    {"format_json", test_format_json},
    {"format_msgpack", test_format_msgpack},
    {"max_records", test_max_records},
    {NULL, NULL}
};
