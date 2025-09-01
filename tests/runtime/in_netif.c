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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <errno.h>
#include "flb_tests_runtime.h"

struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd (unused) */
    int o_ffd;         /* Output fd */
};

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int  num_output = 0;

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
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
    i_ffd = flb_input(ctx->flb, (char *) "netif", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx, int ret)
{
    TEST_CHECK(ctx != NULL);

    sleep(1);
    if (ret == 0) {
        flb_stop(ctx->flb);
    }
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static void clear_output_num()
{
    pthread_mutex_lock(&result_mutex);
    num_output = 0;
    pthread_mutex_unlock(&result_mutex);
}

static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);

    return ret;
}

static flb_sds_t get_interface_str()
{
    struct ifaddrs *ifap = NULL;
    flb_sds_t ret_str;
    int ret = 0;

    ret = getifaddrs(&ifap);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("getifaddrs failed errno=%d", errno);
        return NULL;
    }

    if (!TEST_CHECK(ifap != NULL)) {
        TEST_MSG("failed to get ifaddrs");
        return NULL;
    }
    ret_str = flb_sds_create(ifap->ifa_name);
    freeifaddrs(ifap);

    /* printf("ret:%s\n", ret_str); */

    return ret_str;
}

static int cb_count_msgpack_map_size(void *record, size_t size, void *data)
{
    msgpack_unpacked result;
    msgpack_object *obj;
    struct flb_time tm;
    size_t off = 0;
    int map_size;

    if (!TEST_CHECK(data != NULL)) {
        flb_error("data is NULL");
    }

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (!TEST_CHECK(result.data.type == MSGPACK_OBJECT_ARRAY)) {
            continue;
        }
        flb_time_pop_from_msgpack(&tm, &result, &obj);

        if (!TEST_CHECK(obj->type == MSGPACK_OBJECT_MAP)) {
            continue;
        }
        map_size = get_output_num();
        if (obj->via.map.size > map_size) {
            pthread_mutex_lock(&result_mutex);
            num_output = obj->via.map.size;
            pthread_mutex_unlock(&result_mutex);
        }
    }
    msgpack_unpacked_destroy(&result);

    flb_free(record);
    return 0;
}

static int cb_count_msgpack_events(void *record, size_t size, void *data)
{
    msgpack_unpacked result;
    size_t off = 0;

    if (!TEST_CHECK(data != NULL)) {
        flb_error("data is NULL");
    }

    /* Iterate each item array and apply rules */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        pthread_mutex_lock(&result_mutex);
        num_output++;
        pthread_mutex_unlock(&result_mutex);
    }
    msgpack_unpacked_destroy(&result);

    flb_free(record);
    return 0;
}

static void flb_test_normal()
{
    int ret;
    int got;
    int unused = 0;
    flb_sds_t ifname;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;

    cb_data.cb = cb_count_msgpack_events;
    cb_data.data = &unused;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ifname = get_interface_str();
    if (!TEST_CHECK(ifname != NULL)) {
        TEST_MSG("can't get interface name");
        flb_free(ctx);
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "interface", ifname,
                        "interval_sec", "0",
                        "interval_nsec", "500000000", /* 500 ms */
                        "test_at_init", "true",
                        NULL);
    TEST_CHECK(ret==0);

    flb_sds_destroy(ifname);

    clear_output_num();

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got != 0)) {
        TEST_MSG("expect: >=1 got: %d", got);
    }

    test_ctx_destroy(ctx, ret);
}

static void flb_test_no_interface()
{
    int ret;
    int unused = 0;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;

    cb_data.cb = cb_count_msgpack_events;
    cb_data.data = &unused;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    clear_output_num();

    /* It should be error */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret != 0);

    test_ctx_destroy(ctx, ret);
}

static void flb_test_invalid_interface()
{
    int ret;
    int unused = 0;
    char *ifname = "\t\n";
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;


    cb_data.cb = cb_count_msgpack_events;
    cb_data.data = &unused;
    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "interface", ifname,
                        "interval_sec", "0",
                        "interval_nsec", "500000000", /* 500 ms */
                        "test_at_init", "true",
                        NULL);
    TEST_CHECK(ret==0);

    clear_output_num();

    /* It should be error */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret != 0);

    test_ctx_destroy(ctx, ret);
}

static void flb_test_verbose()
{
    int ret;
    int got;
    int unused = 0;
    int expect = 10;
    flb_sds_t ifname;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb_data;

    cb_data.cb = cb_count_msgpack_map_size;
    cb_data.data = &unused;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ifname = get_interface_str();
    if (!TEST_CHECK(ifname != NULL)) {
        TEST_MSG("can't get interface name");
        flb_free(ctx);
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "interface", ifname,
                        "interval_sec", "0",
                        "interval_nsec", "500000000", /* 500 ms */
                        "test_at_init", "true",
                        "verbose", "true",
                        NULL);
    TEST_CHECK(ret==0);

    flb_sds_destroy(ifname);

    clear_output_num();

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(1500); /* waiting flush */
    got = get_output_num();

    if (!TEST_CHECK(got > expect)) {
        TEST_MSG("expect: >10 got: %d", got);
    }

    test_ctx_destroy(ctx, ret);
}

TEST_LIST = {
    {"normal case", flb_test_normal},
    {"no interface", flb_test_no_interface},
    {"invalid interface", flb_test_invalid_interface},
    {"verbose", flb_test_verbose},
    {NULL, NULL}
};
