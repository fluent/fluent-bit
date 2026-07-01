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
#include <msgpack.h>
#include "flb_tests_runtime.h"
#include "data/common/json_long.h"    /* JSON_LONG    */

struct filter_test {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd */
    int o_ffd;         /* Output fd */
};

struct expect_str {
    char *str;
    int  found;
};


/* Callback to check expected results */
static int cb_check_result(void *record, size_t size, void *data)
{
    char *p;
    char *result;
    struct expect_str *expected;

    expected = (struct expect_str*)data;
    result = (char *) record;

    if (!TEST_CHECK(expected != NULL)) {
        flb_error("expected is NULL");
    }
    if (!TEST_CHECK(result != NULL)) {
        flb_error("result is NULL");
    }

    while(expected != NULL && expected->str != NULL) {
        if (expected->found == FLB_TRUE) {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p != NULL)) {
                flb_error("Expected to find: '%s' in result '%s'",
                          expected->str, result);
            }
        }
        else {
            p = strstr(result, expected->str);
            if(!TEST_CHECK(p == NULL)) {
                flb_error("'%s' should be removed in result '%s'",
                          expected->str, result);
            }
        }

        /*
         * If you want to debug your test
         *
         * printf("Expect: '%s' in result '%s'", expected, result);
         */

        expected++;
    }

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
    f_ffd = flb_filter(ctx->flb, (char *) "record_modifier", NULL);
    TEST_CHECK(f_ffd >= 0);
    flb_filter_set(ctx->flb, f_ffd, "match", "*", NULL);
    ctx->f_ffd = f_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(o_ffd >= 0);
    flb_output_set(ctx->flb, o_ffd,
                   "match", "test",
                   NULL);
    ctx->o_ffd = o_ffd;

    return ctx;
}

static void filter_test_destroy(struct filter_test *ctx)
{
    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

static void flb_records()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct expect_str expect[] = {
      {"\"new_key\":\"new_val\"", FLB_TRUE},
      {"\"add_key\":\"add_val\"", FLB_TRUE},
      {"\"k\":\"sample\"", FLB_TRUE},
      {NULL, FLB_TRUE}
    };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "record", "new_key new_val",
                         "record", "add_key add_val",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"k\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

static void flb_allowlist_keys()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct expect_str expect[] = {
      {"\"aaa\":\"ok\"", FLB_TRUE},
      {"\"bbb\":\"ok\"", FLB_TRUE},
      {"\"ccc\":\"removed\"", FLB_FALSE},
      {NULL, FLB_TRUE}
    };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "allowlist_key", "aaa",
                         "allowlist_key", "bbb",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    /* The pair "ccc":"removed" should be removed */
    p = "[0, {\"aaa\":\"ok\",\"ccc\":\"removed\",\"bbb\":\"ok\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

static void flb_whitelist_keys()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct expect_str expect[] = {
      {"\"aaa\":\"ok\"", FLB_TRUE},
      {"\"bbb\":\"ok\"", FLB_TRUE},
      {"\"ccc\":\"removed\"", FLB_FALSE},
      {NULL, FLB_TRUE}
    };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "whitelist_key", "aaa",
                         "whitelist_key", "bbb",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    /* The pair "ccc":"removed" should be removed */
    p = "[0, {\"aaa\":\"ok\",\"ccc\":\"removed\",\"bbb\":\"ok\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

static void flb_remove_keys()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct expect_str expect[] = {
      {"\"aaa\":\"ok\"", FLB_TRUE},
      {"\"bbb\":\"ok\"", FLB_TRUE},
      {"\"ccc\":\"removed\"", FLB_FALSE},
      {"\"ddd\":\"removed\"", FLB_FALSE},
      {NULL, FLB_TRUE}
    };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "remove_key", "ccc",
                         "remove_key", "ddd",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    /* The pairs "ccc" and "ddd" should be removed */
    p = "[0, {\"aaa\":\"ok\",\"ccc\":\"removed\",\"ddd\":\"removed\",\"bbb\":\"ok\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}

static void flb_multiple()
{
    int len;
    int ret;
    int bytes;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;
    struct expect_str expect[] = {
      {"\"aaa\":\"ok\"", FLB_TRUE},
      {"\"new_key\":\"new_val\"", FLB_TRUE},
      {"\"ddd\":\"removed\"", FLB_FALSE},
      {NULL, FLB_TRUE}
    };

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "record",     "new_key new_val",
                         "allowlist_key", "new_key",
                         "allowlist_key", "aaa",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_result;
    cb_data.data = &expect;

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"aaa\":\"ok\",\"ddd\":\"removed\",\"bbb\":\"ok\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}


/* https://github.com/fluent/fluent-bit/issues/3968 */
void flb_test_json_long()
{
    int ret;
    int size = sizeof(JSON_LONG) - 1;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "record_modifier", NULL);
    TEST_CHECK(filter_ffd >= 0);
    flb_filter_set(ctx, filter_ffd, "match", "test", NULL);

    /* Start */
    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    /* Ingest data sample */
    flb_lib_push(ctx, in_ffd, (char *) JSON_LONG, size);

    flb_time_msleep(1500); /* waiting flush */
    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_exclusive_setting()
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", "1", "grace", "1",
                    "log_level", "error",
                    NULL);

    /* Lib input mode */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(in_ffd >= 0);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    filter_ffd = flb_filter(ctx, (char *) "record_modifier", NULL);
    TEST_CHECK(filter_ffd >= 0);
    flb_filter_set(ctx, filter_ffd, "match", "test", NULL);

    ret = flb_filter_set(ctx, filter_ffd,
                         "allowlist_key", "aaa",
                         "remove_key", "bbb",
                         NULL);

    /* Start */
    ret = flb_start(ctx);

    /* It should be error since "allowlist_key" and "remove_key" are exclusive */
    TEST_CHECK(ret != 0);

    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}

#define UUID_KEY_NAME "uuid"
static int cb_check_uuid(void *record, size_t size, void *data)
{
    char uuid[256] = {0};
    msgpack_unpacked result;
    msgpack_object obj;
    size_t off = 0;
    int ret;
    int i_map;
    int map_size;
    int uuid_found = FLB_FALSE;
    char uuid_part[5][16];

#ifndef FLB_HAVE_OPENSSL
    if (!TEST_CHECK(1 == 0)) {
        /* flb_utils_uuid_v4_gen function needs openssl */
        TEST_MSG("uuid_key needs OpenSSL");
        return -1;
    }
#endif

    if (!TEST_CHECK(record != NULL)) {
        TEST_MSG("data is null");
        return -1;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, record, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        obj = result.data;
        /*
        msgpack_object_print(stdout, obj);
        */
        if (!TEST_CHECK(obj.type == MSGPACK_OBJECT_ARRAY && obj.via.array.size == 2)) {
            TEST_MSG("array error. type = %d", obj.type);
            continue;
        }
        obj = obj.via.array.ptr[1];
        if (!TEST_CHECK(obj.type == MSGPACK_OBJECT_MAP)) {
            TEST_MSG("map error. type = %d", obj.type);
            continue;
        }
        map_size = obj.via.map.size;
        for (i_map=0; i_map<map_size; i_map++) {
            if (obj.via.map.ptr[i_map].key.type != MSGPACK_OBJECT_STR) {
                continue;
            }
            if (strncmp(UUID_KEY_NAME, obj.via.map.ptr[i_map].key.via.str.ptr, strlen(UUID_KEY_NAME)) == 0) {
                memcpy(&uuid[0], obj.via.map.ptr[i_map].val.via.str.ptr, obj.via.map.ptr[i_map].val.via.str.size);
                ret = sscanf(&uuid[0], "%8s-%4s-%4s-%4s-%12s", &uuid_part[0][0], &uuid_part[1][0], &uuid_part[2][0], &uuid_part[3][0], &uuid_part[4][0]);
                if (!TEST_CHECK(ret == 5)) {
                    TEST_MSG("ret should be 5. ret=%d", ret);
                }
                uuid_found = FLB_TRUE;
            }
        }
    }

    if (!TEST_CHECK(uuid_found == FLB_TRUE)) {
        TEST_MSG("uuid not found");
    }

    msgpack_unpacked_destroy(&result);
    flb_free(record);

    return 0;
}

static void flb_uuid_key()
{
    int len;
    int ret;
    int bytes;
    int not_used;
    char *p;
    struct flb_lib_out_cb cb_data;
    struct filter_test *ctx;

    /* Prepare output callback with expected result */
    cb_data.cb = cb_check_uuid;
    cb_data.data = &not_used;

    /* Create test context */
    ctx = filter_test_create((void *) &cb_data);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Configure filter */
    ret = flb_filter_set(ctx->flb, ctx->f_ffd,
                         "uuid_key", UUID_KEY_NAME,
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Ingest data samples */
    p = "[0, {\"key_name\":\"sample\"}]";
    len = strlen(p);
    bytes = flb_lib_push(ctx->flb, ctx->i_ffd, p, len);
    TEST_CHECK(bytes == len);

    filter_test_destroy(ctx);
}


/* test list */
TEST_LIST = {
    {"json_long"           , flb_test_json_long },
    {"remove_keys"         , flb_remove_keys},
    {"records"             , flb_records},
    {"allowlist_keys"      , flb_allowlist_keys},
    {"whitelist_keys"      , flb_whitelist_keys},
    {"multiple"            , flb_multiple},
    {"exclusive_setting"   , flb_exclusive_setting},
    {"uuid_key"            , flb_uuid_key},
    {NULL, NULL}
};
