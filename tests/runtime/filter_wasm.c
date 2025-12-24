/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_http_client.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>
#include "flb_tests_runtime.h"

#define DPATH_WASM       FLB_TESTS_DATA_PATH "/data/wasm"
#define FLUSH_INTERVAL "1.0"
#ifdef _WIN32
    #define TIME_EPSILON_MS 30
#else
    #define TIME_EPSILON_MS 10
#endif

pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
char *output = NULL;
int  num_output = 0;

/* MsgPack Output Capture Helpers */
static char  *mp_output = NULL;
static size_t mp_output_size = 0;

void set_output(char *val)
{
    pthread_mutex_lock(&result_mutex);
    output = val;
    pthread_mutex_unlock(&result_mutex);
}

char *get_output(void)
{
    char *val;

    pthread_mutex_lock(&result_mutex);
    val = output;
    pthread_mutex_unlock(&result_mutex);

    return val;
}

static void clear_output()
{
    pthread_mutex_lock(&result_mutex);
    output = NULL;
    pthread_mutex_unlock(&result_mutex);
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

static void set_msgpack_output_copy(void *data, size_t size)
{
    char *tmp;

    pthread_mutex_lock(&result_mutex);
    /* Append data instead of overwriting it */
    tmp = flb_realloc(mp_output, mp_output_size + size);
    if (tmp) {
        mp_output = tmp;
        memcpy(mp_output + mp_output_size, data, size);
        mp_output_size += size;
    }

    pthread_mutex_unlock(&result_mutex);
}

static void clear_msgpack_output()
{
    pthread_mutex_lock(&result_mutex);
    if (mp_output) {
        flb_free(mp_output);
    }
    mp_output = NULL;
    mp_output_size = 0;
    pthread_mutex_unlock(&result_mutex);
}

static int get_msgpack_output(char **out_buf, size_t *out_size)
{
    pthread_mutex_lock(&result_mutex);
    *out_buf  = mp_output;
    *out_size = mp_output_size;
    pthread_mutex_unlock(&result_mutex);
    return (*out_buf != NULL && *out_size > 0) ? 0 : -1;
}

static int cb_store_msgpack_output(void *record, size_t size, void *data)
{
    (void) data;
    if (record != NULL && size > 0) {
        set_msgpack_output_copy(record, size);
    }
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

int callback_test(void* data, size_t size, void* cb_data)
{
    if (size > 0) {
        flb_debug("[test_filter_wasm] received message: %s", (char*)data);
        set_output(data); /* success */
    }
    return 0;
}

void wait_with_timeout(uint32_t timeout_ms, char **out_result)
{
    struct flb_time start_time;
    struct flb_time end_time;
    struct flb_time diff_time;
    uint64_t elapsed_time_flb = 0;
    char *output = NULL;

    flb_time_get(&start_time);

    while (true) {
        output = get_output();

        if (output != NULL) {
            *out_result = output;
            break;
        }

        flb_time_msleep(100);
        flb_time_get(&end_time);
        flb_time_diff(&end_time, &start_time, &diff_time);
        elapsed_time_flb = flb_time_to_nanosec(&diff_time) / 1000000;

        if (elapsed_time_flb > timeout_ms - TIME_EPSILON_MS) {
            flb_warn("[timeout] elapsed_time: %ld", elapsed_time_flb);
            // Reached timeout.
            break;
        }
    }
}

/* Helpers for MsgPack Object Lookup */
static msgpack_object *mp_map_get(msgpack_object *map, const char *key)
{
    size_t i;
    msgpack_object_kv *kv;

    if (!map || map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    kv = map->via.map.ptr;
    for (i = 0; i < map->via.map.size; i++) {
        if (kv[i].key.type == MSGPACK_OBJECT_STR) {
            if (strlen(key) == kv[i].key.via.str.size &&
                memcmp(kv[i].key.via.str.ptr, key, kv[i].key.via.str.size) == 0) {
                return &kv[i].val;
            }
        }
    }
    return NULL;
}

static int mp_str_eq(msgpack_object *o, const char *s)
{
    if (!o || o->type != MSGPACK_OBJECT_STR) {
        return FLB_FALSE;
    }
    if (o->via.str.size != strlen(s)) {
        return FLB_FALSE;
    }
    return memcmp(o->via.str.ptr, s, o->via.str.size) == 0 ? FLB_TRUE : FLB_FALSE;
}

struct http_client_ctx {
    struct flb_upstream      *u;
    struct flb_connection    *u_conn;
    struct flb_config        *config;
    struct mk_event_loop     *evl;
};

#define PORT_OTEL 4318
#define JSON_CONTENT_TYPE "application/json"

struct http_client_ctx* http_client_ctx_create()
{
    struct http_client_ctx *ret_ctx = NULL;
    struct mk_event_loop *evl = NULL;

    ret_ctx = flb_calloc(1, sizeof(struct http_client_ctx));
    if (!TEST_CHECK(ret_ctx != NULL)) {
        flb_errno();
        TEST_MSG("flb_calloc(http_client_ctx) failed");
        return NULL;
    }

    evl = mk_event_loop_create(16);
    if (!TEST_CHECK(evl != NULL)) {
        TEST_MSG("mk_event_loop failed");
        flb_free(ret_ctx);
        return NULL;
    }
    ret_ctx->evl = evl;
    flb_engine_evl_init();
    flb_engine_evl_set(evl);

    ret_ctx->config = flb_config_init();
    if(!TEST_CHECK(ret_ctx->config != NULL)) {
        TEST_MSG("flb_config_init failed");
        mk_event_loop_destroy(evl);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u = flb_upstream_create(ret_ctx->config, "127.0.0.1", PORT_OTEL, 0, NULL);
    if (!TEST_CHECK(ret_ctx->u != NULL)) {
        TEST_MSG("flb_upstream_create failed");
        flb_config_exit(ret_ctx->config);
        mk_event_loop_destroy(evl);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u_conn = flb_upstream_conn_get(ret_ctx->u);
    TEST_CHECK(ret_ctx->u_conn != NULL);

    ret_ctx->u_conn->upstream = ret_ctx->u;

    return ret_ctx;
}

void http_client_ctx_destroy(struct http_client_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->u_conn) {
        flb_upstream_conn_release(ctx->u_conn);
        ctx->u_conn = NULL;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
        ctx->u = NULL;
    }

    if (ctx->config) {
        flb_config_exit(ctx->config);
        ctx->config = NULL;
    }

    if (ctx->evl) {
        mk_event_loop_destroy(ctx->evl);
        ctx->evl = NULL;
    }

    flb_free(ctx);
}

void flb_test_append_tag(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *output = NULL;
    char *input = "[0, {\"key\":\"val\"}]";
    char *result;
    struct flb_lib_out_cb cb_data;

    /* clear previous output */
    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "wasm_path", DPATH_WASM "/append_tag.wasm",
                         "function_name", "filter_append_tag",
                         NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test.wasm", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test.wasm",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);
    result = strstr(output, "\"tag\":\"test.wasm\"");
    TEST_CHECK(result != NULL);

    /* clean up */
    flb_lib_free(output);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_helloworld(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "wasm_path", DPATH_WASM "/say_hello.wasm",
                         "function_name", "filter_say_hello",
                         NULL);
    /* Input */
    in_ffd = flb_input(ctx, (char *) "dummy", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_numerics_records(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *output = NULL;
    char *input = "[0, {\"key\":\"val\"}]";
    char *result;
    struct flb_lib_out_cb cb_data;

    /* clear previous output */
    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "wasm_path", DPATH_WASM "/numeric_records.wasm",
                         "function_name", "filter_numeric_records",
                         NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test.wasm", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test.wasm",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);

    /* check if float (for int keys)*/
    result = strstr(output, "\"wasm_int1\":10.");
    if (!TEST_CHECK(result == NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"wasm_int2\":100.");
    if (!TEST_CHECK(result == NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* check if float (for float keys)*/
    result = strstr(output, "\"wasm_float1\":10.5");
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"wasm_float2\":100.5");
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* check if float (for exp style float key)*/
    result = strstr(output, "\"wasm_exp_float\":0.00354");
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* check if float (for truncated float key)*/
    result = strstr(output, "\"wasm_truncate_float\":120");
    if (!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"wasm_truncate_float\":120.");
    if (!TEST_CHECK(result == NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* clean up */
    flb_lib_free(output);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_array_contains_null(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *output = NULL;
    char *input = "[0, {\"hello\": [1, null, \"world\"]}]";
    char *result;
    struct flb_lib_out_cb cb_data;

    /* clear previous output */
    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "wasm_path", DPATH_WASM "/modify_record.wasm",
                         "function_name", "filter_modify_record",
                         NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test.wasm", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test.wasm",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);

    result = strstr(output, "[1,null,\"world\"]");
    if(!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }
    result = strstr(output, "\"modify\":\"yes\"");
    if(!TEST_CHECK(result != NULL)) {
        TEST_MSG("output:%s\n", output);
    }

    /* clean up */
    flb_lib_free(output);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_drop_all_records(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *output = NULL;
    char *input = "[0, {\"key\":\"val\"}]";
    struct flb_lib_out_cb cb_data;

    clear_output_num();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = cb_count_msgpack_events;
    cb_data.data = NULL;

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "wasm_path", DPATH_WASM "/drop_record.wasm",
                         "function_name", "filter_drop_record",
                         NULL);
    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output); /* waiting flush */

    ret = get_output_num();
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("error. got %d expect 0", ret);
    }

    flb_stop(ctx);
    flb_destroy(ctx);
}


void flb_test_append_kv_on_msgpack(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    char *output = NULL;
    char *input = "[0, {\"key\":\"val\"}]";
    char *result;
    struct flb_lib_out_cb cb_data;

    /* clear previous output */
    clear_output();

    /* Create context, flush every second (some checks omitted here) */
    ctx = flb_create();
    flb_service_set(ctx, "flush", FLUSH_INTERVAL, "grace", "1", NULL);

    /* Prepare output callback context*/
    cb_data.cb = callback_test;
    cb_data.data = NULL;

    /* Filter */
    filter_ffd = flb_filter(ctx, (char *) "wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);
    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "*",
                         "event_format", "msgpack",
                         "wasm_path", DPATH_WASM "/msgpack/filter_rust_mp.wasm",
                         "function_name", "rust_filter_mp",
                         NULL);

    /* Input */
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test.wasm.mp", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* Lib output */
    out_ffd = flb_output(ctx, (char *) "lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd,
                   "match", "test.wasm.mp",
                   "format", "json",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret==0);

    flb_lib_push(ctx, in_ffd, input, strlen(input));
    wait_with_timeout(2000, &output);
    result = strstr(output, "\"platform\":\"wasm\"");
    TEST_CHECK(result != NULL);

    /* clean up */
    flb_lib_free(output);

    flb_stop(ctx);
    flb_destroy(ctx);
}

void flb_test_wasm_preserve_otlp_group_metadata(void)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;
    int filter_ffd;

    struct flb_lib_out_cb cb_data;

    struct flb_http_client *c;
    struct http_client_ctx *httpc;
    size_t b_sent;

    char  *packed = NULL;
    size_t packed_size = 0;

    int found_group_start = FLB_FALSE;
    int found_group_end   = FLB_FALSE;
    int found_normal      = FLB_FALSE;
    int group_ok          = FLB_FALSE;

    msgpack_object *resource;
    msgpack_object *scope;
    msgpack_object *attrs;
    msgpack_object *svc;
    msgpack_object *name;
    msgpack_object *obj;
    msgpack_object *head;

    msgpack_unpacked result;
    msgpack_object *rec;
    size_t off = 0;
    int32_t seconds = 0;
    msgpack_object *ts_obj;
    unsigned char *p;
    int32_t tmp;

    const char *payload =
        "{"
        "\"resourceLogs\":[{"
          "\"resource\":{"
            "\"attributes\":[{"
              "\"key\":\"service.name\","
              "\"value\":{\"stringValue\":\"filter-service\"}"
            "}]"
          "},"
          "\"scopeLogs\":[{"
            "\"scope\":{\"name\":\"my.scope\"},"
            "\"logRecords\":[{"
              "\"timeUnixNano\":\"1660296023390371588\","
              "\"body\":{\"stringValue\":\"{\\\"message\\\":\\\"dummy\\\"}\"}"
            "}]"
          "}]"
        "}]"
        "}";

    clear_msgpack_output();

    ctx = flb_create();
    flb_service_set(ctx,
                    "flush", FLUSH_INTERVAL,
                    "grace", "1",
                    "http_server", "on",
                    "http_listen", "127.0.0.1",
                    "http_port", "2020",
                    NULL);

    /* OpenTelemetry input */
    in_ffd = flb_input(ctx, (char *)"opentelemetry", NULL);
    TEST_CHECK(in_ffd >= 0);

    /* WASM filter */
    filter_ffd = flb_filter(ctx, (char *)"wasm", NULL);
    TEST_CHECK(filter_ffd >= 0);

    ret = flb_filter_set(ctx, filter_ffd,
                         "Match", "v1_logs",
                         "wasm_path", DPATH_WASM "/say_hello.wasm",
                         "function_name", "filter_say_hello",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Output (lib, raw msgpack) */
    cb_data.cb    = cb_store_msgpack_output;
    cb_data.data = NULL;

    out_ffd = flb_output(ctx, (char *)"lib", (void *)&cb_data);
    TEST_CHECK(out_ffd >= 0);

    flb_output_set(ctx, out_ffd,
                   "match", "*",
                   NULL);

    ret = flb_start(ctx);
    TEST_CHECK(ret == 0);

    httpc = http_client_ctx_create();
    TEST_CHECK(httpc != NULL);

    c = flb_http_client(httpc->u_conn,
                        FLB_HTTP_POST,
                        "/v1/logs",
                        payload,
                        strlen(payload),
                        "127.0.0.1",
                        4318,
                        NULL,
                        0);
    TEST_CHECK(c != NULL);

    ret = flb_http_add_header(c,
                              FLB_HTTP_HEADER_CONTENT_TYPE,
                              strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE,
                              strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);

    ret = flb_http_do(c, &b_sent);
    TEST_CHECK(ret == 0);
    TEST_CHECK(b_sent > 0);
    TEST_CHECK(c->resp.status == 201);

    flb_time_msleep(1500);

    ret = get_msgpack_output(&packed, &packed_size);
    TEST_CHECK(ret == 0);

    /* Decode msgpack stream and validate group markers are preserved */
    if (packed && packed_size > 0) {
        msgpack_unpacked_init(&result);

        /*
         * lib output receives a msgpack "chunk" which is typically:
         * [ [ts, meta, body], [ts, meta, body], ... ]
         * msgpack_unpack_next returns one object at a time from the buffer.
         */
        while (msgpack_unpack_next(&result, packed, packed_size, &off) == MSGPACK_UNPACK_SUCCESS) {
            /* result.data is the record itself: [[ts, meta], body] */
            rec = &result.data;

            if (rec->type != MSGPACK_OBJECT_ARRAY || rec->via.array.size < 2) {
                continue;
            }

            /* Check header [ts, meta] */
            head = &rec->via.array.ptr[0];
            if (head->type != MSGPACK_OBJECT_ARRAY || head->via.array.size < 2) {
                continue;
            }

            ts_obj = &head->via.array.ptr[0];
            obj    = &rec->via.array.ptr[1];

            /* Decode Timestamp to determine record type
             * Group Start: -1
             * Group End:   -2
             */
            if (ts_obj->type == MSGPACK_OBJECT_EXT && ts_obj->via.ext.type == 0) {
                /* flb_time: 8 bytes (4 bytes sec, 4 bytes nsec). Big Endian. */
                p = (const unsigned char *)ts_obj->via.ext.ptr;
                tmp = (uint32_t)(p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]);
                seconds = (int32_t)tmp;
            }
            else if (ts_obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                seconds = (int32_t)ts_obj->via.i64;
            }
            else {
                /* Assume normal record if it's a positive integer or float */
                seconds = 0;
            }

            if (seconds == -1) { /* FLB_LOG_EVENT_GROUP_START */
                found_group_start = FLB_TRUE;

                resource = mp_map_get(obj, "resource");
                scope    = mp_map_get(obj, "scope");
                attrs    = resource ? mp_map_get(resource, "attributes") : NULL;
                svc      = attrs ? mp_map_get(attrs, "service.name") : NULL;
                name     = scope ? mp_map_get(scope, "name") : NULL;

                if (mp_str_eq(svc, "filter-service") && mp_str_eq(name, "my.scope")) {
                    group_ok = FLB_TRUE;
                }
            }
            else if (seconds == -2) {
                /* FLB_LOG_EVENT_GROUP_END */
                found_group_end = FLB_TRUE;
            }
            else {
                /* Normal Record */
                found_normal = FLB_TRUE;
            }
        }
        msgpack_unpacked_destroy(&result);
    }

    TEST_CHECK(found_group_start == FLB_TRUE);
    TEST_CHECK(found_group_end == FLB_TRUE);
    TEST_CHECK(found_normal == FLB_TRUE);
    TEST_CHECK(group_ok == FLB_TRUE);

    /* cleanup */
    flb_http_client_destroy(c);
    http_client_ctx_destroy(httpc);

    flb_stop(ctx);
    flb_destroy(ctx);
    clear_msgpack_output();
}

TEST_LIST = {
    {"hello_world", flb_test_helloworld},
    {"append_tag", flb_test_append_tag},
    {"numeric_records", flb_test_numerics_records},
    {"array_contains_null", flb_test_array_contains_null},
    {"drop_all_records", flb_test_drop_all_records},
    {"append_kv_on_msgpack_format", flb_test_append_kv_on_msgpack},
    {"wasm_preserve_otlp_group_metadata",
     flb_test_wasm_preserve_otlp_group_metadata},
    {NULL, NULL}
};
