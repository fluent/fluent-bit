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
#include <fluent-bit.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_http_client.h>
#include <monkey/mk_core.h>
#include "flb_tests_runtime.h"

#define JSON_CONTENT_TYPE "application/json"
#define JSON_CHARSET_CONTENT_TYPE "application/json; charset=utf-8"

struct http_client_ctx {
    struct flb_upstream      *u;
    struct flb_connection    *u_conn;
    struct flb_config        *config;
    struct mk_event_loop     *evl;
};

struct test_ctx {
    flb_ctx_t *flb;    /* Fluent Bit library context */
    int i_ffd;         /* Input fd  */
    int f_ffd;         /* Filter fd (unused) */
    int o_ffd;         /* Output fd */
    struct http_client_ctx *httpc;
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

/* Callback to check expected results */
static int cb_check_result_json(void *record, size_t size, void *data)
{
    char *p;
    char *expected;
    char *result;
    int num = get_output_num();

    set_output_num(num+1);

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

    ret_ctx->u = flb_upstream_create(ret_ctx->config, "127.0.0.1", 9880, 0, NULL);
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

static struct test_ctx *test_ctx_create(struct flb_lib_out_cb *data)
{
    int i_ffd;
    int o_ffd;
    struct test_ctx *ctx = NULL;

    ctx = flb_calloc(1, sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("flb_calloc failed");
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
    i_ffd = flb_input(ctx->flb, (char *) "http", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;

    return ctx;
}

int http_client_ctx_destroy(struct http_client_ctx* ctx)
{
    if (!TEST_CHECK(ctx != NULL)) {
        return -1;
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }
    if (ctx->config) {
        flb_config_exit(ctx->config);
    }
    if (ctx->evl) {
        mk_event_loop_destroy(ctx->evl);
    }

    flb_free(ctx);
    return 0;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    TEST_CHECK(ctx != NULL);
    if (ctx->httpc) {
        http_client_ctx_destroy(ctx->httpc);
    }

    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void flb_test_http()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;

    char *buf = "{\"test\":\"msg\"}";

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ctx->httpc = http_client_ctx_create();
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/", buf, strlen(buf),
                        "127.0.0.1", 9880, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("http_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == 201)) {
        TEST_MSG("http response code error. expect: 201, got: %d\n", c->resp.status);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}
void flb_test_http_successful_response_code(char *response_code)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;

    char *buf = "{\"test\":\"msg\"}";

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "successful_response_code", response_code,
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ctx->httpc = http_client_ctx_create();
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/", buf, strlen(buf),
                        "127.0.0.1", 9880, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("http_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == atoi(response_code))) {
        TEST_MSG("http response code error. expect: %d, got: %d\n", atoi(response_code), c->resp.status);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_http_json_charset_header(char *response_code)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;

    char *buf = "[{\"test\":\"msg\"}]";

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "http2", "off",
                        "successful_response_code", response_code,
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ctx->httpc = http_client_ctx_create();
    TEST_CHECK(ctx->httpc != NULL);

    flb_time_msleep(1500);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/", buf, strlen(buf),
                        "127.0.0.1", 9880, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CHARSET_CONTENT_TYPE, strlen(JSON_CHARSET_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("http_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == atoi(response_code))) {
        TEST_MSG("http response code error. expect: %d, got: %d\n", atoi(response_code), c->resp.status);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_http_successful_response_code_200()
{
    flb_test_http_successful_response_code("200");
    flb_test_http_json_charset_header("200");
}

void flb_test_http_successful_response_code_204()
{
    flb_test_http_successful_response_code("204");
    flb_test_http_json_charset_header("204");
}

void flb_test_http_failure_400_bad_json() {
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    size_t b_sent;

    char *buf = "\"INVALIDJSON";

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd, NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ctx->httpc = http_client_ctx_create();
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/", buf, strlen(buf),
                        "127.0.0.1", 9880, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("http_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == 400)) {
        TEST_MSG("http response code error. expect: %d, got: %d\n", 400, c->resp.status);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_http_failure_400_bad_disk_write()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    size_t b_sent;

    char *buf = "{\"foo\": \"bar\"}";

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_service_set(ctx->flb,
                          "storage.path", "/tmp/http-input-test-404-bad-write",
                          NULL);
    TEST_CHECK(ret == 0);

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "storage.type", "filesystem",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    flb_time_msleep(5000);

    rmdir("/tmp/http-input-test-404-bad-write.fail/http.0");
    rmdir("/tmp/http-input-test-404-bad-write.fail");

    rename("/tmp/http-input-test-404-bad-write",
           "/tmp/http-input-test-404-bad-write.fail");

    ctx->httpc = http_client_ctx_create();
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/", buf, strlen(buf),
                        "127.0.0.1", 9880, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("http_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == 400)) {
        TEST_MSG("http response code error. expect: %d, got: %d\n", 400, c->resp.status);
    }

    rename("/tmp/http-input-test-404-bad-write.fail",
           "/tmp/http-input-test-404-bad-write");

    /* waiting to flush */
    flb_time_msleep(1500);

    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void test_http_tag_key(char *input)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;

    char *buf = input;

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "tag_key", "tag",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "new_tag",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ctx->httpc = http_client_ctx_create();
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/", buf, strlen(buf),
                        "127.0.0.1", 9880, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("http_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == 201)) {
        TEST_MSG("http response code error. expect: 201, got: %d\n", c->resp.status);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_http_tag_key_with_map_input()
{
    test_http_tag_key("{\"tag\":\"new_tag\",\"test\":\"msg\"}");
}

void flb_test_http_tag_key_with_array_input()
{
    test_http_tag_key("[{\"tag\":\"new_tag\",\"test\":\"msg\"}]");
}

TEST_LIST = {
    {"http", flb_test_http},
    {"successful_response_code_200", flb_test_http_successful_response_code_200},
    {"successful_response_code_204", flb_test_http_successful_response_code_204},
    {"failure_response_code_400_bad_json", flb_test_http_failure_400_bad_json},
    {"failure_response_code_400_bad_disk_write", flb_test_http_failure_400_bad_disk_write},
    {"tag_key_with_map_input", flb_test_http_tag_key_with_map_input},
    {"tag_key_with_array_input", flb_test_http_tag_key_with_array_input},
    {NULL, NULL}
};
