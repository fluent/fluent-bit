/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2023 The Fluent Bit Authors
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
#include <fluent-bit/flb_gzip.h>
#include <monkey/mk_core.h>
#include "flb_tests_runtime.h"

/* Test data */
#include "data/in_elasticsearch/json_bulk.h" /* NDBULK_JSON */

#define NDJSON_CONTENT_TYPE "application/x-ndjson"

struct in_elasticsearch_client_ctx {
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
    struct in_elasticsearch_client_ctx *httpc;
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

struct in_elasticsearch_client_ctx* in_elasticsearch_client_ctx_create(int port)
{
    struct in_elasticsearch_client_ctx *ret_ctx = NULL;
    struct mk_event_loop *evl = NULL;

    ret_ctx = flb_calloc(1, sizeof(struct in_elasticsearch_client_ctx));
    if (!TEST_CHECK(ret_ctx != NULL)) {
        flb_errno();
        TEST_MSG("flb_calloc(in_elasticsearch_client_ctx) failed");
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

    ret_ctx->u = flb_upstream_create(ret_ctx->config, "127.0.0.1", port, 0, NULL);
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
    i_ffd = flb_input(ctx->flb, (char *) "elasticsearch", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;

    return ctx;
}

int in_elasticsearch_client_ctx_destroy(struct in_elasticsearch_client_ctx* ctx)
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
        in_elasticsearch_client_ctx_destroy(ctx->httpc);
    }

    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void flb_test_in_elasticsearch_version()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    size_t b_sent;
    char *expected = "\"version\":{\"number\":\"8.0.0\",\"build_flavor\"";
    char *buf = NULL;
    int port = 9201;
    char sport[16];

    snprintf(sport, 16, "%d", port);

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "port", sport,
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

    ctx->httpc = in_elasticsearch_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_GET, "/", NULL, 0,
                        "127.0.0.1", port, NULL, 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("in_elasticsearch_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == 200)) {
        TEST_MSG("http response code error. expect: 200, got: %d\n", c->resp.status);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    buf = strstr(c->resp.payload, expected);
    if (!TEST_CHECK(buf != NULL)) {
      TEST_MSG("http request for version info failed");
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_in_elasticsearch(char *write_op, int port, char *tag)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;
    char buf[64];
    char expected[64];
    char sport[16];

    snprintf(buf, 64,  "{\"%s\":{\"_index\":\"fluent-bit\",\"_id\":1}}\n{\"test\":\"msg\"}\n", write_op);
    snprintf(expected, 64, "\"@meta\":{\"%s\":{\"_index\":\"fluent-bit\",\"_id\":1}},\"test\":\"msg\"", write_op);

    snprintf(sport, 16, "%d", port);

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "port", sport,
                        NULL);
    TEST_CHECK(ret == 0);
    if (tag != NULL) {
        ret = flb_input_set(ctx->flb, ctx->i_ffd,
                            "tag", tag,
                            NULL);
        TEST_CHECK(ret == 0);
    }

    if (tag != NULL) {
        ret = flb_output_set(ctx->flb, ctx->o_ffd,
                             "match", tag,
                             "format", "json",
                             NULL);
        TEST_CHECK(ret == 0);
    }
    else {
        ret = flb_output_set(ctx->flb, ctx->o_ffd,
                             "match", "*",
                             "format", "json",
                             NULL);
        TEST_CHECK(ret == 0);
    }

    /* Start the engine */
    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ctx->httpc = in_elasticsearch_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/_bulk", buf, strlen(buf),
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              NDJSON_CONTENT_TYPE, strlen(NDJSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("in_elasticsearch_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == 200)) {
        TEST_MSG("http response code error. expect: 200, got: %d\n", c->resp.status);
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

void flb_test_in_elasticsearch_index_op()
{
    flb_test_in_elasticsearch("index", 9202, NULL);
}

void flb_test_in_elasticsearch_create_op()
{
    flb_test_in_elasticsearch("create", 9203, NULL);
}

void flb_test_in_elasticsearch_invalid(char *write_op, int status, char *expected_op, int port)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;
    char buf[64];
    char expected[64];
    char *ret_buf = NULL;
    char sport[16];

    snprintf(buf, 64,  "{\"%s\":{\"_index\":\"fluent-bit\",\"_id\":1}}\n{\"test\":\"msg\"}\n", write_op);
    snprintf(expected, 64, "{\"%s\":{\"status\":%d", expected_op, status);

    snprintf(sport, 16, "%d", port);

    clear_output_num();

    cb_data.cb = NULL;
    cb_data.data = NULL;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "port", sport,
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

    ctx->httpc = in_elasticsearch_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/_bulk", buf, strlen(buf),
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              NDJSON_CONTENT_TYPE, strlen(NDJSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("in_elasticsearch_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == 200)) {
        TEST_MSG("http response code error. expect: 200, got: %d\n", c->resp.status);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num == 0))  {
        TEST_MSG("invalid ingested requests");
    }
    ret_buf = strstr(c->resp.payload, expected);
    if (!TEST_CHECK(ret_buf != NULL)) {
      TEST_MSG("http request for bulk failed");
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_in_elasticsearch_update_op()
{
    flb_test_in_elasticsearch_invalid("update", 403, "update", 9204);
}

void flb_test_in_elasticsearch_delete_op()
{
    flb_test_in_elasticsearch_invalid("delete", 404, "delete", 9205);
}

void flb_test_in_elasticsearch_nonexistent_op()
{
    flb_test_in_elasticsearch_invalid("nonexistent", 400, "unknown", 9206);
}

void flb_test_in_elasticsearch_multi_ops()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    int port = 9207;
    char sport[16];
    size_t b_sent;
    char *buf = NDJSON_BULK;
    char *expected = ":{\"_index\":\"test\",\"_id\":";
    char *ret_buf = NULL;
    char *ret_expected = "{\"errors\":true,\"items\":[";

    snprintf(sport, 16, "%d", port);

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "port", sport,
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

    ctx->httpc = in_elasticsearch_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/_bulk", buf, strlen(buf),
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              NDJSON_CONTENT_TYPE, strlen(NDJSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("in_elasticsearch_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == 200)) {
        TEST_MSG("http response code error. expect: 200, got: %d\n", c->resp.status);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }
    ret_buf = strstr(c->resp.payload, ret_expected);
    if (!TEST_CHECK(ret_buf != NULL)) {
      TEST_MSG("bulk request for multi write ops failed");
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_in_elasticsearch_multi_ops_gzip()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    int port = 9208;
    char sport[16];
    size_t b_sent;
    char *buf = NDJSON_BULK;
    char *expected = ":{\"_index\":\"test\",\"_id\":";
    char *ret_buf = NULL;
    char *ret_expected = "{\"errors\":true,\"items\":[";
    void *final_data;
    size_t final_bytes;

    snprintf(sport, 16, "%d", port);

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = expected;

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "port", sport,
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

    ctx->httpc = in_elasticsearch_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    ret = flb_gzip_compress((void *) buf, strlen(buf), &final_data, &final_bytes);
    TEST_CHECK(ret != -1);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/_bulk", final_data, final_bytes,
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              NDJSON_CONTENT_TYPE, strlen(NDJSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    /* Add Content-Encoding: gzip */
    ret = flb_http_add_header(c, "Content-Encoding", 16, "gzip", 4);
    TEST_CHECK(ret == 0);

    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("in_elasticsearch_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == 200)) {
        TEST_MSG("http response code error. expect: 200, got: %d\n", c->resp.status);
    }
    flb_free(final_data);

    /* waiting to flush */
    flb_time_msleep(1500);

    num = get_output_num();
    if (!TEST_CHECK(num > 0))  {
        TEST_MSG("no outputs");
    }
    ret_buf = strstr(c->resp.payload, ret_expected);
    if (!TEST_CHECK(ret_buf != NULL)) {
      TEST_MSG("bulk request for multi write ops failed");
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_in_elasticsearch_node_info()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int port = 9208;
    char sport[16];
    size_t b_sent;
    char *expected = "{\"_nodes\":{\"total\":1,\"successful\":1,\"failed\":0},\"nodes\":{\"";
    char *buf = NULL;

    snprintf(sport, 16, "%d", port);

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "port", sport,
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

    ctx->httpc = in_elasticsearch_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_GET, "/_nodes/http", NULL, 0,
                        "127.0.0.1", port, NULL, 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("in_elasticsearch_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == 200)) {
        TEST_MSG("http response code error. expect: 200, got: %d\n", c->resp.status);
    }

    /* waiting to flush */
    flb_time_msleep(1500);

    buf = strstr(c->resp.payload, expected);
    if (!TEST_CHECK(buf != NULL)) {
      TEST_MSG("http request for version info failed");
    }
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_in_elasticsearch_tag_key()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;
    int port = 9209;
    char sport[16];

    char *buf = "{\"index\":{\"_index\":\"fluent-bit\"}}\n{\"test\":\"msg\",\"tag\":\"new_tag\"}\n";

    snprintf(sport, 16, "%d", port);

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"@meta\":{\"index\":{\"_index\":\"fluent-bit\"}},\"test\":\"msg\",\"tag\":\"new_tag\"";

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("test_ctx_create failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "port", sport,
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

    ctx->httpc = in_elasticsearch_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/_bulk", buf, strlen(buf),
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              NDJSON_CONTENT_TYPE, strlen(NDJSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("in_elasticsearch_client failed");
        exit(EXIT_FAILURE);
    }

    ret = flb_http_do(c, &b_sent);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("ret error. ret=%d\n", ret);
    }
    else if (!TEST_CHECK(b_sent > 0)){
        TEST_MSG("b_sent size error. b_sent = %lu\n", b_sent);
    }
    else if (!TEST_CHECK(c->resp.status == 200)) {
        TEST_MSG("http response code error. expect: 200, got: %d\n", c->resp.status);
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

void flb_test_in_elasticsearch_index_op_with_plugin_tag()
{
    flb_test_in_elasticsearch("index", 9210, "es.index");
}

TEST_LIST = {
    {"version", flb_test_in_elasticsearch_version},
    {"index_op", flb_test_in_elasticsearch_index_op},
    {"create_op", flb_test_in_elasticsearch_create_op},
    {"update_op", flb_test_in_elasticsearch_update_op},
    {"delete_op", flb_test_in_elasticsearch_delete_op},
    {"nonexistent_op", flb_test_in_elasticsearch_nonexistent_op},
    {"multi_ops", flb_test_in_elasticsearch_multi_ops},
    {"multi_ops_gzip", flb_test_in_elasticsearch_multi_ops_gzip},
    {"index_op_with_plugin_tag", flb_test_in_elasticsearch_index_op_with_plugin_tag},
    {"node_info", flb_test_in_elasticsearch_node_info},
    {"tag_key", flb_test_in_elasticsearch_tag_key},
    {NULL, NULL}
};
