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
#include "../../plugins/in_splunk/splunk_prot.h"

#define JSON_CONTENT_TYPE "application/json"

struct in_splunk_client_ctx {
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
    struct in_splunk_client_ctx *httpc;
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

struct in_splunk_client_ctx* splunk_client_ctx_create(int port)
{
    struct in_splunk_client_ctx *ret_ctx = NULL;
    struct mk_event_loop *evl = NULL;

    ret_ctx = flb_calloc(1, sizeof(struct in_splunk_client_ctx));
    if (!TEST_CHECK(ret_ctx != NULL)) {
        flb_errno();
        TEST_MSG("flb_calloc(splunk_client_ctx) failed");
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
    i_ffd = flb_input(ctx->flb, (char *) "splunk", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;

    /* Output */
    o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    ctx->o_ffd = o_ffd;

    return ctx;
}

int splunk_client_ctx_destroy(struct in_splunk_client_ctx* ctx)
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
        splunk_client_ctx_destroy(ctx->httpc);
    }

    sleep(1);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

void flb_test_splunk_health()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    size_t b_sent;
    char *expected = "{\"text\":\"Success\",\"code\":200}";
    char *buf = NULL;
    int port = 8808;
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

    ctx->httpc = splunk_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_GET, "/services/collector/health", NULL, 0,
                        "127.0.0.1", port, NULL, 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("splunk_client failed");
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

void flb_test_splunk(int port, char *endpoint)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;
    char *buf = "{\"event\": \"Pony 1 has left the barn\"}{\"event\": \"Pony 2 has left the barn\"}{\"event\": \"Pony 3 has left the barn\", \"nested\": {\"key1\": \"value1\"}}";
    char *expected = "\"event\":";
    char sport[16];
    flb_sds_t target;

    target = flb_sds_create_size(64);
    flb_sds_cat(target, endpoint, strlen(endpoint));

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

    ctx->httpc = splunk_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, target, buf, strlen(buf),
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("splunk_client failed");
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
    flb_sds_destroy(target);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_splunk_collector()
{
    flb_test_splunk(8809, "/services/collector");
}

void flb_test_splunk_collector_event()
{
    flb_test_splunk(8810, "/services/collector/event");
}

void flb_test_splunk_raw(int port, char *endpoint)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;
    char *buf = "1, 2, 3... Hello, world!";
    char *expected = "\"log\":";
    char sport[16];

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

    ctx->httpc = splunk_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, endpoint, buf, strlen(buf),
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("splunk_client failed");
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

void flb_test_splunk_collector_raw()
{
    flb_test_splunk_raw(8811, "/services/collector/raw");
}

void flb_test_splunk_raw_multilines(int port)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;
    char *buf = "127.0.0.1 - admin [28/Sep/2016:09:05:26.875 -0700] \"GET /servicesNS/admin/launcher/data/ui/views?count=-1 HTTP/1.0\" 200 126721 - - - 6ms" \
            "127.0.0.1 - admin [28/Sep/2016:09:05:26.917 -0700] \"GET /servicesNS/admin/launcher/data/ui/nav/default HTTP/1.0\" 200 4367 - - - 6ms" \
            "127.0.0.1 - admin [28/Sep/2016:09:05:26.941 -0700] \"GET /services/apps/local?search=disabled%3Dfalse&count=-1 HTTP/1.0\" 200 31930 - - - 4ms" \
            "127.0.0.1 - admin [28/Sep/2016:09:05:26.954 -0700] \"GET /services/apps/local?search=disabled%3Dfalse&count=-1 HTTP/1.0\" 200 31930 - - - 3ms" \
            "127.0.0.1 - admin [28/Sep/2016:09:05:26.968 -0700] \"GET /servicesNS/admin/launcher/data/ui/views?digest=1&count=-1 HTTP/1.0\" 200 58672 - - - 5ms";
    char *expected = "\"log\":";
    char sport[16];

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

    ctx->httpc = splunk_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/services/collector/raw", buf, strlen(buf),
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("splunk_client failed");
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

void flb_test_splunk_collector_raw_multilines()
{
    flb_test_splunk_raw_multilines(8812);
}

void flb_test_splunk_tag_key()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;
    int port = 8812;
    char sport[16];

    char *buf = "{\"event\": \"Pony 1 has left the barn\",\"tag\":\"new_tag\"}";

    snprintf(sport, 16, "%d", port);

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"event\":\"Pony 1 has left the barn\",\"tag\":\"new_tag\"";

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

    ctx->httpc = splunk_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/services/collector", buf, strlen(buf),
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("splunk_client failed");
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

void flb_test_splunk_gzip(int port, char *endpoint)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;
    char *buf = "{\"event\": \"Pony 1 has left the barn\"}{\"event\": \"Pony 2 has left the barn\"}{\"event\": \"Pony 3 has left the barn\", \"nested\": {\"key1\": \"value1\"}}";
    char *expected = "\"event\":";
    char sport[16];
    flb_sds_t target;
    void *final_data;
    size_t final_bytes;

    target = flb_sds_create_size(64);
    flb_sds_cat(target, endpoint, strlen(endpoint));

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

    ctx->httpc = splunk_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    ret = flb_gzip_compress((void *) buf, strlen(buf), &final_data, &final_bytes);
    TEST_CHECK(ret != -1);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, target, final_data, final_bytes,
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    /* Add Content-Encoding: gzip */
    ret = flb_http_add_header(c, "Content-Encoding", 16, "gzip", 4);
    TEST_CHECK(ret == 0);

    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("splunk_client failed");
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
    flb_sds_destroy(target);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_splunk_collector_gzip()
{
    flb_test_splunk_gzip(8813, "/services/collector");
}

void flb_test_splunk_collector_event_gzip()
{
    flb_test_splunk_gzip(8814, "/services/collector/event");
}

void flb_test_splunk_raw_multilines_gzip(int port)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;
    char *buf = "127.0.0.1 - admin [28/Sep/2016:09:05:26.875 -0700] \"GET /servicesNS/admin/launcher/data/ui/views?count=-1 HTTP/1.0\" 200 126721 - - - 6ms" \
            "127.0.0.1 - admin [28/Sep/2016:09:05:26.917 -0700] \"GET /servicesNS/admin/launcher/data/ui/nav/default HTTP/1.0\" 200 4367 - - - 6ms" \
            "127.0.0.1 - admin [28/Sep/2016:09:05:26.941 -0700] \"GET /services/apps/local?search=disabled%3Dfalse&count=-1 HTTP/1.0\" 200 31930 - - - 4ms" \
            "127.0.0.1 - admin [28/Sep/2016:09:05:26.954 -0700] \"GET /services/apps/local?search=disabled%3Dfalse&count=-1 HTTP/1.0\" 200 31930 - - - 3ms" \
            "127.0.0.1 - admin [28/Sep/2016:09:05:26.968 -0700] \"GET /servicesNS/admin/launcher/data/ui/views?digest=1&count=-1 HTTP/1.0\" 200 58672 - - - 5ms";
    char *expected = "\"log\":";
    char sport[16];
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

    ctx->httpc = splunk_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    ret = flb_gzip_compress((void *) buf, strlen(buf), &final_data, &final_bytes);
    TEST_CHECK(ret != -1);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/services/collector/raw", final_data, final_bytes,
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    /* Add Content-Encoding: gzip */
    ret = flb_http_add_header(c, "Content-Encoding", 16, "gzip", 4);
    TEST_CHECK(ret == 0);

    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("splunk_client failed");
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
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_splunk_collector_raw_multilines_gzip()
{
    flb_test_splunk_raw_multilines_gzip(8815);
}

#define SPLUNK_HEC_TOKEN "Splunk b386261b-d949-411a-b4e8-0103211aa7ae"

void flb_test_splunk_auth_header(int port, char *endpoint)
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;
    char *buf = "{\"event\": \"Pony 1 has left the barn\"}{\"event\": \"Pony 2 has left the barn\"}{\"event\": \"Pony 3 has left the barn\", \"nested\": {\"key1\": \"value1\"}}";
    char *expected = "\"@splunk_token\":";
    char sport[16];
    flb_sds_t target;

    target = flb_sds_create_size(64);
    flb_sds_cat(target, endpoint, strlen(endpoint));

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
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "store_token_in_metadata", "false",
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

    ctx->httpc = splunk_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, target, buf, strlen(buf),
                        "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_AUTH, strlen(FLB_HTTP_HEADER_AUTH),
                              SPLUNK_HEC_TOKEN, strlen(SPLUNK_HEC_TOKEN));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("splunk_client failed");
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
    flb_sds_destroy(target);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
}

void flb_test_splunk_collector_event_hec_token_key()
{
    flb_test_splunk_auth_header(8816, "/services/collector/event");
}

void flb_test_splunk_collector_raw_hec_token_key()
{
    flb_test_splunk_auth_header(8817, "/services/collector/raw");
}

/* 1.0 endpoints */

void flb_test_splunk_collector_raw_1_0()
{
    flb_test_splunk_raw(8818, "/services/collector/raw/1.0");
}

void flb_test_splunk_collector_event_1_0()
{
    flb_test_splunk(8819, "/services/collector/event/1.0");
}

void flb_test_splunk_xff_extract()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    int ret;
    int num;
    size_t b_sent;
    char *buf = "{\"event\": \"Pony 1 has left the barn\"}";
    char *expected = "\"xff\":\"203.0.113.1\"";
    char *xff_value = " 203.0.113.1, 70.41.3.18, 150.172.238.178";
    char sport[16];
    int port = 8820;

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
                        "add_remote_addr", "true",
                        "remote_addr_key", "xff",
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

    ctx->httpc = splunk_client_ctx_create(port);
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/services/collector/event",
                        buf, strlen(buf), "127.0.0.1", port, NULL, 0);
    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE,
                              strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);
    ret = flb_http_add_header(c, SPLUNK_XFF_HEADER,
                              strlen(SPLUNK_XFF_HEADER),
                              xff_value, strlen(xff_value));
    TEST_CHECK(ret == 0);
    if (!TEST_CHECK(c != NULL)) {
        TEST_MSG("splunk_client failed");
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

TEST_LIST = {
    {"health", flb_test_splunk_health},
    {"collector", flb_test_splunk_collector},
    {"collector_event", flb_test_splunk_collector_event},
    {"collector_event_1.0", flb_test_splunk_collector_event_1_0},
    {"collector_raw", flb_test_splunk_collector_raw},
    {"collector_raw_1.0", flb_test_splunk_collector_raw_1_0},
    {"collector_raw_multilines", flb_test_splunk_collector_raw_multilines},
    {"collector_gzip", flb_test_splunk_collector_gzip},
    {"collector_event_gzip", flb_test_splunk_collector_event_gzip},
    {"collector_raw_multilines_gzip", flb_test_splunk_collector_raw_multilines_gzip},
    {"tag_key", flb_test_splunk_tag_key},
    {"collector_event_with_auth_key", flb_test_splunk_collector_event_hec_token_key},
    {"collector_raw_with_auth_key", flb_test_splunk_collector_raw_hec_token_key},
    {"collector_xff_extract", flb_test_splunk_xff_extract},
    {NULL, NULL}
};
