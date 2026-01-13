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
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>

#include <fluent-bit.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_http_client.h>
#include <monkey/mk_core.h>
#include "flb_tests_runtime.h"

#define JSON_CONTENT_TYPE "application/json"
#define JSON_CHARSET_CONTENT_TYPE "application/json; charset=utf-8"
#define MOCK_JWKS_BODY "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"test\",\"n\":\"xCUx72fXOyrjUZiiPJZIa7HtYHdQo_LAAkYG3yAcl1mwmh8pXrXB71xSDBI5SZDtKW4g6FEzYmP0jv3xwBdrZO2HQYwdxpCLhiMKEF0neC5w4NsjFlZKpnO53GN5W_c95bEhlVbh7O2q3PZVDhF5x9bdjlDS84NA0CY2l10UbSvIz12XR8uXqt6w9WVznrCe7ucSex3YPBTwll8Tm5H1rs1tPSx_9D0CJtZvxhKfgJtDyJJmV9syI6hlRgXnAsOonycOGSLryaIBtttxKUwy6QQkA-qSLZe2EcG2XoeBy10geOZ4WKGRiGubuuDpB1yFFy4mXQULJF6anO2osE31SQ\",\"e\":\"AQAB\"}]}"
#define MOCK_VALID_JWT "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE4OTM0NTYwMDAsImlzcyI6Imlzc3VlciIsImF1ZCI6ImF1ZGllbmNlIiwiYXpwIjoiY2xpZW50MSJ9.TqWs06LUpQa0FGLejnOkWAD6v562d5CUh2NwsJ7iAuae9-WNFBKU6mP1zAaoafla6o5npee7RfbSzZNFI4PKhqAj69789JjAYV7IW-GSuMwJejHdVOWmCc5lmcZPH0EVxEkHA6lFQxYQwDCrfQ8Sd4Q3vYCV6sLPENcuNpQi9ytjVjaZs_7ONH2oA-sZ7EUchqJJoIBPfjit2yYsq9NeemxCzYMtngiC-IX12eEfaQ1cVYPIjhhN_NaMvapznp-BW4gnXkNoAZ1S-p1axWWY-6UgRdMYOr0Hy5PHQ9fCuHJ6Z-blYdtuGavCUGHK5ghX-JdH1WJ51F89992dQ5yF_w"

struct jwks_mock_server {
    int listen_fd;
    int port;
    int stop;
    pthread_t thread;
};

static void jwks_mock_send_response(int fd)
{
    char buffer[512];

    snprintf(buffer, sizeof(buffer),
             "HTTP/1.1 200 OK\r\n"
             "Content-Length: %zu\r\n"
             "Content-Type: application/json\r\n"
             "Connection: close\r\n\r\n"
             "%s",
             strlen(MOCK_JWKS_BODY), MOCK_JWKS_BODY);

    send(fd, buffer, strlen(buffer), 0);
}

static void *jwks_mock_server_thread(void *data)
{
    struct jwks_mock_server *server = (struct jwks_mock_server *) data;
    fd_set rfds;
    struct timeval tv;
    int client_fd;

    client_fd = -1;
    while (!server->stop) {
        FD_ZERO(&rfds);
        FD_SET(server->listen_fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        if (select(server->listen_fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
            continue;
        }

        client_fd = accept(server->listen_fd, NULL, NULL);
        if (client_fd < 0) {
            continue;
        }

        jwks_mock_send_response(client_fd);
        close(client_fd);
    }

    return NULL;
}

static int jwks_mock_server_start(struct jwks_mock_server *server)
{
    int on = 1;
    struct sockaddr_in addr;
    socklen_t len;
    int flags;

    memset(server, 0, sizeof(struct jwks_mock_server));

    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listen_fd < 0) {
        return -1;
    }

    setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(server->listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(server->listen_fd);
        return -1;
    }

    len = sizeof(addr);
    if (getsockname(server->listen_fd, (struct sockaddr *) &addr, &len) < 0) {
        close(server->listen_fd);
        return -1;
    }

    server->port = ntohs(addr.sin_port);

    if (listen(server->listen_fd, 4) < 0) {
        close(server->listen_fd);
        return -1;
    }

    flags = fcntl(server->listen_fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(server->listen_fd, F_SETFL, flags | O_NONBLOCK);
    }

    if (pthread_create(&server->thread, NULL, jwks_mock_server_thread, server) != 0) {
        close(server->listen_fd);
        return -1;
    }

    return 0;
}

static void jwks_mock_server_stop(struct jwks_mock_server *server)
{
    if (server->listen_fd <= 0) {
        return;
    }

    server->stop = 1;
    pthread_join(server->thread, NULL);
    close(server->listen_fd);
}

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

void flb_test_http_legacy()
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

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "http2", "off",
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

void flb_test_http_oauth2_requires_token()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    struct jwks_mock_server jwks;
    char jwks_url[64];
    int ret;
    size_t b_sent;

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    if (!TEST_CHECK(jwks_mock_server_start(&jwks) == 0)) {
        TEST_MSG("unable to start mock jwks server");
        return;
    }

    snprintf(jwks_url, sizeof(jwks_url), "http://127.0.0.1:%d/jwks", jwks.port);

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        jwks_mock_server_stop(&jwks);
        return;
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "oauth2.validate", "true",
                        "oauth2.issuer", "issuer",
                        "oauth2.jwks_url", jwks_url,
                        "oauth2.allowed_audience", "audience",
                        "oauth2.allowed_clients", "client1",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ctx->httpc = http_client_ctx_create();
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/", "{\"test\":\"msg\"}", 15,
                        "127.0.0.1", 9880, NULL, 0);
    TEST_CHECK(c != NULL);

    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);

    ret = flb_http_do(c, &b_sent);
    TEST_CHECK(ret == 0);
    TEST_CHECK(c->resp.status == 401);

    flb_time_msleep(500);
    TEST_CHECK(get_output_num() == 0);

    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
    jwks_mock_server_stop(&jwks);
}

void flb_test_http_oauth2_accepts_valid_token()
{
    struct flb_lib_out_cb cb_data;
    struct test_ctx *ctx;
    struct flb_http_client *c;
    struct jwks_mock_server jwks;
    char jwks_url[64];
    int ret;
    size_t b_sent;

    clear_output_num();

    cb_data.cb = cb_check_result_json;
    cb_data.data = "\"test\":\"msg\"";

    if (!TEST_CHECK(jwks_mock_server_start(&jwks) == 0)) {
        TEST_MSG("unable to start mock jwks server");
        return;
    }

    snprintf(jwks_url, sizeof(jwks_url), "http://127.0.0.1:%d/jwks", jwks.port);

    ctx = test_ctx_create(&cb_data);
    if (!TEST_CHECK(ctx != NULL)) {
        jwks_mock_server_stop(&jwks);
        return;
    }

    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "oauth2.validate", "true",
                        "oauth2.issuer", "issuer",
                        "oauth2.jwks_url", jwks_url,
                        "oauth2.allowed_audience", "audience",
                        "oauth2.allowed_clients", "client1",
                        NULL);
    TEST_CHECK(ret == 0);

    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    ctx->httpc = http_client_ctx_create();
    TEST_CHECK(ctx->httpc != NULL);

    c = flb_http_client(ctx->httpc->u_conn, FLB_HTTP_POST, "/", "{\"test\":\"msg\"}", 15,
                        "127.0.0.1", 9880, NULL, 0);
    TEST_CHECK(c != NULL);

    ret = flb_http_add_header(c, FLB_HTTP_HEADER_CONTENT_TYPE, strlen(FLB_HTTP_HEADER_CONTENT_TYPE),
                              JSON_CONTENT_TYPE, strlen(JSON_CONTENT_TYPE));
    TEST_CHECK(ret == 0);

    ret = flb_http_add_header(c, FLB_HTTP_HEADER_AUTH, strlen(FLB_HTTP_HEADER_AUTH),
                              "Bearer " MOCK_VALID_JWT,
                              strlen("Bearer " MOCK_VALID_JWT));
    TEST_CHECK(ret == 0);

    ret = flb_http_do(c, &b_sent);
    TEST_CHECK(ret == 0);
    TEST_CHECK(c->resp.status == 201);

    flb_time_msleep(1500);
    TEST_CHECK(get_output_num() > 0);

    flb_http_client_destroy(c);
    flb_upstream_conn_release(ctx->httpc->u_conn);
    test_ctx_destroy(ctx);
    jwks_mock_server_stop(&jwks);
}

TEST_LIST = {
    {"http", flb_test_http},
    {"http_legacy", flb_test_http_legacy},
    {"successful_response_code_200", flb_test_http_successful_response_code_200},
    {"successful_response_code_204", flb_test_http_successful_response_code_204},
    {"failure_response_code_400_bad_json", flb_test_http_failure_400_bad_json},
    {"failure_response_code_400_bad_disk_write", flb_test_http_failure_400_bad_disk_write},
    {"tag_key_with_map_input", flb_test_http_tag_key_with_map_input},
    {"tag_key_with_array_input", flb_test_http_tag_key_with_array_input},
    {"oauth2_requires_token", flb_test_http_oauth2_requires_token},
    {"oauth2_accepts_valid_token", flb_test_http_oauth2_accepts_valid_token},
    {NULL, NULL}
};
