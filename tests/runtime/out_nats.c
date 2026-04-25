/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_stream.h>
#include <fluent-bit/flb_time.h>

#include "flb_tests_runtime.h"

#define DEFAULT_IO_TIMEOUT 10
#define DEFAULT_HOST       "127.0.0.1"
#define DEFAULT_PORT       "54222"

#define TLS_CERTIFICATE_HOSTNAME "leo.vcap.me"
#define TLS_CERTIFICATE_FILENAME FLB_TESTS_DATA_PATH "/data/tls/certificate.pem"
#define TLS_PRIVATE_KEY_FILENAME FLB_TESTS_DATA_PATH "/data/tls/private_key.pem"

struct test_ctx {
    flb_ctx_t *flb;
    int i_ffd;
    int o_ffd;
};

struct server_ctx {
    struct flb_config *config;
    struct flb_tls *tls;
    char buf[4096];
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int use_tls;
    int ready;
};

static struct test_ctx *test_ctx_create(void)
{
    int i_ffd;
    int o_ffd;
    struct test_ctx *ctx;

    ctx = flb_calloc(1, sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        flb_errno();
        return NULL;
    }

    ctx->flb = flb_create();
    if (!TEST_CHECK(ctx->flb != NULL)) {
        flb_free(ctx);
        return NULL;
    }

    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    i_ffd = flb_input(ctx->flb, (char *) "dummy", NULL);
    TEST_CHECK(i_ffd >= 0);
    ctx->i_ffd = i_ffd;
    flb_input_set(ctx->flb, ctx->i_ffd,
                  "tag", "camera.one",
                  "samples", "1",
                  "dummy", "{\"msg\":\"hello world\"}",
                  NULL);

    o_ffd = flb_output(ctx->flb, (char *) "nats", NULL);
    TEST_CHECK(o_ffd >= 0);
    ctx->o_ffd = o_ffd;

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->flb) {
        flb_stop(ctx->flb);
        flb_destroy(ctx->flb);
    }

    flb_free(ctx);
}

static void read_nats_payload(struct flb_connection *client_connection,
                              char *buf, size_t buf_size)
{
    int ret;
    int total = 0;

    while (total < buf_size - 1) {
        ret = flb_io_net_read(client_connection,
                              (void *) (buf + total),
                              buf_size - total - 1);
        if (ret <= 0) {
            break;
        }

        total += ret;
        buf[total] = '\0';

        if (strstr(buf, "\r\nPUB camera.one ") != NULL ||
            strncmp(buf, "PUB camera.one ", 15) == 0) {
            break;
        }
    }
}

static void *server_thread(void *data)
{
    unsigned short int port;
    struct server_ctx *server;
    struct flb_net_setup downstream_net_setup;
    struct flb_downstream *downstream;
    struct flb_connection *client_connection;

    server = data;
    port = strtoul(DEFAULT_PORT, NULL, 10);

    memset(&downstream_net_setup, 0, sizeof(downstream_net_setup));
    flb_net_setup_init(&downstream_net_setup);
    downstream_net_setup.io_timeout = DEFAULT_IO_TIMEOUT;

    downstream = flb_downstream_create(FLB_TRANSPORT_TCP,
                                       server->use_tls == FLB_TRUE ?
                                       FLB_IO_TCP | FLB_IO_TLS : FLB_IO_TCP,
                                       DEFAULT_HOST,
                                       port,
                                       server->tls,
                                       server->config,
                                       &downstream_net_setup);
    TEST_CHECK(downstream != NULL);

    pthread_mutex_lock(&server->mutex);
    server->ready = FLB_TRUE;
    pthread_cond_signal(&server->cond);
    pthread_mutex_unlock(&server->mutex);

    if (!downstream) {
        return NULL;
    }

    flb_stream_disable_async_mode(&downstream->base);
    flb_net_socket_blocking(downstream->server_fd);

    client_connection = flb_downstream_conn_get(downstream);
    TEST_CHECK(client_connection != NULL);

    if (client_connection) {
        read_nats_payload(client_connection, server->buf, sizeof(server->buf));
    }

    flb_downstream_destroy(downstream);

    return NULL;
}

static void run_nats_connect_test(int use_tls)
{
    int ret;
    struct test_ctx *ctx;
    struct flb_tls *tls = NULL;
    struct server_ctx server;
    pthread_t tid;

    memset(&server, 0, sizeof(server));
    pthread_mutex_init(&server.mutex, NULL);
    pthread_cond_init(&server.cond, NULL);

    ctx = test_ctx_create();
    if (!TEST_CHECK(ctx != NULL)) {
        return;
    }

    if (use_tls == FLB_TRUE) {
        ret = flb_output_set(ctx->flb, ctx->o_ffd,
                             "match",      "*",
                             "host",       DEFAULT_HOST,
                             "port",       DEFAULT_PORT,
                             "user",       "admin",
                             "password",   "1234567",
                             "tls",        "on",
                             "tls.verify", "no",
                             "tls.vhost",  TLS_CERTIFICATE_HOSTNAME,
                             NULL);
    }
    else {
        ret = flb_output_set(ctx->flb, ctx->o_ffd,
                             "match",    "*",
                             "host",     DEFAULT_HOST,
                             "port",     DEFAULT_PORT,
                             "user",     "admin",
                             "password", "1234567",
                             NULL);
    }
    TEST_CHECK(ret == 0);

    if (use_tls == FLB_TRUE) {
        ret = flb_tls_init();
        TEST_CHECK(ret == 0);

        tls = flb_tls_create(FLB_TLS_SERVER_MODE,
                             FLB_FALSE,
                             FLB_TRUE,
                             TLS_CERTIFICATE_HOSTNAME,
                             NULL,
                             NULL,
                             TLS_CERTIFICATE_FILENAME,
                             TLS_PRIVATE_KEY_FILENAME,
                             NULL);
        TEST_CHECK(tls != NULL);
    }

    server.config = ctx->flb->config;
    server.tls = tls;
    server.use_tls = use_tls;

    ret = pthread_create(&tid, NULL, server_thread, &server);
    TEST_CHECK(ret == 0);

    pthread_mutex_lock(&server.mutex);
    while (server.ready == FLB_FALSE) {
        pthread_cond_wait(&server.cond, &server.mutex);
    }
    pthread_mutex_unlock(&server.mutex);

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    pthread_join(tid, NULL);
    sleep(1);

    if (tls) {
        flb_tls_destroy(tls);
    }

    TEST_CHECK(strstr(server.buf, "CONNECT {") != NULL);
    TEST_CHECK(strstr(server.buf, "\"user\":\"admin\"") != NULL);
    TEST_CHECK(strstr(server.buf, "\"pass\":\"1234567\"") != NULL);
    TEST_CHECK(strstr(server.buf,
                      use_tls == FLB_TRUE ?
                      "\"ssl_required\":true" :
                      "\"ssl_required\":false") != NULL);

    if (use_tls == FLB_TRUE) {
        TEST_CHECK(strstr(server.buf, "PUB camera.one ") != NULL);
    }

    test_ctx_destroy(ctx);
    pthread_cond_destroy(&server.cond);
    pthread_mutex_destroy(&server.mutex);
}

void flb_test_nats_connect_auth_tls(void)
{
    run_nats_connect_test(FLB_TRUE);
}

TEST_LIST = {
    {"nats_connect_auth_tls", flb_test_nats_connect_auth_tls},
    {NULL, NULL}
};
