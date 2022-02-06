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
#include <monkey/mk_core.h>
#include <fluent-bit.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>
#include <monkey/mk_lib.h>
#include <pthread.h>
#include <time.h>
#include "flb_tests_internal.h"

#define HTTP_PORT 8080

struct upstream_ctx {
    struct flb_config *config;
    struct flb_upstream *upstream;
    mk_ctx_t *mk_ctx;
    int vhost_id;
};

static void cb_http_get(mk_request_t *request, void *data)
{
    mk_http_status(request, 200);
    mk_http_send(request, "OK", 2, NULL);
    mk_http_done(request);
}

struct flb_config *create_config()
{
    struct flb_config *config = NULL;
    
    config = flb_calloc(1, sizeof(struct flb_config));
    if (config == NULL) {
        return NULL;
    }
    mk_list_init(&config->upstreams);

    return config;
}

void config_exit(struct flb_config* config)
{
    flb_free(config);
}

int cleanup(struct upstream_ctx *u_ctx)
{
    int ret = 0;
    struct mk_event_loop *evl = NULL;
    struct flb_upstream *u = NULL;
    struct flb_config *config = NULL;
    mk_ctx_t   *mk_ctx = NULL;

    if (u_ctx == NULL) {
        return -1;
    }
    u = u_ctx->upstream;
    config = u_ctx->config;
    mk_ctx = u_ctx->mk_ctx;

    if (u) {
        ret = flb_upstream_destroy(u);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("flb_upstream_destroy failed");
            return -1;
        }
    }

    evl = flb_engine_evl_get();
    if (evl) {
        flb_engine_evl_set(NULL);
        mk_event_loop_destroy(evl);
    }

    if (config) {
        config_exit(config);
    }

    if (mk_ctx) {
        mk_stop(mk_ctx);
        mk_destroy(mk_ctx);
    }

    flb_free(u_ctx);

    return ret;
}

int start_http_server(struct upstream_ctx *u_ctx)
{
    char host_port[256];

    snprintf(&host_port[0], sizeof(host_port), "localhost:%d", HTTP_PORT);

    mk_config_set(u_ctx->mk_ctx, "Listen", &host_port[0], NULL);
    if(!TEST_CHECK(mk_start(u_ctx->mk_ctx) == 0)) {
        TEST_MSG("failed to setup http server");
        cleanup(u_ctx);
        return -1;
    }
    return 0;
}

int setup(struct upstream_ctx **ctx)
{
    struct mk_event_loop *evl = NULL;
    struct upstream_ctx *u_ctx = NULL;

    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("input ctx is NULL");
        return -1;
    }

    u_ctx = flb_calloc(1, sizeof(struct upstream_ctx));
    if (!TEST_CHECK(u_ctx != NULL)) {
        TEST_MSG("failed to allocate u_ctx");
        return -1;
    }
    u_ctx->config = create_config();
    if (!TEST_CHECK(u_ctx->config != NULL)) {
        TEST_MSG("config is NULL");
        flb_free(u_ctx);
        return -1;
    }
    evl = mk_event_loop_create(256);
    if (!TEST_CHECK(evl != NULL)) {
        TEST_MSG("evl is NULL");
        config_exit(u_ctx->config);
        flb_free(u_ctx);
        return -1;
    }
    u_ctx->config->evl = evl;

    /* flb_upstream_conn needs flb_engine_evl */
    flb_engine_evl_init();
    flb_engine_evl_set(evl);

    /* create upstream */
    u_ctx->upstream = flb_upstream_create(u_ctx->config, "localhost", HTTP_PORT, 0, NULL);
    if (!TEST_CHECK(u_ctx->upstream != NULL)) {
        TEST_MSG("upstream is NULL");
        config_exit(u_ctx->config);
        flb_free(u_ctx);
        return -1;
    }
    u_ctx->upstream->flags = 0; /* clear flags */


    /* create monkey server */
    u_ctx->mk_ctx = mk_create();
    if (!TEST_CHECK(u_ctx->mk_ctx != NULL)) {
        TEST_MSG("mk_ctx is NULL");
        config_exit(u_ctx->config);
        flb_upstream_destroy(u_ctx->upstream);
        flb_free(u_ctx);
    }

    u_ctx->vhost_id = mk_vhost_create(u_ctx->mk_ctx, NULL);
    mk_vhost_handler(u_ctx->mk_ctx, u_ctx->vhost_id, "/", cb_http_get, NULL);

    *ctx = u_ctx;
    return 0;
}


void test_upstream_create_destroy()
{
    struct upstream_ctx *u_ctx = NULL;
    int ret;

    ret = setup(&u_ctx);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("setup failed");
        return;
    }
    ret = cleanup(u_ctx);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cleanup failed");
        return;
    }
}

void test_upstream_create_keepalive()
{
    struct upstream_ctx *u_ctx = NULL;
    struct flb_upstream_conn *conn = NULL;
    
    int ret;
    int i;

    if (!TEST_CHECK(setup(&u_ctx) == 0)) {
        TEST_MSG("setup failed");
        return;
    }

    u_ctx->upstream->net.keepalive = FLB_TRUE;
    if (!TEST_CHECK(start_http_server(u_ctx) == 0)) {
        TEST_MSG("failed to start http server");
        return;
    }

    for (i=0; i<10000; i++) {
        conn = flb_upstream_conn_get(u_ctx->upstream);
        if (!TEST_CHECK(conn != NULL)) {
            TEST_MSG("%d: conn is NULL", i);
            break;
        }
        if (!TEST_CHECK(flb_upstream_conn_release(conn) == 0)) {
            TEST_MSG("%d: flb_upstream_conn_release failed", i);
            break;
        }
    }

    ret = cleanup(u_ctx);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cleanup failed");
        return;
    }
}

int http_get(struct flb_upstream *upstream)
{
    struct flb_upstream_conn *conn;
    struct flb_http_client *hc = NULL;
    char body[4096] = {0};
    size_t bytes = 0;
    int ret;

    conn = flb_upstream_conn_get(upstream);
    if (!TEST_CHECK(conn != NULL)) {
        TEST_MSG("conn is NULL");
        return -1;
    }
    /* create http client */
    hc = flb_http_client(conn, FLB_HTTP_GET, "/",
                         &body[0], sizeof(body),
                         "localhost", HTTP_PORT,
                         NULL,0);
    if(!TEST_CHECK(hc != NULL)) {
        TEST_MSG("http client is NULL");
        flb_upstream_conn_release(conn);
        return -1;
    }
    /* HTTP GET */
    ret = flb_http_do(hc, &bytes);
    if (!TEST_CHECK(ret == 0 && hc->resp.status == 200)) {
        TEST_MSG("flb_http_do failed=%d status=%d", ret, hc->resp.status);
        flb_http_client_destroy(hc);
        flb_upstream_conn_release(conn);
        return -1;
    }
    
    /*
     * Debug printf
     * printf("body:%s\n", hc->resp.data);
     */
    
    flb_http_client_destroy(hc);
    
    if (!TEST_CHECK(flb_upstream_conn_release(conn) == 0)) {
        TEST_MSG("flb_upstream_conn_release failed");
        return -1;
    }
    return 0;
}


void test_upstream_http_get()
{
    struct upstream_ctx *u_ctx = NULL;
    
    int ret;
    int i;

    if (!TEST_CHECK(setup(&u_ctx) == 0)) {
        TEST_MSG("setup failed");
        return;
    }

    if (!TEST_CHECK(start_http_server(u_ctx) == 0)) {
        TEST_MSG("failed to start http server");
        return;
    }

    for (i=0; i<10000; i++) {
        ret = http_get(u_ctx->upstream);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("%d: failed", i);
            break;
        }
    }

    ret = cleanup(u_ctx);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cleanup failed");
        return;
    }
}

struct thread_arg{
    struct flb_upstream *upstream;
    int interval_nsec;
    pthread_mutex_t *mutex;
};

void *http_get_thread(void *args)
{
    int i;
    struct thread_arg *t_arg = (struct thread_arg*)args;
    int ret;
    struct timespec tm;

    tm.tv_sec = 0;
    tm.tv_nsec = t_arg->interval_nsec;

    for (i=0; i<500; i++) {
        nanosleep(&tm, NULL);
        pthread_mutex_lock(t_arg->mutex);
        ret = http_get(t_arg->upstream);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("  %d:failed", i);
            pthread_mutex_unlock(t_arg->mutex);
            return NULL;
        }
        pthread_mutex_unlock(t_arg->mutex);
    }
    return NULL;
}


/* 
 * TODO: This test case causes SIGSEGV.
 *       It doesn't happend when net.keepalive = FLB_FALSE;
 *       We should fix keepalive issue.
 */
void test_upstream_keepalive_multi_thread()
{
    struct upstream_ctx *u_ctx = NULL;
    struct thread_arg t_arg;
    pthread_mutex_t test_mutex;
    pthread_t test_id;
    
    int ret;
    int i;

    pthread_mutex_init(&test_mutex, NULL);

    if (!TEST_CHECK(setup(&u_ctx) == 0)) {
        TEST_MSG("setup failed");
        pthread_mutex_destroy(&test_mutex);
        return;
    }

    /* If net.keepalive is FLB_FALSE, this test will exit successfully. */
    u_ctx->upstream->net.keepalive = FLB_TRUE;

    if (!TEST_CHECK(start_http_server(u_ctx) == 0)) {
        TEST_MSG("failed to start http server");
        pthread_mutex_destroy(&test_mutex);
        return;
    }
    t_arg.upstream = u_ctx->upstream;
    t_arg.interval_nsec = 500 * 1000; /* 500 usec */
    t_arg.mutex = &test_mutex;

    ret = pthread_create(&test_id, NULL, http_get_thread, (void*)&t_arg);

    /* TEST_CHECK is not thread-safe */
    pthread_mutex_lock(&test_mutex);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("pthread_create failed ret=%d", ret);
        pthread_mutex_unlock(&test_mutex);
        pthread_mutex_destroy(&test_mutex);
        return;
    }
    pthread_mutex_unlock(&test_mutex);

    for (i=0; i<10000; i++) {
        pthread_mutex_lock(&test_mutex);
        ret = http_get(t_arg.upstream);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("  %d:failed", i);
            pthread_mutex_unlock(&test_mutex);
            goto end;
        }
        pthread_mutex_unlock(&test_mutex);
    }
    pthread_join(test_id, NULL);
    ret = cleanup(u_ctx);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("cleanup failed");
    }
 end:
    pthread_mutex_destroy(&test_mutex);

}

TEST_LIST = {
    { "upstream_create_destroy"         , test_upstream_create_destroy},
    { "upstream_create_keepalive"       , test_upstream_create_keepalive},
    { "upstream_http_get"               , test_upstream_http_get},
    /* 
     * This test case causes SIGSEGV.
    { "upstream_keepalive_multi_thread" , test_upstream_keepalive_multi_thread},
    */
    { NULL, NULL }
};
