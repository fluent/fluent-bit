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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_time_utils.h>
#include <fluent-bit/flb_network.h>

#define STATUS_OK        1
#define STATUS_ERROR     0
#define STATUS_PENDING  -1
#define CALLBACK_TIME    2 /* 2 seconds */

#define SERVER_PORT      "9092"
#define SERVER_IFACE     "0.0.0.0"

struct unit_test {
    int id;
    int coll_id;
    int status;
    char *desc;
};

struct unit_test tests[] = {
    {0, 0, STATUS_PENDING, "collector time"},
    {1, 0, STATUS_PENDING, "collector fd_event"},
    {2, 0, STATUS_PENDING, "collector fd_server | socket"},
    {3, 0, STATUS_PENDING, "plugin paused from engine"},
    {4, 0, STATUS_PENDING, "plugin resumed from engine"},
};

#define UNIT_TESTS_SIZE  (sizeof(tests) / sizeof(struct unit_test))

struct event_test {
    flb_pipefd_t pipe[2];
    int server_fd;
    int client_coll_id;
    struct flb_upstream *upstream;
    struct unit_test *tests;
    struct flb_input_instance *ins;
};

static void set_unit_test_status(struct event_test *ctx, int id, int status)
{
    struct unit_test *ut;

    ut = &ctx->tests[id];
    ut->status = status;
}

static int config_destroy(struct event_test *ctx)
{
    if (!ctx) {
        return 0;
    }

    if (ctx->tests) {
        flb_free(ctx->tests);
    }

    if (ctx->pipe[0] > 0) {
        flb_socket_close(ctx->pipe[0]);
    }
    if (ctx->pipe[1] > 0) {
        flb_socket_close(ctx->pipe[1]);
    }
    if (ctx->server_fd > 0) {
        flb_socket_close(ctx->server_fd);
    }

    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }

    flb_free(ctx);
    return 0;
}

static int cb_collector_time(struct flb_input_instance *ins,
                            struct flb_config *config, void *in_context)
{
    int diff;
    int ret;
    uint64_t val;
    time_t now;
    struct unit_test *ut;
    struct event_test *ctx = (struct event_test *) in_context;

    now = time(NULL);
    diff = now - config->init_time;
    /* For macOS, we sometimes get the +1 longer time elapse.
     * To handle this, we simply add +1 as a delta for checking interval. */
    if (diff > (CALLBACK_TIME + 1)) {
        flb_plg_error(ins, "cb_collector_time difference failed: %i seconds", diff);
        set_unit_test_status(ctx, 0, STATUS_ERROR);
        flb_engine_exit(config);
    }

    /* disable the collector */
    ut = &ctx->tests[0];
    flb_input_collector_pause(ut->coll_id, ins);

    /*
     * before to return, trigger test 1 (collector_fd_event) by writing a byte
     * to our local pipe.
     */
    val = 1;
    ret = write(ctx->pipe[1], &val, sizeof(val));
    if (ret == -1) {
        flb_errno();
        set_unit_test_status(ctx, 0, STATUS_ERROR);
        flb_engine_exit(config);
    }

    set_unit_test_status(ctx, 0, STATUS_OK);
    flb_plg_info(ins, "[OK] collector_time");
    FLB_INPUT_RETURN(0);
}

static int cb_collector_fd(struct flb_input_instance *ins,
                           struct flb_config *config, void *in_context)
{
    uint64_t val = 0;
    size_t bytes;
    struct unit_test *ut;
    struct event_test *ctx = (struct event_test *) in_context;

    bytes = read(ctx->pipe[0], &val, sizeof(val));
    if (bytes <= 0) {
        flb_errno();
        set_unit_test_status(ctx, 1, STATUS_ERROR);
        flb_engine_exit(config);
    }
    else {
        flb_plg_info(ins, "[OK] collector_fd");
    }

    /* disable the collector */
    ut = &ctx->tests[1];
    flb_input_collector_pause(ut->coll_id, ins);
    set_unit_test_status(ctx, 1, STATUS_OK);

    FLB_INPUT_RETURN(0);
}

static int cb_collector_server_socket(struct flb_input_instance *ins,
                                      struct flb_config *config, void *in_context)
{
    int fd;
    struct unit_test *ut;
    struct event_test *ctx = in_context;

    /* Accept the new connection */
    fd = flb_net_accept(ctx->server_fd);
    if (fd == -1) {
        flb_plg_error(ins, "could not accept new connection");
        return -1;
    }

    /* sleep co-routine for 500ms */
    flb_time_sleep(500);
    flb_socket_close(fd);

    ut = &ctx->tests[2];
    flb_input_collector_pause(ut->coll_id, ins);
    set_unit_test_status(ctx, 2, STATUS_OK);

    flb_plg_info(ins, "[OK] collector_server_socket");

    /* tell the engine to deliver a pause request */
    flb_plg_info(ins, "test pause/resume in 5 seconds...");
    flb_input_test_pause_resume(ins, 5);

    /* return */
    FLB_INPUT_RETURN(0);
}

static int cb_collector_server_client(struct flb_input_instance *ins,
                                      struct flb_config *config, void *in_context)
{
    struct flb_connection *u_conn;
    struct event_test *ctx = (struct event_test *) in_context;

    /* get the upstream connection (localhost) */
    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ins, "could not connect to socket server");
        return -1;
    }

    flb_time_sleep(200);
    flb_upstream_conn_release(u_conn);

    /* disable this collector */
    flb_input_collector_pause(ctx->client_coll_id, ins);
    FLB_INPUT_RETURN(0);
}

static struct event_test *config_create(struct flb_input_instance *ins)
{
    size_t size;
    struct event_test *ctx;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct event_test));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    size = sizeof(struct unit_test) * UNIT_TESTS_SIZE;
    ctx->tests = flb_malloc(size);
    if (!ctx->tests) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }
    memcpy(ctx->tests, &tests, size);
    return ctx;
}

/* Initialize plugin */
static int cb_event_test_init(struct flb_input_instance *ins,
                              struct flb_config *config, void *data)
{
    int fd;
    int ret;
    struct unit_test *ut;
    struct event_test *ctx = NULL;
    struct flb_upstream *upstream;

    /* Allocate space for the configuration */
    ctx = config_create(ins);
    if (!ctx) {
        return -1;
    }
    flb_input_set_context(ins, ctx);

    /* unit test 0: collector_time */
    ret = flb_input_set_collector_time(ins, cb_collector_time,
                                       CALLBACK_TIME, 0, config);
    if (ret < 0) {
        config_destroy(ctx);
        return -1;
    }
    ut = &ctx->tests[0];
    ut->coll_id = ret;

    /* unit test 1: collector_fd_event */
    ret = flb_pipe_create(ctx->pipe);
    if (ret == -1) {
        flb_errno();
        config_destroy(ctx);
        return -1;
    }
    ret = flb_input_set_collector_event(ins,
                                        cb_collector_fd,
                                        ctx->pipe[0],
                                        config);
    if (ret < 0) {
        config_destroy(ctx);
        return -1;
    }
    ut = &ctx->tests[1];
    ut->coll_id = ret;

    /* unit test 2: collector_socket */
    fd = flb_net_server(SERVER_PORT, SERVER_IFACE,
                        FLB_NETWORK_DEFAULT_BACKLOG_SIZE,
                        FLB_FALSE);
    if (fd < 0) {
        flb_errno();
        config_destroy(ctx);
        return -1;
    }
    flb_net_socket_nonblocking(fd);
        ctx->server_fd = fd;

    /* socket server */
    ret = flb_input_set_collector_socket(ins,
                                         cb_collector_server_socket,
                                         ctx->server_fd,
                                         config);
    if (ret == -1) {
        config_destroy(ctx);
        return -1;
    }
    ut = &ctx->tests[2];
    ut->coll_id = ret;

    /* socket client: connect to socket server to trigger the event */
    ret = flb_input_set_collector_time(ins, cb_collector_server_client,
                                       CALLBACK_TIME * 2, 0, config);
    if (ret < 0) {
        config_destroy(ctx);
        return -1;
    }
    ctx->client_coll_id = ret;

    /* upstream context for socket client */
    upstream = flb_upstream_create(config, "127.0.0.1", atoi(SERVER_PORT),
                                   FLB_IO_TCP, NULL);
    if (!upstream) {
        config_destroy(ctx);
        return -1;
    }
    ctx->upstream = upstream;
    flb_input_upstream_set(ctx->upstream, ins);

    return 0;
}

static int cb_event_test_pre_run(struct flb_input_instance *ins,
                                 struct flb_config *config, void *in_context)
{
    flb_plg_info(ins, "pre run OK");
    return -1;
}

static void cb_event_test_pause(void *data, struct flb_config *config)
{
    struct event_test *ctx = data;

    set_unit_test_status(ctx, 3, STATUS_OK);
    flb_plg_info(ctx->ins, "[OK] engine has paused the plugin");
}

static void cb_event_test_resume(void *data, struct flb_config *config)
{
    struct event_test *ctx = data;

    set_unit_test_status(ctx, 4, STATUS_OK);
    flb_plg_info(ctx->ins, "[OK] engine has resumed the plugin");

    flb_engine_exit(config);
}

static int in_event_test_exit(void *data, struct flb_config *config)
{
    int i;
    int failed = FLB_FALSE;
    struct event_test *ctx = data;
    struct unit_test *ut;
    (void) *config;

    /* check tests */
    for (i = 0; i < UNIT_TESTS_SIZE; i++) {
        ut = &ctx->tests[i];
        if (ut->status != STATUS_OK) {
            flb_plg_error(ctx->ins, "unit test #%i '%s' failed",
                          i, ut->desc);
            failed = FLB_TRUE;
        }
        else {
            flb_plg_info(ctx->ins, "unit test #%i '%s' succeeded",
                         i, ut->desc);
        }
    }

    /* if one test failed, perform an abrupt exit with proper error */
    if (failed) {
        exit(EXIT_FAILURE);
    }

    config_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
   /* EOF */
   {0}
};

struct flb_input_plugin in_event_test_plugin = {
    .name         = "event_test",
    .description  = "Event tests for input plugins",
    .cb_init      = cb_event_test_init,
    .cb_pre_run   = cb_event_test_pre_run,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = cb_event_test_pause,
    .cb_resume    = cb_event_test_resume,
    .cb_exit      = in_event_test_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_CORO | FLB_INPUT_THREADED
};
