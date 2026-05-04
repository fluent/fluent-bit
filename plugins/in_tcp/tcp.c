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
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_downstream_worker.h>
#include <msgpack.h>

#include "tcp.h"
#include "tcp_conn.h"
#include "tcp_config.h"

static int in_tcp_collect_ctx(struct flb_in_tcp_config *ctx);
static int in_tcp_collect(struct flb_input_instance *in,
                          struct flb_config *config, void *in_context);

static void in_tcp_connections_destroy(struct flb_in_tcp_config *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct tcp_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct tcp_conn, _head);
        tcp_conn_del(conn);
    }
}

static int in_tcp_worker_listener_event(void *data)
{
    struct mk_event *event;

    event = data;

    return in_tcp_collect_ctx(event->data);
}

static int in_tcp_start_listener(struct flb_in_tcp_config *ctx,
                                 struct flb_config *config,
                                 struct flb_net_setup *net_setup,
                                 struct mk_event_loop *event_loop,
                                 int use_collector)
{
    int ret;
    unsigned short int port;

    port = (unsigned short int) strtoul(ctx->tcp_port, NULL, 10);

    ctx->downstream = flb_downstream_create(FLB_TRANSPORT_TCP,
                                            ctx->ins->flags,
                                            ctx->listen,
                                            port,
                                            ctx->ins->tls,
                                            config,
                                            net_setup);

    if (ctx->downstream == NULL) {
        flb_plg_error(ctx->ins,
                      "could not initialize downstream on %s:%s. Aborting",
                      ctx->listen, ctx->tcp_port);
        return -1;
    }

    flb_input_downstream_set(ctx->downstream, ctx->ins);

    if (use_collector == FLB_TRUE) {
        ret = flb_input_set_collector_socket(ctx->ins,
                                             in_tcp_collect,
                                             ctx->downstream->server_fd,
                                             config);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Could not set collector for IN_TCP input plugin");
            return -1;
        }

        ctx->collector_id = ret;
    }
    else {
        ctx->event_loop = event_loop;
        MK_EVENT_NEW(&ctx->listener_event);
        ctx->listener_event.type = FLB_ENGINE_EV_CUSTOM;
        ctx->listener_event.data = ctx;
        ctx->listener_event.handler = in_tcp_worker_listener_event;

        ret = mk_event_add(event_loop,
                           ctx->downstream->server_fd,
                           FLB_ENGINE_EV_CUSTOM,
                           MK_EVENT_READ,
                           &ctx->listener_event);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not register TCP worker listener");
            return -1;
        }

        ctx->listener_registered = FLB_TRUE;
    }

    return 0;
}

static int in_tcp_worker_init(struct flb_downstream_worker *worker,
                              void *parent,
                              void **worker_context)
{
    int ret;
    struct flb_in_tcp_config *ctx;
    struct flb_in_tcp_config *parent_ctx;

    parent_ctx = parent;

    ctx = tcp_config_init(parent_ctx->ins);
    if (ctx == NULL) {
        return -1;
    }

    *worker_context = ctx;

    ctx->collector_id = -1;
    ctx->ins = parent_ctx->ins;
    ctx->workers = parent_ctx->workers;
    ctx->worker_id = worker->worker_id;
    ctx->use_ingress_queue = FLB_TRUE;
    ctx->net_setup = parent_ctx->ins->net_setup;
    ctx->net_setup.share_port = FLB_TRUE;
    mk_list_init(&ctx->connections);

    ret = in_tcp_start_listener(ctx,
                                parent_ctx->ins->config,
                                &ctx->net_setup,
                                worker->event_loop,
                                FLB_FALSE);
    if (ret == 0) {
        flb_downstream_thread_safe(ctx->downstream);
    }

    return ret;
}

static void in_tcp_worker_exit(struct flb_downstream_worker *worker,
                               void *worker_context)
{
    struct flb_in_tcp_config *ctx;

    (void) worker;

    ctx = worker_context;

    in_tcp_connections_destroy(ctx);
    tcp_config_destroy(ctx);
}

static void in_tcp_worker_maintenance(struct flb_downstream_worker *worker,
                                      void *worker_context)
{
    struct flb_in_tcp_config *ctx;

    (void) worker;

    ctx = worker_context;

    if (ctx->downstream != NULL) {
        flb_downstream_conn_timeouts_stream(ctx->downstream);
        flb_downstream_conn_pending_destroy(ctx->downstream);
    }
}

static int in_tcp_workers_start(struct flb_in_tcp_config *ctx)
{
    struct flb_downstream_worker_options options;

    memset(&options, 0, sizeof(struct flb_downstream_worker_options));
    options.workers = ctx->workers;
    options.config = ctx->ins->config;
    options.parent = ctx;
    options.cb_init = in_tcp_worker_init;
    options.cb_exit = in_tcp_worker_exit;
    options.cb_maintenance = in_tcp_worker_maintenance;

    return flb_downstream_worker_runtime_start(&ctx->runtime, &options);
}

static void in_tcp_workers_stop(struct flb_in_tcp_config *ctx)
{
    flb_downstream_worker_runtime_stop(ctx->runtime);
    ctx->runtime = NULL;
}

static void in_tcp_worker_pause(struct flb_downstream_worker *worker,
                                void *worker_context,
                                void *data)
{
    struct flb_in_tcp_config *ctx;

    (void) worker;
    (void) data;

    ctx = worker_context;

    if (ctx->downstream != NULL) {
        flb_downstream_pause(ctx->downstream);
    }
}

static void in_tcp_worker_resume(struct flb_downstream_worker *worker,
                                 void *worker_context,
                                 void *data)
{
    struct flb_in_tcp_config *ctx;

    (void) worker;
    (void) data;

    ctx = worker_context;

    if (ctx->downstream != NULL) {
        flb_downstream_resume(ctx->downstream);
    }
}

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new TCP instance which will wait for
 * JSON map messages.
 */
static int in_tcp_collect(struct flb_input_instance *in,
                          struct flb_config *config, void *in_context)
{
    (void) in;
    (void) config;

    return in_tcp_collect_ctx(in_context);
}

static int in_tcp_collect_ctx(struct flb_in_tcp_config *ctx)
{
    struct flb_connection    *connection;
    struct tcp_conn          *conn;

    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        /* connection dropped (e.g. paused) */
        return 0;
    }

    flb_plg_trace(ctx->ins, "new TCP connection arrived FD=%i", connection->fd);

    conn = tcp_conn_add(connection, ctx);

    if (conn == NULL) {
        flb_plg_error(ctx->ins, "could not accept new connection");

        flb_downstream_conn_release(connection);

        return -1;
    }

    return 0;
}

/* Initialize plugin */
static int in_tcp_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int                       ret;
    struct flb_in_tcp_config *ctx;

    (void) data;

    /* Allocate space for the configuration */
    ctx = tcp_config_init(in);
    if (!ctx) {
        return -1;
    }
    ctx->collector_id = -1;
    ctx->ins = in;
    mk_list_init(&ctx->connections);

    /* Set the context */
    flb_input_set_context(in, ctx);

    if (ctx->workers <= 0) {
        ctx->workers = 1;
    }

    if (ctx->workers > 1) {
        ret = flb_input_ingress_enable(in);
        if (ret != 0) {
            tcp_config_destroy(ctx);
            return -1;
        }

        ret = in_tcp_workers_start(ctx);
        if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "could not start TCP listener workers on %s:%s. Aborting",
                          ctx->listen, ctx->tcp_port);
            tcp_config_destroy(ctx);
            return -1;
        }
    }
    else {
        ret = in_tcp_start_listener(ctx, config, &in->net_setup, NULL, FLB_TRUE);
        if (ret != 0) {
            tcp_config_destroy(ctx);
            return -1;
        }
    }

    flb_plg_info(ctx->ins,
                 "listening on %s:%s with %i worker%s",
                 ctx->listen, ctx->tcp_port, ctx->workers,
                 ctx->workers == 1 ? "" : "s");

    return 0;
}

static int in_tcp_exit(void *data, struct flb_config *config)
{
    struct flb_in_tcp_config *ctx;

    (void) *config;

    ctx = data;

    in_tcp_workers_stop(ctx);
    in_tcp_connections_destroy(ctx);

    tcp_config_destroy(ctx);

    return 0;
}

static void in_tcp_pause(void *data, struct flb_config *config)
{
    struct flb_in_tcp_config *ctx = data;
    struct mk_list *head;
    struct mk_list *tmp;
    struct tcp_conn *conn;

    (void) config;

    if (ctx->runtime != NULL) {
        flb_downstream_worker_runtime_foreach(ctx->runtime,
                                              in_tcp_worker_pause,
                                              NULL);
        return;
    }

    flb_downstream_pause(ctx->downstream);

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct tcp_conn, _head);
        if (conn->busy) {
            conn->pending_close = FLB_TRUE;
            continue;
        }

        tcp_conn_del(conn);
    }
}

static void in_tcp_resume(void *data, struct flb_config *config)
{
    struct flb_in_tcp_config *ctx = data;

    (void) config;

    if (ctx->runtime != NULL) {
        flb_downstream_worker_runtime_foreach(ctx->runtime,
                                              in_tcp_worker_resume,
                                              NULL);
        return;
    }

    flb_downstream_resume(ctx->downstream);
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_tcp_config, format_name),
     "Set the format: json or none"
    },
    {
     FLB_CONFIG_MAP_STR, "separator", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_tcp_config, raw_separator),
     "Set separator"
    },
    {
     FLB_CONFIG_MAP_STR, "parser", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_tcp_config, parser_name),
     "Optional parser for line-delimited records"
    },
    {
      FLB_CONFIG_MAP_STR, "chunk_size", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_tcp_config, chunk_size_str),
      "Set the chunk size"
    },
    {
      FLB_CONFIG_MAP_STR, "buffer_size", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_tcp_config, buffer_size_str),
      "Set the buffer size"
    },
    {
      FLB_CONFIG_MAP_STR, "source_address_key", (char *) NULL,
      0, FLB_TRUE, offsetof(struct flb_in_tcp_config, source_address_key),
      "Key where the source address will be injected"
    },
    {
      FLB_CONFIG_MAP_INT, "workers", "1",
      0, FLB_TRUE, offsetof(struct flb_in_tcp_config, workers),
      "Set the number of TCP listener workers"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_tcp_plugin = {
    .name         = "tcp",
    .description  = "TCP",
    .cb_init      = in_tcp_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_tcp_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_tcp_pause,
    .cb_resume    = in_tcp_resume,
    .cb_exit      = in_tcp_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_IO_OPT_TLS
};
