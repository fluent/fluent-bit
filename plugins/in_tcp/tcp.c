/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_network.h>
#include <msgpack.h>

#include "tcp.h"
#include "tcp_conn.h"
#include "tcp_config.h"

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new TCP instance which will wait for
 * JSON map messages.
 */
static int in_tcp_collect(struct flb_input_instance *in,
                          struct flb_config *config, void *in_context)
{
    struct flb_connection      *connection;
    struct flb_coro            *coroutine;
    struct tcp_conn            *conn;
    struct flb_in_tcp_config   *ctx;
    int                         ret;

    ctx = in_context;

    coroutine = flb_coro_get();
    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could not accept new connection");

        return -1;
    }

    // ret = flb_io_net_accept(connection, coroutine);

    // if (ret != 0) {
    //     flb_plg_error(ctx->ins, "could not accept new connection");

    //     flb_downstream_conn_release(connection);

    //     return -1;
    // }

    /* Accept the new connection */
    // fd = flb_net_accept(ctx->server_fd);
    // if (fd == -1) {
    //     flb_plg_error(ctx->ins, "could not accept new connection");
    //     return -1;
    // }

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
    int ret;
    struct flb_in_tcp_config *ctx;
    (void) data;

    /* Allocate space for the configuration */
    ctx = tcp_config_init(in);
    if (!ctx) {
        return -1;
    }
    ctx->ins = in;
    mk_list_init(&ctx->connections);

    /* Set the context */
    flb_input_set_context(in, ctx);

    ctx->downstream = flb_downstream_create(config,
                                            ctx->listen,
                                            ctx->tcp_port,
                                            in->flags,
                                            in->tls);

    if (ctx->downstream == NULL) {
        flb_plg_error(ctx->ins,
                      "could not initialize downstream on %s:%s. Aborting",
                      ctx->listen, ctx->tcp_port);

        tcp_config_destroy(ctx);

        return -1;
    }

    MK_EVENT_ZERO(&ctx->downstream->event);

    /* Create TCP server */
    // ctx->server_fd = flb_net_server(ctx->tcp_port, ctx->listen);
    // if (ctx->server_fd > 0) {
    //     flb_plg_info(ctx->ins, "listening on %s:%s", ctx->listen, ctx->tcp_port);
    // }
    // else {
    //     flb_plg_error(ctx->ins, "could not bind address %s:%s. Aborting",
    //                   ctx->listen, ctx->tcp_port);
    //     tcp_config_destroy(ctx);
    //     return -1;
    // }
    // flb_net_socket_nonblocking(ctx->server_fd);

    ctx->evl = config->evl;

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(in,
                                         in_tcp_collect,
                                         ctx->downstream->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for IN_TCP input plugin");
        tcp_config_destroy(ctx);
        return -1;
    }

    return 0;
}

static int in_tcp_exit(void *data, struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    (void) *config;
    struct flb_in_tcp_config *ctx = data;
    struct tcp_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct tcp_conn, _head);

        tcp_conn_del(conn);
    }

    flb_downstream_destroy(ctx->downstream);

    tcp_config_destroy(ctx);
    return 0;
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
      FLB_CONFIG_MAP_STR, "chunk_size", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_tcp_config, chunk_size_str),
      "Set the chunk size"
    },
    {
      FLB_CONFIG_MAP_STR, "buffer_size", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_tcp_config, buffer_size_str),
      "Set the buffer size"
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
    .cb_exit      = in_tcp_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET | FLB_IO_OPT_TLS,
};
