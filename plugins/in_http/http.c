/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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


#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>

#include "http.h"
#include "http_conn.h"
#include "http_config.h"

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new TCP instance which will wait for
 * JSON map messages.
 */
static int in_http_collect(struct flb_input_instance *ins,
                           struct flb_config *config, void *in_context)
{
    int fd;
    struct flb_http *ctx = in_context;
    struct http_conn *conn;

    /* Accept the new connection */
    fd = flb_net_accept(ctx->server_fd);
    if (fd == -1) {
        flb_plg_error(ctx->ins, "could not accept new connection");
        return -1;
    }

    flb_plg_trace(ctx->ins, "new TCP connection arrived FD=%i", fd);
    conn = http_conn_add(fd, ctx);
    if (!conn) {
        return -1;
    }
    return 0;
}

static int in_http_init(struct flb_input_instance *ins,
                        struct flb_config *config, void *data)
{
    int ret;
    struct flb_http *ctx;

    /* Create context and basic conf */
    ctx = http_config_create(ins);
    if (!ctx) {
        return -1;
    }

    /* Set the context */
    flb_input_set_context(ins, ctx);

    ctx->evl = config->evl;

    /* Create HTTP listener */
    ctx->server_fd = flb_net_server(ctx->tcp_port, ctx->listen);
    if (ctx->server_fd > 0) {
        flb_plg_info(ctx->ins, "listening on %s:%s", ctx->listen, ctx->tcp_port);
    }
    else {
        flb_plg_error(ctx->ins, "could not bind address %s:%s. Aborting",
                      ctx->listen, ctx->tcp_port);
        http_config_destroy(ctx);
        return -1;
    }

    /* Set the socket non-blocking */
    flb_net_socket_nonblocking(ctx->server_fd);

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(ins,
                                         in_http_collect,
                                         ctx->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for IN_TCP input plugin");
        http_config_destroy(ctx);
        return -1;
    }

    return 0;
}

static int in_http_exit(void *data, struct flb_config *config)
{
    struct flb_http *ctx = data;
    (void) config;

    if (!ctx) {
        return 0;
    }

    http_config_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SIZE, "buffer_max_size", HTTP_BUFFER_MAX_SIZE,
     0, FLB_TRUE, offsetof(struct flb_http, buffer_max_size),
     ""
    },

    {
     FLB_CONFIG_MAP_SIZE, "buffer_chunk_size", HTTP_BUFFER_CHUNK_SIZE,
     0, FLB_TRUE, offsetof(struct flb_http, buffer_chunk_size),
     ""
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_http_plugin = {
    .name         = "http",
    .description  = "HTTP",
    .cb_init      = in_http_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_http_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = in_http_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET,
};
