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
#include <msgpack.h>

#include "gelf.h"
#include "gelf_conn.h"
#include "gelf_config.h"

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new TCP instance which will wait for
 * JSON map messages.
 */
static int in_gelf_collect(struct flb_input_instance *in,
                               struct flb_config *config,
                               void *in_context)
{
    int fd;
    struct flb_in_gelf_config *ctx = in_context;
    struct gelf_conn *conn;

    /* Accept the new connection */
    fd = flb_net_accept(ctx->server_fd);
    if (fd == -1) {
        flb_plg_error(ctx->ins, "could not accept new connection");
        return -1;
    }

    flb_plg_trace(ctx->ins, "new GELF connection arrived FD=%i", fd);
    conn = gelf_conn_add(fd, ctx);
    if (!conn) {
        return -1;
    }
    return 0;
}

/* Initialize plugin */
static int in_gelf_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_gelf_config *ctx;
    (void) data;

    ctx = gelf_config_init(in);
    if (!ctx) {
        return -1;
    }
    ctx->ins = in;
    mk_list_init(&ctx->connections);

    /* Set the context */
    flb_input_set_context(in, ctx);

    if (ctx->mode == FLB_GELF_TCP) {
        ctx->server_fd = flb_net_server(ctx->port, ctx->listen);
    } else {
        flb_plg_error(ctx->ins, "UDP mode not implemented");
        return -1;
    }
    if (ctx->server_fd > 0) {
        flb_plg_info(ctx->ins, "[in_gelf] listening on %s:%s/%s)",
                     ctx->listen, ctx->port,
                     (ctx->mode == FLB_GELF_TCP) ? "TCP" : "UDP");
    }
    else {
        flb_plg_error(ctx->ins, "could not bind address %s:%s. Aborting",
                      ctx->listen, ctx->port);
        gelf_config_destroy(ctx);
        return -1;
    }
    flb_net_socket_nonblocking(ctx->server_fd);

    ctx->evl = config->evl;

    /* Collect events for every opened connection to our socket */
    ret = flb_input_set_collector_socket(in,
                                         in_gelf_collect,
                                         ctx->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for in_gelf input plugin");
        gelf_config_destroy(ctx);
        return -1;
    }

    return 0;
}

static int in_gelf_exit(void *data, struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    (void) *config;
    struct flb_in_gelf_config *ctx = data;
    struct gelf_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct gelf_conn, _head);
        gelf_conn_del(conn);
    }

    gelf_config_destroy(ctx);
    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_gelf_plugin = {
    .name         = "gelf",
    .description  = "GELF Input",
    .cb_init      = in_gelf_init,
    .cb_collect   = in_gelf_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_gelf_exit,
    .flags        = FLB_INPUT_NET,
};
