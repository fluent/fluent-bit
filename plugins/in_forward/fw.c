/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_network.h>

#ifdef FLB_HAVE_UNIX_SOCKET
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include "fw.h"
#include "fw_conn.h"
#include "fw_config.h"

#ifdef FLB_HAVE_UNIX_SOCKET
static int fw_unix_create(struct flb_in_fw_config *ctx)
{
    flb_sockfd_t fd = -1;
    unsigned long len;
    size_t address_length;
    struct sockaddr_un address;

    fd = flb_net_socket_create(AF_UNIX, FLB_TRUE);
    if (fd == -1) {
        return -1;
    }

    ctx->server_fd = fd;

    /* Prepare the unix socket path */
    unlink(ctx->unix_path);
    len = strlen(ctx->unix_path);

    address.sun_family = AF_UNIX;
    sprintf(address.sun_path, "%s", ctx->unix_path);
    address_length = sizeof(address.sun_family) + len + 1;
    if (bind(fd, (struct sockaddr *) &address, address_length) != 0) {
        flb_errno();
        close(fd);
        return -1;
    }

    if (listen(fd, 5) != 0) {
        flb_errno();
        close(fd);
        return -1;
    }
    return 0;
}
#endif

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new FW instance which will wait for
 * MessagePack records.
 */
static int in_fw_collect(struct flb_input_instance *i_ins,
                         struct flb_config *config, void *in_context)
{
    int fd;
    struct flb_in_fw_config *ctx = in_context;
    struct fw_conn *conn;
    (void) i_ins;

    /* Accept the new connection */
    fd = flb_net_accept(ctx->server_fd);
    if (fd == -1) {
        flb_error("[in_fw] could not accept new connection");
        return -1;
    }

    flb_trace("[in_fw] new TCP connection arrived FD=%i", fd);
    conn = fw_conn_add(fd, ctx);
    if (!conn) {
        return -1;
    }
    return 0;
}

/* Initialize plugin */
static int in_fw_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_fw_config *ctx;
    (void) data;

    /* Allocate space for the configuration */
    ctx = fw_config_init(in);
    if (!ctx) {
        return -1;
    }
    ctx->in = in;
    mk_list_init(&ctx->connections);

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Unix Socket mode */
    if (ctx->unix_path) {
#ifndef FLB_HAVE_UNIX_SOCKET
        flb_error("[in_fw] unix address is not supported %s:%s. Aborting",
            ctx->listen, ctx->tcp_port);
        fw_config_destroy(ctx);
        return -1;
#else
        ret = fw_unix_create(ctx);
        if (ret != 0) {
            flb_error("[in_fw] could not listen on unix://%s",
                      ctx->unix_path);
            fw_config_destroy(ctx);
            return -1;
        }
        flb_info("[in_fw] listening on unix://%s", ctx->unix_path);
#endif
    }
    else {
        /* Create TCP server */
        ctx->server_fd = flb_net_server(ctx->tcp_port, ctx->listen);
        if (ctx->server_fd > 0) {
            flb_info("[in_fw] binding %s:%s", ctx->listen, ctx->tcp_port);
        }
        else {
            flb_error("[in_fw] could not bind address %s:%s. Aborting",
                      ctx->listen, ctx->tcp_port);
            fw_config_destroy(ctx);
            return -1;
        }
    }
    flb_net_socket_nonblocking(ctx->server_fd);

    ctx->evl = config->evl;

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(in,
                                         in_fw_collect,
                                         ctx->server_fd,
                                         config);
    if (ret == -1) {
        flb_error("Could not set collector for IN_FW input plugin");
        fw_config_destroy(ctx);
        return -1;
    }

    return 0;
}

int in_fw_exit(void *data, struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    (void) *config;
    struct flb_in_fw_config *ctx = data;
    struct fw_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct fw_conn, _head);
        fw_conn_del(conn);
    }

    fw_config_destroy(ctx);
    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_forward_plugin = {
    .name         = "forward",
    .description  = "Fluentd in-forward",
    .cb_init      = in_fw_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_fw_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_fw_exit,
    .flags        = FLB_INPUT_NET
};
