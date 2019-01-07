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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "syslog.h"

static int syslog_server_unix_create(struct flb_syslog *ctx)
{
    flb_sockfd_t fd = -1;
    unsigned long len;
    size_t address_length;
    struct sockaddr_un address;

    if (ctx->mode == FLB_SYSLOG_UNIX_TCP) {
        fd = flb_net_socket_create(AF_UNIX, FLB_TRUE);
    }
    else if (ctx->mode == FLB_SYSLOG_UNIX_UDP) {
        fd = flb_net_socket_create_udp(AF_UNIX, FLB_TRUE);
    }

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

    if (ctx->mode == FLB_SYSLOG_UNIX_TCP) {
        if (listen(fd, 5) != 0) {
            flb_errno();
            close(fd);
            return -1;
        }
    }

    return 0;
}

static int syslog_server_net_create(struct flb_syslog *ctx)
{
    if (ctx->mode == FLB_SYSLOG_TCP) {
        ctx->server_fd = flb_net_server(ctx->port, ctx->listen);
    }
    else {
        ctx->server_fd = flb_net_server_udp(ctx->port, ctx->listen);
    }

    if (ctx->server_fd > 0) {
        flb_info("[in_syslog] %s server binding %s:%s",
                 ((ctx->mode == FLB_SYSLOG_TCP) ? "TCP" : "UDP"),
                 ctx->listen, ctx->port);
    }
    else {
        flb_error("[in_syslog] could not bind address %s:%s. Aborting",
                  ctx->listen, ctx->port);
        return -1;
    }

    flb_net_socket_nonblocking(ctx->server_fd);

    return 0;
}

int syslog_server_create(struct flb_syslog *ctx)
{
    int ret;

    if (ctx->mode == FLB_SYSLOG_UDP || ctx->mode == FLB_SYSLOG_UNIX_UDP) {
        /* Create UDP buffer */
        ctx->buffer_data = flb_calloc(1, ctx->buffer_chunk_size);
        if (!ctx->buffer_data) {
            flb_errno();
            return -1;
        }
        ctx->buffer_size = ctx->buffer_chunk_size;
        flb_info("[in_syslog] UDP buffer size set to %lu bytes",
                 ctx->buffer_size);
    }

    if (ctx->mode == FLB_SYSLOG_TCP || ctx->mode == FLB_SYSLOG_UDP) {
        ret = syslog_server_net_create(ctx);
    }
    else {
        /* Create unix socket end-point */
        ret = syslog_server_unix_create(ctx);
    }

    if (ret != 0) {
        return -1;
    }

    return 0;
}

int syslog_server_destroy(struct flb_syslog *ctx)
{
    if (ctx->mode == FLB_SYSLOG_UNIX_TCP || ctx->mode == FLB_SYSLOG_UNIX_UDP) {
        if (ctx->unix_path) {
            unlink(ctx->unix_path);
            flb_free(ctx->unix_path);
        }
    }
    else {
        flb_free(ctx->listen);
        flb_free(ctx->port);
    }

    close(ctx->server_fd);

    return 0;
}
