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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "udp.h"

static int udp_server_unix_create(struct flb_udp *ctx)
{
    flb_sockfd_t fd = -1;
    unsigned long len;
    size_t address_length;
    struct sockaddr_un address;

    fd = flb_net_socket_create_udp(AF_UNIX, FLB_TRUE);

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

    if (chmod(address.sun_path, ctx->unix_perm)) {
        flb_errno();
        flb_error("[in_udp] cannot set permission on '%s' to %04o",
                  address.sun_path, ctx->unix_perm);
        close(fd);
        return -1;
    }

    return 0;
}

static int udp_server_net_create(struct flb_udp *ctx)
{
    ctx->server_fd = flb_net_server_udp(ctx->port, ctx->listen);

    if (ctx->server_fd > 0) {
        flb_info("[in_udp] UDP server binding %s:%s",
                 ctx->listen, ctx->port);
    }
    else {
        flb_error("[in_udp] could not bind address %s:%s. Aborting",
                  ctx->listen, ctx->port);
        return -1;
    }

    flb_net_socket_nonblocking(ctx->server_fd);

    return 0;
}

int udp_server_create(struct flb_udp *ctx)
{
    int ret;

    /* Create UDP buffer */
    ctx->buffer_data = flb_calloc(1, ctx->buffer_chunk_size);
    if (!ctx->buffer_data) {
            flb_errno();
            return -1;
    }
    ctx->buffer_size = ctx->buffer_chunk_size;
    flb_info("[in_udp] UDP buffer size set to %lu bytes",
             ctx->buffer_size);


    if (ctx->mode == FLB_UDP_INET) {
        ret = udp_server_net_create(ctx);
    }
    else {
        /* Create unix socket end-point */
        ret = udp_server_unix_create(ctx);
    }

    if (ret != 0) {
        flb_free(ctx->buffer_data);
        ctx->buffer_data = NULL;
        return -1;
    }

    return 0;
}

int udp_server_destroy(struct flb_udp *ctx)
{
    if (ctx->mode == FLB_UDP_UNIX) {
        if (ctx->unix_path) {
            unlink(ctx->unix_path);
            flb_free(ctx->unix_path);
        }
    }

    if (ctx->port) {
        flb_free(ctx->port);
        ctx->port = NULL;
    }

    if (ctx->server_fd >= 0) {
        close(ctx->server_fd);
        ctx->server_fd = -1;
    }

    if (ctx->buffer_data) {
        flb_free(ctx->buffer_data);
        ctx->buffer_data = NULL;
    }
    return 0;
}
