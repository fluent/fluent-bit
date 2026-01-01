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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_input_plugin.h>

#if !defined(FLB_SYSTEM_WINDOWS)
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>

#include "syslog.h"

static int remove_existing_socket_file(char *socket_path)
{
    struct stat file_data;
    int         result;

    result = stat(socket_path, &file_data);

    if (result == -1) {
        if (errno == ENOENT) {
            return 0;
        }

        flb_errno();

        return -1;
    }

    if (S_ISSOCK(file_data.st_mode) == 0) {
        return -2;
    }

    result = unlink(socket_path);

    if (result != 0) {
        return -3;
    }

    return 0;
}

#if !defined(FLB_SYSTEM_WINDOWS)
static int syslog_server_unix_create(struct flb_syslog *ctx)
{
    int             result;
    int             mode;
    struct flb_tls *tls;

    if (ctx->mode == FLB_SYSLOG_UNIX_TCP) {
        mode = FLB_TRANSPORT_UNIX_STREAM;
        tls = ctx->ins->tls;
    }
    else if (ctx->mode == FLB_SYSLOG_UNIX_UDP) {
        ctx->dgram_mode_flag = FLB_TRUE;

        mode = FLB_TRANSPORT_UNIX_DGRAM;
        tls = NULL;
    }
    else {
        return -1;
    }

    result = remove_existing_socket_file(ctx->unix_path);

    if (result != 0) {
        if (result == -2) {
            flb_plg_error(ctx->ins,
                          "%s exists and it is not a unix socket. Aborting",
                          ctx->unix_path);
        }
        else {
            flb_plg_error(ctx->ins,
                          "could not remove existing unix socket %s. Aborting",
                          ctx->unix_path);
        }

        return -1;
    }

    ctx->downstream = flb_downstream_create(mode,
                                            ctx->ins->flags,
                                            ctx->unix_path,
                                            0,
                                            tls,
                                            ctx->ins->config,
                                            &ctx->ins->net_setup);

    if (ctx->downstream == NULL) {
        return -1;
    }

    if (chmod(ctx->unix_path, ctx->unix_perm)) {
        flb_errno();
        flb_error("[in_syslog] cannot set permission on '%s' to %04o",
                  ctx->unix_path, ctx->unix_perm);

        return -1;
    }

    return 0;
}
#else
static int syslog_server_unix_create(struct flb_syslog *ctx)
{
    return -1;
}
#endif

static int syslog_server_net_create(struct flb_syslog *ctx)
{
    unsigned short int port;
    int                mode;
    struct flb_tls    *tls;

    port = (unsigned short int) strtoul(ctx->port, NULL, 10);

    if (ctx->mode == FLB_SYSLOG_TCP) {
        mode = FLB_TRANSPORT_TCP;
        tls = ctx->ins->tls;
    }
    else if (ctx->mode == FLB_SYSLOG_UDP) {
        ctx->dgram_mode_flag = FLB_TRUE;

        mode = FLB_TRANSPORT_UDP;
        tls = NULL;
    }
    else {
        return -1;
    }

    ctx->downstream = flb_downstream_create(mode,
                                            ctx->ins->flags,
                                            ctx->listen,
                                            port,
                                            tls,
                                            ctx->ins->config,
                                            &ctx->ins->net_setup);

    if (ctx->downstream != NULL) {
        flb_info("[in_syslog] %s server binding %s:%s",
                 ((ctx->mode == FLB_SYSLOG_TCP) ? "TCP" : "UDP"),
                 ctx->listen, ctx->port);
    }
    else {
        flb_error("[in_syslog] could not bind address %s:%s. Aborting",
                  ctx->listen, ctx->port);

        return -1;
    }

    if (ctx->receive_buffer_size) {
        if (flb_net_socket_rcv_buffer(ctx->downstream->server_fd,
                                      ctx->receive_buffer_size)) {
            flb_error("[in_syslog] could not set rcv buffer to %ld. Aborting",
                      ctx->receive_buffer_size);
            return -1;
        }
    }

    flb_net_socket_nonblocking(ctx->downstream->server_fd);

    return 0;
}

int syslog_server_create(struct flb_syslog *ctx)
{
    int ret;

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
    if (ctx->collector_id != -1) {
        flb_input_collector_delete(ctx->collector_id, ctx->ins);

        ctx->collector_id = -1;
    }

    if (ctx->downstream != NULL) {
        flb_downstream_destroy(ctx->downstream);

        ctx->downstream = NULL;
    }

    if (ctx->mode == FLB_SYSLOG_UNIX_TCP || ctx->mode == FLB_SYSLOG_UNIX_UDP) {
        if (ctx->unix_path) {
            unlink(ctx->unix_path);
        }
    }
    else {
        flb_free(ctx->port);
    }

    return 0;
}
