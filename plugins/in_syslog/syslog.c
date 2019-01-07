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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>

#include "syslog.h"
#include "syslog_conf.h"
#include "syslog_server.h"
#include "syslog_conn.h"
#include "syslog_prot.h"

/* cb_collect callback */
static int in_syslog_collect_tcp(struct flb_input_instance *i_ins,
                                 struct flb_config *config, void *in_context)
{
    int fd;
    struct flb_syslog *ctx = in_context;
    struct syslog_conn *conn;
    (void) i_ins;

    /* Accept the new connection */
    fd = flb_net_accept(ctx->server_fd);
    if (fd == -1) {
        flb_error("[in_syslog] could not accept new connection");
        return -1;
    }

    flb_trace("[in_syslog] new Unix connection arrived FD=%i", fd);
    conn = syslog_conn_add(fd, ctx);
    if (!conn) {
        return -1;
    }

    return 0;
}

/*
 * Collect a datagram, per Syslog specification a datagram contains only
 * one syslog message and it should not exceed 1KB.
 */
static int in_syslog_collect_udp(struct flb_input_instance *i_ins,
                                 struct flb_config *config,
                                 void *in_context)
{
    int bytes;
    struct flb_syslog *ctx = in_context;
    (void) i_ins;

    bytes = recvfrom(ctx->server_fd,
                     ctx->buffer_data, ctx->buffer_size - 1, 0,
                     NULL, NULL);
    if (bytes > 0) {
        ctx->buffer_data[bytes] = '\0';
        ctx->buffer_len = bytes;
        syslog_prot_process_udp(ctx->buffer_data, ctx->buffer_len, ctx);
    }
    else {
        flb_errno();
    }
    ctx->buffer_len = 0;

    return 0;
}

/* Initialize plugin */
static int in_syslog_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_syslog *ctx;

    /* Allocate space for the configuration */
    ctx = syslog_conf_create(in, config);
    if (!ctx) {
        flb_error("[in_syslog] could not initialize plugin");
        return -1;
    }

    if ((ctx->mode == FLB_SYSLOG_UNIX_TCP || ctx->mode == FLB_SYSLOG_UNIX_UDP)
        && !ctx->unix_path) {
        flb_error("[in_syslog] Unix path not defined");
        syslog_conf_destroy(ctx);
        return -1;
    }

    /* Create Unix Socket */
    ret = syslog_server_create(ctx);
    if (ret == -1) {
        syslog_conf_destroy(ctx);
        return -1;
    }

    /* Set context */
    flb_input_set_context(in, ctx);

    /* Collect events for every opened connection to our socket */
    if (ctx->mode == FLB_SYSLOG_UNIX_TCP ||
        ctx->mode == FLB_SYSLOG_TCP) {
        ret = flb_input_set_collector_socket(in,
                                             in_syslog_collect_tcp,
                                             ctx->server_fd,
                                             config);
    }
    else {
        ret = flb_input_set_collector_socket(in,
                                             in_syslog_collect_udp,
                                             ctx->server_fd,
                                             config);
    }

    if (ret == -1) {
        flb_error("[in_syslog] Could not set collector");
        syslog_conf_destroy(ctx);
    }

    return 0;
}

static int in_syslog_exit(void *data, struct flb_config *config)
{
    struct flb_syslog *ctx = data;
    (void) config;

    syslog_conn_exit(ctx);
    syslog_conf_destroy(ctx);

    return 0;
}


struct flb_input_plugin in_syslog_plugin = {
    .name         = "syslog",
    .description  = "Syslog",
    .cb_init      = in_syslog_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_exit      = in_syslog_exit,
    .flags        = FLB_INPUT_NET
};
