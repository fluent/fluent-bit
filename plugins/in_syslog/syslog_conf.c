/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_utils.h>

#include "syslog.h"
#include "syslog_server.h"
#include "syslog_conf.h"

struct flb_syslog *syslog_conf_create(struct flb_input_instance *ins,
                                      struct flb_config *config)
{
    const char *tmp;
    char port[16];
    struct flb_syslog *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_syslog));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->evl = config->evl;
    ctx->ins = ins;
    ctx->buffer_data = NULL;
    mk_list_init(&ctx->connections);

    /* Syslog mode: unix_udp, unix_tcp, tcp or udp */
    tmp = flb_input_get_property("mode", ins);
    if (tmp) {
        if (strcasecmp(tmp, "unix_tcp") == 0) {
            ctx->mode = FLB_SYSLOG_UNIX_TCP;
        }
        else if (strcasecmp(tmp, "unix_udp") == 0) {
            ctx->mode = FLB_SYSLOG_UNIX_UDP;
        }
        else if (strcasecmp(tmp, "tcp") == 0) {
            ctx->mode = FLB_SYSLOG_TCP;
        }
        else if (strcasecmp(tmp, "udp") == 0) {
            ctx->mode = FLB_SYSLOG_UDP;
        }
        else {
            flb_error("[in_syslog] Unknown syslog mode %s", tmp);
            flb_free(ctx);
            return NULL;
        }
    }
    else {
        ctx->mode = FLB_SYSLOG_UNIX_UDP;
    }

    /* Check if TCP mode was requested */
    if (ctx->mode == FLB_SYSLOG_TCP || ctx->mode == FLB_SYSLOG_UDP) {
        /* Listen interface (if not set, defaults to 0.0.0.0:5140) */
        flb_input_net_default_listener("0.0.0.0", 5140, ins);
        ctx->listen = ins->host.listen;
        snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
        ctx->port = flb_strdup(port);
    }

    /* Unix socket path and permission */
    if (ctx->mode == FLB_SYSLOG_UNIX_UDP || ctx->mode == FLB_SYSLOG_UNIX_TCP) {
        tmp = flb_input_get_property("path", ins);
        if (tmp) {
            ctx->unix_path = flb_strdup(tmp);
        }

        tmp = flb_input_get_property("unix_perm", ins);
        if (tmp) {
            ctx->unix_perm = strtol(tmp, NULL, 8) & 07777;
        } else {
            ctx->unix_perm = 0644;
        }
    }

    /* Buffer Chunk Size */
    tmp = flb_input_get_property("buffer_chunk_size", ins);
    if (!tmp) {
        ctx->buffer_chunk_size = FLB_SYSLOG_CHUNK; /* 32KB */
    }
    else {
        ctx->buffer_chunk_size = flb_utils_size_to_bytes(tmp);
    }

    /* Buffer Max Size */
    tmp = flb_input_get_property("buffer_max_size", ins);
    if (!tmp) {
        ctx->buffer_max_size = ctx->buffer_chunk_size;
    }
    else {
        ctx->buffer_max_size  = flb_utils_size_to_bytes(tmp);
    }

    /* Parser */
    tmp = flb_input_get_property("parser", ins);
    if (tmp) {
        ctx->parser = flb_parser_get(tmp, config);
    }
    else {
        if (ctx->mode == FLB_SYSLOG_TCP || ctx->mode == FLB_SYSLOG_UDP) {
            ctx->parser = flb_parser_get("syslog-rfc5424", config);
        }
        else {
            ctx->parser = flb_parser_get("syslog-rfc3164-local", config);
        }
    }

    if (!ctx->parser) {
        flb_error("[in_syslog] parser not set");
        syslog_conf_destroy(ctx);
        return NULL;
    }

#ifdef FLB_HAVE_UTF8_ENCODER
    /* utf8 encoder */
    tmp = flb_input_get_property("encoding", ins);
    if (tmp) {
        ctx->encoding = flb_encoding_open(tmp);
        if (!ctx->encoding) {
            flb_error("[in_syslog] illegal encoding: %s", tmp);
            syslog_conf_destroy(ctx);
            return NULL;
        }
    }
#endif

    return ctx;
}

int syslog_conf_destroy(struct flb_syslog *ctx)
{
    if (ctx->buffer_data) {
        flb_free(ctx->buffer_data);
        ctx->buffer_data = NULL;
    }

#ifdef FLB_HAVE_UTF8_ENCODER
    if(ctx->encoding) {
        flb_encoding_close(ctx->encoding);
    }
#endif

    syslog_server_destroy(ctx);
    flb_free(ctx);

    return 0;
}
