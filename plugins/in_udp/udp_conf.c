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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_utils.h>

#include "udp.h"
#include "udp_server.h"
#include "udp_conf.h"

struct flb_udp *udp_conf_create(struct flb_input_instance *ins,
                                      struct flb_config *config)
{
    const char *tmp;
    int port_num;
    const char *bind_addr;
    char port[64];
    struct flb_udp *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_udp));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->evl = config->evl;
    ctx->ins = ins;
    ctx->buffer_data = NULL;
    ctx->server_fd = -1;
    ctx->rtrim = 1;

    mk_list_init(&ctx->connections);

    /* Udp mode: unix / inet */
    tmp = flb_input_get_property("mode", ins);
    if (tmp) {
        if (strcasecmp(tmp, "unix") == 0) {
            ctx->mode = FLB_UDP_UNIX;
        }
        else if (strcasecmp(tmp, "inet") == 0) {
            ctx->mode = FLB_UDP_INET;
        }
        else {
            flb_error("[in_udp] Unknown udp mode %s", tmp);
            udp_conf_destroy(ctx);
            return NULL;
        }
    }
    else {
        ctx->mode = FLB_UDP_UNIX;
    }

    /* Check if TCP mode was requested */

    if (ctx->mode == FLB_UDP_INET) {

        tmp = flb_input_get_property("port", ins);
        if (tmp) {
            port_num = strtol(tmp, NULL, 10);
        } else {
            port_num = 5588;
        }
        /*
            flb_error("[in_udp] no udp port");
            udp_conf_destroy(ctx);
            return NULL;
        */

        tmp = flb_input_get_property("bind", ins);
        if (tmp) {
            bind_addr = tmp;
        } else {
            bind_addr = "0.0.0.0";
        }
        /* Listen interface (if not set, defaults to 0.0.0.0:5140) */
        flb_input_net_default_listener(bind_addr, port_num, ins);
        ctx->listen = ins->host.listen;
        snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
        ctx->port = flb_strdup(port);
    }

    /* Unix socket path and permission */
    if (ctx->mode == FLB_UDP_UNIX) {

        tmp = flb_input_get_property("path", ins);
        if (!tmp) {
            flb_error("[in_udp] no udp/unix no path given");
            udp_conf_destroy(ctx);
            return NULL;
        }
        ctx->unix_path = flb_strdup(tmp);

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
        ctx->buffer_chunk_size = FLB_UDP_CHUNK; /* 32KB */
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

    /* multiline */
    tmp = flb_input_get_property("multi_line", ins);
    if (tmp) {
        ctx->multi_line = flb_utils_bool(tmp);
    }

    /* rtrim  (right trim input) */
    tmp = flb_input_get_property("rtrim", ins);
    if (tmp) {
        ctx->rtrim = flb_utils_bool(tmp);
    }

    /* Parser */
    tmp = flb_input_get_property("parser", ins);
    if (tmp) {
        ctx->parser = flb_parser_get(tmp, config);
    }

    return ctx;
}

int udp_conf_destroy(struct flb_udp *ctx)
{
    if (ctx->buffer_data) {
        flb_free(ctx->buffer_data);
        ctx->buffer_data = NULL;
    }

    udp_server_destroy(ctx);

    flb_free(ctx);

    return 0;
}
