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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <msgpack.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>

#include "udp.h"
#include "udp_conf.h"
#include "udp_server.h"
#include "udp_conn.h"
#include "udp_prot.h"

/* cb_collect callback */
/*
 * Collect a datagrams
 */
static int in_udp_collect_udp(struct flb_input_instance *i_ins,
                                 struct flb_config *config,
                                 void *in_context)
{
    int bytes;
    char *nl;
    char *line;
    char *endp;
    struct flb_udp *ctx = in_context;
    (void) i_ins;

    bytes = recvfrom(ctx->server_fd,
                     ctx->buffer_data, ctx->buffer_size - 1, 0,
                     NULL, NULL);
    if (bytes > 0) {
        ctx->buffer_data[bytes] = '\0';
        ctx->buffer_len = bytes;
        if (ctx->multi_line) {
            line = ctx->buffer_data;
            endp = ctx->buffer_data + bytes;
            while ((nl = strchr(line,'\n')) != NULL) {
                *nl = 0;
                if ((nl - line) > 0) {
                    udp_prot_process_udp(line, nl - line, ctx);
                }
                line = nl + 1;
            }
            if (line < endp) {
                udp_prot_process_udp(line, endp - line, ctx);
            }
        } else {
            udp_prot_process_udp(ctx->buffer_data, ctx->buffer_len, ctx);
        }
    }
    else {
        flb_errno();
    }
    ctx->buffer_len = 0;

    return 0;
}

/* Initialize plugin */
static int in_udp_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_udp *ctx;

    /* Allocate space for the configuration */
    ctx = udp_conf_create(in, config);
    if (!ctx) {
        flb_plg_error(in, "could not initialize plugin");
        return -1;
    }

    if ((ctx->mode == FLB_UDP_UNIX) && !ctx->unix_path) {
        flb_plg_error(ctx->ins, "Unix path not defined");
        udp_conf_destroy(ctx);
        return -1;
    }

    /* Create Unix Socket */
    ret = udp_server_create(ctx);
    if (ret == -1) {
        udp_conf_destroy(ctx);
        return -1;
    }

    /* Set context */
    flb_input_set_context(in, ctx);

    /* Collect events for every opened connection to our socket */
    ret = flb_input_set_collector_socket(in,
                                         in_udp_collect_udp,
                                         ctx->server_fd,
                                         config);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector");
        udp_conf_destroy(ctx);
    }

    return 0;
}

static int in_udp_exit(void *data, struct flb_config *config)
{
    struct flb_udp *ctx = data;
    (void) config;

    udp_conn_exit(ctx);
    udp_conf_destroy(ctx);

    return 0;
}


struct flb_input_plugin in_udp_plugin = {
    .name         = "udp",
    .description  = "Udp",
    .cb_init      = in_udp_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_exit      = in_udp_exit,
    .flags        = FLB_INPUT_NET
};
