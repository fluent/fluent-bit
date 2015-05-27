/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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
#include <assert.h>
#include <errno.h>

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>

#include "td.h"
#include "td_http.h"
#include "td_config.h"

struct flb_output_plugin out_td_plugin;

int cb_td_init(struct flb_config *config)
{
    int ret;
    struct flb_out_td_config *ctx;

    if (!config->file) {
        flb_utils_error_c("TD output requires a configuration file");
    }

    ctx = td_config_init(config->file);
    if (!ctx) {
        return -1;
    }

    ret = flb_output_set_context("td", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for td output plugin");
    }

    return 0;
}

int cb_td_pre_run(void *out_context, struct flb_config *config)
{
    int fd;
    struct flb_out_td_config *ctx = out_context;

    fd = flb_net_tcp_connect(out_td_plugin.host,
                             out_td_plugin.port);
    if (fd <= 0) {
        return -1;
    }

    ctx->fd = fd;
    return 0;
}

int cb_td_flush(void *data, size_t bytes, void *out_context,
                struct flb_config *config)
{
    int n;
    char buf[1024];
    size_t w_bytes;
    size_t out_len;
    char *request;
    struct flb_out_td_config *ctx = out_context;

    request = td_http_request(data, bytes, &out_len, ctx, config);
    w_bytes = write(ctx->fd, request, out_len);
    if (w_bytes < 0) {
        perror("write");
        /* FIXME: handle connection timeout */
        if (errno == EBADF) {
            close(ctx->fd);
            ctx->fd = flb_net_tcp_connect(out_td_plugin.host,
                                          out_td_plugin.port);
        }
    }
    free(request);

    n = read(ctx->fd, buf, 4096);
    buf[n] = '\0';

    flb_debug("[TD] API server response:\n%s", buf);
    return w_bytes;
}

/* Plugin reference */
struct flb_output_plugin out_td_plugin = {
    .name           = "td",
    .description    = "Treasure Data",
    .cb_init        = cb_td_init,
    .cb_pre_run     = cb_td_pre_run,
    .cb_flush       = cb_td_flush,
    .flags          = FLB_OUTPUT_TCP | FLB_OUTPUT_SSL | FLB_OUTPUT_NOPROT,
    .host           = "api.treasuredata.com",
    .port           = 80,
};
