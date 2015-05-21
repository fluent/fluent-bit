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

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>

#include "fluentd.h"

struct flb_output_plugin out_fluentd_plugin;

int cb_fluentd_init(struct flb_config *config)
{
    int ret;
    struct flb_out_fluentd_config *ctx;

    ctx = calloc(1, sizeof(struct flb_out_fluentd_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }

    ret = flb_output_set_context("fluentd", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for fluentd output plugin");
    }

    return 0;
}

int cb_fluentd_pre_run(void *out_context, struct flb_config *config)
{
    int fd;
    struct flb_out_fluentd_config *ctx = out_context;

    fd = flb_net_tcp_connect(out_fluentd_plugin.host,
                             out_fluentd_plugin.port);
    if (fd <= 0) {
        return -1;
    }

    ctx->fd = fd;
    return 0;
}

int cb_fluentd_flush(void *data, size_t bytes, void *out_context)
{
    int fd, len;
    (void) out_context;

    fd = flb_net_tcp_connect(out_fluentd_plugin.host,
                             out_fluentd_plugin.port);
    if (fd <= 0) {
        return -1;
    }

    /* FIXME: plain TCP write */
    len = write(fd, data, bytes);
    close(fd);

    return len;
}

/* Plugin reference */
struct flb_output_plugin out_fluentd_plugin = {
    .name         = "fluentd",
    .description  = "Fluentd log collector",
    .cb_init      = cb_fluentd_init,
    .cb_pre_run   = cb_fluentd_pre_run,
    .cb_flush     = cb_fluentd_flush,
    .flags        = FLB_OUTPUT_TCP,
};
