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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>

#include "in_lib.h"

/* Initialize plugin */
int in_lib_init(struct flb_config *config)
{
    int fd;
    int ret;
    struct flb_in_lib_config *ctx;

    /* Allocate space for the configuration */
    ctx = malloc(sizeof(struct flb_in_lib_config));
    if (!ctx) {
        return -1;
    }
    ctx->msgp_len = 0;

    /* Set the context */
    ret = flb_input_set_context("lib", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for STDIN input plugin");
    }

    printf("input lib plugin: context = %p\n", ctx);
    return 0;
}

int in_lib_ingest(void *in_context, void *data, size_t bytes)
{
    int out_size;
    char *pack;
    struct flb_in_lib_config *ctx = in_context;

    flb_debug("lib_push() = %i", bytes);
    if (bytes == -1) {
        return -1;
    }
    ctx->buf_len += bytes;

    /* Initially we should support JSON input */
    pack = flb_pack_json(ctx->buf, ctx->buf_len, &out_size);
    if (!pack) {
        flb_debug("LIB data incomplete, waiting for more data...");
        return -1;
    }
    ctx->buf_len = 0;

    memcpy(ctx->msgp + ctx->msgp_len, pack, out_size);
    ctx->msgp_len += out_size;
    free(pack);

    return 0;
}

void *in_lib_flush(void *in_context, int *size)
{
    char *buf;
    struct flb_in_lib_config *ctx = in_context;

    buf = malloc(ctx->msgp_len);
    memcpy(buf, ctx->msgp, ctx->msgp_len);
    *size = ctx->msgp_len;
    ctx->msgp_len = 0;

    return buf;
}

/* Plugin reference */
struct flb_input_plugin in_lib_plugin = {
    .name         = "lib",
    .description  = "Library mode Input",
    .cb_init      = in_lib_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_ingest    = in_lib_ingest,
    .cb_flush_buf = in_lib_flush
};
