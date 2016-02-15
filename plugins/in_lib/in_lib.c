/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <fluent-bit/flb_error.h>
#include "in_lib.h"

/* Initialize plugin */
int in_lib_init(struct flb_input_instance *in,
                struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_lib_config *ctx;
    (void) data;

    /* Allocate space for the configuration */
    ctx = malloc(sizeof(struct flb_in_lib_config));
    if (!ctx) {
        return -1;
    }

    ctx->buf_size = LIB_BUF_CHUNK;
    ctx->buf_data = calloc(1, LIB_BUF_CHUNK);
    ctx->buf_len = 0;

    if (!ctx->buf_data) {
        flb_utils_error_c("Could not allocate initial buf memory buffer");
    }

    ctx->msgp_size = LIB_BUF_CHUNK;
    ctx->msgp_data = malloc(LIB_BUF_CHUNK);
    ctx->msgp_len = 0;

    /* Init communication channel */
    flb_input_channel_init(in);
    ctx->fd = in->channel[0];

    if (!ctx->msgp_data) {
        flb_utils_error_c("Could not allocate initial msgp memory buffer");
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_event(in,
                                        in_lib_collect,
                                        ctx->fd,
                                        config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for LIB input plugin");
    }

    flb_pack_state_init(&ctx->state);
    return 0;
}

int in_lib_exit(void *data, struct flb_config *config)
{
    (void) config;
    struct flb_in_lib_config *ctx = data;

    if (ctx->buf_data) {
        free(ctx->buf_data);
    }

    if (ctx->msgp_data) {
        free(ctx->msgp_data);
    }

    free(ctx);
    return 0;
}

int in_lib_collect(struct flb_config *config, void *in_context)
{
    int n;
    int ret;
    int bytes;
    int out_size;
    int capacity;
    int size;
    char *ptr;
    char *pack;
    struct flb_in_lib_config *ctx = in_context;

    capacity = (ctx->buf_size - ctx->buf_len);

    /* Allocate memory as required (FIXME: this will be limited in later) */
    if (capacity == 0) {
        size = ctx->buf_size + LIB_BUF_CHUNK;
        ptr = realloc(ctx->buf_data, size);
        if (!ptr) {
            perror("realloc");
            return -1;
        }
        ctx->buf_data = ptr;
        ctx->buf_size = size;
        capacity = LIB_BUF_CHUNK;
    }

    bytes = read(ctx->fd,
                 ctx->buf_data + ctx->buf_len,
                 capacity);
    flb_debug("in_lib read() = %i", bytes);
    if (bytes == -1) {
        perror("read");
        if (errno == -EPIPE) {
            return -1;
        }
        return 0;
    }
    ctx->buf_len += bytes;

    /* initially we should support json input */
    ret = flb_pack_json_state(ctx->buf_data, ctx->buf_len,
                              &pack, &out_size, &ctx->state);
    if (ret == FLB_ERR_JSON_PART) {
        flb_debug("lib data incomplete, waiting for more data...");
        return 0;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_debug("lib data invalid");
        flb_pack_state_reset(&ctx->state);
        flb_pack_state_init(&ctx->state);
        return -1;
    }
    ctx->buf_len = 0;

    capacity = (ctx->msgp_size - ctx->msgp_len);
    if (capacity < out_size) {
        n = ((out_size - capacity) / LIB_BUF_CHUNK) + 1;
        size = ctx->msgp_size + (LIB_BUF_CHUNK * n);
        ptr = realloc(ctx->msgp_data, size);
        if (!ptr) {
            perror("realloc");
            free(pack);
            flb_pack_state_reset(&ctx->state);
            flb_pack_state_init(&ctx->state);
            return -1;
        }
        ctx->msgp_data = ptr;
        ctx->msgp_size = size;
    }

    memcpy(ctx->msgp_data + ctx->msgp_len, pack, out_size);
    ctx->msgp_len += out_size;
    free(pack);

    flb_pack_state_reset(&ctx->state);
    flb_pack_state_init(&ctx->state);

    return 0;
}

void *in_lib_flush(void *in_context, int *size)
{
    char *buf;
    struct flb_in_lib_config *ctx = in_context;

    if (ctx->msgp_len == 0) {
        *size = 0;
        return NULL;
    }

    buf = malloc(ctx->msgp_len);
    memcpy(buf, ctx->msgp_data, ctx->msgp_len);
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
    .cb_ingest    = NULL,
    .cb_flush_buf = in_lib_flush,
    .cb_exit      = in_lib_exit
};
