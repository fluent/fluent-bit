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

#include "in_stdin.h"

/* Initialize plugin */
int in_stdin_init(struct flb_config *config)
{
    int fd;
    int ret;
    struct flb_in_stdin_config *ctx;

    /* Allocate space for the configuration */
    ctx = malloc(sizeof(struct flb_in_stdin_config));
    if (!ctx) {
        return -1;
    }

    /* initialize MessagePack buffers */
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);
    ctx->buffer_id = 0;

    /* Clone the standard input file descriptor */
    fd = dup(STDIN_FILENO);
    if (fd == -1) {
        perror("dup");
        flb_utils_error_c("Could not open standard input!");
    }
    ctx->fd = fd;

    /* Set the context */
    ret = flb_input_set_context("stdin", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for STDIN input plugin");
    }

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_event("stdin",
                                        in_stdin_collect,
                                        ctx->fd,
                                        config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for STDIN input plugin");
    }

    return 0;
}

int in_stdin_collect(struct flb_config *config, void *in_context)
{
    int bytes;
    int out_size;
    char *pack;
    msgpack_unpacked result;
    size_t start = 0, off = 0;
    struct flb_in_stdin_config *ctx = in_context;

    bytes = read(ctx->fd,
                 ctx->buf + ctx->buf_len,
                 sizeof(ctx->buf) - ctx->buf_len);
    flb_debug("in_stdin read() = %i", bytes);
    if (bytes <= 0) {
        return -1;
    }
    ctx->buf_len += bytes;

    /* Initially we should support JSON input */
    pack = flb_pack_json(ctx->buf, ctx->buf_len, &out_size);
    if (!pack) {
        flb_debug("STDIN data incomplete, waiting for more data...");
        return 0;
    }
    ctx->buf_len = 0;

    /* Queue the data with time field */
    msgpack_unpacked_init(&result);

    while (msgpack_unpack_next(&result, pack, out_size, &off)) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            /* { map => val, map => val, map => val } */
            msgpack_pack_array(&ctx->mp_pck, 2);
            msgpack_pack_uint64(&ctx->mp_pck, time(NULL));
            msgpack_pack_bin_body(&ctx->mp_pck, pack + start, off - start);
        } else {
            msgpack_pack_bin_body(&ctx->mp_pck, pack + start, off - start);
        }
        ctx->buffer_id++;

        start = off;
    }
    msgpack_unpacked_destroy(&result);

    free(pack);
    return 0;
}

void *in_stdin_flush(void *in_context, int *size)
{
    char *buf;
    msgpack_sbuffer *sbuf;
    struct flb_in_stdin_config *ctx = in_context;

    if (ctx->buffer_id == 0)
        goto fail;

    sbuf = &ctx->mp_sbuf;
    *size = sbuf->size;
    buf = malloc(sbuf->size);
    if (!buf)
        goto fail;

    /* set a new buffer and re-initialize our MessagePack context */
    memcpy(buf, sbuf->data, sbuf->size);
    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    ctx->buffer_id = 0;

    return buf;

fail:
    return NULL;
}

/* Plugin reference */
struct flb_input_plugin in_stdin_plugin = {
    .name         = "stdin",
    .description  = "Standard Input",
    .cb_init      = in_stdin_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_stdin_collect,
    .cb_flush_buf = in_stdin_flush
};
