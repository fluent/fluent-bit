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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_error.h>

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>

#include "in_stdin.h"

/* Initialize plugin */
int in_stdin_init(struct flb_input_instance *in,
                  struct flb_config *config, void *data)
{
    int fd;
    int ret;
    int buffer_size;
    char *tmp;
    struct flb_in_stdin_config *ctx;
    (void) data;

    /* Allocate space for the configuration */
    ctx = malloc(sizeof(struct flb_in_stdin_config));
    if (!ctx) {
        return -1;
    }

    /* Configure buffer size */
    tmp = flb_input_get_property("buffer_size", in);
    if (!tmp) {
        /* Set to default: 32kb */
        buffer_size = (32 * 1024);
    }
    else {
        /* Buffer size is specified in KB unit */
        buffer_size = atoi(tmp) * 1024;
    }
    flb_debug("[stdin] buffer_size=%i bytes", buffer_size);
    if (buffer_size < 1) {
        free(ctx);
        return -1;
    }
    ctx->buf_len  = 0;
    ctx->buf_size = buffer_size;
    ctx->buf_data = malloc(ctx->buf_size);
    if (!ctx->buf_data) {
        perror("malloc");
        free(ctx);
        return -1;
    }

    /* Initialize JSON pack state */
    flb_pack_state_init(&ctx->pack_state);

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
    flb_input_set_context(in, ctx);

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_event(in,
                                        in_stdin_collect,
                                        ctx->fd,
                                        config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for STDIN input plugin");
    }

    return 0;
}

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length);
}

static inline int process_pack(struct flb_in_stdin_config *ctx,
                               char *pack, size_t size)
{
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object entry;

    ctx->buffer_id++;

    /* First pack the results, iterate concatenated messages */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, pack, size, &off)) {
        entry = result.data;

        msgpack_pack_array(&ctx->mp_pck, 2);
        msgpack_pack_uint64(&ctx->mp_pck, time(NULL));

        msgpack_pack_map(&ctx->mp_pck, 1);
        msgpack_pack_bin(&ctx->mp_pck, 3);
        msgpack_pack_bin_body(&ctx->mp_pck, "msg", 3);
        msgpack_pack_object(&ctx->mp_pck, entry);
    }

    msgpack_unpacked_destroy(&result);

    return 0;
}

int in_stdin_collect(struct flb_config *config, void *in_context)
{
    int bytes;
    int ret;
    int available;
    jsmntok_t *t;
    struct flb_in_stdin_config *ctx = in_context;

    while (1) {
        available = (ctx->buf_size - 1) - ctx->buf_len;
        if (available > 1) {
            bytes = read(ctx->fd, ctx->buf_data + ctx->buf_len, available);
            flb_trace("in_stdin read() = %i", bytes);

            if (bytes == -1) {
                if (errno == EPIPE || errno == EINTR) {
                    return -1;
                }
                return 0;
            }
            else if (bytes == 0) {
                return -1;
            }
        }
        ctx->buf_len += bytes;

        /* Always set a delimiter to avoid buffer trash */
        ctx->buf_data[ctx->buf_len] = '\0';

        /* Check if our buffer is full */
        if (ctx->buffer_id + 1 == 100) {
            ret = flb_engine_flush(config, &in_stdin_plugin);
            if (ret == -1) {
                ctx->buffer_id = 0;
            }
        }

        char *pack;
        int out_size;

        ret = flb_pack_json_state(ctx->buf_data, ctx->buf_len,
                                  &pack, &out_size, &ctx->pack_state);
        if (ret == FLB_ERR_JSON_PART) {
            flb_debug("[in_serial] JSON incomplete, waiting for more data...");
            continue;
        }
        else if (ret == FLB_ERR_JSON_INVAL) {
            flb_debug("[in_serial] invalid JSON message, skipping");
            flb_pack_state_reset(&ctx->pack_state);
            flb_pack_state_init(&ctx->pack_state);
            ctx->pack_state.multiple = FLB_TRUE;
            ctx->buf_len = 0;
            continue;
        }

        process_pack(ctx, pack, out_size);
        free(pack);

        /* Get the last token */
        t = &ctx->pack_state.tokens[ctx->pack_state.tokens_count - 1];
        consume_bytes(ctx->buf_data, t->end + 1, ctx->buf_len - t->end - 1);

        ctx->buf_len -= t->end + 1;
        ctx->buf_data[ctx->buf_len] = '\0';
        flb_pack_state_reset(&ctx->pack_state);
        flb_pack_state_init(&ctx->pack_state);

        ctx->pack_state.multiple = FLB_TRUE;
    }

    return 0;
}

void *in_stdin_flush(void *in_context, size_t *size)
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

/* Cleanup serial input */
int in_stdin_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_stdin_config *ctx = in_context;

    close(ctx->fd);
    flb_pack_state_reset(&ctx->pack_state);
    free(ctx->buf_data);
    free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_stdin_plugin = {
    .name         = "stdin",
    .description  = "Standard Input",
    .cb_init      = in_stdin_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_stdin_collect,
    .cb_flush_buf = in_stdin_flush,
    .cb_exit      = in_stdin_exit
};
