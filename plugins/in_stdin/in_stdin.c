/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_parser.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "in_stdin.h"

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline int pack_json(struct flb_in_stdin_config *ctx,
                            char *data, size_t data_size)
{
    time_t t;
    size_t off = 0;
    size_t start = 0;
    msgpack_unpacked result;

    /* Queue the data with time field */
    msgpack_unpacked_init(&result);

    flb_input_buf_write_start(ctx->i_in);

    t = time(NULL);
    while (msgpack_unpack_next(&result, data, data_size, &off)) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            /* { map => val, map => val, map => val } */
            msgpack_pack_array(&ctx->i_in->mp_pck, 2);
            msgpack_pack_uint64(&ctx->i_in->mp_pck, t);
            msgpack_pack_str_body(&ctx->i_in->mp_pck, data + start, off - start);
        } else {
            msgpack_pack_str_body(&ctx->i_in->mp_pck, data + start, off - start);
        }
        start = off;
    }
    flb_input_buf_write_end(ctx->i_in);
    msgpack_unpacked_destroy(&result);

    return 0;
}

static inline int pack_regex(struct flb_in_stdin_config *ctx,
                             time_t time, char *data, size_t data_size)
{
    flb_input_buf_write_start(ctx->i_in);

    msgpack_pack_array(&ctx->i_in->mp_pck, 2);
    msgpack_pack_uint64(&ctx->i_in->mp_pck, time);
    msgpack_sbuffer_write(&ctx->i_in->mp_sbuf, data, data_size);

    flb_input_buf_write_end(ctx->i_in);

    return 0;
}

static int in_stdin_collect(struct flb_input_instance *i_ins,
                            struct flb_config *config, void *in_context)
{
    int bytes = 0;
    int pack_size;
    int ret;
    char *pack;
    void *out_buf;
    size_t out_size;
    time_t out_time = 0;
    struct flb_in_stdin_config *ctx = in_context;

    bytes = read(ctx->fd,
                 ctx->buf + ctx->buf_len,
                 sizeof(ctx->buf) - ctx->buf_len);
    flb_trace("in_stdin read() = %i", bytes);

    if (bytes == 0) {
        flb_warn("[in_stdin] end of file (stdin closed by remote end)");
    }

    if (bytes <= 0) {
        flb_input_collector_pause(ctx->coll_fd, ctx->i_in);
        flb_engine_exit(config);
        return -1;
    }
    ctx->buf_len += bytes;
    ctx->buf[ctx->buf_len] = '\0';

    while (ctx->buf_len > 0) {
        /* Try built-in JSON parser */
        if (!ctx->parser) {
            ret = flb_pack_json(ctx->buf, ctx->buf_len, &pack, &pack_size);
            if (ret != 0) {
                flb_warn("STDIN data incomplete, waiting for more data...");
                return 0;
            }
            pack_json(ctx, pack, out_size);
            flb_free(pack);
        }
        else {
            /* Use the defined parser */
            ret = flb_parser_do(ctx->parser, ctx->buf, ctx->buf_len,
                                &out_buf, &out_size, &out_time);
            if (ret >= 0) {
                pack_regex(ctx, out_time, out_buf, out_size);
                flb_free(out_buf);
            }
            else {
                /* we need more data ? */
                flb_trace("[in_stdin] data mismatch or incomplete");
                return 0;
            }
        }

        if (ret == ctx->buf_len) {
            ctx->buf_len = 0;
            break;
        }
        else if (ret > 0) {
            /*
             * 'ret' is the last byte consumed by the regex engine, we need
             * to advance it position.
             */
            ret++;
            consume_bytes(ctx->buf, ret, ctx->buf_len);
            ctx->buf_len -= ret;
            ctx->buf[ctx->buf_len] = '\0';
        }
    }
    return 0;
}

/* Initialize plugin */
static int in_stdin_init(struct flb_input_instance *in,
                         struct flb_config *config, void *data)
{
    int fd;
    int ret;
    char *tmp;
    struct flb_in_stdin_config *ctx;
    (void) data;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_in_stdin_config));
    if (!ctx) {
        return -1;
    }
    ctx->buf_len = 0;
    ctx->i_in = in;

    /* Clone the standard input file descriptor */
    fd = dup(STDIN_FILENO);
    if (fd == -1) {
        perror("dup");
        flb_utils_error_c("Could not open standard input!");
    }
    ctx->fd = fd;

    tmp = flb_input_get_property("parser", in);
    if (tmp) {
        ctx->parser = flb_parser_get(tmp, config);
        if (!ctx->parser) {
            flb_error("[in_stdin] requested parser '%s' not found", tmp);
        }
    }
    else {
        ctx->parser = NULL;
    }

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
    ctx->coll_fd = ret;

    return 0;
}

/* Cleanup serial input */
static int in_stdin_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_stdin_config *ctx = in_context;

    if (ctx->fd >= 0) {
        close(ctx->fd);
    }
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_stdin_plugin = {
    .name         = "stdin",
    .description  = "Standard Input",
    .cb_init      = in_stdin_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_stdin_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_stdin_exit
};
