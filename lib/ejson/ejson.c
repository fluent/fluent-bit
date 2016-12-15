/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  eJSON
 *  =====
 *  Copyright 2016 Eduardo Silva <eduardo@monkey.io>
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
#include <string.h>
#include <assert.h>
#include <float.h>
#include "ejson.h"

static inline int check_entries_space(struct ejs_ctx *ctx)
{
    if (ctx->entries_pos + 2 >= EJS_ENTRIES_MAX) {
        return -1;
    }
    return 0;
}

static inline int check_buf_space(struct ejs_ctx *ctx, int length)
{
    if (ctx->buf_pos + length >= ctx->buf_size) {
        return -1;
    }
    return 0;
}

/* Initialize the context */
int ejs_init(struct ejs_ctx *ctx, unsigned int buf_size)
{
    ctx->entries_pos = 0;
    ctx->buf_pos = 0;
    ctx->buf_size = buf_size;

    return 0;
}

int ejs_buf_size(struct ejs_ctx *ctx, unsigned int buf_size)
{
    ctx->buf_size = buf_size;
    return 0;
}

int ejs_add_array(struct ejs_ctx *ctx, unsigned char *buf)
{
    if (check_entries_space(ctx) != 0) {
        return EJS_ERROR_ENTRIES;
    }

    if (check_buf_space(ctx, 2) != 0) {
        return EJS_ERROR_NOMEM;
    }

    buf[ctx->buf_pos++] = '[';
    buf[ctx->buf_pos] = '\0';

    EJS_TYPE_ADD(ctx, EJS_ARRAY);

    return EJS_OK;
}

int ejs_end_array(struct ejs_ctx *ctx, unsigned char *buf)
{
    if (check_buf_space(ctx, 2) != 0) {
        return EJS_ERROR_NOMEM;
    }

    buf[ctx->buf_pos++] = ']';
    buf[ctx->buf_pos] = '\0';
    ctx->entries_pos--;

    return EJS_OK;
}

int ejs_add_string(struct ejs_ctx *ctx, unsigned char *buf,
                   unsigned char *str, size_t length)
{
    if (check_buf_space(ctx, length + 4) != 0) {
        return EJS_ERROR_NOMEM;
    }

    if (buf[ctx->buf_pos - 1] != '{' && buf[ctx->buf_pos -1] != '[' &&
        buf[ctx->buf_pos - 1] != ':') {
        buf[ctx->buf_pos++] = ',';
    }

    buf[ctx->buf_pos++] = '"';
    memcpy(buf + ctx->buf_pos, str, length);
    ctx->buf_pos += length;
    buf[ctx->buf_pos++] = '"';
    buf[ctx->buf_pos] = '\0';

    return EJS_OK;
}

int ejs_add_map(struct ejs_ctx *ctx, unsigned char *buf)
{
    if (check_buf_space(ctx, 2) != 0) {
        return EJS_ERROR_NOMEM;
    }

    if (ctx->buf_pos > 0) {
        if (buf[ctx->buf_pos - 1] != '{' && buf[ctx->buf_pos -1] != '[') {
            buf[ctx->buf_pos++] = ',';
        }
    }

    buf[ctx->buf_pos++] = '{';
    buf[ctx->buf_pos] = '\0';

    EJS_TYPE_ADD(ctx, EJS_OBJECT);
    return EJS_OK;
}

int ejs_end_map(struct ejs_ctx *ctx, unsigned char *buf)
{
    if (check_buf_space(ctx, 2) != 0) {
        return EJS_ERROR_NOMEM;
    }

    buf[ctx->buf_pos++] = '}';
    buf[ctx->buf_pos] = '\0';
    EJS_TYPE_DEL(ctx);

    return EJS_OK;
}

int ejs_add_map_key(struct ejs_ctx *ctx, unsigned char *buf,
                    unsigned char *k_buf, size_t k_length)
{
    int ret;
    assert(EJS_TYPE(ctx) != EJS_OBJECT);

    ret = ejs_add_string(ctx, buf, k_buf, k_length);
    if (ret != EJS_OK) {
        return ret;
    }

    buf[ctx->buf_pos++] = ':';
    EJS_TYPE_ADD(ctx, EJS_MAP_KEY);
    return ret;
}

int ejs_add_num(struct ejs_ctx *ctx, unsigned char *buf, double val)
{
    int ret;
    int max = 15; /* DBL_MAX is  140729402243144 (15 bytes worse case) */

    if (check_buf_space(ctx, max + 3) != 0) {
        return EJS_ERROR_NOMEM;
    }

    ret = snprintf(buf + ctx->buf_pos,
                   ctx->buf_size - ctx->buf_pos, "%.16g", val);
    if (ret == -1) {
        return EJS_ERROR_INVAL;
    }

    ctx->buf_pos += ret;
    return 0;
}
