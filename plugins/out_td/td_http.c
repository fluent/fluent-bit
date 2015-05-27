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
#include <string.h>
#include <zlib.h>

#include <fluent-bit/flb_config.h>
#include "td_config.h"

#define TD_HTTP_HEADER_SIZE  512

static inline void strm_init(z_stream *strm)
{
    strm->zalloc = Z_NULL;
    strm->zfree  = Z_NULL;
    strm->opaque = Z_NULL;

    deflateInit2(strm, Z_DEFAULT_COMPRESSION,
                 Z_DEFLATED, 31, 9, Z_DEFAULT_STRATEGY);
}

static void *gzip_compress(void *data, size_t len, size_t *out_len)
{
    int res;
    int flush;
    int err;
    int status;
    int buf_len;
    void *buf;
    ssize_t ret = 0;
    z_stream strm;

    strm_init(&strm);

    buf_len = len + 32;
    buf = malloc(buf_len);
    if (!buf) {
        perror("malloc");
        return NULL;
    }

    strm.next_in   = data;
    strm.avail_in  = len;
    strm.total_out = 0;
    flush = Z_NO_FLUSH;

    while (1) {
        strm.next_out  = buf + strm.total_out;
        strm.avail_out = buf_len - strm.total_out;

        if (strm.avail_in == 0) {
            flush = Z_FINISH;
        }

        status = deflate(&strm, flush);
        if (status == Z_STREAM_END) {
            break;
        }
        else if (status != Z_OK) {
            deflateEnd(&strm);
            free(buf);
            return NULL;
        }
    }
    deflateEnd(&strm);
    *out_len = strm.total_out;

    return buf;
}

char *td_http_request(void *data, size_t len,
                      size_t *out_len,
                      struct flb_out_td_config *ctx, struct flb_config *config)
{
    int ret;
    size_t gz_size;
    char *gz;
    char *req;
    char *fmt =
        "PUT /v3/table/import/%s/%s/msgpack.gz HTTP/1.1\r\n"
        "Host: api.treasuredata.com:80\r\n"
        "User-Agent: Fluent-Bit\r\n"
        "Authorization: TD1 %s\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Type: application/gzip\r\n"
        "Content-Length: %lu\r\n\r\n";

    gz = gzip_compress(data, len, &gz_size);
    if (!gz) {
        return NULL;
    }

    req = malloc(TD_HTTP_HEADER_SIZE + gz_size);
    if (!req) {
        free(gz);
        return NULL;
    }

    ret = snprintf(req, TD_HTTP_HEADER_SIZE + gz_size,
                   fmt,
                   ctx->db_name, ctx->db_table,
                   ctx->api,
                   gz_size);
    if (ret == -1) {
        free(gz);
        free(req);
        return NULL;
    }

    memcpy(req + ret, gz, gz_size);
    *out_len = ret + gz_size;
    free(gz);

    return req;
}
