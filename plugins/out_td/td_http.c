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
#include <string.h>
#include <zlib.h>

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_http_client.h>
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
    int flush;
    int status;
    int buf_len;
    void *buf;
    z_stream strm;

    strm_init(&strm);

    buf_len = len + 32;
    buf = flb_malloc(buf_len);
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
            flb_free(buf);
            return NULL;
        }
    }
    deflateEnd(&strm);
    *out_len = strm.total_out;

    return buf;
}

struct flb_http_client *td_http_client(struct flb_upstream_conn *u_conn,
                                       void *data, size_t len,
                                       char **body,
                                       struct flb_out_td_config *ctx,
                                       struct flb_config *config)
{
    int pos = 0;
    int api_len;
    size_t gz_size;
    char *gz;
    char *tmp;
    struct flb_http_client *c;

    /* Compress data */
    gz = gzip_compress(data, len, &gz_size);
    if (!gz) {
        return NULL;
    }

    /* Compose URI */
    tmp = flb_malloc(512);
    if (!tmp) {
        flb_free(gz);
        return NULL;
    }
    snprintf(tmp, 256,
             "/v3/table/import/%s/%s/msgpack.gz",
             ctx->db_name, ctx->db_table);

    /* Create client */
    c = flb_http_client(u_conn, FLB_HTTP_PUT, tmp,
                        gz, gz_size, NULL, 0, NULL);
    if (!c) {
        flb_free(tmp);
        flb_free(gz);
        return NULL;
    }

    /* Add custom headers */
    tmp[pos++] = 'T';
    tmp[pos++] = 'D';
    tmp[pos++] = '1';
    tmp[pos++] = ' ';

    api_len = strlen(ctx->api);
    memcpy(tmp + pos, ctx->api, api_len);
    pos += api_len;

    flb_http_add_header(c,
                        "Authorization", 13,
                        tmp, pos);
    flb_http_add_header(c,
                        "Content-Type", 12,
                        "application/gzip", 16);
    flb_free(tmp);
    *body = gz;

    return c;
}
