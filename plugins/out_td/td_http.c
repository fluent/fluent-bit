/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_http_client.h>

#include "td_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define TD_HTTP_HEADER_SIZE  512

struct flb_http_client *td_http_client(struct flb_connection *u_conn,
                                       void *data, size_t len,
                                       char **body,
                                       struct flb_td *ctx,
                                       struct flb_config *config)
{
    int ret;
    int pos = 0;
    int api_len;
    size_t gz_size;
    void *gz_data;
    char *tmp;
    struct flb_http_client *c;

    /* Compress data */
    ret = flb_gzip_compress(data, len, &gz_data, &gz_size);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "error compressing data");
        return NULL;
    }

    /* Compose URI */
    tmp = flb_malloc(512);
    if (!tmp) {
        flb_free(gz_data);
        return NULL;
    }
    snprintf(tmp, 256,
             "/v3/table/import/%s/%s/msgpack.gz",
             ctx->db_name, ctx->db_table);

    /* Create client */
    c = flb_http_client(u_conn, FLB_HTTP_PUT, tmp,
                        gz_data, gz_size, NULL, 0, NULL, 0);
    if (!c) {
        flb_free(tmp);
        flb_free(gz_data);
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
    *body = gz_data;

    return c;
}
