/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_time.h>

#include "syslog.h"
#include "syslog_conn.h"

#include <string.h>

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline int pack_line(struct flb_syslog *ctx,
                            struct flb_time *time, char *data, size_t data_size)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_time_append_to_msgpack(time, &mp_pck, 0);
    msgpack_sbuffer_write(&mp_sbuf, data, data_size);

    flb_input_chunk_append_raw(ctx->ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

int syslog_prot_process(struct syslog_conn *conn)
{
    int len;
    int ret;
    char *p;
    char *eof;
    char *end;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time;
    struct flb_syslog *ctx = conn->ctx;

    eof = conn->buf_data;
    end = conn->buf_data + conn->buf_len;

    /* Always parse while some remaining bytes exists */
    while (eof < end) {
        /* Lookup the ending byte */
        eof = p = conn->buf_data + conn->buf_parsed;
        while (*eof != '\n' && *eof != '\0' && eof < end) {
            eof++;
        }

        /* Incomplete message */
        if (eof == end || (*eof != '\n' && *eof != '\0')) {
            break;
        }

        /* No data ? */
        len = (eof - p);
        if (len == 0) {
            consume_bytes(conn->buf_data, 1, conn->buf_len);
            conn->buf_len--;
            conn->buf_parsed = 0;
            conn->buf_data[conn->buf_len] = '\0';
            end = conn->buf_data + conn->buf_len;

            if (conn->buf_len == 0) {
                break;
            }

            continue;
        }

        /* Process the string */
        ret = flb_parser_do(ctx->parser, p, len,
                            &out_buf, &out_size, &out_time);
        if (ret >= 0) {
            pack_line(ctx, &out_time, out_buf, out_size);
            flb_free(out_buf);
        }
        else {
            flb_plg_warn(ctx->ins, "error parsing log message with parser '%s'",
                         ctx->parser->name);
            flb_plg_debug(ctx->ins, "unparsed log message: %.*s", len, p);
        }

        conn->buf_parsed += len + 1;
        end = conn->buf_data + conn->buf_len;
        eof = conn->buf_data + conn->buf_parsed;
    }

    if (conn->buf_parsed > 0) {
        consume_bytes(conn->buf_data, conn->buf_parsed, conn->buf_len);
        conn->buf_len -= conn->buf_parsed;
        conn->buf_parsed = 0;
        conn->buf_data[conn->buf_len] = '\0';
    }

    return 0;
}

static int syslog_append_client_data(char **map_data, size_t *map_size, struct flb_syslog *ctx, 
                                      struct flb_syslog_client_info *client_info) {

    int map_num;
    int i;
    int len;
    int extra_count = 0;
    char * hn = NULL;
    struct hostent *he = NULL;
    char * ret_buf = 0;
    size_t outsize;

    msgpack_packer pck;
    msgpack_sbuffer sbuf;
    msgpack_unpacked result;
    size_t off = 0;

    if (ctx->addr_key) {
        hn = inet_ntoa(client_info->client.sin_addr);
        if (hn != NULL) {
            extra_count++;
        }
    }

    if (ctx->host_key) {
        he = gethostbyaddr(&client_info->client, client_info->client_len, AF_INET);
        if (he != NULL) {
            extra_count++;
        }
    }

    if (*map_data == NULL){
        return -1;
    }

    msgpack_unpacked_init(&result);
    if ( (i=msgpack_unpack_next(&result, *map_data, *map_size, &off)) != MSGPACK_UNPACK_SUCCESS ){
        return -1;
    }
    if (result.data.type != MSGPACK_OBJECT_MAP) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    len = result.data.via.map.size;
    map_num = len + extra_count;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&pck, map_num);

    for(i=0; i<len; i++) {
        msgpack_pack_object(&pck, result.data.via.map.ptr[i].key);
        msgpack_pack_object(&pck, result.data.via.map.ptr[i].val);
    }

    if (hn != NULL) {
        msgpack_pack_str(&pck, strlen(ctx->addr_key));
        msgpack_pack_str_body(&pck, ctx->addr_key, strlen(ctx->addr_key));
        msgpack_pack_str(&pck, strlen(hn));
        msgpack_pack_str_body(&pck, hn, strlen(hn));
    }

    if (he != NULL) {
        int he_length = strlen(he->h_name);
        msgpack_pack_str(&pck, strlen(ctx->host_key));
        msgpack_pack_str_body(&pck, ctx->host_key, strlen(ctx->host_key));
        msgpack_pack_str(&pck, he_length);
        msgpack_pack_str_body(&pck, he->h_name, he_length);
    }

    msgpack_unpacked_destroy(&result);

    outsize = sbuf.size;
    ret_buf  = flb_malloc(sbuf.size);

    if (ret_buf == NULL) {
        flb_errno();
        msgpack_sbuffer_destroy(&sbuf);
        return -1;
    }
    memcpy(ret_buf, sbuf.data, sbuf.size);

    msgpack_sbuffer_destroy(&sbuf);

    // Free original map data
    flb_free(*map_data);

    *map_size = outsize;
    *map_data = ret_buf;

    return 0;
}

int syslog_prot_process_udp(char *buf, size_t size, struct flb_syslog *ctx, struct flb_syslog_client_info *client_info)
{
    int ret;
    void *out_buf;
    size_t out_size;

    struct flb_time out_time = {0};

    ret = flb_parser_do(ctx->parser, buf, size,
                        &out_buf, &out_size, &out_time);
    if (ret >= 0) {
        if (ctx->addr_key || ctx->host_key) {
            if (0 != syslog_append_client_data((char **) &out_buf, &out_size, ctx, client_info)) {
                flb_plg_warn(ctx->ins, "error adding client_info in '%s'",
                     ctx->parser->name);
            }
        }

        if (flb_time_to_double(&out_time) == 0) {
            flb_time_get(&out_time);
        }

        pack_line(ctx, &out_time, out_buf, out_size);

        flb_free(out_buf);
    }
    else {
        flb_plg_warn(ctx->ins, "error parsing log message with parser '%s'",
                     ctx->parser->name);
        flb_plg_debug(ctx->ins, "unparsed log message: %.*s",
                      (int) size, buf);
        return -1;
    }

    return 0;
}
