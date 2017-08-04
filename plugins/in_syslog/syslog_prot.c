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

#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_parser.h>

#include "syslog.h"
#include "syslog_conn.h"

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline int pack_line(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                            time_t time, char *data, size_t data_size)
{
    msgpack_pack_array(mp_pck, 2);
    msgpack_pack_uint64(mp_pck, time);
    msgpack_sbuffer_write(mp_sbuf, data, data_size);
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
    time_t out_time;
    struct flb_syslog *ctx = conn->ctx;

    msgpack_sbuffer *out_sbuf;
    msgpack_packer *out_pck;

    out_sbuf = &conn->in->mp_sbuf;
    out_pck  = &conn->in->mp_pck;

    flb_input_buf_write_start(conn->in);

    eof = p = conn->buf_data;
    end = conn->buf_data + conn->buf_len;

    /* Always parse while some remaining bytes exists */
    while (eof < end) {

        /* Lookup the ending byte */
        eof = conn->buf_data + conn->buf_parsed;
        while (*eof != '\n' && *eof != '\0' && eof < end) {
            eof++;
        }

        /* Incomplete message */
        if (eof == end || (*eof != '\n' && *eof != '\0')) {
            return 0;
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
                return 0;
            }

            continue;
        }

        /* Process the string */
        ret = flb_parser_do(ctx->parser, p, len,
                            &out_buf, &out_size, &out_time);
        if (ret >= 0) {
            pack_line(out_sbuf, out_pck, out_time,
                      out_buf, out_size);
            flb_free(out_buf);
        }
        else {
            flb_warn("[in_syslog] error parsing log message");
        }

        conn->buf_parsed += len + 1;
        end = conn->buf_data + conn->buf_len;
        eof = p = conn->buf_data + conn->buf_parsed;
    }

    consume_bytes(conn->buf_data, conn->buf_parsed, conn->buf_len);
    conn->buf_len -= conn->buf_parsed;
    conn->buf_parsed = 0;
    conn->buf_data[conn->buf_len] = '\0';

    flb_input_buf_write_end(conn->in);

    return 0;
}
