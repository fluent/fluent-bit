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
                            struct flb_time *time, char *data, size_t data_size)
{
    msgpack_pack_array(mp_pck, 2);
    flb_time_append_to_msgpack(time, mp_pck, 0);
    msgpack_sbuffer_write(mp_sbuf, data, data_size);
    return 0;
}

int syslog_prot_process(struct syslog_conn *conn)
{
    int len;
    int ret;
    int lines = 0;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time;
    struct flb_syslog *ctx = conn->ctx;
    const char ends[] = "\r\n\0";

    msgpack_sbuffer *out_sbuf;
    msgpack_packer *out_pck;

    out_sbuf = &conn->in->mp_sbuf;
    out_pck  = &conn->in->mp_pck;

    flb_input_buf_write_start(conn->in);

    while ((len = strcspn(conn->buf_data, ends))) {
        if (len == 0) {
            if (conn->buf_len > 0) {
                consume_bytes(conn->buf_data, 1, conn->buf_len);
                conn->buf_len--;
            }
            conn->buf_parsed = 0;
            conn->buf_data[conn->buf_len] = '\0';
            if (conn->buf_len == 0) {
                break;
            }
            continue;
        }

        ret = flb_parser_do(ctx->parser, conn->buf_data, len,
                            &out_buf, &out_size, &out_time);
        if (ret >= 0) {
            pack_line(out_sbuf, out_pck, &out_time,
                      out_buf, out_size);
            flb_free(out_buf);
        }
        else {
            flb_warn("[in_syslog] error parsing log message");
        }

        consume_bytes(conn->buf_data, len + 1, conn->buf_len);
        conn->buf_len -= len + 1;
        conn->buf_data[conn->buf_len] = '\0';
        conn->buf_parsed = 0;
        lines++;
    }

    flb_input_buf_write_end(conn->in);

    return lines;
}
