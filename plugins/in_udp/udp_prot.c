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
#include <fluent-bit/flb_pack.h>

#include "udp.h"
#include "udp_conn.h"

#include <string.h>


static size_t rtrimlen(char *buf,  size_t size)
{
    uint8_t *b = (uint8_t*) buf;
    uint8_t *p;
    if (size <= 0) {
        return size;
    }
    for (p = (uint8_t*) b + (size - 1); p >= b; p--) {
        if (*p > 32) {
            return p - b + 1;
        }
    }
    return 0;
}

static inline int pack_line(struct flb_udp *ctx,
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


int udp_prot_process_parsed(char *buf, size_t size, struct flb_udp *ctx)
{
    int ret;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time = {0};

    ret = flb_parser_do(ctx->parser, buf, size,
                        &out_buf, &out_size, &out_time);
    if (ret >= 0) {
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

int udp_prot_process_unparsed(char *buf, size_t size, struct flb_udp *ctx)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);

    flb_pack_time_now(&mp_pck);

    msgpack_pack_map(&mp_pck, 1);
    /* key: message == 7 */
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "message",7);

    /* value: input  */
    msgpack_pack_str(&mp_pck, size);
    msgpack_pack_str_body(&mp_pck, buf,size);

    flb_input_chunk_append_raw(ctx->ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);

    msgpack_sbuffer_destroy(&mp_sbuf);
    return 0;
}

int udp_prot_process_udp(char *buf, size_t size, struct flb_udp *ctx)
{
    if (ctx->rtrim) {
        size = rtrimlen(buf, size);
    }

    if (ctx->parser) {
        udp_prot_process_parsed(buf, size, ctx);
    } else {
        udp_prot_process_unparsed(buf, size, ctx);
    }
    return 0;
}
