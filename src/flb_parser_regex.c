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

#define _GNU_SOURCE
#include <time.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_regex.h>
#include <msgpack.h>

struct regex_cb_ctx {
    time_t time_lookup;
    struct flb_parser *parser;
    msgpack_packer *pck;
};

static void cb_results(unsigned char *name, unsigned char *value,
                       size_t vlen, void *data)
{
    int len;
    (void) data;
    char *time_key;
    struct regex_cb_ctx *pcb = data;
    struct flb_parser *parser = pcb->parser;
    struct tm tm = {0};

    len = strlen((char *)name);

    /* Check if there is a time lookup field */
    if (parser->time_fmt) {
        if (parser->time_key) {
            time_key = parser->time_key;
        }
        else {
            time_key = "time";
        }

        if (strcmp((char *) name, time_key) == 0) {
            if (strptime((char *) value, parser->time_fmt, &tm) != NULL) {
                pcb->time_lookup = mktime(&tm);
                return;
            }
            else {
                flb_error("[parser] Invalid time format %s", parser->time_fmt);
                return;
            }
        }
    }

    msgpack_pack_str(pcb->pck, len);
    msgpack_pack_str_body(pcb->pck, (char *) name, len);
    msgpack_pack_str(pcb->pck, vlen);
    msgpack_pack_str_body(pcb->pck, (char *) value, vlen);
}

int flb_parser_regex_do(struct flb_parser *parser,
                        char *buf, size_t length,
                        void **out_buf, size_t *out_size,
                        time_t *out_time)
{
    ssize_t n;
    int arr_size;
    struct flb_regex_search result;
    struct regex_cb_ctx pcb;

    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    n = flb_regex_do(parser->regex, (unsigned char *) buf, length, &result);
    if (n <= 0) {
        return -1;
    }

    /* Prepare new outgoing buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    if (parser->time_fmt) {
        arr_size = (n - 1);
    }
    else {
        arr_size = n;
    }

    msgpack_pack_map(&tmp_pck, arr_size);

    /* Callback context */
    pcb.pck = &tmp_pck;
    pcb.parser = parser;
    pcb.time_lookup = 0;

    /* Iterate results and compose new buffer */
    flb_regex_parse(parser->regex, &result, cb_results, &pcb);

    /* Export results */
    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;
    *out_time = pcb.time_lookup;

    return 0;
}
