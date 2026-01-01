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

#define _GNU_SOURCE
#include <time.h>

#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parser_decoder.h>

/*
 *  http://ltsv.org
 *
 *  ltsv        = *(record NL) [record]
 *  record      = [field *(TAB field)]
 *  field       = label ":" field-value
 *  label       = 1*lbyte
 *  field-value = *fbyte
 *
 *  TAB   = %x09
 *  NL    = [%x0D] %x0A
 *  lbyte = %x30-39 / %x41-5A / %x61-7A / "_" / "." / "-" ;; [0-9A-Za-z_.-]
 *  fbyte = %x01-08 / %x0B / %x0C / %x0E-FF
 */

static char ltvs_label[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static char ltvs_field[256] = {
    0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};


static int ltsv_parser(struct flb_parser *parser,
                       const char *in_buf, size_t in_size,
                       msgpack_packer *tmp_pck,
                       char *time_key, size_t time_key_len,
                       time_t *time_lookup, double *tmfrac,
                       size_t *map_size)
{
    int ret;
    struct flb_tm tm = {0};
    const unsigned char *label = NULL;
    size_t label_len = 0;
    const unsigned char *field = NULL;
    size_t field_len = 0;
    const unsigned char *c = (const unsigned char *)in_buf;
    const unsigned char *end = c + in_size;
    int last_byte;
    int do_pack = FLB_TRUE;

    /* if map_size is 0 only count the number of k:v */
    if (*map_size == 0) {
        do_pack = FLB_FALSE;
    }

    while (c < end) {
        label = c;
        while ((c < end) && ltvs_label[*c]) {
            c++;
        }
        label_len = c - label;
        if (c == end) {
            break;
        }

        if (*c != ':') {
            break;
        }
        c++;

        field = c;
        if (c != end) {
            while ((c < end) && ltvs_field[*c]) {
                c++;
            }
        }
        field_len = c - field;

        if (label_len > 0) {
            int time_found = FLB_FALSE;

            if (parser->time_fmt && label_len == time_key_len &&
                field_len > 0 &&
                !strncmp((const char *)label, time_key, label_len)) {
                if (do_pack) {
                    ret = flb_parser_time_lookup((const char *) field, field_len,
                                                  0, parser, &tm, tmfrac);
                    if (ret == -1) {
                       flb_error("[parser:%s] Invalid time format %s",
                                 parser->name, parser->time_fmt_full);
                       return -1;
                    }
                    *time_lookup = flb_parser_tm2time(&tm, parser->time_system_timezone);
                }
                time_found = FLB_TRUE;
            }

            if (time_found == FLB_FALSE || parser->time_keep == FLB_TRUE) {
                if (do_pack) {
                    if (parser->types_len != 0) {
                        flb_parser_typecast((const char*) label, label_len,
                                            (const char*) field, field_len,
                                            tmp_pck,
                                            parser->types,
                                            parser->types_len);
                    }
                    else {
                        msgpack_pack_str(tmp_pck, label_len);
                        msgpack_pack_str_body(tmp_pck, (const char *)label, label_len);
                        msgpack_pack_str(tmp_pck, field_len);
                        msgpack_pack_str_body(tmp_pck, (const char *)field, field_len);
                    }
                }
                else {
                    (*map_size)++;
                }
            }
        }

        if (c == end) {
            break;
        }
        if (*c == '\t') {
            c++;
        }
        if (c == end) {
            break;
        }

        if (*c == '\r') {
            c++;
            if (c == end) {
                break;
            }
            if (*c == '\n') {
                c++;
            }
            break;
        }
        if (*c == '\n') {
            c++;
            break;
        }
    }
    last_byte = (const char *)c - in_buf;

    return last_byte;
}

int flb_parser_ltsv_do(struct flb_parser *parser,
                       const char *in_buf, size_t in_size,
                       void **out_buf, size_t *out_size,
                       struct flb_time *out_time)
{
    int ret;
    time_t time_lookup;
    double tmfrac = 0;
    struct flb_time *t;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    char *dec_out_buf;
    size_t dec_out_size;
    size_t map_size;
    char *time_key;
    size_t time_key_len;
    int last_byte;

    if (parser->time_key) {
        time_key = parser->time_key;
    }
    else {
        time_key = "time";
    }
    time_key_len = strlen(time_key);
    time_lookup = 0;

    /* count the number of key value pairs */
    map_size = 0;
    ltsv_parser(parser, in_buf, in_size, NULL,
                time_key, time_key_len,
                &time_lookup, &tmfrac, &map_size);
    if (map_size == 0) {
        return -1;
    }

    /* Prepare new outgoing buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&tmp_pck, map_size);

    last_byte = ltsv_parser(parser, in_buf, in_size, &tmp_pck,
                            time_key, time_key_len,
                            &time_lookup, &tmfrac, &map_size);
    if (last_byte < 0) {
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return last_byte;
    }

    /* Export results */
    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    t = out_time;
    t->tm.tv_sec  = time_lookup;
    t->tm.tv_nsec = (tmfrac * 1000000000);

    /* Check if some decoder was specified */
    if (parser->decoders) {
        ret = flb_parser_decoder_do(parser->decoders,
                                    tmp_sbuf.data, tmp_sbuf.size,
                                    &dec_out_buf, &dec_out_size);
        if (ret == 0) {
            *out_buf = dec_out_buf;
            *out_size = dec_out_size;
            msgpack_sbuffer_destroy(&tmp_sbuf);
        }
    }

    return last_byte;
}
