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

#define _GNU_SOURCE
#include <time.h>

#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parser_decoder.h>
#include <fluent-bit/flb_unescape.h>
#include <fluent-bit/flb_mem.h>

/*
 * https://brandur.org/logfmt
 * https://godoc.org/github.com/kr/logfmt
 *
 * ident_byte = any byte greater than ' ', excluding '=' and '"'
 * string_byte = any byte excluding '"' and '\'
 * garbage = !ident_byte
 * ident = ident_byte, { ident byte }
 * key = ident
 * value = ident | '"', { string_byte | '\', '"' }, '"'
 * pair = key, '=', value | key, '=' | key
 * message = { garbage, pair }, garbage
 */

static char ident_byte[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1,
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
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

static int logfmt_parser(struct flb_parser *parser,
                         const char *in_buf, size_t in_size,
                         msgpack_packer *tmp_pck,
                         char *time_key, size_t time_key_len,
                         time_t *time_lookup, double *tmfrac,
                         size_t *map_size)
{
    int ret;
    struct tm tm = {0};
    const unsigned char *key = NULL;
    size_t key_len = 0;
    const unsigned char *value = NULL;
    size_t value_len = 0;
    const unsigned char *c = (const unsigned char *)in_buf;
    const unsigned char *end = c + in_size;
    int last_byte;
    int do_pack = FLB_TRUE;
    int value_str = FLB_FALSE;
    int value_escape = FLB_FALSE;

    /* if map_size is 0 only count the number of k:v */
    if (*map_size == 0) {
        do_pack = FLB_FALSE;
    }

    while (c < end) {
        /* garbage */
        while ((c < end) && !ident_byte[*c]) {
            c++;
        }
        if (c == end) {
            break;
        }
        /* key */
        key = c;
        while ((c < end) && ident_byte[*c]) {
            c++;
        }
        if (c == end) {
            break;
        }

        key_len = c - key;
        /* value */
        value_len = 0;
        value_str = FLB_FALSE;
        value_escape =  FLB_FALSE;

        if (*c == '=') {
            c++;
            if (c < end) {
                if (*c == '"') {
                    c++;
                    value = c;
                    value_str = FLB_TRUE;
                    while (c < end) {
                        if (*c != '\\' && *c!= '"') {
                            c++;
                        }
                        else if (*c == '\\') {
                            value_escape =  FLB_TRUE;
                            c++;
                            if (c == end) {
                                break;
                            }
                            c++;
                        }
                        else {
                            break;
                        }
                    }
                    value_len = c - value;
                    if (c < end && *c == '\"') {
                        c++;
                    }
                }
                else {
                   value = c;
                   while ((c < end) && ident_byte[*c]) {
                      c++;
                   }
                   value_len = c - value;
                }
            }
        }

        if (key_len > 0) {
            int time_found = FLB_FALSE;

            if (parser->time_fmt && key_len == time_key_len &&
                value_len > 0 &&
                !strncmp((const char *)key, time_key, key_len)) {
                if (do_pack) {
                    ret = flb_parser_time_lookup((const char *) value, value_len,
                                                  0, parser, &tm, tmfrac);
                    if (ret == -1) {
                       flb_error("[parser:%s] Invalid time format %s.",
                                 parser->name, parser->time_fmt);
                       return -1;
                    }
                    *time_lookup = flb_parser_tm2time(&tm);
                }
                time_found = FLB_TRUE;
            }

            if (time_found == FLB_FALSE || parser->time_keep == FLB_TRUE) {
                if (do_pack) {
                    if (parser->types_len != 0) {
                        flb_parser_typecast((const char*) key, key_len,
                                            (const char*) value, value_len,
                                            tmp_pck,
                                            parser->types,
                                            parser->types_len);
                    }
                    else {
                        msgpack_pack_str(tmp_pck, key_len);
                        msgpack_pack_str_body(tmp_pck, (const char *)key, key_len);
                        if (value_len == 0) {
                            if (value_str == FLB_TRUE) {
                                msgpack_pack_str(tmp_pck, 0);
                            }
                            else {
                                msgpack_pack_nil(tmp_pck);
                            }
                        }
                        else {
                            if (value_escape == FLB_TRUE) {
                                int out_len;
                                char *out_str;

                                out_str = flb_malloc(value_len + 1);
                                if (out_str == NULL) {
                                    flb_errno();
                                    return -1;
                                }
                                out_str[0] = 0;
                                flb_unescape_string_utf8((const char *)value,
                                                          value_len,
                                                          out_str);
                                out_len = strlen(out_str);

                                msgpack_pack_str(tmp_pck, out_len);
                                msgpack_pack_str_body(tmp_pck,
                                                      out_str,
                                                      out_len);

                                flb_free(out_str);
                            }
                            else {
                                msgpack_pack_str(tmp_pck, value_len);
                                msgpack_pack_str_body(tmp_pck,
                                                      (const char *)value,
                                                      value_len);
                            }
                        }
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

int flb_parser_logfmt_do(struct flb_parser *parser,
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
    time_lookup = time(NULL);

    /* count the number of key value pairs */
    map_size = 0;
    logfmt_parser(parser, in_buf, in_size, NULL,
                  time_key, time_key_len,
                  &time_lookup, &tmfrac, &map_size);
    if (map_size == 0) {
        return -1;
    }

    /* Prepare new outgoing buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&tmp_pck, map_size);

    last_byte = logfmt_parser(parser, in_buf, in_size, &tmp_pck,
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
