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
    time_t time_now;
    struct flb_parser *parser;
    msgpack_packer *pck;
};

/*
 * Taken from Facebook Engineering post:
 *
 * https://www.facebook.com/notes/facebook-engineering/three-optimization-tips-for-c/10151361643253920
 */

static inline uint32_t digits10(uint64_t v) {
    if (v < 10) return 1;
    if (v < 100) return 2;
    if (v < 1000) return 3;
    if (v < 1000000000000UL) {
        if (v < 100000000UL) {
            if (v < 1000000) {
                if (v < 10000) return 4;
                return 5 + (v >= 100000);
            }
            return 7 + (v >= 10000000UL);
        }
        if (v < 10000000000UL) {
            return 9 + (v >= 1000000000UL);
        }
        return 11 + (v >= 100000000000UL);
    }
    return 12 + digits10(v / 1000000000000UL);
}

static unsigned u64_to_str(uint64_t value, char* dst) {
    static const char digits[201] =
        "0001020304050607080910111213141516171819"
        "2021222324252627282930313233343536373839"
        "4041424344454647484950515253545556575859"
        "6061626364656667686970717273747576777879"
        "8081828384858687888990919293949596979899";
    uint32_t const length = digits10(value);
    uint32_t next = length - 1;
    while (value >= 100) {
        int const i = (value % 100) * 2;
        value /= 100;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
        next -= 2;
    }

    /* Handle last 1-2 digits */
    if (value < 10) {
        dst[next] = '0' + (uint32_t) value;
    } else {
        int i = (uint32_t) value * 2;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
    }
    return length;
}

static void cb_results(unsigned char *name, unsigned char *value,
                       size_t vlen, void *data)
{
    int len;
    char *fmt;
    char tmp[64];
    char *p;
    char *time_key;
    struct regex_cb_ctx *pcb = data;
    struct flb_parser *parser = pcb->parser;
    struct tm tm = {0};
    (void) data;

    len = strlen((char *) name);

    /* Check if there is a time lookup field */
    if (parser->time_fmt) {
        if (parser->time_key) {
            time_key = parser->time_key;
        }
        else {
            time_key = "time";
        }

        if (strcmp((char *) name, time_key) == 0) {
            if (parser->time_with_year == FLB_TRUE) {
                p = strptime((char *) value, parser->time_fmt, &tm);
            }
            else {
                memcpy(tmp, value, vlen);
                fmt = tmp + vlen;
                *fmt++ = ' ';

                /*
                 * This is not the most elegant way but for now it let
                 * get the work done.
                 */
                localtime_r(&pcb->time_now, &tm);
                uint64_t t = tm.tm_year + 1900;
                u64_to_str(t, fmt);
                fmt += 4;
                *fmt = '\0';

                p = strptime(tmp, parser->time_fmt_year, &tm);
            }

            if (p != NULL) {
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
    pcb.time_now = time(NULL);

    /* Iterate results and compose new buffer */
    flb_regex_parse(parser->regex, &result, cb_results, &pcb);

    /* Export results */
    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;
    *out_time = pcb.time_lookup;

    return 0;
}
