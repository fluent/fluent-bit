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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_parser_decoder.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_str.h>

#include <msgpack.h>

/* don't do this at home */
#define pack_uint16(buf, d) _msgpack_store16(buf, (uint16_t) d)
#define pack_uint32(buf, d) _msgpack_store32(buf, (uint32_t) d)

struct regex_cb_ctx {
    int num_skipped;
    time_t time_lookup;
    time_t time_now;
    double time_frac;
    struct flb_parser *parser;
    msgpack_packer *pck;
};

static void cb_results(const char *name, const char *value,
                       size_t vlen, void *data)
{
    int len;
    int ret;
    double frac = 0;
    char *time_key;
    char tmp[255];
    struct regex_cb_ctx *pcb = data;
    struct flb_parser *parser = pcb->parser;
    struct flb_tm tm = {0};
    (void) data;

    if (vlen == 0 && parser->skip_empty) {
        pcb->num_skipped++;
        return;
    }

    len = strlen(name);

    /* Check if there is a time lookup field */
    if (parser->time_fmt) {
        if (parser->time_key) {
            time_key = parser->time_key;
        }
        else {
            time_key = "time";
        }

        if (strcmp(name, time_key) == 0) {
            /* Lookup time */
            ret = flb_parser_time_lookup(value, vlen,
                                         pcb->time_now, parser, &tm, &frac);
            if (ret == -1) {
                if (vlen > sizeof(tmp) - 1) {
                    vlen = sizeof(tmp) - 1;
                }
                memcpy(tmp, value, vlen);
                tmp[vlen] = '\0';
                flb_warn("[parser:%s] invalid time format %s for '%s'",
                         parser->name, parser->time_fmt_full, tmp);
                pcb->num_skipped++;
                return;
            }

            pcb->time_frac = frac;
            pcb->time_lookup = flb_parser_tm2time(&tm, parser->time_system_timezone);

            if (parser->time_keep == FLB_FALSE) {
                pcb->num_skipped++;
                return;
            }
        }
    }

    if (parser->types_len != 0) {
        flb_parser_typecast(name, len,
                            value, vlen,
                            pcb->pck,
                            parser->types,
                            parser->types_len);
    }
    else {
        msgpack_pack_str(pcb->pck, len);
        msgpack_pack_str_body(pcb->pck, name, len);
        msgpack_pack_str(pcb->pck, vlen);
        msgpack_pack_str_body(pcb->pck, value, vlen);
    }
}

int flb_parser_regex_do(struct flb_parser *parser,
                        const char *buf, size_t length,
                        void **out_buf, size_t *out_size,
                        struct flb_time *out_time)
{
    int ret;
    int arr_size;
    int last_byte;
    ssize_t n;
    size_t dec_out_size;
    char *dec_out_buf;
    char *tmp;
    struct flb_regex_search result;
    struct regex_cb_ctx pcb;
    struct flb_time *t;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    n = flb_regex_do(parser->regex, buf, length, &result);
    if (n <= 0) {
        return -1;
    }

    /* Prepare new outgoing buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Set a Map size with the exact number of matches returned by regex */
    arr_size = n;
    msgpack_pack_map(&tmp_pck, arr_size);

    /* Callback context */
    pcb.pck = &tmp_pck;
    pcb.parser = parser;
    pcb.num_skipped = 0;
    pcb.time_lookup = 0;
    pcb.time_frac = 0;
    pcb.time_now = 0;

    /* Iterate results and compose new buffer */
    last_byte = flb_regex_parse(parser->regex, &result, cb_results, &pcb);
    if (last_byte == -1) {
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return -1;
    }

    /*
     * There some special cases when the Parser have a 'time' handling
     * requirement, meaning: lookup for this 'time' key and resolve the
     * real date of the record. If so, the parser by default will
     * keep the original 'time' key field found but in other scenarios
     * it may ask to skip it.
     *
     * If a time lookup is specified and the parser ask to skip the record
     * and the time key is found, we need to adjust the msgpack header
     * map size, initially we set a size to include all keys found, but
     * until now we just know we are not going to include it.
     *
     * In addition, keys without associated values are skipped too and we
     * must take this into account in msgpack header map size adjustment.
     *
     * In order to avoid to create a new msgpack buffer and repack the
     * map entries, we just position at the header byte and do the
     * proper adjustment in our original buffer. Note that for cases
     * where the map is large enough '<= 65535' or '> 65535' we have
     * to use internal msgpack api functions since packing the bytes
     * in Big-Endian is a requirement.
     */
     if (pcb.num_skipped > 0) {

        arr_size = (n - pcb.num_skipped);

        tmp = tmp_sbuf.data;
        uint8_t h = tmp[0];
        if (h >> 4 == 0x8) { /* 1000xxxx */
            *tmp = (uint8_t) 0x8 << 4 | ((uint8_t) arr_size);
        }
        else if (h == 0xde) {
            tmp++;
            pack_uint16(tmp, arr_size);
        }
        else if (h == 0xdf) {
            tmp++;
            pack_uint32(tmp, arr_size);
        }
    }

    /* Export results */
    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

    t = out_time;
    t->tm.tv_sec  = pcb.time_lookup;
    t->tm.tv_nsec = (pcb.time_frac * 1000000000);

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

    /*
     * The return the value >= 0, belongs to the LAST BYTE consumed by the
     * regex engine. If the last byte is lower than string length, means
     * there is more data to be processed (maybe it's a stream).
     */
    return last_byte;
}
