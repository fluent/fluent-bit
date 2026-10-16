/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#define CRI_SPACE_DELIM ' '

int flb_parser_cri_do(struct flb_parser *parser,
                        const char *in_buf, size_t in_size,
                        void **out_buf, size_t *out_size,
                        struct flb_time *out_time)
{
    int ret;
    time_t time_lookup = 0;
    double tmfrac = 0;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    char *dec_out_buf;
    size_t dec_out_size;
    size_t map_size = 4;  /* always 4 fields for CRI */
    char *time_key;
    size_t time_key_len;
    char* end_of_line = NULL;
    char* token_end = NULL;

    if (parser->time_key) {
        time_key = parser->time_key;
    }
    else {
        time_key = "time";
    }
    time_key_len = strlen(time_key);

    /* Time */
    token_end = memchr(in_buf, CRI_SPACE_DELIM, in_size);
    
    /* after we find 'time' field (which is variable length),
     * we also check that we have enough room for static size fields
     * - 1 space + stream (6 chars) + 1 space
     * - _p (1 char) + 1 space
     * = 10 characters past 'time' field
     */
    if (token_end == NULL || token_end-in_buf+10 > in_size) {
        return -1;
    }

    struct flb_tm tm = {0};
    ret = flb_parser_time_lookup(in_buf, token_end-in_buf,
        0, parser, &tm, &tmfrac);
    if (ret == -1) {
        flb_error("[parser:%s] Invalid time format %s",
                    parser->name, parser->time_fmt_full);
        return -1;
    }

    /* Prepare new outgoing buffer, then add time to it */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&tmp_pck, map_size);

    msgpack_pack_str(&tmp_pck, time_key_len);
    msgpack_pack_str_body(&tmp_pck, time_key, time_key_len);
    msgpack_pack_str(&tmp_pck, token_end-in_buf);
    msgpack_pack_str_body(&tmp_pck, in_buf, token_end-in_buf);
    token_end = token_end + 1; /* time + a space */

    /* Stream */
    if (!(!strncmp(token_end, "stdout ", 7) || !strncmp(token_end, "stderr ", 7))) {
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return -1;
    }

    msgpack_pack_str(&tmp_pck, 6);
    msgpack_pack_str_body(&tmp_pck, "stream", 6);
    msgpack_pack_str(&tmp_pck, 6);
    msgpack_pack_str_body(&tmp_pck, token_end, 6);
    token_end = token_end + 7; /* stream + a space */

    /* Partial/Full Indicator (P|F) */
    if (!(!strncmp(token_end, "F ", 2) || !strncmp(token_end, "P ", 2))) {
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return -1;
    }
    msgpack_pack_str(&tmp_pck, 2);
    msgpack_pack_str_body(&tmp_pck, "_p", 2);
    msgpack_pack_str(&tmp_pck, 1);
    msgpack_pack_str_body(&tmp_pck, token_end, 1);
    token_end = token_end + 2; /* indicator + a space */

    /* Log */
    end_of_line = memchr(token_end, '\n', in_size-(token_end-in_buf));
    if (end_of_line == NULL) {
        end_of_line = memchr(token_end, '\r', in_size-(token_end-in_buf));
    }
    if (end_of_line == NULL || end_of_line-token_end > in_size) {
        end_of_line = (char *)in_buf+in_size;
    }

    msgpack_pack_str(&tmp_pck, 3);
    msgpack_pack_str_body(&tmp_pck, "log", 3);
    msgpack_pack_str(&tmp_pck, end_of_line-token_end);
    msgpack_pack_str_body(&tmp_pck, token_end, end_of_line-token_end);

    /* Export results */
    time_lookup = flb_parser_tm2time(&tm, parser->time_system_timezone);
    out_time->tm.tv_sec = time_lookup;
    out_time->tm.tv_nsec = (tmfrac * 1000000000);

    *out_buf = tmp_sbuf.data;
    *out_size = tmp_sbuf.size;

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

    return end_of_line-in_buf;
}
