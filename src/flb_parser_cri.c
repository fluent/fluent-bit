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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_parser_decoder.h>

#include <msgpack.h>
#include <string.h>

#define CRI_SPACE_DELIM ' '

/*
 * Fixed size section that follows the time field:
 *
 *   1 space + stream (6 chars) + 1 space + flag (1 char) + 1 space
 */
#define CRI_FIXED_LEN   10

/*
 * Check if the delimiter found after the time candidate is followed by a
 * stream name and a partial/full flag.
 */
static inline int cri_fixed_fields(const char *p)
{
    if (memcmp(p, " stdout ", 8) != 0 && memcmp(p, " stderr ", 8) != 0) {
        return FLB_FALSE;
    }

    if ((p[8] != 'F' && p[8] != 'P') || p[9] != CRI_SPACE_DELIM) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

int flb_parser_cri_do(struct flb_parser *parser,
                      const char *in_buf, size_t in_size,
                      void **out_buf, size_t *out_size,
                      struct flb_time *out_time)
{
    int ret;
    int map_size = 4;
    double tmfrac = 0;
    size_t time_len;
    size_t time_key_len;
    size_t log_len;
    size_t dec_out_size;
    char *dec_out_buf;
    char *time_key;
    const char *end;
    const char *token_end;
    const char *stream;
    const char *flag;
    const char *log;
    const char *end_of_line;
    time_t time_lookup = 0;
    struct flb_tm tm = {0};
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;

    if (parser->time_key) {
        time_key = parser->time_key;
    }
    else {
        time_key = "time";
    }
    time_key_len = strlen(time_key);

    /*
     * Time: the field ends at the first delimiter that is followed by the
     * stream and the flag, it cannot be empty. A line of a container runtime
     * always matches on the first delimiter; looking further keeps the same
     * result of the regular expression used before by this parser:
     *
     *   ^(?<time>.+?) (?<stream>stdout|stderr) (?<_p>F|P) (?<log>.*)$
     */
    end = in_buf + in_size;
    token_end = in_buf;

    while (1) {
        if ((size_t) (end - token_end) < CRI_FIXED_LEN) {
            return -1;
        }

        token_end = memchr(token_end, CRI_SPACE_DELIM,
                           (end - token_end) - (CRI_FIXED_LEN - 1));
        if (token_end == NULL) {
            return -1;
        }

        if (token_end > in_buf && cri_fixed_fields(token_end) == FLB_TRUE) {
            break;
        }
        token_end++;
    }

    time_len = token_end - in_buf;
    stream = token_end + 1;
    flag = stream + 7;
    log = flag + 2;

    /* Log: the content ends at the first line feed, if any */
    end_of_line = memchr(log, '\n', end - log);
    if (end_of_line == NULL) {
        end_of_line = end;
    }
    log_len = end_of_line - log;

    if (parser->time_fmt) {
        ret = flb_parser_time_lookup(in_buf, time_len, 0, parser, &tm, &tmfrac);
        if (ret == -1) {
            flb_warn("[parser:%s] invalid time format %s for '%.*s'",
                     parser->name, parser->time_fmt_full,
                     time_len > 254 ? 254 : (int) time_len, in_buf);
            /* the lookup may have set the fraction before it failed */
            tmfrac = 0;
            map_size--;
        }
        else {
            time_lookup = flb_parser_tm2time_parser(&tm, parser);
            if (parser->time_keep == FLB_FALSE) {
                map_size--;
            }
        }
    }

    /* Prepare new outgoing buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&tmp_pck, map_size);

    if (map_size == 4) {
        msgpack_pack_str(&tmp_pck, time_key_len);
        msgpack_pack_str_body(&tmp_pck, time_key, time_key_len);
        msgpack_pack_str(&tmp_pck, time_len);
        msgpack_pack_str_body(&tmp_pck, in_buf, time_len);
    }

    msgpack_pack_str(&tmp_pck, 6);
    msgpack_pack_str_body(&tmp_pck, "stream", 6);
    msgpack_pack_str(&tmp_pck, 6);
    msgpack_pack_str_body(&tmp_pck, stream, 6);

    msgpack_pack_str(&tmp_pck, 2);
    msgpack_pack_str_body(&tmp_pck, "_p", 2);
    msgpack_pack_str(&tmp_pck, 1);
    msgpack_pack_str_body(&tmp_pck, flag, 1);

    msgpack_pack_str(&tmp_pck, 3);
    msgpack_pack_str_body(&tmp_pck, "log", 3);
    msgpack_pack_str(&tmp_pck, log_len);
    msgpack_pack_str_body(&tmp_pck, log, log_len);

    /* Export results */
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

    /* Last byte consumed, same contract of the regex backend */
    return end_of_line - in_buf;
}
