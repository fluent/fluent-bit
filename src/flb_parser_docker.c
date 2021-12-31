/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_unescape.h>

/* pack JSON string */
static inline int pack_string_token(struct flb_pack_state *state,
                                    int unescape_utf8,
                                    const char *str, int len,
                                    msgpack_packer *pck)
{
    int s;
    int out_len;
    char *tmp;
    char *out_buf;

    if (state->buf_size < len + 1) {
        s = len + 1;
        tmp = flb_realloc(state->buf_data, s);
        if (!tmp) {
            flb_errno();
            return -1;
        }
        else {
            state->buf_data = tmp;
            state->buf_size = s;
        }
    }
    out_buf = state->buf_data;

    /* Unescape string if needed */
    if (unescape_utf8) {
        out_len = flb_unescape_string_utf8(str, len, out_buf);

        /* Pack unescaped text */
        msgpack_pack_str(pck, out_len);
        msgpack_pack_str_body(pck, out_buf, out_len);
    }
    else {
        /* Pack raw text */
        msgpack_pack_str(pck, len);
        msgpack_pack_str_body(pck, str, len);
        out_len = len;
    }

    return out_len;
}

/* convert JSON tokens to msgpack */
static int process_tokens(struct flb_pack_state *state, const char *js,
                          char **out_buf, size_t *out_size, int *n_records,
                          int *time_token)
{
    int i;
    int ret;
    int flen;
    int arr_size;
    int records = 0;
    int time_id = -1;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    jsmntok_t *tokens;
    const jsmntok_t *t;

    tokens = state->tokens;
    arr_size = state->tokens_count;

    if (arr_size == 0) {
        return -1;
    }

    /* initialize buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    for (i = 0; i < arr_size ; i++) {
        t = &tokens[i];

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
        }

        if (t->parent == -1) {
            records++;
        }

        flen = (t->end - t->start);

        if (t->type == JSMN_STRING) {
            if (t->escaped) {
                ret = pack_string_token(state, FLB_TRUE,
                                        js + t->start, flen, &mp_pck);
            }
            else {
                ret = pack_string_token(state, FLB_FALSE,
                                        js + t->start, flen, &mp_pck);

                /* the time value is a non-scaped string field */
                if (flen == 4 && (memcmp(js + t->start, "time", 4) == 0)) {
                    /* 'time' value is the next token */
                    time_id = i + 1;
                }
            }

            if (ret == -1) {
                msgpack_sbuffer_destroy(&mp_sbuf);
                return -1;
            }
        }
        else if (t->type == JSMN_OBJECT) {
            msgpack_pack_map(&mp_pck, t->size);
        }
    }

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;
    *n_records = records;

    if (time_id <= state->tokens_count) {
        *time_token = time_id;
    }

    return 0;
}

static int docker_json_to_msgpack(struct flb_parser *parser,
                                  const char *js_buf, size_t js_len,
                                  char **out_buf, size_t *out_size,
                                  int *n_records, int *root_type,
                                  struct flb_time *out_time)
{
    int len;
    int ret;
    int time_token = -1;
    time_t time_lookup;
    char *ptr;
    char tmp[255];
    struct tm tm = {0};
    double tmfrac = 0;
    const jsmntok_t *t;
    struct flb_pack_state *state = &parser->json_state;

    /* tokenize */
    ret = flb_json_tokenise(js_buf, js_len, state);
    if (ret != 0) {
        return -1;
    }

    if (state->tokens_count == 0) {
        return -1;
    }

    ret = process_tokens(state, js_buf, out_buf, out_size, n_records, &time_token);
    if (ret != 0) {
        return -1;
    }

    /* root token time */
    *root_type = state->tokens[0].type;

    /* process time lookup */
    if (time_token >= 0) {
        t = &state->tokens[time_token];

        len = t->end - t->start;
        ptr = (char *) js_buf + t->start;

        /* Lookup time */
        ret = flb_parser_time_lookup(ptr, len,
                                     0, parser, &tm, &tmfrac);
        if (ret == -1) {
            if (len > sizeof(tmp) - 1) {
                len = sizeof(tmp) - 1;
            }

            memcpy(tmp, ptr, len);
            tmp[len] = '\0';
            flb_warn("[parser:%s] invalid time format %s for '%s'",
                     parser->name, parser->time_fmt_full, tmp);
            time_lookup = 0;
        }
        else {
            /* set timestamp */
            time_lookup = flb_parser_tm2time(&tm);
            out_time->tm.tv_sec  = time_lookup;
            out_time->tm.tv_nsec = (tmfrac * 1000000000);
        }
    }

    return 0;
}

int flb_parser_docker_do(struct flb_parser *parser,
                         const char *in_buf, size_t in_size,
                         void **out_buf, size_t *out_size,
                         struct flb_time *out_time)
{
    int ret;
    int total_records = 0;
    int root_type = -1;
    char *mp_buf = NULL;
    size_t mp_size;

    flb_pack_state_recycle(&parser->json_state);

    /* Convert incoming in_buf JSON message to message pack format */
    ret = docker_json_to_msgpack(parser, in_buf, in_size,
                                 &mp_buf, &mp_size,
                                 &total_records, &root_type, out_time);

    /* check return */
    if (ret != 0) {
        return -1;
    }

    if (total_records != 1) {
        flb_free(mp_buf);
        return -1;
    }

    /* Make sure object is a map */
    if (root_type != FLB_PACK_JSON_OBJECT) {
        flb_free(mp_buf);
        return -1;
    }

    *out_buf = mp_buf;
    *out_size = mp_size;

    return *out_size;
}
