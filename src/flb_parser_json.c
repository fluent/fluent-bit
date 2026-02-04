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
#include <math.h>
#include <stdbool.h>
#include <time.h>

#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_pack_json.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parser_decoder.h>

static bool flb_parser_json_timestamp_str(struct flb_parser *parser,
                                          const char *ptr, size_t len,
                                          struct flb_time *out_time)
{
    int ret;
    double tmfrac = 0;
    struct flb_tm tm = {0};
    time_t tmint = 0;

    if (!parser->time_fmt) {
        return false;
    }

    /* Lookup time */
    ret = flb_parser_time_lookup(ptr, len, 0, parser, &tm, &tmfrac);
    if (ret == -1) {
        flb_warn("[parser:%s] invalid time format %s for '%.*s'",
                 parser->name, parser->time_fmt_full, len > 254 ? 254 : (int)len, ptr);
        return false;
    }

    tmint = flb_parser_tm2time(&tm, parser->time_system_timezone);

    out_time->tm.tv_sec  = tmint;
    out_time->tm.tv_nsec = tmfrac * 1000000000;

    return true;
}

static bool flb_parser_json_timestamp_f64(struct flb_parser *parser,
                                          double val,
                                          struct flb_time *out_time)
{
    double tmfrac = 0;
    double tmint = 0;

    if (parser->time_numeric_unit <= 0) {
        flb_warn("[parser:%s] invalid non-string time", parser->name);
        return false;
    }

    tmfrac = modf(val / parser->time_numeric_unit, &tmint);

    out_time->tm.tv_sec  = tmint;
    out_time->tm.tv_nsec = tmfrac * 1000000000;

    return true;
}

int flb_parser_json_do(struct flb_parser *parser,
                       const char *in_buf, size_t in_size,
                       void **out_buf, size_t *out_size,
                       struct flb_time *out_time)
{
    int i;
    int time_index;
    int ret;
    int slen;
    int root_type;
    int records;
    bool time_ok;
    char *mp_buf = NULL;
    char *time_key;
    char *tmp_out_buf = NULL;
    size_t tmp_out_size = 0;
    size_t off = 0;
    size_t map_size;
    size_t mp_size;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;
    msgpack_unpacked result;
    msgpack_object map;
    msgpack_object *k = NULL;
    msgpack_object *v = NULL;
    size_t consumed;
    struct flb_pack_opts pack_opts = {0};

    consumed = 0;

    /* Convert incoming in_buf JSON message to message pack format */
    pack_opts.backend = FLB_PACK_JSON_BACKEND_YYJSON;
    ret = flb_pack_json_recs_ext(in_buf, in_size, &mp_buf, &mp_size,
                                 &root_type, &records, &consumed,
                                 &pack_opts);
    if (ret != 0) {
        return -1;
    }

    if (records != 1) {
        flb_free(mp_buf);

        return -1;
    }

    /* Make sure object is a map */
    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, mp_buf, mp_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        map = result.data;
        if (map.type != MSGPACK_OBJECT_MAP) {
            flb_free(mp_buf);
            msgpack_unpacked_destroy(&result);

            return -1;
        }
    }
    else {
        if (mp_size > 0) {
            flb_free(mp_buf);
        }

        msgpack_unpacked_destroy(&result);

        return -1;
    }

    /* Export results (might change later) */
    tmp_out_buf = mp_buf;
    tmp_out_size = mp_size;

    /* Do we have some decoders set ? */
    if (parser->decoders) {
        ret = flb_parser_decoder_do(parser->decoders,
                                    mp_buf, mp_size,
                                    &tmp_out_buf, &tmp_out_size);
        if (ret == 0) {
            /* re-process the unpack context */
            off = 0;
            msgpack_unpacked_destroy(&result);
            msgpack_unpacked_init(&result);
            msgpack_unpack_next(&result, tmp_out_buf, tmp_out_size, &off);
            map = result.data;
        }
    }

    /* Set the possible outgoing buffer */
    *out_buf = tmp_out_buf;
    *out_size = tmp_out_size;
    if (mp_buf != tmp_out_buf) {
        flb_free(mp_buf);
        mp_buf = NULL;
    }

    /* Do time resolution ? */
    if (!parser->time_fmt && parser->time_numeric_unit <= 0) {
        msgpack_unpacked_destroy(&result);

        return (int) consumed;
    }

    if (parser->time_key) {
        time_key = parser->time_key;
    }
    else {
        time_key = "time";
    }
    slen = strlen(time_key);

    /* Lookup time field */
    map_size = map.via.map.size;
    time_index = map_size;
    for (i = 0; i < map_size; i++) {
        k = &map.via.map.ptr[i].key;
        v = &map.via.map.ptr[i].val;

        if (k->via.str.size != slen) {
            continue;
        }

        /* Ensure the pointer we are about to read is not NULL */
        if (k->via.str.ptr == NULL) {
            if (mp_buf == tmp_out_buf) {
                flb_free(mp_buf);
            }
            else {
                flb_free(mp_buf);
                flb_free(tmp_out_buf);
            }
            *out_buf = NULL;
            msgpack_unpacked_destroy(&result);

            return -1;
        }

        if (strncmp(k->via.str.ptr, time_key, k->via.str.size) == 0) {
            time_index = i;
            /* We found the key, break the loop and keep the index */
            break;
        }

        k = NULL;
        v = NULL;
    }

    /* No time_key field found */
    if (i >= map_size || !k || !v) {
        msgpack_unpacked_destroy(&result);

        return (int) consumed;
    }

    /* Ensure we have an accurate type */
    switch(v->type) {
        case MSGPACK_OBJECT_STR:
            time_ok = flb_parser_json_timestamp_str(parser, v->via.str.ptr, v->via.str.size, out_time);
            break;

        case MSGPACK_OBJECT_FLOAT32:
        case MSGPACK_OBJECT_FLOAT64:
            time_ok = flb_parser_json_timestamp_f64(parser, v->via.f64, out_time);
            break;

        case MSGPACK_OBJECT_POSITIVE_INTEGER:
            time_ok = flb_parser_json_timestamp_f64(parser, v->via.u64, out_time);
            break;

        default:
            time_ok = false;
            break;
    }

    if (time_ok && parser->time_keep == FLB_FALSE) {
        /* Compose a new map without the time_key field */
        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        msgpack_pack_map(&mp_pck, map_size - 1);

        for (i = 0; i < map_size; i++) {
            if (i == time_index) {
                continue;
            }

            msgpack_pack_object(&mp_pck, map.via.map.ptr[i].key);
            msgpack_pack_object(&mp_pck, map.via.map.ptr[i].val);
        }

        /* Export the proper buffer */
        flb_free(tmp_out_buf);

        *out_buf = mp_sbuf.data;
        *out_size = mp_sbuf.size;
    }

    msgpack_unpacked_destroy(&result);

    return (int) consumed;
}
