/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

int flb_parser_json_do(struct flb_parser *parser,
                       const char *in_buf, size_t in_size,
                       void **out_buf, size_t *out_size,
                       struct flb_time *out_time)
{
    int i;
    int skip;
    int ret;
    int slen;
    int root_type;
    int records;
    int time_error = FLB_FALSE;
    int time_precision;
    int time_type;
    double tmfrac = 0;
    double tmp_time = 0;
    char *end;
    char *mp_buf = NULL;
    char *time_key;
    char *tmp_out_buf = NULL;
    char tmp[255];
    size_t tmp_out_size = 0;
    size_t off = 0;
    size_t map_size;
    size_t mp_size;
    size_t len;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;
    msgpack_unpacked result;
    msgpack_object map;
    msgpack_object *k = NULL;
    msgpack_object *v = NULL;
    time_t time_lookup;
    struct flb_tm tm = {0};
    struct flb_time *t;
    size_t consumed;

    consumed = 0;

    /* Convert incoming in_buf JSON message to message pack format */
    ret = flb_pack_json_recs(in_buf, in_size, &mp_buf, &mp_size, &root_type,
                             &records, &consumed);
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
    if (!parser->time_fmt && !parser->time_type) {
        msgpack_unpacked_destroy(&result);

        return (int) consumed;
    }

    if (parser->time_type) {
        time_type = parser->time_type;
    }
    else {
        time_type = FLB_PARSER_TYPE_STRING;
    }

    if (parser->time_precision) {
        time_precision = parser->time_precision;
    }
    else {
        time_precision = FLB_TIME_PRECISION_SECONDS;
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
    skip = map_size;
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
            /* We found the key, break the loop and keep the index */
            if (parser->time_keep == FLB_FALSE) {
                skip = i;
                break;
            }
            else {
                skip = -1;
            }
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

    /* Lookup time based on expected type */
    switch(time_type) {
    case FLB_PARSER_TYPE_INT:
        {
            switch(v->type) {
            case MSGPACK_OBJECT_POSITIVE_INTEGER:
                time_lookup = v->via.u64;
                break;
            case MSGPACK_OBJECT_FLOAT:
                time_lookup = v->via.f64;
                break;
            case MSGPACK_OBJECT_STR:
                time_lookup = strtol(v->via.str.ptr, &end, 10);
                break;
            default:
                time_error = FLB_TRUE;
            }

            switch (time_precision) {
            case FLB_TIME_PRECISION_NANOSECONDS:
                tmfrac = (time_lookup % 1000000000) / 1000000000.0;
                time_lookup = time_lookup / 1000000000;
                break;
            case FLB_TIME_PRECISION_MICROSECONDS:
                tmfrac = (time_lookup % 1000000) / 1000000.0;
                time_lookup = time_lookup / 1000000;
                break;
            case FLB_TIME_PRECISION_MILLISECONDS:
                tmfrac = (time_lookup % 1000) / 1000.0;
                time_lookup = time_lookup / 1000;
                break;
            case FLB_TIME_PRECISION_SECONDS:
                break;
            default:
                time_error = FLB_TRUE;
            }
        }
        break;
    case FLB_PARSER_TYPE_FLOAT:
        {
            switch (v->type) {
            case MSGPACK_OBJECT_POSITIVE_INTEGER:
                tmp_time = v->via.u64;
                break;
            case MSGPACK_OBJECT_FLOAT:
                tmp_time = v->via.f64;
                break;
            case MSGPACK_OBJECT_STR:
                tmp_time = strtod(v->via.str.ptr, &end);
                break;
            default:
                time_error = FLB_TRUE;
            }

            switch (time_precision) {
            case FLB_TIME_PRECISION_NANOSECONDS:
                time_lookup = tmp_time / 1000000000;
                tmfrac = (tmp_time / 1000000000.0) - time_lookup;
                break;
            case FLB_TIME_PRECISION_MICROSECONDS:
                time_lookup = tmp_time / 1000000;
                tmfrac = (tmp_time / 1000000.0) - time_lookup;
                break;
            case FLB_TIME_PRECISION_MILLISECONDS:
                time_lookup = tmp_time / 1000;
                tmfrac = (tmp_time / 1000.0) - time_lookup;
                break;
            case FLB_TIME_PRECISION_SECONDS:
                time_lookup = tmp_time;
                tmfrac = tmp_time - time_lookup;
                break;
            default:
                time_error = FLB_TRUE;
            }
        }
        break;
    case FLB_PARSER_TYPE_STRING:
        {
            if (v->type == MSGPACK_OBJECT_STR) {
                ret = flb_parser_time_lookup(v->via.str.ptr, v->via.str.size,
                                            0, parser, &tm, &tmfrac);
                if (ret == -1) {
                    len = v->via.str.size;
                    if (len > sizeof(tmp) - 1) {
                        len = sizeof(tmp) - 1;
                    }
                    memcpy(tmp, v->via.str.ptr, len);
                    tmp[len] = '\0';
                    flb_warn("[parser:%s] invalid time format %s for '%s'",
                            parser->name, parser->time_fmt_full, tmp);
                    time_lookup = 0;
                    skip = map_size;
                }
                else {
                    time_lookup = flb_parser_tm2time(&tm);
                }
            } else {
                time_error = FLB_TRUE;
            }
        }
        break;
    default:
        time_error = FLB_TRUE;
    }
    if (time_error == FLB_TRUE) {
        msgpack_unpacked_destroy(&result);

        return (int) consumed;
    }

    /* Compose a new map without the time_key field */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    if (parser->time_keep == FLB_FALSE && skip < map_size) {
        msgpack_pack_map(&mp_pck, map_size - 1);
    }
    else {
        msgpack_pack_map(&mp_pck, map_size);
    }

    for (i = 0; i < map_size; i++) {
        if (i == skip) {
            continue;
        }

        msgpack_pack_object(&mp_pck, map.via.map.ptr[i].key);
        msgpack_pack_object(&mp_pck, map.via.map.ptr[i].val);
    }

    /* Export the proper buffer */
    flb_free(tmp_out_buf);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    t = out_time;
    t->tm.tv_sec  = time_lookup;
    t->tm.tv_nsec = (tmfrac * 1000000000);

    msgpack_unpacked_destroy(&result);

    return (int) consumed;
}
