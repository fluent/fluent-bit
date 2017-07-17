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

#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mem.h>

int flb_parser_json_do(struct flb_parser *parser,
                       char *buf, size_t length,
                       void **out_buf, size_t *out_size,
                       struct flb_time *out_time)
{
    int i;
    int skip;
    int ret;
    int mp_size;
    int slen;
    double tmfrac = 0;
    char *mp_buf;
    char *time_key;
    size_t off = 0;
    size_t map_size;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;
    msgpack_unpacked result;
    msgpack_object map;
    msgpack_object *k = NULL;
    msgpack_object *v = NULL;
    time_t time_lookup;
    struct tm tm = {0};
    struct flb_time *t;

    ret = flb_pack_json(buf, length, &mp_buf, &mp_size);
    if (ret != 0) {
        return -1;
    }

    /* Make sure object is a map */
    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, mp_buf, mp_size, &off)) {
        map = result.data;
        if (map.type != MSGPACK_OBJECT_MAP) {
            flb_free(mp_buf);
            msgpack_unpacked_destroy(&result);
            return -1;
        }
    }

    /* Export results (might change later) */
    *out_buf = mp_buf;
    *out_size = mp_size;

    /* Do time resolution ? */
    if (!parser->time_fmt) {
        msgpack_unpacked_destroy(&result);
        return length;
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
        return length;
    }

    /* Lookup time */
    ret = flb_parser_time_lookup((char *) v->via.str.ptr, v->via.str.size,
                                 0, parser, &tm, &tmfrac);
    if (ret == -1) {
        msgpack_unpacked_destroy(&result);
        return length;
    }
    time_lookup = flb_parser_tm2time(&tm);

    /* Compose a new map without the time_key field */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    if (parser->time_keep == FLB_FALSE) {
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

    /* Release original json->msgpack buffer*/
    flb_free(mp_buf);

    /* Export the proper buffer */
    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;


    t = out_time;
    t->tm.tv_sec  = time_lookup;
    t->tm.tv_nsec = (tmfrac * 1000000000);

    msgpack_unpacked_destroy(&result);
    return length;
}
