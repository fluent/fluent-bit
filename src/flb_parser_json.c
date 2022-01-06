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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_parser_decoder.h>

int flb_parser_json_do(struct flb_parser *parser,
                       const char *in_buf, size_t in_size,
                       void **out_buf, size_t *out_size,
                       struct flb_time *out_time)
{
    int i;
    int time_id = -1;
    int ret;
    int slen;
    int root_type = -1;
    int records;
    double tmfrac = 0;
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
    struct tm tm = {0};
    struct flb_time *t;
    struct flb_mp_map_header mh;

    flb_pack_state_recycle(&parser->json_state);

    /* Convert incoming in_buf JSON message to message pack format */
    ret = flb_pack_json_recs(&parser->json_state,
                             in_buf, in_size, &mp_buf, &mp_size, &root_type,
                             &records);
    if (ret != 0) {
        return -1;
    }

    if (records != 1) {
        flb_free(mp_buf);
        return -1;
    }

    /* Make sure object is a map */
    if (root_type != FLB_PACK_JSON_OBJECT) {
        flb_free(mp_buf);
        return -1;
    }

    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, mp_buf, mp_size, &off);
    map = result.data;

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
    if (!parser->time_fmt) {
        msgpack_unpacked_destroy(&result);
        return *out_size;
    }

    if (parser->time_key) {
        time_key = parser->time_key;
        slen = flb_sds_len(parser->time_key);
    }
    else {
        time_key = "time";
        slen = 4;
    }

    /* Lookup time field */
    map_size = map.via.map.size;
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

        if (memcmp(k->via.str.ptr, time_key, k->via.str.size) == 0) {
            /* We found the key, break the loop and keep the index */
            if (parser->time_keep == FLB_FALSE) {
                time_id = i;
                break;
            }
            else {
                time_id = -1;
            }
            break;
        }

        k = NULL;
        v = NULL;
    }

    /* No time_key field found */
    if (i >= map_size || !k || !v) {
        msgpack_unpacked_destroy(&result);
        return *out_size;
    }

    /* Ensure we have an accurate type */
    if (v->type != MSGPACK_OBJECT_STR) {
        msgpack_unpacked_destroy(&result);
        return *out_size;
    }

    /* Lookup time */
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
    }
    else {
        time_lookup = flb_parser_tm2time(&tm);
    }

    if (time_id >= 0 && parser->time_keep == FLB_FALSE) {
        /* Compose a new map without the time_key field */
        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        flb_mp_map_header_init(&mh, &mp_pck);

        for (i = 0; i < map_size; i++) {
            if (i == time_id) {
                continue;
            }

            flb_mp_map_header_append(&mh);
            msgpack_pack_object(&mp_pck, map.via.map.ptr[i].key);
            msgpack_pack_object(&mp_pck, map.via.map.ptr[i].val);
        }
        flb_mp_map_header_end(&mh);

        /* Export the proper buffer */
        flb_free(tmp_out_buf);
        *out_buf = mp_sbuf.data;
        *out_size = mp_sbuf.size;
    }

    msgpack_unpacked_destroy(&result);

    t = out_time;
    t->tm.tv_sec  = time_lookup;
    t->tm.tv_nsec = (tmfrac * 1000000000);

    return *out_size;
}
