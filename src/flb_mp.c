/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

static inline int mp_count(void *data, size_t bytes, msgpack_zone *zone)
{
    int c = 0;
    size_t off = 0;
    msgpack_zone *t = NULL;
    msgpack_object obj;

    if (!zone) {
        t = msgpack_zone_new(MSGPACK_ZONE_CHUNK_SIZE);
        if (!t) {
            return -1;
        }
    }
    else {
        t = zone;
    }

    while (msgpack_unpack(data, bytes, &off, t, &obj) == MSGPACK_UNPACK_SUCCESS) {
        c++;
    }

    msgpack_zone_clear(t);
    if (t != zone) {
        msgpack_zone_free(t);
    }

    return c;
}

int flb_mp_count(void *data, size_t bytes)
{
    return mp_count(data, bytes, NULL);
}

int flb_mp_count_zone(void *data, size_t bytes, msgpack_zone *zone)
{
    return mp_count(data, bytes, zone);
}
