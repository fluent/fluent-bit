/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <msgpack.h>
#include <mpack/mpack.h>

/* don't do this at home */
#define pack_uint16(buf, d) _msgpack_store16(buf, (uint16_t) d)
#define pack_uint32(buf, d) _msgpack_store32(buf, (uint32_t) d)

int flb_mp_count(const void *data, size_t bytes)
{
    int count = 0;
    mpack_reader_t reader;

    mpack_reader_init_data(&reader, (const char *) data, bytes);
    while (mpack_reader_remaining(&reader, NULL) > 0) {
        count++;
        mpack_discard(&reader);
    }

    mpack_reader_destroy(&reader);
    return count;
}

/* Adjust a mspack header buffer size */
void flb_mp_set_map_header_size(char *buf, int arr_size)
{
    uint8_t h;
    char *tmp = buf;

    h = tmp[0];
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
