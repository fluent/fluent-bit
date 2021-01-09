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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mp.h>

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

/*
 * msgpack-c requires to set the number of the entries in a map beforehand. For our
 * use case this adds some complexity, having developers to count all possible
 * entries that might be added.
 *
 * As a workaround and to avoid map's recomposition over and over, this simple API
 * allows to initialize the array header, 'register' new entries (as counters) and
 * finalize, upon finalization the proper array header size is adjusted.
 *
 * To make things easier, we make sure msgpack-c always register an array type of
 * 32 bits (identified by 0xdf, for number of entries >= 65536). Yes, for every
 * array using this API it will use 2 more bytes, not a big ideal. So whoever
 * uses this API, use it only if you don't know the exact number of entries to add.
 *
 * MANDATORY: make sure to always initialize, register every entry and finalize,
 * otherwise you will get a corrupted or incomplete msgpack buffer.
 *
 * Usage example
 * =============
 *
 *  struct flb_mp_map_head mh;
 *
 *  flb_mp_map_header_init(&mh, mp_pck);
 *
 *  -- First key/value entry --
 *  flb_mp_map_header_append(&mh);
 *  msgpack_pack_str(mp_pck, 4);
 *  msgpack_pack_str_body(mp_pck, "cool", 4);
 *  msgpack_pack_true(mp_pck);
 *
 *  -- Second key/value entry --
 *  flb_mp_map_header_append(&mh);
 *  msgpack_pack_str(mp_pck, 4);
 *  msgpack_pack_str_body(mp_pck, "slow", 4);
 *  msgpack_pack_false(mp_pck);
 *
 *  -- Finalize Map --
 *  flb_mp_map_header_end(&mh);
 */
int flb_mp_map_header_init(struct flb_mp_map_header *mh, msgpack_packer *mp_pck)
{
    msgpack_sbuffer *mp_sbuf;

    mp_sbuf = (msgpack_sbuffer *) mp_pck->data;

    /* map sbuffer */
    mh->data = mp_pck->data;

    /* Reset entries */
    mh->entries = 0;

    /* Store the next byte available */
    mh->offset = mp_sbuf->size;

    /*
     * Pack a map with size = 65536, so we force the underlaying msgpack-c
     * to use a 32 bit buffer size (0xdf), reference:
     *
     * - https://github.com/msgpack/msgpack/blob/master/spec.md#map-format-family
     */
    return msgpack_pack_map(mp_pck, 65536);
}

int flb_mp_map_header_append(struct flb_mp_map_header *mh)
{
    mh->entries++;
    return mh->entries;
}

void flb_mp_map_header_end(struct flb_mp_map_header *mh)
{
    char *ptr;
    msgpack_sbuffer *mp_sbuf;

    mp_sbuf = mh->data;
    ptr = (char *) mp_sbuf->data + mh->offset;
    flb_mp_set_map_header_size(ptr, mh->entries);
}
