/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <string.h>
#include <msgpack.h>
#include <fluent-bit/flb_config.h>

char *flb_utils_pack_hello(struct flb_config *config, int *size)
{
    int tag_len;
    char *buf;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;

    tag_len = strlen(config->tag);

    /* initialize buffers */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_array(&pck, 3);

    /* pack Tag, Time and Record */
    msgpack_pack_raw(&pck, tag_len);
    msgpack_pack_raw_body(&pck, config->tag, tag_len);
    msgpack_pack_uint64(&pck, time(NULL));
    msgpack_pack_raw(&pck, 5);
    msgpack_pack_raw_body(&pck, "hello", 5);

    /* dump data back to a new buffer */
    *size = sbuf.size;
    buf = malloc(sbuf.size);
    memcpy(buf, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);

    return buf;
}
