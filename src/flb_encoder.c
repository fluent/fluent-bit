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

#include <fluent-bit/flb_encoder.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>

#ifdef FLB_HAVE_UTF8_ENCODER
#include <tutf8e.h>

#define TUTF8_BUFFER_SIZE 256

flb_encoder flb_get_encoder(const char *encoding)
{
    return tutf8e_encoder(encoding);
}

void flb_msgpack_encode_utf8(flb_encoder encoder, const char *module, msgpack_packer *pk, const void *b, size_t l)
{
    if (encoder) {
        size_t size = 0;
        if (!tutf8e_encoder_buffer_length(encoder, b, l, &size) && size) {
            /* Already UTF8 encoded? */
            if (size == l) {
            }
            /* Small enough for encoding to stack? */
            else if (size<=TUTF8_BUFFER_SIZE) {
                char buffer[TUTF8_BUFFER_SIZE];
                if (!tutf8e_encoder_buffer_encode(encoder, b, l, buffer, &size) && size) {
                    msgpack_pack_str(pk, size);
                    msgpack_pack_str_body(pk, buffer, size);
                    return;
                }
                /* Not expecting to get here ordinarily */
                flb_warn("[%s] failed to encode to UTF8", module);
            }
            /* malloc/free the encoded copy */
            else {
                char *buffer = (char *) flb_malloc(size);
                if (buffer && !tutf8e_encoder_buffer_encode(encoder, b, l, buffer, &size) && size) {
                    msgpack_pack_str(pk, size);
                    msgpack_pack_str_body(pk, buffer, size);
                    free(buffer);
                    return;
                }
                /* Not expecting to get here ordinarily */
                free(buffer);
                flb_warn("[%s] failed to encode to UTF8", module);
            }
        }
        else {
            flb_warn("[%s] failed to encode to UTF8", module);
        }
    }

    /* Could not or need not encode to UTF8 */
    msgpack_pack_str(pk, l);
    msgpack_pack_str_body(pk, b, l);
}
#endif

