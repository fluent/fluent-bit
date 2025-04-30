/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_decode_opentelemetry.h>


int
LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
    struct cfl_list decoded_contexts;
    struct cmt *cmt = NULL;
    size_t off = 0;
    uint8_t decider;
    int result;

    /* At least one byte is needed for deciding which decoder to use */
    if (size < 1) {
        return 0;
    }

    decider = data[0] % 2;

    /* Adjust data pointer since the first byte is used */
    data += 1;
    size -= 1;

    /* Fuzz a given decoder */
    if (decider == 0) {
        result = cmt_decode_opentelemetry_create(&decoded_contexts, data, size,
                                                 &off);
        if (result == CMT_DECODE_OPENTELEMETRY_SUCCESS) {
            cmt_decode_opentelemetry_destroy (&decoded_contexts);
        }
    }
    else {
        result = cmt_decode_msgpack_create(&cmt, (char *) data, size, &off);
        if (result == 0) {
            cmt_destroy(cmt);
        }
    }

    return 0;
}
