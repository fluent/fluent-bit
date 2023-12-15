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
#include <stdlib.h>
#include <stdint.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_mp.h>

#include "flb_fuzz_header.h"

int LLVMFuzzerTestOneInput(unsigned char *data, size_t size)
{
    /* Set flb_malloc_mod to be fuzzer-data dependent */
    if (size < 5) {
        return 0;
    }
    flb_malloc_p = 0;
    flb_malloc_mod = *(int*)data;
    data += 4;
    size -= 4;

    /* Avoid division by zero for modulo operations */
    if (flb_malloc_mod == 0) {
        flb_malloc_mod = 1;
    }

    unsigned char decider = *data;
    data++;
    size--;

    int out_records;
    size_t processed_bytes;
    if (decider % 2 == 0) {
      flb_mp_validate_log_chunk(data, size, &out_records, &processed_bytes);
    }
    else if (decider % 2 == 1) {
        flb_mp_validate_metric_chunk(data, size, &out_records, &processed_bytes);
    }
    return 0;
}
