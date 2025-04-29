/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_mem.h>
#include "flb_fuzz_header.h"
#include <fluent-bit/flb_cfl_record_accessor.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct flb_cfl_record_accessor *updated_cra = NULL;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_variant *vobj = NULL;
    char *null_terminated = NULL;

    /* Limit size to 32KB */
    if (size > 32768 || size < 104) {
        return 0;
    }

    /* Set flb_malloc_mod to be fuzzer-data dependent */
    flb_malloc_p = 0;
    flb_malloc_mod = *(int*)data;
    data += 4;
    size -= 4;

    /* Avoid division by zero for modulo operations */
    if (flb_malloc_mod == 0) {
        flb_malloc_mod = 1;
    }

    null_terminated = get_null_terminated(100, &data, &size);
    if (null_terminated == NULL) {
        return 0;
    }

    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        flb_free(null_terminated);
        return 0;
    }
    
    cfl_kvlist_insert_bool(kvlist, "k2", CFL_TRUE);
    vobj = cfl_variant_create_from_kvlist(kvlist);
    if (vobj != NULL) {
        updated_cra = flb_cfl_ra_create(null_terminated, FLB_TRUE);
    }

    if (updated_cra != NULL) {
        flb_cfl_ra_destroy(updated_cra);
    }
    if (null_terminated != NULL) {
        flb_free(null_terminated);
    }
    if (vobj != NULL) {
        cfl_variant_destroy(vobj);
    }
    return 0;
}
