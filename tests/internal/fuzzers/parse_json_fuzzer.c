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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include "flb_fuzz_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    TIMEOUT_GUARD
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;
    struct flb_config *fuzz_config;
    struct flb_parser *fuzz_parser;

    /* Set flb_malloc_mod to be fuzzer-data dependent */
    if (size < 4) {
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

    /* json parser */
    fuzz_config = flb_config_init();
    if (fuzz_config == NULL) {
        return 0;
    }

    fuzz_parser = flb_parser_create("fuzzer", "json", NULL, FLB_TRUE, NULL,
                                    NULL, NULL, MK_FALSE, MK_TRUE, FLB_FALSE,
                                    NULL, 0, NULL, fuzz_config);
    if (fuzz_parser) {
        flb_parser_do(fuzz_parser, (char*)data, size,
                      &out_buf, &out_size, &out_time);

        if (out_buf != NULL) {
            free(out_buf);
        }

        flb_parser_destroy(fuzz_parser);
    }
    flb_config_exit(fuzz_config);

    return 0;
}
