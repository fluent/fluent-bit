/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit.h>
#include "flb_fuzz_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int ret;
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Set fuzzer-malloc chance of failure */
    flb_malloc_p = 0;
    flb_malloc_mod = 25000;


    ctx = flb_create();
    flb_service_set(ctx, "Flush", "1", "Grace", "1", "Log_Level", "error", NULL);
    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    if (in_ffd >= 0) {
        flb_input_set(ctx, in_ffd, "tag", "test", NULL);

        out_ffd = flb_output(ctx, (char *) "stdout", NULL);
        if (out_ffd >= 0) {
            flb_output_set(ctx, out_ffd, "match", "test", NULL);

            ret = flb_start(ctx);
            if (ret == 0) {
                char *p = get_null_terminated(size, &data, &size);
                for (int i = 0; i < strlen(p); i++) {
                    flb_lib_push(ctx, in_ffd, p+i, 1);
                }
                free(p);

                sleep(1); /* waiting flush */
            }
        }
    }
    flb_stop(ctx);
    flb_destroy(ctx);

    return 0;
}
