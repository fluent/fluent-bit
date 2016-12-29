/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
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

#include <fluent-bit.h>

int main()
{
    int i;
    int n;
    int ret;
    char tmp[256];
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    /* Initialize library */
    ctx = flb_create();

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, (char *) "test", NULL);

    out_ffd = flb_output(ctx, (char *) "stdout", NULL);
    flb_output_set(ctx, out_ffd, (char *) "test", NULL);

    /* Start the background worker */
    flb_start(ctx);

    /* Push some data */
    for (i = 0; i < 100; i++) {
        n = snprintf(tmp, sizeof(tmp) - 1,
                     "[%lu, {\"key\": \"val %i\"}]",
                     time(NULL), i);
        printf("%s\n", tmp);
        flb_lib_push(ctx, in_ffd, tmp, n);
    }

    flb_stop(ctx);

    /* Release Resources */
    flb_destroy(ctx);

    return 0;
}
