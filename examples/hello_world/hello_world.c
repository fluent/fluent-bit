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

#include <unistd.h>
#include <fluent-bit.h>

int main()
{
    int i;
    int n;
    char tmp[256];
    struct flb_lib_ctx *ctx;

    /* Initialize library */
    ctx = flb_lib_init(NULL, "stdout", NULL);
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Verbose mode */
    /*
    flb_config_verbose(FLB_TRUE);
    */

    /* Start the background worker */
    flb_lib_start(ctx);

    /* Push some data */
    for (i = 0; i < 100; i++) {
        n = snprintf(tmp, sizeof(tmp) - 1, "{\"key\": \"val %i\"}", i);
        flb_lib_push(ctx, tmp, n);
    }

    flb_lib_stop(ctx);

    /* Release Resources */
    flb_lib_exit(ctx);

    return 0;
}
