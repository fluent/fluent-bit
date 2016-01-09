/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit - Output data to Treasure Data
 *  =========================================
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

int main(int argc, char **argv)
{
    int i;
    int n;
    int ret;
    int time_field;
    char tmp[256];
    struct flb_lib_ctx *ctx;

    if (argc < 2) {
        fprintf(stderr, "Usage: td /path/to/configuration.file\n");
        exit(EXIT_FAILURE);
    }

    /* Initialize library */
    ctx = flb_lib_init(NULL, (char *) "td");
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    /* Load a configuration file (required by TD output plugin) */
    ret = flb_lib_config_file(ctx, argv[1]);
    if (ret != 0) {
        exit(EXIT_FAILURE);
    }

    /* Start the background worker */
    flb_lib_start(ctx);

    /* Push some data */
    time_field = time(NULL) - 100;
    for (i = 0; i < 100; i++) {
        n = snprintf(tmp, sizeof(tmp) - 1,
                     "{\"time\": %i, \"key\": \"val %i\"}", time_field, i);
        flb_lib_push(ctx, tmp, n);
        time_field++;
    }

    flb_lib_stop(ctx);

    return 0;
}
