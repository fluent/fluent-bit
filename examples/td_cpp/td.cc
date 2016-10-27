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
    flb_ctx_t *ctx;
    int in_ffd;
    int out_ffd;

    if (argc < 2) {
        fprintf(stderr, "Usage: td /path/to/configuration.file\n");
        exit(EXIT_FAILURE);
    }

    /* Initialize library */
    ctx = flb_create();
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test");

    out_ffd = flb_output(ctx, (char *) "td", NULL);
    flb_output_set(ctx, out_ffd, "tag", "test");

    /* Load a configuration file (required by TD output plugin) */
    ret = flb_lib_config_file(ctx, argv[1]);
    if (ret != 0) {
        exit(EXIT_FAILURE);
    }

    /* Start the background worker */
    flb_start(ctx);

    /* Push some data */
    time_field = time(NULL) - 100;
    for (i = 0; i < 100; i++) {
        n = snprintf(tmp, sizeof(tmp) - 1,
                     "[%i, {\"key\": \"val %i\"}]",
                     time_field, i);
        flb_lib_push(ctx, in_ffd, tmp, n);
        time_field++;
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    return 0;
}
