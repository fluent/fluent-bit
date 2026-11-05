/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit Demo
 *  ===============
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <fluent-bit-minimal.h>
#include <msgpack.h>

int my_stdout_json(void *record, size_t size, void *data)
{
    printf("[%s]",__FUNCTION__);
    printf("%s",(char*)record);
    printf("\n");

    flb_lib_free(record);
    return 0;
}

int my_stdout_msgpack(void* data, size_t size)
{
    printf("[%s]",__FUNCTION__);
    msgpack_object_print(stdout, *(msgpack_object*)data);
    printf("\n");

    flb_lib_free(data);
    return 0;
}

int main()
{
    int i;
    int n;
    char tmp[256];
    flb_ctx_t *ctx;
    struct flb_lib_out_cb callback;
    int in_ffd;
    int out_ffd;

    /* Initialize library */
    ctx = flb_create();
    if (!ctx) {
        exit(EXIT_FAILURE);
    }

    in_ffd = flb_input(ctx, "lib", NULL);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    /* Register my callback function */

    /* JSON format */
    callback.cb = my_stdout_json;
    callback.data = NULL;

    out_ffd = flb_output(ctx, "lib", &callback);
    flb_output_set(ctx, out_ffd, "match", "test", "format", "json", NULL);

    /* Msgpack format */
    /*
    out_ffd = flb_output(ctx, "lib", my_stdout_msgpack);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);
    */

    /* Start the background worker */
    flb_start(ctx);

    /* Push some data */
    for (i = 0; i < 100; i++) {
        n = snprintf(tmp, sizeof(tmp) - 1,
                     "[%f, {\"key\": \"val %i\"}]",
                     flb_time_now(), i);
        flb_lib_push(ctx, in_ffd, tmp, n);
    }

    flb_stop(ctx);

    /* Release Resources */
    flb_destroy(ctx);

    return 0;
}
