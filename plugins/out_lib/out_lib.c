/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>

#include <msgpack.h>

#include "out_lib.h"


/**
 * User callback is passed from flb_output(ctx, output, callback)
 *
 *  The prototype of callback should be
 *   int (*callback)(void* data, size_t size );
 *    @param   data  The data which comes from input plugin.
 *    @param   size  The size of data.
 *    @return  success ? 0 : negative value
 *
 */
static int out_lib_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    struct flb_out_lib_config *ctx = NULL;

    (void) config;
    (void) data;

    ctx = calloc(1, sizeof(struct flb_out_lib_config));
    if (ctx == NULL) {
        perror("calloc");
        return -1;
    }
    if (ins->data != NULL) {
        /* set user callback */
        ctx->user_callback = ins->data;
    }else{
        flb_error("[out_lib] Callback is NULL");
        free(ctx);
        return -1;
    }

    flb_output_set_context(ins, ctx);
    return 0;
}

static int out_lib_flush(void *data, size_t bytes,
                         char *tag, int tag_len,
                         struct flb_input_instance *i_ins,
                         void *out_context,
                         struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0;
    struct flb_out_lib_config *ctx = out_context;
    unsigned char* data_for_user   = NULL;
    (void) i_ins;
    (void) config;
    (void) tag;
    (void) tag_len;

    if (ctx->user_callback == NULL) {
        flb_error("[out_lib] Callback is NULL");
        return -1;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        data_for_user = calloc(1, bytes);
        /* FIXME: Now we return raw msgpack
                  we should return JSON format.
         */
        memcpy(data_for_user, &result.data, bytes);
        ctx->user_callback((void*)data_for_user, bytes);
    }
    msgpack_unpacked_destroy(&result);

    return bytes;
}

static int out_lib_exit(void *data, struct flb_config *config)
{
    struct flb_out_lib_config *ctx = data;

    free(ctx);
    return 0;
}

struct flb_output_plugin out_lib_plugin = {
    .name         = "lib",
    .description  = "Library mode Output",
    .cb_init      = out_lib_init,
    .cb_flush     = out_lib_flush,
    .cb_exit      = out_lib_exit,
    .flags        = 0,
};
