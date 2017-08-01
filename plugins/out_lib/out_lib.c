/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include "out_lib.h"

#define PLUGIN_NAME "out_lib"

static int configure(struct flb_out_lib_config *ctx,
                     struct flb_output_instance *ins)
{
    char *tmp;

    tmp = flb_output_get_property("format", ins);
    if (!tmp) {
        ctx->format = FLB_OUT_LIB_FMT_MSGPACK;
    }
    else {
        if (strcasecmp(tmp, FLB_FMT_STR_MSGPACK) == 0) {
            ctx->format = FLB_OUT_LIB_FMT_MSGPACK;
        }
        else if (strcasecmp(tmp, FLB_FMT_STR_JSON) == 0) {
            ctx->format = FLB_OUT_LIB_FMT_JSON;
        }
    }

    return 0;
}


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

    ctx = flb_calloc(1, sizeof(struct flb_out_lib_config));
    if (ctx == NULL) {
        perror("calloc");
        return -1;
    }
    if (ins->data != NULL) {
        /* set user callback */
        ctx->user_callback = ins->data;
    }
    else{
        flb_error("[out_lib] Callback is not set");
        flb_free(ctx);
        return -1;
    }

    configure(ctx, ins);
    flb_output_set_context(ins, ctx);

    return 0;
}

static void out_lib_flush(void *data, size_t bytes,
                          char *tag, int tag_len,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    size_t off = 0;
    size_t last_off = 0;
    size_t data_size = 0;
    char *data_for_user = NULL;
    msgpack_unpacked result;
    struct flb_out_lib_config *ctx = out_context;
    (void) i_ins;
    (void) config;
    (void) tag;
    (void) tag_len;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        switch(ctx->format) {
        case FLB_OUT_LIB_FMT_MSGPACK:
            /* copy raw bytes */
            data_for_user = flb_malloc(bytes);
            if (!data_for_user) {
                flb_errno();
                msgpack_unpacked_destroy(&result);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
            memcpy(data_for_user, &result.data, bytes);
            data_size = bytes;
            break;
        case FLB_OUT_LIB_FMT_JSON:
            /* JSON is larger than msgpack, just a hint */
            data_size = (off - last_off) + 128;
            last_off   = off;
            data_for_user = flb_msgpack_to_json_str(data_size, &result.data);
            if (!data_for_user) {
                msgpack_unpacked_destroy(&result);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }
            data_size = strlen(data_for_user);
            break;
        }

        /* Invoke user callback */
        ctx->user_callback(data_for_user, data_size);
    }

    msgpack_unpacked_destroy(&result);
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int out_lib_exit(void *data, struct flb_config *config)
{
    struct flb_out_lib_config *ctx = data;

    flb_free(ctx);
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
