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
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include "out_lib.h"

#define PLUGIN_NAME "out_lib"
static int configure(struct flb_out_lib_config *ctx,
                      struct flb_output_instance   *ins)
{
    char* format = NULL;
    
    /* default */
    ctx->format = FLB_OUT_LIB_FMT_MSGPACK;

    format = flb_output_get_property("format", ins);
    if (format == NULL) {
        /* using default */
        return 0;
    }

    flb_debug("[%s]fomrat is \"%s\"",PLUGIN_NAME, format);

    if (!strcasecmp(format, FLB_FMT_STR_JSON)) {
        ctx->format = FLB_OUT_LIB_FMT_JSON;
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
    }else{
        flb_error("[%s] Callback is NULL",PLUGIN_NAME);
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
    msgpack_unpacked result;
    size_t off = 0;
    size_t last_off = 0;
    size_t alloc_size = 0;
    int    ret = 0;
    struct flb_out_lib_config *ctx = out_context;
    unsigned char* data_for_user   = NULL;
    (void) i_ins;
    (void) config;
    (void) tag;
    (void) tag_len;

    if (ctx->user_callback == NULL) {
        flb_error("[%s] Callback is NULL",PLUGIN_NAME);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        switch(ctx->format){
        case FLB_OUT_LIB_FMT_MSGPACK:
            data_for_user = flb_calloc(1, bytes);
            memcpy(data_for_user, &result.data, bytes);
            break;
        case FLB_OUT_LIB_FMT_JSON:
            alloc_size = (off - last_off)+128;/* JSON is larger than msgpack */
            last_off   = off;
            data_for_user = flb_calloc(1, alloc_size);
            if (data_for_user == NULL) {
                flb_error("[%s] allocate failed",PLUGIN_NAME);
                continue;/* FIXME */
            }
            ret =  flb_msgpack_to_json(data_for_user, alloc_size, &result);
            if (ret<0) {
                /* buffer size is small, so retry with bigger buffer */
                flb_free(data_for_user);
                alloc_size *= 2;
                data_for_user = flb_calloc(1, alloc_size);
                if (data_for_user == NULL) {
                    flb_error("[%s] allocate failed",PLUGIN_NAME);
                    continue;/* FIXME */
                }
                ret =  flb_msgpack_to_json(data_for_user, alloc_size, &result);
            }
            break;
        default:
            flb_error("[%s] unknown format",PLUGIN_NAME);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        ctx->user_callback((void*)data_for_user, bytes);
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
