/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <stdio.h>

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_lib.h>
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

    tmp = flb_output_get_property("max_records", ins);
    if (tmp) {
        ctx->max_records = atoi(tmp);
    }
    else {
        ctx->max_records = 0;
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
    struct flb_lib_out_cb *cb_data = data;
    (void) config;

    ctx = flb_calloc(1, sizeof(struct flb_out_lib_config));
    if (ctx == NULL) {
        flb_errno();
        return -1;
    }

    if (cb_data) {
        /* Set user callback and data */
        ctx->cb_func = cb_data->cb;
        ctx->cb_data = cb_data->data;
    }
    else {
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
    int len;
    int count = 0;
    size_t off = 0;
    size_t last_off = 0;
    size_t data_size = 0;
    size_t alloc_size = 0;
    size_t out_size = 0;
    char *buf = NULL;
    char *out_buf = NULL;
    char *data_for_user = NULL;
    msgpack_object *obj;
    msgpack_unpacked result;
    struct flb_time tm;
    struct flb_out_lib_config *ctx = out_context;
    (void) i_ins;
    (void) config;
    (void) tag;
    (void) tag_len;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (ctx->max_records > 0 && count >= ctx->max_records) {
            break;
        }
        switch(ctx->format) {
        case FLB_OUT_LIB_FMT_MSGPACK:
            alloc_size = (off - last_off);

            /* copy raw bytes */
            data_for_user = flb_malloc(alloc_size);
            if (!data_for_user) {
                flb_errno();
                msgpack_unpacked_destroy(&result);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            memcpy(data_for_user, (char *) data + last_off, alloc_size);
            data_size = alloc_size;
            break;
        case FLB_OUT_LIB_FMT_JSON:
            /* JSON is larger than msgpack */
            alloc_size = (off - last_off) + 128;

            flb_time_pop_from_msgpack(&tm, &result, &obj);
            buf = flb_msgpack_to_json_str(alloc_size, obj);
            if (!buf) {
                msgpack_unpacked_destroy(&result);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            len = strlen(buf);
            out_size = len + 32;
            out_buf = flb_malloc(out_size);
            if (!out_buf) {
                flb_errno();
                msgpack_unpacked_destroy(&result);
                FLB_OUTPUT_RETURN(FLB_ERROR);
            }

            len = snprintf(out_buf, out_size, "[%f, %s]",
                           flb_time_to_double(&tm),
                           buf);
            flb_free(buf);
            data_for_user = out_buf;
            data_size = len;
            break;
        }

        /* Invoke user callback */
        ctx->cb_func(data_for_user, data_size, ctx->cb_data);
        last_off = off;
        count++;
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
