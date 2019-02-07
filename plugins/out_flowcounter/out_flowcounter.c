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
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>


#include "out_flowcounter.h"

#define PLUGIN_NAME "out_flowcounter"

static void count_initialized(struct flb_out_fcount_buffer* buf)
{
    buf->bytes  = 0;
    buf->counts = 0;
}

static int time_is_valid(time_t t, struct flb_out_fcount_config* ctx)
{
    if (t < ctx->buf[ctx->index].until - ctx->tick) {
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

static int configure(struct flb_out_fcount_config *ctx,
                     struct flb_output_instance   *ins,
                     struct flb_config *config)
{
    char* pval = NULL;
    int i;
    time_t base = time(NULL);

    /* default */
    ctx->unit = FLB_UNIT_MIN;
    ctx->tick         = 60;

    pval = flb_output_get_property("unit", ins);

    if (pval != NULL) {
        /* check unit of duration */
        if (!strcasecmp(pval, FLB_UNIT_SEC)) {
            ctx->unit = FLB_UNIT_SEC;
            ctx->tick = 1;
        }
        else if (!strcasecmp(pval, FLB_UNIT_HOUR)) {
            ctx->unit = FLB_UNIT_HOUR;
            ctx->tick = 3600;
        }
        else if(!strcasecmp(pval, FLB_UNIT_DAY)) {
            ctx->unit = FLB_UNIT_DAY;
            ctx->tick = 86400;
        }
    }
    
    pval = flb_output_get_property("event_based", ins);
    if (pval != NULL && flb_utils_bool(pval)) {
        ctx->event_based = FLB_TRUE;
    }
    else {
        ctx->event_based = FLB_FALSE;
    }

    flb_debug("[%s]unit is \"%s\"",PLUGIN_NAME, ctx->unit);

    /* initialize buffer */
    ctx->size  = (config->flush / ctx->tick) + 1;
    flb_debug("[%s]buffer size=%d",PLUGIN_NAME, ctx->size);

    ctx->index = 0;
    ctx->buf = (struct flb_out_fcount_buffer*)
        flb_malloc(sizeof(struct flb_out_fcount_buffer)*ctx->size);

    for (i=0; i<ctx->size; i++) {
        ctx->buf[i].until = base + ctx->tick*i;
        count_initialized(&ctx->buf[i]);
    }

    return 0;
}

static void output_fcount(FILE* f, struct flb_out_fcount_config *ctx,
                          struct flb_out_fcount_buffer *buf)
{
    fprintf(f,
           "[%s] [%lu, {"
           "\"counts\":%"PRIu64", "
           "\"bytes\":%"PRIu64", "
           "\"counts/%s\":%"PRIu64", "
           "\"bytes/%s\":%"PRIu64" }"
           "]\n",
           PLUGIN_NAME, buf->until,
           buf->counts,
           buf->bytes,
           ctx->unit, buf->counts/ctx->tick,
           ctx->unit, buf->bytes/ctx->tick);
    /* TODO filtering with tag? */
}

static void count_up(msgpack_object *obj,
                      struct flb_out_fcount_buffer *ctx, uint64_t size)
{
    ctx->counts++;
    ctx->bytes += size;
    /*TODO parse obj and count up specific data */
}

static int out_fcount_init(struct flb_output_instance *ins, struct flb_config *config,
                   void *data)
{
    (void) data;

    struct flb_out_fcount_config *ctx = NULL;
    ctx = (struct flb_out_fcount_config*)
        flb_malloc(sizeof(struct flb_out_fcount_config));
    if (ctx == NULL) {
        flb_error("[%s] malloc failed",PLUGIN_NAME);
        return -1;
    }
    configure(ctx, ins, config);
    flb_output_set_context(ins, ctx);

    return 0;
}

static struct flb_out_fcount_buffer* seek_buffer(time_t t,
                        struct flb_out_fcount_config* ctx)
{
    int i = ctx->index;
    int32_t diff;

    while(1) {
        diff = (int32_t)difftime(ctx->buf[i].until, t);
        if (diff >= 0 && diff <= ctx->tick) {
            return &ctx->buf[i];
        }
        i++;

        if (i >= ctx->size) {
            i = 0;
        }

        if(i == ctx->index) {
            break;
        }
    }
    return NULL;
}



static void out_fcount_flush(void *data, size_t bytes,
                     char *tag, int tag_len,
                     struct flb_input_instance *i_ins,
                     void *out_context,
                     struct flb_config *config)
{
    msgpack_unpacked result;
    msgpack_object *obj;
    struct flb_out_fcount_config *ctx = out_context;
    struct flb_out_fcount_buffer *buf = NULL;
    size_t off = 0;
    time_t t;
    uint64_t last_off   = 0;
    uint64_t byte_data  = 0;
    struct flb_time tm;
    (void) i_ins;
    (void) config;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        flb_time_pop_from_msgpack(&tm, &result, &obj);

        if (ctx->event_based == FLB_FALSE) {
            flb_time_get(&tm);
        }
        t = tm.tm.tv_sec;
        if (time_is_valid(t, ctx) == FLB_FALSE) {
            flb_warn("[%s] Out of range. Skip the record.", PLUGIN_NAME);
            continue;
        }

        byte_data     = (uint64_t)(off - last_off);
        last_off      = off;

        buf = seek_buffer(t, ctx);

        while(buf == NULL) {
            /* flush buffer */
            output_fcount(stdout, ctx, &ctx->buf[ctx->index]);
            count_initialized(&ctx->buf[ctx->index]);
            ctx->buf[ctx->index].until += ctx->tick * ctx->size;

            ctx->index++;
            if (ctx->index >= ctx->size) {
                ctx->index = 0;
            }
            buf = seek_buffer(t, ctx);
        }

        if (buf != NULL) {
            count_up(&result.data, buf, byte_data);
        }
    }
    msgpack_unpacked_destroy(&result);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int out_fcount_exit(void *data, struct flb_config* config)
{
    struct flb_out_fcount_config *ctx = data;

    flb_free(ctx->buf);
    flb_free(ctx);
    return 0;
}

struct flb_output_plugin out_flowcounter_plugin = {
    .name         = "flowcounter",
    .description  = "FlowCounter",
    .cb_init      = out_fcount_init,
    .cb_flush     = out_fcount_flush,
    .cb_exit      = out_fcount_exit,
    .flags        = 0,
};
