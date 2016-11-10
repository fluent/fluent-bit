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
#include <stdlib.h>
#include <time.h>

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>

#include <msgpack.h>


#include "out_fcount.h"

#define PLUGIN_NAME "out_fcount"

static int configure(struct flb_out_fcount_config *ctx,
                      struct flb_output_instance   *ins)
{
    char* unit = NULL;
    
    /* default */
    ctx->unit = FLB_UNIT_MIN;
    ctx->tick         = 60;

    unit = flb_output_get_property("unit", ins);
    if (unit == NULL) {
        /* using default */
        return 0;
    }

    flb_debug("[%s]unit is \"%s\"",PLUGIN_NAME, unit);

    if (!strcasecmp(unit, FLB_UNIT_SEC)) {
        ctx->unit = FLB_UNIT_SEC;
        ctx->tick = 1;
    }
    else if (!strcasecmp(unit, FLB_UNIT_HOUR)) {
        ctx->unit = FLB_UNIT_HOUR;
        ctx->tick = 3600;
    }
    else if(!strcasecmp(unit, FLB_UNIT_DAY)) {
        ctx->unit = FLB_UNIT_DAY;
        ctx->tick = 86400;
    }

    return 0;
}


static void count_initialized(struct flb_out_fcount_config* config)
{
    config->bytes  = 0;
    config->counts = 0;
}

static void output_fcount(FILE* f, struct flb_out_fcount_config *ctx, char* tag)
{
    fprintf(f,"[%s] %s:{",PLUGIN_NAME,tag);
    fprintf(f,
           "\"counts\":%lu, \"bytes\":%lu, \"counts/%s\":%lu, \"bytes/%s\":%lu}\n",
           ctx->counts,
           ctx->bytes,
           ctx->unit, ctx->counts/ctx->tick,
           ctx->unit, ctx->bytes/ctx->tick);
    /* TODO filtering with tag? */
}

static void count_up(msgpack_object *obj,
                      struct flb_out_fcount_config *ctx, uint64_t size)
{
    ctx->counts++;
    ctx->bytes += size;
    /*TODO parse obj and count up specific data */
}

static time_t get_timestamp_from_msgpack(msgpack_object *p)
{
    if (p != NULL && p->via.array.size != 0) {
        return p->via.array.ptr[0].via.u64; /* FIXME */
    }
    else{
        return 0;
    }
}

static int out_fcount_init(struct flb_output_instance *ins, struct flb_config *config,
                   void *data)
{
    (void) config;
    (void) data;

    struct flb_out_fcount_config *ctx = NULL;
    ctx = (struct flb_out_fcount_config*)
        flb_malloc(sizeof(struct flb_out_fcount_config));
    if (ctx == NULL) {
        flb_error("[%s] malloc failed",PLUGIN_NAME);
        return -1;
    }
    configure(ctx, ins);

    count_initialized(ctx);
    ctx->last_checked = time(NULL);

    flb_output_set_context(ins, ctx);

    return 0;
}

static void out_fcount_flush(void *data, size_t bytes,
                     char *tag, int tag_len,
                     struct flb_input_instance *i_ins,
                     void *out_context,
                     struct flb_config *config)
{
    msgpack_unpacked result;
    struct flb_out_fcount_config *ctx = out_context;
    size_t off = 0;
    time_t t;
    int32_t diff;
    uint64_t last_off   = 0;
    uint64_t byte_data  = 0;

    (void) i_ins;
    (void) config;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        t = get_timestamp_from_msgpack(&result.data);
        byte_data     = (uint64_t)(off - last_off);
        last_off      = off;

        if ((diff = (int32_t)difftime(t,ctx->last_checked))< 0) {
            flb_error("[%s]time paradox?",PLUGIN_NAME);
            continue;
        }
        flb_debug("[%s] %lu(%d) byte_data:%lu",
                  PLUGIN_NAME,ctx->last_checked,diff, byte_data);

        while(diff > ctx->tick) {
            output_fcount(stdout, ctx, tag);
            count_initialized(ctx);

            ctx->last_checked += ctx->tick;
            diff -= ctx->tick;
        }
        if (diff >= 0) {
            count_up(&result.data, ctx, byte_data);
        }
    }
    msgpack_unpacked_destroy(&result);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int out_fcount_exit(void *data, struct flb_config* config)
{
    struct flb_out_fcount_config *ctx = data;

    flb_free(ctx);
    return 0;
}

struct flb_output_plugin out_fcount_plugin = {
    .name         = "fcount",
    .description  = "FlowCount",
    .cb_init      = out_fcount_init,
    .cb_flush     = out_fcount_flush,
    .cb_exit      = out_fcount_exit,
    .flags        = 0,
};
