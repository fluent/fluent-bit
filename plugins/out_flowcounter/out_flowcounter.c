/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>

#include "out_flowcounter.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>


#define PLUGIN_NAME "out_flowcounter"

static void count_initialized(struct flb_out_fcount_buffer* buf)
{
    buf->bytes  = 0;
    buf->counts = 0;
}

static int time_is_valid(time_t t, struct flb_flowcounter *ctx)
{
    if (t < ctx->buf[ctx->index].until - ctx->tick) {
        return FLB_FALSE;
    }
    return FLB_TRUE;
}

static int configure(struct flb_flowcounter *ctx,
                     struct flb_output_instance *ins,
                     struct flb_config *config)
{
    int i;
    time_t base = time(NULL);
    const char* pval = NULL;

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

    flb_plg_debug(ctx->ins, "unit is \"%s\"", ctx->unit);

    /* initialize buffer */
    ctx->size  = (config->flush / ctx->tick) + 1;
    flb_plg_debug(ctx->ins, "buffer size=%d", ctx->size);

    ctx->index = 0;
    ctx->buf = flb_malloc(sizeof(struct flb_out_fcount_buffer) * ctx->size);
    if (!ctx->buf) {
        flb_errno();
        return -1;
    }

    for (i = 0; i < ctx->size; i++) {
        ctx->buf[i].until = base + ctx->tick*i;
        count_initialized(&ctx->buf[i]);
    }

    return 0;
}

static void output_fcount(FILE *f, struct flb_flowcounter *ctx,
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
    int ret;
    (void) data;

    struct flb_flowcounter *ctx = NULL;

    ctx = flb_malloc(sizeof(struct flb_flowcounter));
    if (ctx == NULL) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    ret = configure(ctx, ins, config);
    if (ret < 0) {
        flb_free(ctx);
        return -1;
    }

    flb_output_set_context(ins, ctx);

    return 0;
}

static struct flb_out_fcount_buffer* seek_buffer(time_t t,
                                                 struct flb_flowcounter *ctx)
{
    int i = ctx->index;
    int32_t diff;

    while (1) {
        diff = (int32_t) difftime(ctx->buf[i].until, t);
        if (diff >= 0 && diff <= ctx->tick) {
            return &ctx->buf[i];
        }
        i++;

        if (i >= ctx->size) {
            i = 0;
        }

        if (i == ctx->index) {
            break;
        }
    }
    return NULL;
}



static void out_fcount_flush(const void *data, size_t bytes,
                             const char *tag, int tag_len,
                             struct flb_input_instance *i_ins,
                             void *out_context,
                             struct flb_config *config)
{
    msgpack_unpacked result;
    msgpack_object *obj;
    struct flb_flowcounter *ctx = out_context;
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
            flb_plg_warn(ctx->ins, "out of range. Skip the record");
            continue;
        }

        byte_data     = (uint64_t)(off - last_off);
        last_off      = off;

        buf = seek_buffer(t, ctx);

        while (buf == NULL) {
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
    struct flb_flowcounter *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx->buf);
    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "unit", NULL,
     0, FLB_FALSE, 0,
     NULL
    },
    {
     FLB_CONFIG_MAP_BOOL, "event_based", "false",
     0, FLB_TRUE, offsetof(struct flb_flowcounter, event_based),
     NULL
    },

    /* EOF */
    {0}
};

struct flb_output_plugin out_flowcounter_plugin = {
    .name         = "flowcounter",
    .description  = "FlowCounter",
    .cb_init      = out_fcount_init,
    .cb_flush     = out_fcount_flush,
    .cb_exit      = out_fcount_exit,
    .config_map   = config_map,
    .flags        = 0,
};
