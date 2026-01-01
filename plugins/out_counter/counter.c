/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mp.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

struct flb_counter_ctx {
    uint64_t total;
};

static int cb_counter_init(struct flb_output_instance *ins,
                           struct flb_config *config,
                           void *data)
{
    (void) ins;
    (void) config;
    (void) data;
    struct flb_counter_ctx *ctx;

    ctx = flb_malloc(sizeof(struct flb_counter_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->total = 0;
    flb_output_set_context(ins, ctx);
    if (flb_output_config_map_set(ins, (void *)ctx) == -1) {
        flb_plg_error(ins, "unable to load configuration");
        flb_free(ctx);
        return -1;
    }

    return 0;
}

static void cb_counter_flush(struct flb_event_chunk *event_chunk,
                             struct flb_output_flush *out_flush,
                             struct flb_input_instance *i_ins,
                             void *out_context,
                             struct flb_config *config)
{
    (void) i_ins;
    (void) out_context;
    (void) config;
    size_t cnt;
    struct flb_counter_ctx *ctx = out_context;
    struct flb_time tm;

    /* Count number of parent items */
    cnt = flb_mp_count(event_chunk->data, event_chunk->size);
    ctx->total += cnt;

    flb_time_get(&tm);
    printf("%f,%lu (total = %"PRIu64")\n", flb_time_to_double(&tm), cnt,
           ctx->total);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_counter_exit(void *data, struct flb_config *config)
{
    struct flb_counter_ctx *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
   /* EOF */
   {0}
};

struct flb_output_plugin out_counter_plugin = {
    .name         = "counter",
    .description  = "Records counter",
    .cb_init      = cb_counter_init,
    .cb_flush     = cb_counter_flush,
    .cb_exit      = cb_counter_exit,
    .config_map   = config_map,
    .flags        = 0,
};
