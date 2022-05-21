/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#define FLB_EXIT_FLUSH_COUNT  "1"

struct flb_exit {
    int is_running;
    int count;

    /* config */
    int flush_count;
};

static int cb_exit_init(struct flb_output_instance *ins, struct flb_config *config,
                        void *data)
{
    int ret;
    (void) config;
    (void) data;
    struct flb_exit *ctx;

    ctx = flb_malloc(sizeof(struct flb_exit));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->count = 0;
    ctx->is_running = FLB_TRUE;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_exit_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    (void) i_ins;
    (void) out_context;
    struct flb_exit *ctx = out_context;

    ctx->count++;
    if (ctx->is_running == FLB_TRUE && ctx->count >= ctx->flush_count) {
        flb_engine_exit(config);
        ctx->is_running = FLB_FALSE;
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_exit_exit(void *data, struct flb_config *config)
{
    struct flb_exit *ctx = data;
    (void) config;

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_INT, "flush_count", FLB_EXIT_FLUSH_COUNT,
     0, FLB_TRUE, offsetof(struct flb_exit, flush_count),
     NULL
    },

    /* EOF */
    {0}
};

struct flb_output_plugin out_exit_plugin = {
    .name         = "exit",
    .description  = "Exit after a number of flushes (test purposes)",
    .cb_init      = cb_exit_init,
    .cb_flush     = cb_exit_flush,
    .cb_exit      = cb_exit_exit,
    .config_map   = config_map,
    .flags        = 0,
};
