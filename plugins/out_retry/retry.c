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
#include <fluent-bit/flb_pack.h>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>


/* Retry context, only works with one instance */
struct retry_ctx {
    int n_retry;                     /* max retries before real flush (OK) */
    int count;                       /* number of retries done */
    struct flb_output_instance *ins; /* plugin instance */
};


static int cb_retry_init(struct flb_output_instance *ins,
                         struct flb_config *config,
                         void *data)
{
    (void) config;
    (void) data;
    struct retry_ctx *ctx;
    int ret;

    ctx = flb_calloc(1, sizeof(struct retry_ctx));
    if (!ctx) {
        return -1;
    }
    ctx->ins = ins;
    ctx->count = 0;

    ret = flb_output_config_map_set(ins, ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        return -1;
    }

    flb_output_set_context(ins, ctx);
    return 0;
}

static void cb_retry_flush(struct flb_event_chunk *event_chunk,
                           struct flb_output_flush *out_flush,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    (void) i_ins;
    (void) out_context;
    (void) config;
    struct retry_ctx *ctx;

    ctx = out_context;
    ctx->count++;

    if (ctx->count <= ctx->n_retry) {
        flb_plg_debug(ctx->ins, "retry %i/%i", ctx->count, ctx->n_retry);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    else {
        flb_plg_debug(ctx->ins, "flush", ctx->count, ctx->n_retry);
        ctx->count = 0;
    }

    flb_pack_print(event_chunk->data, event_chunk->size);
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_retry_exit(void *data, struct flb_config *config)
{
    struct retry_ctx *ctx = data;
    (void) config;

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
   {
    FLB_CONFIG_MAP_INT, "retry", "3",
    0, FLB_TRUE, offsetof(struct retry_ctx, n_retry),
    "Number of retries."
   },
   {0}
};

struct flb_output_plugin out_retry_plugin = {
    .name         = "retry",
    .description  = "Issue a retry upon flush request",
    .cb_init      = cb_retry_init,
    .cb_flush     = cb_retry_flush,
    .cb_exit      = cb_retry_exit,
    .config_map   = config_map,
    .flags        = 0,
};
