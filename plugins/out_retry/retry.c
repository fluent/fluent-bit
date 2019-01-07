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
#include <unistd.h>
#include <fcntl.h>

#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_output.h>

/* Retry context, only works with one instance */
struct retry_ctx {
    int n_retry;       /* max retries before real flush (OK) */
    int count;         /* number of retries done             */
};

int cb_retry_init(struct flb_output_instance *ins,
                  struct flb_config *config,
                  void *data)
{
    (void) config;
    (void) data;
    char *tmp;
    struct retry_ctx *ctx;

    ctx = flb_malloc(sizeof(struct retry_ctx));
    if (!ctx) {
        return -1;
    }
    ctx->count = 0;

    tmp = flb_output_get_property("retries", ins);
    if (!tmp) {
        ctx->n_retry = 3;
    }
    else {
        ctx->n_retry = atoi(tmp);
    }

    flb_output_set_context(ins, ctx);
    return 0;
}

static void cb_retry_flush(void *data, size_t bytes,
                           char *tag, int tag_len,
                           struct flb_input_instance *i_ins,
                           void *out_context,
                           struct flb_config *config)
{
    (void) data;
    (void) bytes;
    (void) tag;
    (void) tag_len;
    (void) i_ins;
    (void) out_context;
    (void) config;
    struct retry_ctx *ctx;

    ctx = out_context;
    ctx->count++;

    if (ctx->count <= ctx->n_retry) {
        flb_debug("[retry] retry %i/%i", ctx->count, ctx->n_retry);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }
    else {
        flb_debug("[retry] flush", ctx->count, ctx->n_retry);
        ctx->count = 0;
    }

    flb_pack_print(data, bytes);
    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_retry_exit(void *data, struct flb_config *config)
{
    struct retry_ctx *ctx = data;
    (void) config;

    flb_free(ctx);
    return 0;
}

struct flb_output_plugin out_retry_plugin = {
    .name         = "retry",
    .description  = "Issue a retry upon flush request",
    .cb_init      = cb_retry_init,
    .cb_flush     = cb_retry_flush,
    .cb_exit      = cb_retry_exit,
    .flags        = 0,
};
