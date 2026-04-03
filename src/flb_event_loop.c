/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_mem.h>

int flb_event_loop_create(flb_ctx_t *ctx)
{
    int ret;
    struct flb_config *config;

    if (ctx == NULL || ctx->config == NULL)
        return FLB_LIB_ERROR;

    config = ctx->config;

    /* Create the event loop to receive notifications */
    ctx->event_loop = mk_event_loop_create(256);
    if (!ctx->event_loop)
        goto error_0;

    config->ch_evl = ctx->event_loop;

    /* Prepare the notification channels */
    ctx->event_channel = flb_calloc(1, sizeof(struct mk_event));
    if (!ctx->event_channel) {
        flb_error("[lib] could not allocate event channel");
        goto error_1;
    }

    MK_EVENT_ZERO(ctx->event_channel);

    ret = mk_event_channel_create(config->ch_evl,
                                  &config->ch_notif[0],
                                  &config->ch_notif[1],
                                  ctx->event_channel);
    if (ret != 0) {
        flb_error("[lib] could not create notification channels");
        goto error_2;
    }

    return 0;

error_2:
    flb_free(ctx->event_channel);
    ctx->event_channel = NULL;
error_1:
    mk_event_loop_destroy(ctx->event_loop);
    ctx->event_loop = NULL;
error_0:
    config->ch_evl = NULL;
    return FLB_LIB_ERROR;
}

int flb_event_loop_destroy(flb_ctx_t *ctx)
{
    struct flb_config *config;

    if (ctx == NULL || ctx->config == NULL)
        return 0;

    config = ctx->config;
    if (ctx->event_channel != NULL) {
        mk_event_channel_destroy(config->ch_evl,
                                 config->ch_notif[0],
                                 config->ch_notif[1],
                                 ctx->event_channel);
        flb_free(ctx->event_channel);
        ctx->event_channel = NULL;
    }

    if (ctx->event_loop != NULL) {
        mk_event_loop_destroy(ctx->event_loop);
        ctx->event_loop = NULL;
        config->ch_evl = NULL;
    }

    return 0;
}

