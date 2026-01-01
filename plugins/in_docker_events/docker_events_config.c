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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>

#include "docker_events.h"
#include "docker_events_config.h"

/**
 * Function to initialize docker_events plugin.
 *
 * @param ins     Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 *
 * @return struct flb_in_de_config* Pointer to the plugin's
 *         structure on success, NULL on failure.
 */
struct flb_in_de_config *de_config_init(struct flb_input_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    const char *tmp;
    struct flb_in_de_config *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_in_de_config));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Allocate buffer for events */
    ctx->buf = flb_malloc(ctx->buf_size);
    if (!ctx->buf) {
        flb_errno();
        flb_free(ctx);
        return NULL;
    }

    tmp = flb_input_get_property("parser", ins);
    if (tmp) {
        ctx->parser = flb_parser_get(tmp, config);
        if (ctx->parser == NULL) {
            flb_plg_error(ctx->ins, "requested parser '%s' not found", tmp);
            flb_free(ctx->buf);
            flb_free(ctx);
            return NULL;
        }
    }

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "error initializing event encoder : %d", ret);

        de_config_destroy(ctx);

        ctx = NULL;
    }

    return ctx;
}

/**
 * Function to destroy docker_events plugin.
 *
 * @param ctx  Pointer to flb_in_de_config
 *
 * @return int 0
 */
int de_config_destroy(struct flb_in_de_config *ctx)
{
    if (ctx->buf) {
        flb_free(ctx->buf);
    }

    flb_log_event_encoder_destroy(&ctx->log_encoder);

    flb_free(ctx);
    return 0;
}
