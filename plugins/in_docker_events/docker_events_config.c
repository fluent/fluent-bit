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

#include <stdlib.h>
#include <fluent-bit/flb_utils.h>

#include "docker_events.h"
#include "docker_events_config.h"

/**
 * Function to initialize docker_events plugin.
 *
 * @param i_ins   Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 *
 * @return struct flb_in_de_config* Pointer to the plugin's
 *         structure on success, NULL on failure.
 */
struct flb_in_de_config* de_config_init(struct flb_input_instance *i_ins,
                                        struct flb_config *config)
{
    const char *p;
    struct flb_in_de_config *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_in_de_config));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    p = flb_input_get_property("unix_path", i_ins);
    if (p) {
        ctx->unix_path = flb_strdup(p);
    }
    else {
        ctx->unix_path = flb_strdup(DEFAULT_UNIX_SOCKET_PATH);
    }

    p = flb_input_get_property("buffer_size", i_ins);
    if (!p) {
        ctx->buf_size = DEFAULT_BUF_SIZE;
    }
    else {
        ctx->buf_size = flb_utils_size_to_bytes(p);
    }
    ctx->buf = flb_malloc(ctx->buf_size);

    p = flb_input_get_property("parser", i_ins);
    if (p) {
        ctx->parser = flb_parser_get(p, config);
        if (ctx->parser == NULL) {
            flb_error("[in_docker_events] requested parser '%s' not found", p);
            return NULL;
        }
    }

    p = flb_input_get_property("field_name", i_ins);
    if (p) {
        ctx->key = flb_strdup(p);
    }
    else {
        ctx->key = flb_strdup(DEFAULT_KEY);
    }
    ctx->key_len = strlen(ctx->key);

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
    if (ctx->unix_path) {
        flb_free(ctx->unix_path);
    }
    if (ctx->buf) {
        flb_free(ctx->buf);
    }
    if (ctx->key) {
        flb_free(ctx->key);
    }

    flb_free(ctx);

    return 0;
}
