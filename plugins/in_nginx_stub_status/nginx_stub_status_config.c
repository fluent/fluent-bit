/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>

#include "nginx_stub_status.h"
#include "nginx_stub_status_config.h"

/**
 * Function to initialize nginx_stub_status plugin.
 *
 * @param ins     Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 *
 * @return struct flb_in_nss_config* Pointer to the plugin's
 *         structure on success, NULL on failure.
 */
struct flb_in_nss_config *nss_config_init(struct flb_input_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    struct flb_in_nss_config *ctx;
    struct flb_upstream *upstream;


    ctx = flb_calloc(1, sizeof(struct flb_in_nss_config));
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

    upstream = flb_upstream_create(config, ctx->host, ctx->port, FLB_IO_TCP, NULL);
    if (!upstream) {
        flb_error("[nginx_stub_status] upstream initialization error");
        return NULL;
    }
    ctx->upstream = upstream;

    return ctx;
}

/**
 * Function to destroy nginx_stub_status plugin.
 *
 * @param ctx  Pointer to flb_in_nss_config
 *
 * @return int 0
 */
int nss_config_destroy(struct flb_in_nss_config *ctx)
{
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }
    flb_free(ctx);
    return 0;
}
