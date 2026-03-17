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
#include <fluent-bit/flb_oauth2_jwt.h>
#include "opentelemetry.h"

/* default HTTP port for OTLP/HTTP is 4318 */
#define OTLP_HTTP_PORT    4318

struct flb_opentelemetry *opentelemetry_config_create(struct flb_input_instance *ins)
{
    int ret;
    char port[8];
    struct flb_opentelemetry *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_opentelemetry));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->oauth2_cfg.jwks_refresh_interval = 300;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    if (ins->oauth2_jwt_config_map && mk_list_size(&ins->oauth2_jwt_properties) > 0) {
        ret = flb_config_map_set(&ins->oauth2_jwt_properties,
                                 ins->oauth2_jwt_config_map,
                                 &ctx->oauth2_cfg);
        if (ret == -1) {
            flb_free(ctx);
            return NULL;
        }
    }

    /* Listen interface (if not set, defaults to 0.0.0.0:4318) */
    flb_input_net_default_listener("0.0.0.0", OTLP_HTTP_PORT, ins);

    ctx->listen = flb_strdup(ins->host.listen);
    snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
    ctx->tcp_port = flb_strdup(port);

    return ctx;
}

int opentelemetry_config_destroy(struct flb_opentelemetry *ctx)
{
    flb_http_server_destroy(&ctx->http_server);

    if (ctx->oauth2_ctx) {
        flb_oauth2_jwt_context_destroy(ctx->oauth2_ctx);
        ctx->oauth2_ctx = NULL;
    }

    flb_free(ctx->listen);
    flb_free(ctx->tcp_port);
    flb_free(ctx);

    return 0;
}
