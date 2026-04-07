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

#include "http.h"
#include "http_config.h"

struct flb_http *http_config_create(struct flb_input_instance *ins)
{
    char                       port[8];
    int                        ret;
    struct flb_http           *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_http));
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

    /* Apply OAuth2 JWT config map properties if any */
    if (ins->oauth2_jwt_config_map && mk_list_size(&ins->oauth2_jwt_properties) > 0) {
        ret = flb_config_map_set(ins->config,
                                 &ins->oauth2_jwt_properties,
                                 ins->oauth2_jwt_config_map,
                                 &ctx->oauth2_cfg);
        if (ret == -1) {
            flb_free(ctx);
            return NULL;
        }
    }

    /* Listen interface (if not set, defaults to 0.0.0.0:9880) */
    flb_input_net_default_listener("0.0.0.0", 9880, ins);

    ctx->listen = flb_strdup(ins->host.listen);
    snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
    ctx->tcp_port = flb_strdup(port);

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "error initializing event encoder : %d", ret);
        http_config_destroy(ctx);
        return NULL;
    }

    /* Create record accessor for tag_key if specified */
    if (ctx->tag_key) {
        ctx->ra_tag_key = flb_ra_create(ctx->tag_key, FLB_TRUE);
        if (!ctx->ra_tag_key) {
            flb_plg_error(ctx->ins, "invalid record accessor pattern for tag_key: %s", ctx->tag_key);
            http_config_destroy(ctx);
            return NULL;
        }
    }

    return ctx;
}

int http_config_destroy(struct flb_http *ctx)
{
    if (ctx->ra_tag_key) {
        flb_ra_destroy(ctx->ra_tag_key);
    }

    flb_log_event_encoder_destroy(&ctx->log_encoder);
    flb_http_server_destroy(&ctx->http_server);

    if (ctx->oauth2_ctx) {
        flb_oauth2_jwt_context_destroy(ctx->oauth2_ctx);
        ctx->oauth2_ctx = NULL;
        ctx->oauth2_cfg.issuer = NULL;
        ctx->oauth2_cfg.jwks_url = NULL;
        ctx->oauth2_cfg.allowed_audience = NULL;
    }
    else {
        if (ctx->oauth2_cfg.issuer) {
            flb_sds_destroy(ctx->oauth2_cfg.issuer);
        }

        if (ctx->oauth2_cfg.jwks_url) {
            flb_sds_destroy(ctx->oauth2_cfg.jwks_url);
        }

        if (ctx->oauth2_cfg.allowed_audience) {
            flb_sds_destroy(ctx->oauth2_cfg.allowed_audience);
        }
    }


    flb_free(ctx->listen);
    flb_free(ctx->tcp_port);
    flb_free(ctx);
    return 0;
}
