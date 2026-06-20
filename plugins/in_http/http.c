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
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>

#include "http.h"
#include "http_prot.h"
#include "http_config.h"

static int in_http_init(struct flb_input_instance *ins,
                        struct flb_config *config, void *data)
{
    int                 ret;
    struct flb_http    *ctx;
    struct flb_http_server_options http_server_options;

    (void) data;

    /* Create context and basic conf */
    ctx = http_config_create(ins);
    if (!ctx) {
        return -1;
    }

    /* Populate context with config map defaults and incoming properties */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        http_config_destroy(ctx);
        return -1;
    }

    if (ctx->oauth2_cfg.validate) {
        if (!ctx->oauth2_cfg.issuer || !ctx->oauth2_cfg.jwks_url) {
            flb_plg_error(ctx->ins, "oauth2.issuer and oauth2.jwks_url are required when oauth2.validate is enabled");
            http_config_destroy(ctx);
            return -1;
        }

        if (ctx->oauth2_cfg.jwks_refresh_interval <= 0) {
            ctx->oauth2_cfg.jwks_refresh_interval = 300;
        }

        ctx->oauth2_ctx = flb_oauth2_jwt_context_create(config, &ctx->oauth2_cfg);
        if (!ctx->oauth2_ctx) {
            flb_plg_error(ctx->ins, "unable to create oauth2 jwt context");
            http_config_destroy(ctx);
            return -1;
        }
    }

    /* Set the context */
    flb_input_set_context(ins, ctx);

    ret = flb_input_http_server_options_init(&http_server_options,
                                             ins,
                                             (FLB_HTTP_SERVER_FLAG_KEEPALIVE |
                                              FLB_HTTP_SERVER_FLAG_AUTO_INFLATE),
                                             http_prot_handle_ng,
                                             ctx);
    if (ret == 0) {
        if (http_server_options.workers > 1) {
            ret = flb_input_ingress_enable(ins);
        }
    }
    if (ret == 0) {
        ret = flb_http_server_init_with_options(&ctx->http_server,
                                                &http_server_options);

        if (ret == 0) {
            ret = flb_http_server_start(&ctx->http_server);
        }

        if (ret == 0 && ctx->http_server.downstream != NULL) {
            ret = flb_input_downstream_set(ctx->http_server.downstream, ins);
        }
    }

    if (ret != 0) {
        flb_plg_error(ctx->ins,
                      "could not start http server on %s:%u. Aborting",
                      ins->host.listen, ins->host.port);

        http_config_destroy(ctx);

        return -1;
    }

    flb_plg_info(ctx->ins,
                 "listening on %s:%u with %i worker%s",
                 ins->host.listen,
                 ins->host.port,
                 ctx->http_server.workers,
                 ctx->http_server.workers == 1 ? "" : "s");

    if (ctx->successful_response_code != 200 &&
        ctx->successful_response_code != 201 &&
        ctx->successful_response_code != 204) {
        flb_plg_error(ctx->ins, "%d is not supported response code. Use default 201",
                      ctx->successful_response_code);
        ctx->successful_response_code = 201;
    }

    return 0;
}

static int in_http_exit(void *data, struct flb_config *config)
{
    struct flb_http *ctx;

    (void) config;

    ctx = data;

    if (ctx != NULL) {
        http_config_destroy(ctx);
    }

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "add_remote_addr", "false",
     0, FLB_TRUE, offsetof(struct flb_http, add_remote_addr),
     "Adds REMOTE_ADDR field to the record. The value of REMOTE_ADDR is the client's address."
    },

    {
     FLB_CONFIG_MAP_STR, "remote_addr_key", REMOTE_ADDR_KEY,
     0, FLB_TRUE, offsetof(struct flb_http, remote_addr_key),
     "Key name for the remote address field added to the record."
    },

    {
     FLB_CONFIG_MAP_SLIST_1, "success_header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_http, success_headers),
     "Add an HTTP header key/value pair on success. Multiple headers can be set."
    },

    {
     FLB_CONFIG_MAP_STR, "tag_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_http, tag_key),
     "Specify a key name for extracting the tag from incoming request data."
    },

    {
     FLB_CONFIG_MAP_INT, "successful_response_code", "201",
     0, FLB_TRUE, offsetof(struct flb_http, successful_response_code),
     "Set successful response code. 200, 201 and 204 are supported."
    },

    {
     FLB_CONFIG_MAP_BOOL, "enable_health_endpoint", "false",
     0, FLB_TRUE, offsetof(struct flb_http, enable_health_endpoint),
     "Enable the GET /health endpoint for this input instance."
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_http_plugin = {
    .name         = "http",
    .description  = "HTTP",
    .cb_init      = in_http_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = in_http_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_INPUT_HTTP_SERVER | FLB_IO_OPT_TLS
};
