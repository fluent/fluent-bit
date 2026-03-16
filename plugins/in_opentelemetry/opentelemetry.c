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
#include <fluent-bit/flb_config.h>

#include "opentelemetry.h"
#include "opentelemetry_prot.h"
#include "opentelemetry_config.h"

static int in_opentelemetry_init(struct flb_input_instance *ins,
                                 struct flb_config *config, void *data)
{
    int                       ret;
    struct flb_opentelemetry *ctx;
    struct flb_http_server_options http_server_options;

    (void) config;
    (void) data;

    /* Create context and basic conf */
    ctx = opentelemetry_config_create(ins);
    if (!ctx) {
        return -1;
    }

    /* Populate context with config map defaults and incoming properties */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        opentelemetry_config_destroy(ctx);
        return -1;
    }

    /* Set the context */
    flb_input_set_context(ins, ctx);

    ret = flb_input_http_server_options_init(
            &http_server_options,
            ins,
            (FLB_HTTP_SERVER_FLAG_KEEPALIVE | FLB_HTTP_SERVER_FLAG_AUTO_INFLATE),
            opentelemetry_prot_handle_ng,
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
                      "could not initialize http server on %s:%u. Aborting",
                      ins->host.listen, ins->host.port);

        opentelemetry_config_destroy(ctx);

        return -1;
    }

    flb_plg_info(ctx->ins, "listening on %s:%u with %i worker%s",
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

static int in_opentelemetry_exit(void *data, struct flb_config *config)
{
    struct flb_opentelemetry *ctx;

    (void) config;

    ctx = data;

    if (ctx != NULL) {
        opentelemetry_config_destroy(ctx);
    }

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "profiles_support", "false",
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, profile_support_enabled),
     "This is an experimental feature whoses specification is not stable yet, " \
     "feel free to test it but please do not enable this in production " \
     "environments"
    },
    {
     FLB_CONFIG_MAP_BOOL, "encode_profiles_as_log", "false",
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, encode_profiles_as_log),
     "Encode profiles received as text and ingest them in the logging pipeline"
    },

    {
     FLB_CONFIG_MAP_STR, "tag_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, tag_key),
     "Record accessor key to use for generating tags from incoming records"
    },
    {
     FLB_CONFIG_MAP_BOOL, "tag_from_uri", "true",
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, tag_from_uri),
     "If true, tag will be created from uri. e.g. v1_metrics from /v1/metrics ."
    },
    {
     FLB_CONFIG_MAP_INT, "successful_response_code", "201",
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, successful_response_code),
     "Set successful response code. 200, 201 and 204 are supported."
    },
    {
     FLB_CONFIG_MAP_BOOL, "raw_traces", "false",
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, raw_traces),
     "Forward traces without processing"
    },

    {
     FLB_CONFIG_MAP_STR, "logs_metadata_key", "otlp",
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, logs_metadata_key),
     "Key name to store OpenTelemetry logs metadata in the record"
    },
    {
     FLB_CONFIG_MAP_STR, "logs_body_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, logs_body_key),
     "Key to use for the logs body. If unset, body key-value pairs will be " \
     "used as the log record, and other types will be nested under a key."
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_opentelemetry_plugin = {
    .name         = "opentelemetry",
    .description  = "OpenTelemetry",
    .cb_init      = in_opentelemetry_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = in_opentelemetry_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_INPUT_HTTP_SERVER | FLB_IO_OPT_TLS
};
