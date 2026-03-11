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

#include "prom_rw.h"
#include "prom_rw_prot.h"
#include "prom_rw_config.h"

static int prom_rw_init(struct flb_input_instance *ins,
                        struct flb_config *config, void *data)
{
    int                       ret;
    struct flb_prom_remote_write *ctx;
    struct flb_http_server_options http_server_options;

    (void) data;

    /* Create context and basic conf */
    ctx = prom_rw_config_create(ins);
    if (!ctx) {
        return -1;
    }

    /* Populate context with config map defaults and incoming properties */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        prom_rw_config_destroy(ctx);
        return -1;
    }

    ret = flb_input_http_server_options_init(&http_server_options,
                                             ins,
                                             (FLB_HTTP_SERVER_FLAG_KEEPALIVE |
                                              FLB_HTTP_SERVER_FLAG_AUTO_INFLATE),
                                             prom_rw_prot_handle_ng,
                                             ctx);
    if (ret == 0) {
        ret = flb_http_server_init_with_options(&ctx->http_server,
                                                &http_server_options);

        if (ret == 0) {
            ret = flb_http_server_start(&ctx->http_server);
        }

        if (ret == 0) {
            ret = flb_input_downstream_set(ctx->http_server.downstream, ins);
        }
    }

    if (ret != 0) {
        flb_plg_error(ctx->ins,
                      "could not start http server on %s:%u. Aborting",
                      ins->host.listen, ins->host.port);

        prom_rw_config_destroy(ctx);
        return -1;
    }

    flb_input_set_context(ins, ctx);

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

static int prom_rw_exit(void *data, struct flb_config *config)
{
    struct flb_prom_remote_write *ctx;

    (void) config;

    ctx = data;

    if (ctx != NULL) {
        prom_rw_config_destroy(ctx);
    }

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "uri", NULL,
     0, FLB_TRUE, offsetof(struct flb_prom_remote_write, uri),
     "Specify an optional HTTP URI for the target web server, e.g: /something"
    },

    {
     FLB_CONFIG_MAP_BOOL, "tag_from_uri", "true",
     0, FLB_TRUE, offsetof(struct flb_prom_remote_write, tag_from_uri),
     "If true, tag will be created from uri. e.g. v1_metrics from /v1/metrics ."
    },
    {
     FLB_CONFIG_MAP_INT, "successful_response_code", "201",
     0, FLB_TRUE, offsetof(struct flb_prom_remote_write, successful_response_code),
     "Set successful response code. 200, 201 and 204 are supported."
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_prometheus_remote_write_plugin = {
    .name         = "prometheus_remote_write",
    .description  = "Prometheus Remote Write input",
    .cb_init      = prom_rw_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = prom_rw_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_INPUT_HTTP_SERVER | FLB_IO_OPT_TLS
};
