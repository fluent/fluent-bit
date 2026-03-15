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

#include "splunk.h"
#include "splunk_prot.h"
#include "splunk_config.h"

static int in_splunk_init(struct flb_input_instance *ins,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_splunk *ctx;
    struct flb_http_server_options http_server_options;

    (void) config;
    (void) data;

    /* Create context and basic conf */
    ctx = splunk_config_create(ins);
    if (!ctx) {
        return -1;
    }

    /* Populate context with config map defaults and incoming properties */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        splunk_config_destroy(ctx);
        return -1;
    }

    /* Set the context */
    flb_input_set_context(ins, ctx);

    ret = flb_input_http_server_options_init(
            &http_server_options,
            ins,
            (FLB_HTTP_SERVER_FLAG_KEEPALIVE | FLB_HTTP_SERVER_FLAG_AUTO_INFLATE),
            splunk_prot_handle_ng,
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

        splunk_config_destroy(ctx);
        return -1;
    }

    flb_plg_info(ctx->ins, "listening on %s:%u with %i worker%s",
                 ins->host.listen,
                 ins->host.port,
                 ctx->http_server.workers,
                 ctx->http_server.workers == 1 ? "" : "s");
    return 0;
}

static int in_splunk_exit(void *data, struct flb_config *config)
{
    struct flb_splunk *ctx;

    (void) config;

    ctx = data;

    if (ctx != NULL) {
        splunk_config_destroy(ctx);
    }

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SLIST_1, "success_header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_splunk, success_headers),
     "Add an HTTP header key/value pair on success. Multiple headers can be set"
    },

    {
     FLB_CONFIG_MAP_STR, "splunk_token", NULL,
     0, FLB_FALSE, 0,
     "Set valid Splunk HEC tokens for the requests"
    },

    {
     FLB_CONFIG_MAP_BOOL, "store_token_in_metadata", "true",
     0, FLB_TRUE, offsetof(struct flb_splunk, store_token_in_metadata),
     "Store Splunk HEC tokens in metadata. If set as false, they will be stored into records."
    },

    {
     FLB_CONFIG_MAP_STR, "splunk_token_key", "@splunk_token",
     0, FLB_TRUE, offsetof(struct flb_splunk, store_token_key),
     "Set a record key for storing Splunk HEC token for the request"
    },

    {
     FLB_CONFIG_MAP_STR, "tag_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, tag_key),
     "Set a record key to specify the tag of the record"
    },
    {
     FLB_CONFIG_MAP_BOOL, "add_remote_addr", "false",
     0, FLB_TRUE, offsetof(struct flb_splunk, add_remote_addr),
     "Inject a remote address using the X-Forwarded-For header or connection address"
    },
    {
     FLB_CONFIG_MAP_STR, "remote_addr_key", "remote_addr",
     0, FLB_TRUE, offsetof(struct flb_splunk, remote_addr_key),
     "Set a record key for storing the remote address"
    },


    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_splunk_plugin = {
    .name         = "splunk",
    .description  = "Input plugin for Splunk HEC payloads",
    .cb_init      = in_splunk_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = in_splunk_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_INPUT_HTTP_SERVER | FLB_IO_OPT_TLS
};
