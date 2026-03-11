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
#include <fluent-bit/flb_random.h>

#include "in_elasticsearch.h"
#include "in_elasticsearch_config.h"
#include "in_elasticsearch_bulk_prot.h"

static void bytes_to_groupname(unsigned char *data, char *buf, size_t len) {
    int index;
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (len-- > 0) {
        index = (int) data[len];
        index = index % (sizeof(charset) - 1);
        buf[len] = charset[index];
    }
}

static void bytes_to_nodename(unsigned char *data, char *buf, size_t len) {
    int index;
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz";

    while (len-- > 0) {
        index = (int) data[len];
        index = index % (sizeof(charset) - 1);
        buf[len] = charset[index];
    }
}

static int in_elasticsearch_bulk_init(struct flb_input_instance *ins,
                                      struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_elasticsearch *ctx;
    unsigned char rand[16];
    struct flb_http_server_options http_server_options;

    (void) config;
    (void) data;

    /* Create context and basic conf */
    ctx = in_elasticsearch_config_create(ins);
    if (!ctx) {
        return -1;
    }

    /* Populate context with config map defaults and incoming properties */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        in_elasticsearch_config_destroy(ctx);
        return -1;
    }

    /* Set the context */
    flb_input_set_context(ins, ctx);

    if (flb_random_bytes(rand, 16)) {
        flb_plg_error(ctx->ins, "cannot generate cluster name");
        in_elasticsearch_config_destroy(ctx);
        return -1;
    }

    bytes_to_groupname(rand, ctx->cluster_name, 16);

    if (flb_random_bytes(rand, 12)) {
        flb_plg_error(ctx->ins, "cannot generate node name");
        in_elasticsearch_config_destroy(ctx);
        return -1;
    }

    bytes_to_nodename(rand, ctx->node_name, 12);

    ret = flb_input_http_server_options_init(
            &http_server_options,
            ins,
            (FLB_HTTP_SERVER_FLAG_KEEPALIVE | FLB_HTTP_SERVER_FLAG_AUTO_INFLATE),
            in_elasticsearch_bulk_prot_handle_ng,
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
                      "could not initialize http server on %s:%u. Aborting",
                      ins->host.listen, ins->host.port);

        in_elasticsearch_config_destroy(ctx);

        return -1;
    }

    flb_plg_info(ctx->ins, "listening on %s:%u with %i worker%s",
                 ins->host.listen,
                 ins->host.port,
                 ctx->http_server.workers,
                 ctx->http_server.workers == 1 ? "" : "s");

    return 0;
}

static int in_elasticsearch_bulk_exit(void *data, struct flb_config *config)
{
    struct flb_in_elasticsearch *ctx;

    (void) config;

    ctx = data;

    if (ctx != NULL) {
        in_elasticsearch_config_destroy(ctx);
    }

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "tag_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_elasticsearch, tag_key),
     "Specify a key name for extracting as a tag"
    },

    {
     FLB_CONFIG_MAP_STR, "meta_key", "@meta",
     0, FLB_TRUE, offsetof(struct flb_in_elasticsearch, meta_key),
     "Specify a key name for meta information"
    },

    {
     FLB_CONFIG_MAP_STR, "hostname", "localhost",
     0, FLB_TRUE, offsetof(struct flb_in_elasticsearch, hostname),
     "Specify hostname or FQDN. This parameter is effective for sniffering node information."
    },

    {
     FLB_CONFIG_MAP_STR, "version", "8.0.0",
     0, FLB_TRUE, offsetof(struct flb_in_elasticsearch, es_version),
     "Specify returning Elasticsearch server version."
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_elasticsearch_plugin = {
    .name         = "elasticsearch",
    .description  = "HTTP Endpoints for Elasticsearch (Bulk API)",
    .cb_init      = in_elasticsearch_bulk_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = in_elasticsearch_bulk_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_INPUT_HTTP_SERVER | FLB_IO_OPT_TLS
};
