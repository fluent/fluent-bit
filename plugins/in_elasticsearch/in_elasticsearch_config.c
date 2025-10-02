/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include "in_elasticsearch.h"
#include "in_elasticsearch_config.h"
#include "in_elasticsearch_bulk_conn.h"

struct flb_in_elasticsearch *in_elasticsearch_config_create(struct flb_input_instance *ins)
{
    int ret;
    char port[8];
    struct flb_in_elasticsearch *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_in_elasticsearch));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->connections);

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Listen interface (if not set, defaults to 0.0.0.0:9200) */
    flb_input_net_default_listener("0.0.0.0", 9200, ins);

    ctx->listen = flb_sds_create(ins->host.listen);
    snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
    ctx->tcp_port = flb_sds_create(port);

    /* HTTP Server specifics */
    ctx->server = flb_calloc(1, sizeof(struct mk_server));
    ctx->server->keep_alive = MK_TRUE;

    /* monkey detects server->workers == 0 as the server not being initialized at the
     * moment so we want to make sure that it stays that way!
     */

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ctx->log_encoder == NULL) {
        flb_plg_error(ctx->ins, "event encoder initialization error");
        in_elasticsearch_config_destroy(ctx);

        return NULL;
    }

    /* Create record accessor for tag_key if specified */
    if (ctx->tag_key) {
        ctx->ra_tag_key = flb_ra_create(ctx->tag_key, FLB_TRUE);
        if (!ctx->ra_tag_key) {
            flb_plg_error(ctx->ins, "invalid record accessor pattern for tag_key: %s", ctx->tag_key);
            in_elasticsearch_config_destroy(ctx);
            return NULL;
        }
    }

    return ctx;
}

int in_elasticsearch_config_destroy(struct flb_in_elasticsearch *ctx)
{
    if (ctx->ra_tag_key) {
        flb_ra_destroy(ctx->ra_tag_key);
    }

    flb_log_event_encoder_destroy(ctx->log_encoder);

    /* release all connections */
    in_elasticsearch_bulk_conn_release_all(ctx);


    if (ctx->collector_id != -1) {
        flb_input_collector_delete(ctx->collector_id, ctx->ins);

        ctx->collector_id = -1;
    }

    if (ctx->downstream != NULL) {
        flb_downstream_destroy(ctx->downstream);
    }

    if (ctx->enable_http2) {
        flb_http_server_destroy(&ctx->http_server);
    }

    if (ctx->server) {
        flb_free(ctx->server);
    }

    flb_sds_destroy(ctx->listen);
    flb_sds_destroy(ctx->tcp_port);

    flb_free(ctx);

    return 0;
}
