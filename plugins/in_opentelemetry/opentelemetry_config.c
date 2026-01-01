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
#include <fluent-bit/flb_downstream.h>

#include "opentelemetry.h"
#include "http_conn.h"

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
    mk_list_init(&ctx->connections);

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Listen interface (if not set, defaults to 0.0.0.0:4318) */
    flb_input_net_default_listener("0.0.0.0", OTLP_HTTP_PORT, ins);

    ctx->listen = flb_strdup(ins->host.listen);
    snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
    ctx->tcp_port = flb_strdup(port);

    /* HTTP Server specifics */
    ctx->server = flb_calloc(1, sizeof(struct mk_server));
    ctx->server->keep_alive = MK_TRUE;

    /* monkey detects server->workers == 0 as the server not being initialized at the
     * moment so we want to make sure that it stays that way!
     */

    return ctx;
}

int opentelemetry_config_destroy(struct flb_opentelemetry *ctx)
{
    /* release all connections */
    opentelemetry_conn_release_all(ctx);

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

    flb_free(ctx->listen);
    flb_free(ctx->tcp_port);
    flb_free(ctx);

    return 0;
}
