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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>

#include "azure_logs_ingestion_msiauth.h"

char *flb_azure_li_msiauth_token_get(struct flb_oauth2 *ctx)
{
    int ret;
    size_t b_sent;
    time_t now;
    struct flb_connection *u_conn;
    struct flb_http_client *c;

    now = time(NULL);
    if (ctx->access_token) {
        /* validate unexpired token */
        if (ctx->expires_at > now && flb_sds_len(ctx->access_token) > 0) {
            return ctx->access_token;
        }
    }

    /* Get Token and store it in the context */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        flb_error("[azure li msi auth] could not get an upstream connection to %s:%i",
                  ctx->u->tcp_host, ctx->u->tcp_port);
        return NULL;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_GET, ctx->uri,
                        NULL, 0,
                        ctx->host, atoi(ctx->port),
                        NULL, 0);
    if (!c) {
        flb_error("[azure li msi auth] error creating HTTP client context");
        flb_upstream_conn_release(u_conn);
        return NULL;
    }

    /* Append HTTP Header */
    flb_http_add_header(c, "Metadata", 8, "true", 4);

    /* Issue request */
    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_warn("[azure li msi auth] cannot issue request, http_do=%i", ret);
    }
    else {
        flb_info("[azure li msi auth] HTTP Status=%i", c->resp.status);
        if (c->resp.payload_size > 0 && c->resp.status != 200) {
            flb_info("[azure li msi auth] payload:\n%s", c->resp.payload);
        }
    }

    /* Extract token */
    if (c->resp.payload_size > 0 && c->resp.status == 200) {
        ret = flb_oauth2_parse_json_response(c->resp.payload,
                                             c->resp.payload_size, ctx);
        if (ret == 0) {
            flb_info("[azure li msi auth] access token from '%s:%s' retrieved",
                     ctx->host, ctx->port);
            flb_http_client_destroy(c);
            flb_upstream_conn_release(u_conn);
            ctx->expires_at = time(NULL) + ctx->expires_in;
            return ctx->access_token;
        }
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return NULL;
}
