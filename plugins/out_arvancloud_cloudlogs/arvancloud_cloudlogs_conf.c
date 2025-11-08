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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_record_accessor.h>

#include "arvancloud_cloudlogs.h"

struct flb_out_arvancloud_cloudlogs *flb_arvancloud_conf_create(
                                    struct flb_output_instance *ins,
                                    struct flb_config *config)
{
    int io_flags;
    struct flb_upstream *upstream;
    struct flb_out_arvancloud_cloudlogs *ctx;
    const char *tmp;
    char *protocol;
    char *host;
    char *port;
    char *uri;

    io_flags = 0;
    protocol = NULL;
    host = NULL;
    port = NULL;
    uri = NULL;

    ctx = flb_calloc(1, sizeof(struct flb_out_arvancloud_cloudlogs));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    if (flb_output_config_map_set(ins, (void *) ctx) == -1) {
        flb_plg_error(ins, "flb_output_config_map_set failed");
        flb_arvancloud_conf_destroy(ctx);
        return NULL;
    }

    tmp = flb_output_get_property("proxy", ins);
    if (tmp) {
        ctx->proxy = flb_sds_create(tmp);
        if (!ctx->proxy) {
            flb_errno();
            flb_arvancloud_conf_destroy(ctx);
            return NULL;
        }
        if (flb_utils_url_split(tmp, &protocol, &host, &port, &uri)
            == -1) {
            flb_plg_error(ins, "could not parse proxy: '%s'", tmp);
            flb_arvancloud_conf_destroy(ctx);
            return NULL;
        }
        ctx->proxy_host = host;
        ctx->proxy_port = atoi(port);
        flb_free(protocol);
        flb_free(port);
        flb_free(uri);
    }

    /* Force HTTPS */
    io_flags = FLB_IO_TLS;
    ctx->scheme = flb_sds_create("https://");
    if (!ctx->scheme) {
        flb_errno();
        flb_arvancloud_conf_destroy(ctx);
        return NULL;
    }

    if (!ctx->api_key) {
        flb_plg_error(ins, "missing required 'apikey'");
        flb_arvancloud_conf_destroy(ctx);
        return NULL;
    }

    /* Initialize record accessor for log_type_key if configured */
    if (ctx->log_type_key) {
        ctx->ra_log_type_key = flb_ra_create(ctx->log_type_key, FLB_TRUE);
        if (!ctx->ra_log_type_key) {
            flb_plg_error(ins, "invalid log_type_key pattern '%s'",
                          ctx->log_type_key);
            flb_arvancloud_conf_destroy(ctx);
            return NULL;
        }
    }

    /* Initialize record accessor for timestamp_key if configured */
    if (ctx->timestamp_key) {
        ctx->ra_timestamp_key = flb_ra_create(ctx->timestamp_key, FLB_TRUE);
        if (!ctx->ra_timestamp_key) {
            flb_plg_error(ins, "invalid timestamp_key pattern '%s'",
                          ctx->timestamp_key);
            flb_arvancloud_conf_destroy(ctx);
            return NULL;
        }
    }

    /* Hardcode host */
    ctx->host = flb_sds_create("napi.arvancloud.ir");
    if (!ctx->host) {
        flb_errno();
        flb_arvancloud_conf_destroy(ctx);
        return NULL;
    }

    /* Hardcode port */
    ctx->port = 443;

    /* Hardcode uri */
    if (ctx->uri) {
        flb_sds_destroy(ctx->uri);
    }
    ctx->uri = flb_sds_create("/logging/v1/entries/write");
    if (!ctx->uri) {
        flb_arvancloud_conf_destroy(ctx);
        return NULL;
    }

    if (ctx->proxy) {
        upstream = flb_upstream_create(config, ctx->proxy_host,
                                       ctx->proxy_port, io_flags, ins->tls);
    }
    else {
        upstream = flb_upstream_create(config, ctx->host, ctx->port,
                                       io_flags, ins->tls);
    }
    if (!upstream) {
        flb_plg_error(ins, "cannot create upstream context");
        flb_arvancloud_conf_destroy(ctx);
        return NULL;
    }

    ctx->u = upstream;
    flb_output_upstream_set(ctx->u, ins);

    return ctx;
}

int flb_arvancloud_conf_destroy(struct flb_out_arvancloud_cloudlogs *ctx)
{
    if (!ctx) {
        return -1;
    }
    if (ctx->proxy) {
        flb_sds_destroy(ctx->proxy);
    }
    if (ctx->proxy_host) {
        flb_free(ctx->proxy_host);
    }
    if (ctx->scheme) {
        flb_sds_destroy(ctx->scheme);
    }
    if (ctx->host) {
        flb_sds_destroy(ctx->host);
    }
    if (ctx->uri) {
        flb_sds_destroy(ctx->uri);
    }
    if (ctx->ra_log_type_key) {
        flb_ra_destroy(ctx->ra_log_type_key);
    }
    if (ctx->ra_timestamp_key) {
        flb_ra_destroy(ctx->ra_timestamp_key);
    }
    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }
    flb_free(ctx);
    return 0;
}


