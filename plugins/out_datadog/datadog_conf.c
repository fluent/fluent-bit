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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>

#include "datadog.h"
#include "datadog_conf.h"

struct flb_out_datadog *flb_datadog_conf_create(struct flb_output_instance *ins,
                                                struct flb_config *config)
{
    struct flb_out_datadog *ctx = NULL;
    int io_flags = 0;
    struct flb_upstream *upstream;
    const char *api_key;
    const char *tmp;
    flb_sds_t tmp_sds;

    int ret;
    char *protocol = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;

    /* Start resource creation */
    ctx = flb_calloc(1, sizeof(struct flb_out_datadog));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->nb_additional_entries = 0;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "flb_output_config_map_set failed");
        flb_free(ctx);
        return NULL;
    }

    tmp = flb_output_get_property("proxy", ins);
    if (tmp) {
        ret = flb_utils_url_split(tmp, &protocol, &host, &port, &uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'", tmp);
            flb_datadog_conf_destroy(ctx);
            return NULL;
        }

        ctx->proxy_host = host;
        ctx->proxy_port = atoi(port);
        flb_free(protocol);
        flb_free(port);
        flb_free(uri);
    }

    /* use TLS ? */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
        tmp_sds = flb_sds_create("https://");
    }
    else {
        io_flags = FLB_IO_TCP;
        tmp_sds = flb_sds_create("http://");
    }
    if (!tmp_sds) {
        flb_errno();
        flb_datadog_conf_destroy(ctx);
        return NULL;
    }
    ctx->scheme = tmp_sds;
    flb_plg_debug(ctx->ins, "scheme: %s", ctx->scheme);

    /* configure URI */
    api_key = flb_output_get_property("apikey", ins);
    if (api_key == NULL) {
        flb_plg_error(ctx->ins, "no ApiKey configuration key defined");
        flb_datadog_conf_destroy(ctx);
        return NULL;
    }

    /* Tag Key */
    if (ctx->include_tag_key == FLB_TRUE) {
        ctx->nb_additional_entries++;
    }

    tmp = flb_output_get_property("dd_source", ins);
    if (tmp) {
        ctx->nb_additional_entries++;
    }

    tmp = flb_output_get_property("dd_service", ins);
    if (tmp) {
        ctx->nb_additional_entries++;
    }

    tmp = flb_output_get_property("dd_tags", ins);
    if (tmp) {
        ctx->nb_additional_entries++;
    }

    tmp = flb_output_get_property("dd_hostname", ins);
    if (tmp) {
        ctx->nb_additional_entries++;
    }

    tmp = flb_output_get_property("provider", ins);
    ctx->remap = tmp && (strlen(tmp) == strlen(FLB_DATADOG_REMAP_PROVIDER)) && \
        (strncmp(tmp, FLB_DATADOG_REMAP_PROVIDER, strlen(tmp)) == 0);

    ctx->uri = flb_sds_create("/api/v2/logs");
    if (!ctx->uri) {
        flb_plg_error(ctx->ins, "error on uri generation");
        flb_datadog_conf_destroy(ctx);
        return NULL;
    }

    flb_plg_debug(ctx->ins, "uri: %s", ctx->uri);

    /* Get network configuration */
    if (!ins->host.name) {
        tmp_sds = flb_sds_create(FLB_DATADOG_DEFAULT_HOST);
    }
    else {
        tmp_sds = flb_sds_create(ins->host.name);
    }
    if (!tmp_sds) {
        flb_errno();
        flb_datadog_conf_destroy(ctx);
        return NULL;
    }
    ctx->host = tmp_sds;
    flb_plg_debug(ctx->ins, "host: %s", ctx->host);

    if (ins->host.port != 0) {
        ctx->port = ins->host.port;
    }
    if (ctx->port == 0) {
        ctx->port = FLB_DATADOG_DEFAULT_PORT;
        if (ins->use_tls == FLB_FALSE) {
            ctx->port = 80;
        }
    }
    flb_plg_debug(ctx->ins, "port: %i", ctx->port);

    /* Date tag for JSON output */
    ctx->nb_additional_entries++;
    flb_plg_debug(ctx->ins, "json_date_key: %s", ctx->json_date_key);

    /* Compress (gzip) */
    tmp = flb_output_get_property("compress", ins);
    ctx->compress_gzip = FLB_FALSE;
    if (tmp) {
        if (strcasecmp(tmp, "gzip") == 0) {
            ctx->compress_gzip = FLB_TRUE;
        }
    }
    flb_plg_debug(ctx->ins, "compress_gzip: %i", ctx->compress_gzip);

    /* Prepare an upstream handler */
    if (ctx->proxy) {
        flb_plg_trace(ctx->ins, "[out_datadog] Upstream Proxy=%s:%i",
                      ctx->proxy_host, ctx->proxy_port);
        upstream = flb_upstream_create(config,
                                       ctx->proxy_host,
                                       ctx->proxy_port,
                                       io_flags,
                                       ins->tls);
    }
    else {
        upstream = flb_upstream_create(config, ctx->host, ctx->port, io_flags, ins->tls);
    }

    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create Upstream context");
        flb_datadog_conf_destroy(ctx);
        return NULL;
    }
    ctx->upstream = upstream;
    flb_output_upstream_set(ctx->upstream, ins);

    return ctx;
}

int flb_datadog_conf_destroy(struct flb_out_datadog *ctx)
{
    if (!ctx) {
        return -1;
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
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }
    flb_free(ctx);

    return 0;
}
