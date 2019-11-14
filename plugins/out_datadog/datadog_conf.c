/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>

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

    /* Start resource creation */
    ctx = flb_calloc(1, sizeof(struct flb_out_datadog));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->nb_additional_entries = 0;

    /* use TLS ? */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
        ctx->scheme = flb_sds_create("https://");
    }
    else {
        io_flags = FLB_IO_TCP;
        ctx->scheme = flb_sds_create("http://");
    }
    flb_debug("[out_datadog] ctx->scheme: %s", ctx->scheme);
    /* configure URI */
    api_key = flb_output_get_property("apikey", ins);
    if (api_key) {
        ctx->api_key = flb_sds_create(api_key);
    }
    else {
        flb_error("[out_datadog] no ApiKey configuration key defined");
        flb_datadog_conf_destroy(ctx);
        return NULL;
    }
    flb_debug("[out_datadog] ctx->api_key: %s", ctx->api_key);

    /* Include Tag key */
    tmp = flb_output_get_property("include_tag_key", ins);
    if (tmp) {
        ctx->include_tag_key = flb_utils_bool(tmp);
    }
    else {
        ctx->include_tag_key = FLB_FALSE;
    }

    /* Tag Key */
    if (ctx->include_tag_key == FLB_TRUE) {
        ctx->nb_additional_entries++;
        tmp = flb_output_get_property("tag_key", ins);
        if (tmp) {
            ctx->tag_key = flb_sds_create(tmp);
        }
        else {
            ctx->tag_key = flb_sds_create(FLB_DATADOG_DEFAULT_TAG_KEY);
        }
    }

    tmp = flb_output_get_property("dd_source", ins);
    if (tmp) {
        ctx->nb_additional_entries++;
        ctx->dd_source = flb_sds_create(tmp);
    }

    tmp = flb_output_get_property("dd_service", ins);
    if (tmp) {
        ctx->nb_additional_entries++;
        ctx->dd_service = flb_sds_create(tmp);
    }

    tmp = flb_output_get_property("dd_tags", ins);
    if (tmp) {
        ctx->nb_additional_entries++;
        ctx->dd_tags = flb_sds_create(tmp);
    }

    tmp = flb_output_get_property("dd_message_key", ins);
    if (tmp) {
        ctx->dd_message_key = flb_sds_create(tmp);
    }

    tmp = flb_output_get_property("provider", ins);
    ctx->remap = tmp && (strlen(tmp) == strlen(FLB_DATADOG_REMAP_PROVIDER)) && \
        (strncmp(tmp, FLB_DATADOG_REMAP_PROVIDER, strlen(tmp)) == 0);

    ctx->uri = flb_sds_create("/v1/input/");
    if (!ctx->uri) {
        flb_error("[out_datadog] error on uri generation");
        flb_datadog_conf_destroy(ctx);
        return NULL;
    }
    /* Add the api_key to the URI */
    ctx->uri = flb_sds_cat(ctx->uri, ctx->api_key, flb_sds_len(ctx->api_key));
    flb_debug("[out_datadog] ctx->uri: %s", ctx->uri);

    /* Get network configuration */
    if (!ins->host.name) {
        ctx->host = flb_sds_create(FLB_DATADOG_DEFAULT_HOST);
    } else {
        ctx->host = flb_strdup(ins->host.name);
    }
    flb_debug("[out_datadog] ctx->host: %s", ctx->host);

    if (ins->host.port != 0) {
        ctx->port = ins->host.port;
    }
    if (ctx->port == 0) {
        ctx->port = FLB_DATADOG_DEFAULT_PORT;
        if (ins->use_tls == FLB_FALSE) {
            ctx->port = 80;
        }
    }
    flb_debug("[out_datadog] ctx->port: %i", ctx->port);

    /* Date tag for JSON output */
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        ctx->json_date_key = flb_sds_create(tmp);
    }
    else {
        ctx->json_date_key = flb_sds_create(FLB_DATADOG_DEFAULT_TIME_KEY);
    }
    ctx->nb_additional_entries++;
    flb_debug("[out_datadog] ctx->json_date_key: %s", ctx->json_date_key);

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config, ctx->host, ctx->port, io_flags, &ins->tls);
    if (!upstream) {
        flb_error("[out_datadog] cannot create Upstream context");
        flb_datadog_conf_destroy(ctx);
        return NULL;
    }
    ctx->upstream = upstream;

    return ctx;
}

int flb_datadog_conf_destroy(struct flb_out_datadog *ctx)
{
    if (!ctx) {
        return -1;
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
    if (ctx->api_key) {
        flb_sds_destroy(ctx->api_key);
    }
    if (ctx->tag_key) {
        flb_sds_destroy(ctx->tag_key);
    }
    if (ctx->json_date_key) {
        flb_sds_destroy(ctx->json_date_key);
    }
    if (ctx->dd_source) {
        flb_sds_destroy(ctx->dd_source);
    }
    if (ctx->dd_service) {
        flb_sds_destroy(ctx->dd_service);
    }
    if (ctx->dd_tags) {
        flb_sds_destroy(ctx->dd_tags);
    }
    if (ctx->dd_message_key) {
        flb_sds_destroy(ctx->dd_message_key);
    }
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }
    flb_free(ctx);

    return 0;
}
