/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_credentials.h>

#include "es.h"
#include "es_conf.h"

struct flb_elasticsearch *flb_es_conf_create(struct flb_output_instance *ins,
                                             struct flb_config *config)
{

    int io_flags = 0;
    ssize_t ret;
    const char *tmp;
    const char *path;
    struct flb_uri *uri = ins->host.uri;
    struct flb_uri_field *f_index = NULL;
    struct flb_uri_field *f_type = NULL;
    struct flb_upstream *upstream;
    struct flb_elasticsearch *ctx;

    /* Allocate context */
    ctx = flb_calloc(1, sizeof(struct flb_elasticsearch));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    if (uri) {
        if (uri->count >= 2) {
            f_index = flb_uri_get(uri, 0);
            f_type  = flb_uri_get(uri, 1);
        }
    }

    /* Set default network configuration */
    flb_output_net_default("127.0.0.1", 9200, ins);

    /* Populate context with config map defaults and incoming properties */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_es_conf_destroy(ctx);
        return NULL;
    }

    /* use TLS ? */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags,
                                   &ins->tls);
    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create Upstream context");
        flb_es_conf_destroy(ctx);
        return NULL;
    }
    ctx->u = upstream;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    /* Set manual Index and Type */
    if (f_index) {
        ctx->index = flb_strdup(f_index->value); /* FIXME */
    }

    if (f_type) {
        ctx->type = flb_strdup(f_type->value); /* FIXME */
    }

    /* HTTP Payload (response) maximum buffer size (0 == unlimited) */
    if (ctx->buffer_size == -1) {
        ctx->buffer_size = 0;
    }

    /* Elasticsearch: Path */
    path = flb_output_get_property("path", ins);
    if (!path) {
        path = "";
    }

    /* Elasticsearch: Pipeline */
    tmp = flb_output_get_property("pipeline", ins);
    if (tmp) {
        snprintf(ctx->uri, sizeof(ctx->uri) - 1, "%s/_bulk/?pipeline=%s", path, tmp);
    }
    else {
        snprintf(ctx->uri, sizeof(ctx->uri) - 1, "%s/_bulk", path);
    }

#ifdef FLB_HAVE_SIGNV4
    /* AWS Auth */
    ctx->has_aws_auth = FLB_FALSE;
    tmp = flb_output_get_property("aws_auth", ins);
    if (tmp) {
        if (strncasecmp(tmp, "On", 2) == 0) {
            ctx->has_aws_auth = FLB_TRUE;
            flb_plg_warn(ctx->ins,
                         "Enabled AWS Auth. Note: Amazon ElasticSearch "
                         "Service support in Fluent Bit is experimental.");

            tmp = flb_output_get_property("aws_region", ins);
            if (!tmp) {
                flb_plg_error(ctx->ins,
                              "aws_auth enabled but aws_region not set");
                flb_es_conf_destroy(ctx);
                return NULL;
            }
            ctx->aws_region = (char *) tmp;

            ctx->aws_provider = flb_aws_env_provider_create();
            if (!ctx->aws_provider) {
                flb_errno();
                flb_es_conf_destroy(ctx);
                return NULL;
            }

            /* initialize provider in sync mode */
            ctx->aws_provider->provider_vtable->sync(ctx->aws_provider);
            ctx->aws_provider->provider_vtable->get_credentials(ctx->
                                                                aws_provider);
        }
    }
#endif

    return ctx;
}

int flb_es_conf_destroy(struct flb_elasticsearch *ctx)
{
    if (!ctx) {
        return 0;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->aws_provider) {
        flb_aws_provider_destroy(ctx->aws_provider);
    }
    flb_free(ctx);

    return 0;
}
