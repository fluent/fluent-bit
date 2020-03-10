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
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <fluent-bit/flb_config_map.h>

#include "es.h"
#include "es_conf.h"

/* Configure in HA mode */
int es_config_ha(const char *upstream_file,
                             struct flb_elasticsearch *ctx,
                             struct flb_config *config)
{
    int io_flags = 0;
    ssize_t ret;
    const char *tmp;
    const char *path;
    struct mk_list *head;
    struct flb_uri_field *f_index = NULL;
    struct flb_uri_field *f_type = NULL;
    struct flb_upstream_node *node;
    struct flb_elasticsearch_config *ec = NULL;

    ctx->ha_mode = FLB_TRUE;
    ctx->ha = flb_upstream_ha_from_file(upstream_file, config);
    if (!ctx->ha) {
        flb_plg_error(ctx->ins, "cannot load Upstream file");
        return -1;
    }

    /* Iterate nodes and create a forward_config context */
    mk_list_foreach(head, &ctx->ha->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);
        /* Allocate context */
        ec = flb_calloc(1, sizeof(struct flb_elasticsearch_config));
        if (!ec) {
            flb_errno();
            flb_plg_error(ctx->ins, "failed config allocation");
            continue;
        }

        /* Populate context with config map defaults and incoming properties */
        ret = flb_output_config_map_set(ctx->ins, (void *) ec);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "configuration error");
            flb_es_conf_destroy(ec);
            return -1;
        }

        /* Is TLS enabled ? */
        if (node->tls_enabled == FLB_TRUE) {
            io_flags = FLB_IO_TLS;
        }
        else {
            io_flags = FLB_IO_TCP;
        }

        /* Set manual Index and Type */
        if (f_index) {
            ec->index = flb_strdup(f_index->value); /* FIXME */
        }
        else {
            ec->index = flb_strdup(FLB_ES_DEFAULT_INDEX);
        }
        if (f_type) {
            ec->type = flb_strdup(f_type->value); /* FIXME */
        }
        else {
            ec->type = flb_strdup(FLB_ES_DEFAULT_TYPE);
        }

        /* HTTP Payload (response) maximum buffer size (0 == unlimited) */
        if (ec->buffer_size == -1) {
            ec->buffer_size = 0;
        }

        /* Elasticsearch: Path */
        path = flb_upstream_node_get_property("path", node);
        if (!path) {
            path = "";
        }

        /* Elasticsearch: Pipeline */
        tmp = flb_upstream_node_get_property("pipeline", node);
        if (tmp) {
            snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk/?pipeline=%s", path, tmp);
        }
        else {
            snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk", path);
        }

#ifdef FLB_HAVE_SIGNV4
        /* AWS Auth */
        ec->has_aws_auth = FLB_FALSE;
        tmp = flb_upstream_node_get_property("aws_auth", node);
        if (tmp) {
            if (strncasecmp(tmp, "On", 2) == 0) {
                ec->has_aws_auth = FLB_TRUE;
                flb_plg_warn(ctx->ins,
                             "Enabled AWS Auth. Note: Amazon ElasticSearch "
                             "Service support in Fluent Bit is experimental.");

                tmp = flb_upstream_node_get_property("aws_region", node);
                if (!tmp) {
                    flb_plg_error(ctx->ins,
                                  "aws_auth enabled but aws_region not set");
                    flb_es_conf_destroy(ctx);
                    return NULL;
                }
                ec->aws_region = flb_strdup(tmp);
            }
        }
#endif

        /* Initialize and validate es_config context */
        mk_list_add(&ec->_head, &ctx->configs);

        /* Set our elasticsearch_config context into the node */
        flb_upstream_node_set_data(ec, node);
    }

    return 0;
}

int es_config_simple(struct flb_output_instance *ins,
                          struct flb_elasticsearch *ctx,
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
    struct flb_elasticsearch_config *ec = NULL;

    /* Allocate context */
    ec = flb_calloc(1, sizeof(struct flb_elasticsearch_config));
    if (!ec) {
        return -1;
    }

    if (uri) {
        if (uri->count >= 2) {
            f_index = flb_uri_get(uri, 0);
            f_type  = flb_uri_get(uri, 1);
        }
    }

    /* Set default network configuration */
    flb_output_net_default("127.0.0.1", 9200, ins);

    /* Populate context with config map defaults and incoming properties */
    ret = flb_output_config_map_set(ins, (void *) ec);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_es_conf_destroy(ec);
        flb_free(ctx);
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
        flb_es_conf_destroy(ec);
        flb_free(ctx);
        return NULL;
    }
    ctx->u = upstream;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    /* Set manual Index and Type */
    if (f_index) {
        ec->index = flb_strdup(f_index->value); /* FIXME */
    }

    if (f_type) {
        ec->type = flb_strdup(f_type->value); /* FIXME */
    }

    /* HTTP Payload (response) maximum buffer size (0 == unlimited) */
    if (ec->buffer_size == -1) {
        ec->buffer_size = 0;
    }

    /* Elasticsearch: Path */
    path = flb_output_get_property("path", ins);
    if (!path) {
        path = "";
    }

    /* Elasticsearch: Pipeline */
    tmp = flb_output_get_property("pipeline", ins);
    if (tmp) {
        snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk/?pipeline=%s", path, tmp);
    }
    else {
        snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk", path);
    }

#ifdef FLB_HAVE_SIGNV4
    /* AWS Auth */
    ec->has_aws_auth = FLB_FALSE;
    tmp = flb_output_get_property("aws_auth", ins);
    if (tmp) {
        if (strncasecmp(tmp, "On", 2) == 0) {
            ec->has_aws_auth = FLB_TRUE;
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
            ec->aws_region = flb_strdup(tmp);
        }
    }
#endif

    mk_list_add(&ec->_head, &ctx->configs);

    flb_plg_debug(ctx->ins, "[out_es] host=%s port=%i uri=%s index=%s type=%s",
                  ins->host.name, ins->host.port, ec->uri,
                  ec->index, ec->type);

    return 0;
}

int flb_es_conf_destroy(struct flb_elasticsearch_config *ec)
{
    if (!ec) {
        return 0;
    }

    flb_free(ec);

    return 0;
}
