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

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_signv4.h>

#include "es_conf.h"
#include "es_conf_parse.h"
#include "es.h"

static int config_set_properties(struct flb_elasticsearch_config *ec,
                                 struct flb_elasticsearch *ctx,
                                 struct flb_config *config)
{
    size_t len;
    ssize_t ret;
    char *buf;
    const char *tmp;
    const char *path;
    struct flb_uri *uri = ctx->ins->host.uri;
    struct flb_uri_field *f_index = NULL;
    struct flb_uri_field *f_type = NULL;

    if (uri) {
        if (uri->count >= 2) {
            f_index = flb_uri_get(uri, 0);
            f_type  = flb_uri_get(uri, 1);
        }
    }

    /* handle cloud_id */
    ret = flb_es_conf_set_cloud_auth(flb_output_get_property("cloud_id",
                                                             ctx->ins),
                                     ctx);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot configure cloud_id");
        return -1;
    }

    /* Populate context with config map defaults and incoming properties */
    ret = flb_output_config_map_set(ctx->ins, ec);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "configuration error");
        return -1;
    }

    /* handle cloud_auth */
    ret = flb_es_conf_set_cloud_credentials(
            flb_output_get_property("cloud_auth", ctx->ins), ec);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot configure cloud_auth");
        return -1;
    }

    /* Compress (gzip) */
    tmp = flb_output_get_property("compress", ctx->ins);
    ec->compress_gzip = FLB_FALSE;
    if (tmp) {
        if (strcasecmp(tmp, "gzip") == 0) {
            ec->compress_gzip = FLB_TRUE;
        }
    }

    /* Set manual Index and Type */
    if (f_index) {
        ec->index = flb_strdup(f_index->value);
        ec->own_index = FLB_TRUE;
    }

    if (f_type) {
        ec->type = flb_strdup(f_type->value);
        ec->own_type = FLB_TRUE;
    }

    /* HTTP Payload (response) maximum buffer size (0 == unlimited) */
    if (ec->buffer_size == -1) {
        ec->buffer_size = 0;
    }

    /* Elasticsearch: Path */
    path = flb_output_get_property("path", ctx->ins);
    if (!path) {
        path = "";
    }

    /* Elasticsearch: Pipeline */
    tmp = flb_output_get_property("pipeline", ctx->ins);
    if (tmp) {
        snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk/?pipeline=%s", path, tmp);
    }
    else {
        snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk", path);
    }

    if (ec->id_key) {
        ec->ra_id_key = flb_ra_create(ec->id_key, FLB_FALSE);
        if (ec->ra_id_key == NULL) {
            flb_plg_error(ctx->ins, "could not create record accessor for Id Key");
        }
        if (ec->generate_id == FLB_TRUE) {
            flb_plg_warn(ctx->ins, "Generate_ID is ignored when ID_key is set");
            ec->generate_id = FLB_FALSE;
        }
    }

    if (ec->write_operation) {
        if (strcasecmp(ec->write_operation, FLB_ES_WRITE_OP_INDEX) == 0) {
            ec->es_action = flb_strdup(FLB_ES_WRITE_OP_INDEX);
        }
        else if (strcasecmp(ec->write_operation, FLB_ES_WRITE_OP_CREATE) == 0) {
            ec->es_action = flb_strdup(FLB_ES_WRITE_OP_CREATE);
        }
        else if (strcasecmp(ec->write_operation, FLB_ES_WRITE_OP_UPDATE) == 0
            || strcasecmp(ec->write_operation, FLB_ES_WRITE_OP_UPSERT) == 0) {
            ec->es_action = flb_strdup(FLB_ES_WRITE_OP_UPDATE);
        }
        else {
            flb_plg_error(ctx->ins, "wrong Write_Operation (should be one of index, create, update, upsert)");
            return -1;
        }
        if (strcasecmp(ec->es_action, FLB_ES_WRITE_OP_UPDATE) == 0
            && !ec->ra_id_key && ec->generate_id == FLB_FALSE) {
            flb_plg_error(ctx->ins, "Id_Key or Generate_Id must be set when Write_Operation update or upsert");
            return -1;
        }
    }

    if (ec->logstash_prefix_key) {
        if (ec->logstash_prefix_key[0] != '$') {
            len = flb_sds_len(ec->logstash_prefix_key);
            buf = flb_malloc(len + 2);
            if (!buf) {
                flb_errno();
                return -1;
            }
            buf[0] = '$';
            memcpy(buf + 1, ec->logstash_prefix_key, len);
            buf[len + 1] = '\0';

            ec->ra_prefix_key = flb_ra_create(buf, FLB_TRUE);
            flb_free(buf);
        }
        else {
            ec->ra_prefix_key = flb_ra_create(ec->logstash_prefix_key, FLB_TRUE);
        }

        if (!ec->ra_prefix_key) {
            flb_plg_error(ctx->ins, "invalid logstash_prefix_key pattern '%s'", tmp);
            return -1;
        }
    }

#ifdef FLB_HAVE_AWS
    ret = flb_es_set_aws_unsigned_headers(ec);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot configure AWS unsigned headers");
        return -1;
    }

    ret = flb_es_conf_set_aws_provider(
            flb_output_get_property("aws_external_id", ctx->ins),
            flb_output_get_property("aws_role_arn", ctx->ins),
            ec, ctx, config);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot configure AWS authentication");
        return -1;
    }
#endif

    return 0;
}

static int config_validate(struct flb_elasticsearch_config* ec,
                           struct flb_elasticsearch* ctx)
{
    if (ec->index == NULL && ec->logstash_format == FLB_FALSE && ec->generate_id == FLB_FALSE) {
        flb_plg_error(ctx->ins, "index is not set and logstash_format and generate_id are both off");
        return -1;
    }

    return 0;
}

static void elasticsearch_config_destroy(struct flb_elasticsearch_config *ec)
{
    if (ec->ra_id_key) {
        flb_ra_destroy(ec->ra_id_key);
        ec->ra_id_key = NULL;
    }
    if (ec->es_action) {
        flb_free(ec->es_action);
    }

#ifdef FLB_HAVE_AWS
    if (ec->base_aws_provider) {
        flb_aws_provider_destroy(ec->base_aws_provider);
    }

    if (ec->aws_provider) {
        flb_aws_provider_destroy(ec->aws_provider);
    }

    if (ec->aws_tls) {
        flb_tls_destroy(ec->aws_tls);
    }

    if (ec->aws_sts_tls) {
        flb_tls_destroy(ec->aws_sts_tls);
    }

    if (ec->aws_unsigned_headers) {
        flb_slist_destroy(ec->aws_unsigned_headers);
        flb_free(ec->aws_unsigned_headers);
    }
#endif

    if (ec->ra_prefix_key) {
        flb_ra_destroy(ec->ra_prefix_key);
    }

    flb_free(ec->cloud_passwd);
    flb_free(ec->cloud_user);

    if (ec->own_type == FLB_TRUE) {
        flb_free(ec->type);
    }

    if (ec->own_index == FLB_TRUE) {
        flb_free(ec->index);
    }

    flb_free(ec);
}

int es_config_ha(const char *upstream_file, struct flb_elasticsearch *ctx,
                 struct flb_config *config)
{
    int ret;
    struct mk_list *head;
    struct flb_upstream_node *node;
    struct flb_elasticsearch_config *ec;

    /* Create elasticsearch_config context */
    ec = flb_calloc(1, sizeof(struct flb_elasticsearch_config));
    if (!ec) {
        flb_errno();
        flb_plg_error(ctx->ins, "failed config allocation");
        return -1;
    }

    /* Read properties into elasticsearch_config context */
    ret = config_set_properties(ec, ctx, config);
    if (ret != 0) {
        elasticsearch_config_destroy(ec);
        return -1;
    }

    /* Create upstream nodes */
    ctx->ha_mode = FLB_TRUE;
    ctx->ha = flb_upstream_ha_from_file(upstream_file, config);
    if (!ctx->ha) {
        flb_plg_error(ctx->ins, "cannot load Upstream file");
        elasticsearch_config_destroy(ec);
        return -1;
    }

    ret = flb_output_upstream_ha_set(ctx->ha, ctx->ins);
    if (ret != 0) {
        flb_upstream_ha_destroy(ctx->ha);
        elasticsearch_config_destroy(ec);
        return -1;
    }

    /*
     * Iterate over upstreams nodes and link shared elasticsearch_config context
     * with each node
     */
    mk_list_foreach(head, &ctx->ha->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);
        /* Set elasticsearch_config context into the node opaque data */
        flb_upstream_node_set_data(ec, node);
    }

    mk_list_add(&ec->_head, &ctx->configs);

    return 0;
}

int es_config_simple(struct flb_elasticsearch *ctx, struct flb_config *config)
{
    int ret;
    struct flb_elasticsearch_config *ec;
    int io_flags = 0;

    /* Set default network configuration */
    flb_output_net_default(FLB_ES_DEFAULT_HOST, FLB_ES_DEFAULT_PORT, ctx->ins);

    /* Create elasticsearch_config context */
    ec = flb_calloc(1, sizeof(struct flb_elasticsearch_config));
    if (!ec) {
        flb_errno();
        flb_plg_error(ctx->ins, "failed config allocation");
        return -1;
    }

    /* Read properties into elasticsearch_config context */
    ret = config_set_properties(ec, ctx, config);
    if (ret != 0) {
        elasticsearch_config_destroy(ec);
        return -1;
    }

    /* Validate configuration */
    ret = config_validate(ec, ctx);
    if (ret != 0) {
        elasticsearch_config_destroy(ec);
        return -1;
    }

#ifdef FLB_HAVE_TLS
    /* use TLS ? */
    if (ctx->ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }
#else
    io_flags = FLB_IO_TCP;
#endif

    if (ctx->ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Create upstream */
    ctx->ha_mode = FLB_FALSE;
    ctx->u = flb_upstream_create(config,
                                 ctx->ins->host.name,
                                 ctx->ins->host.port,
                                 io_flags,
                                 ctx->ins->tls);
    if (!ctx->u) {
        flb_plg_error(ctx->ins, "cannot create Upstream context");
        elasticsearch_config_destroy(ec);
        return -1;
    }

    ret = flb_output_upstream_set(ctx->u, ctx->ins);
    if (ret != 0) {
        flb_upstream_destroy(ctx->u);
        elasticsearch_config_destroy(ec);
        return -1;
    }

    mk_list_add(&ec->_head, &ctx->configs);

    return 0;
}

struct flb_elasticsearch *flb_es_conf_create(struct flb_output_instance *ins,
                                             struct flb_config *config)
{
    int ret;
    const char *upstream_file;
    struct flb_elasticsearch *ctx;

    /* Allocate context */
    ctx = flb_calloc(1, sizeof(struct flb_elasticsearch));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->ins = ins;
    mk_list_init(&ctx->configs);

    /* Configure HA or simple mode ? */
    upstream_file = flb_output_get_property("upstream", ins);
    if (upstream_file) {
        ret = es_config_ha(upstream_file, ctx, config);
    }
    else {
        ret = es_config_simple(ctx, config);
    }

    if (ret != 0) {
        flb_free(ctx);
        return NULL;
    }

    return ctx;
}

void flb_es_conf_destroy(struct flb_elasticsearch *ctx)
{
    struct flb_elasticsearch_config *ec;
    struct mk_list *head;
    struct mk_list *tmp;

    if (!ctx) {
        return;
    }

    /* Destroy upstreams */
    if (ctx->ha_mode == FLB_TRUE) {
        if (ctx->ha) {
            flb_upstream_ha_destroy(ctx->ha);
        }
    }
    else {
        if (ctx->u) {
            flb_upstream_destroy(ctx->u);
        }
    }

    /* Destroy elasticsearch_config contexts */
    mk_list_foreach_safe(head, tmp, &ctx->configs) {
        ec = mk_list_entry(head, struct flb_elasticsearch_config, _head);

        mk_list_del(&ec->_head);
        elasticsearch_config_destroy(ec);
    }

    flb_free(ctx);
}

struct flb_elasticsearch_config *flb_es_upstream_conf(struct flb_elasticsearch *ctx,
                                                      struct flb_upstream_node *node)
{
    if (!ctx) {
        return NULL;
    }
    if (node) {
        /* Get elasticsearch_config stored in node opaque data */
        return flb_upstream_node_get_data(node);
    }
    if (mk_list_is_empty(&ctx->configs) == 0) {
        return NULL;
    }
    return mk_list_entry_last(&ctx->configs, struct flb_elasticsearch_config, _head);
}
