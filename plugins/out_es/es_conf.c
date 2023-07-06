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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_upstream_node.h>

#include "es.h"
#include "es_conf_parse.h"
#include "es_conf_prop.h"
#include "es_conf.h"

static const char * const es_default_path    = "";
static const char * const es_write_op_index  = FLB_ES_WRITE_OP_INDEX;
static const char * const es_write_op_create = FLB_ES_WRITE_OP_CREATE;
static const char * const es_write_op_update = FLB_ES_WRITE_OP_UPDATE;
static const char * const es_write_op_upsert = FLB_ES_WRITE_OP_UPSERT;

static int config_set_ra_id_key(flb_sds_t id_key, struct flb_elasticsearch_config *ec,
                                struct flb_elasticsearch *ctx)
{
    if (!id_key) {
        return 0;
    }

    ec->ra_id_key = flb_ra_create(id_key, FLB_FALSE);
    if (ec->ra_id_key == NULL) {
        flb_plg_error(ctx->ins, "could not create record accessor for Id Key");
        return -1;
    }
    ec->own_ra_id_key = FLB_TRUE;

    if (ec->generate_id == FLB_TRUE) {
        flb_plg_warn(ctx->ins, "Generate_ID is ignored when ID_key is set");
        ec->generate_id = FLB_FALSE;
    }

    return 0;
}

static int config_set_es_action(const char *write_operation,
                                const struct flb_record_accessor *ra_id_key,
                                int generate_id,
                                struct flb_elasticsearch_config *ec,
                                struct flb_elasticsearch *ctx)
{
    if (!write_operation) {
        return 0;
    }

    if (strcasecmp(write_operation, es_write_op_index) == 0) {
        ec->es_action = es_write_op_index;
    }
    else if (strcasecmp(write_operation, es_write_op_create) == 0) {
        ec->es_action = es_write_op_create;
    }
    else if (strcasecmp(write_operation, es_write_op_update) == 0
             || strcasecmp(write_operation, es_write_op_upsert) == 0) {
        ec->es_action = es_write_op_update;
    }
    else {
        flb_plg_error(ctx->ins,
                      "wrong Write_Operation (should be one of index, create, update, upsert)");
        return -1;
    }

    if (strcasecmp(ec->es_action, es_write_op_update) == 0
        && !ra_id_key
        && generate_id == FLB_FALSE) {
        flb_plg_error(ctx->ins,
                      "Id_Key or Generate_Id must be set when Write_Operation update or upsert");
        return -1;
    }

    return 0;
}

static size_t config_adjust_buffer_size(size_t buffer_size)
{
    /* HTTP Payload (response) maximum buffer size (0 == unlimited) */
    if (buffer_size == -1) {
        return 0;
    }
    return buffer_size;
}

static int config_is_compressed_gzip(const char *compress)
{
    if (strcasecmp(compress, "gzip") == 0) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

static int config_set_pipeline(const char *path, const char *pipeline,
                               struct flb_elasticsearch_config *ec)
{
    int ret;

    if (!path) {
        path = es_default_path;
    }

    if (pipeline && flb_str_emptyval(pipeline) != FLB_TRUE) {
        ret = snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk/?pipeline=%s", path,
                       pipeline);
    }
    else {
        ret = snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk", path);
    }

    if (ret < 0 || ret >= sizeof(ec->uri)) {
        return -1;
    }
    return 0;
}

static int config_set_ra_prefix_key(flb_sds_t logstash_prefix_key,
                                    struct flb_elasticsearch_config *ec,
                                    struct flb_elasticsearch *ctx)
{
    size_t len;
    char *buf;

    if (!logstash_prefix_key) {
        return 0;
    }

    if (logstash_prefix_key[0] != '$') {
        len = flb_sds_len(logstash_prefix_key);
        buf = flb_malloc(len + 2);
        if (!buf) {
            flb_errno();
            return -1;
        }
        buf[0] = '$';
        memcpy(buf + 1, logstash_prefix_key, len);
        buf[len + 1] = '\0';

        ec->ra_prefix_key = flb_ra_create(buf, FLB_TRUE);
        ec->own_ra_prefix_key = FLB_TRUE;
        flb_free(buf);
    }
    else {
        ec->ra_prefix_key = flb_ra_create(logstash_prefix_key, FLB_TRUE);
        ec->own_ra_prefix_key = FLB_TRUE;
    }

    if (!ec->ra_prefix_key) {
        flb_plg_error(ctx->ins, "invalid logstash_prefix_key pattern '%s'",
                      logstash_prefix_key);
        return -1;
    }

    return 0;
}

static int config_set_properties(struct flb_elasticsearch_config *ec,
                                 struct flb_elasticsearch *ctx,
                                 struct flb_config *config)
{
    int ret;
    const char *tmp;
    struct flb_uri *uri = ctx->ins->host.uri;
    struct flb_uri_field *f_index = NULL;
    struct flb_uri_field *f_type = NULL;

    if (uri) {
        if (uri->count >= 2) {
            f_index = flb_uri_get(uri, 0);
            f_type = flb_uri_get(uri, 1);
        }
    }

    /* handle cloud_id */
    ret = flb_es_conf_set_cloud_auth(
            flb_output_get_property(FLB_ES_CONFIG_PROPERTY_CLOUD_ID, ctx->ins), ctx);
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

    ec->buffer_size = config_adjust_buffer_size(ec->buffer_size);

    /* handle cloud_auth */
    ret = flb_es_conf_set_cloud_credentials(
            flb_output_get_property(FLB_ES_CONFIG_PROPERTY_CLOUD_AUTH, ctx->ins), ec);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot configure cloud_auth");
        return -1;
    }

    /* Compress (gzip) */
    tmp = flb_output_get_property(FLB_ES_CONFIG_PROPERTY_COMPRESS, ctx->ins);
    ec->compress_gzip = FLB_FALSE;
    if (tmp) {
        ec->compress_gzip = config_is_compressed_gzip(tmp);
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

    /* Elasticsearch: path and pipeline */
    ret = config_set_pipeline(
            flb_output_get_property(FLB_ES_CONFIG_PROPERTY_PATH, ctx->ins),
            flb_output_get_property(FLB_ES_CONFIG_PROPERTY_PIPELINE, ctx->ins),
            ec);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot configure path and/or pipeline");
        return -1;
    }

    ret = config_set_ra_id_key(ec->id_key, ec, ctx);
    if (ret != 0) {
        return -1;
    }

    ret = config_set_es_action(ec->write_operation, ec->ra_id_key, ec->generate_id, ec,
                               ctx);
    if (ret != 0) {
        return -1;
    }

    ret = config_set_ra_prefix_key(ec->logstash_prefix_key, ec, ctx);
    if (ret != 0) {
        return -1;
    }

#ifdef FLB_HAVE_AWS
    ret = flb_es_set_aws_unsigned_headers(ec);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot configure AWS unsigned headers");
        return -1;
    }

    ret = flb_es_conf_set_aws_provider(
            flb_output_get_property(FLB_ES_CONFIG_PROPERTY_AWS_EXTERNAL_ID, ctx->ins),
            flb_output_get_property(FLB_ES_CONFIG_PROPERTY_AWS_ROLE_ARN, ctx->ins),
            ec, ctx, config);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "cannot configure AWS authentication");
        return -1;
    }
#endif

    return 0;
}

static int parse_bool_property(struct flb_elasticsearch *ctx,
                               const char *property, const char *value,
                               int *out)
{
    int ret;
    ret = flb_utils_bool(value);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "invalid value for boolean property '%s=%s'",
                      property, value);
        return -1;
    }
    *out = ret;
    return 0;
}

static int config_set_node_properties(struct flb_upstream_node *node,
                                      struct flb_elasticsearch_config *ec,
                                      struct flb_elasticsearch_config *base,
                                      struct flb_elasticsearch *ctx,
                                      struct flb_config *config)
{
    const char *tmp;
    int ret;
    const char *path;

#ifdef FLB_HAVE_AWS
    const char *aws_external_id = NULL;
    const char *aws_role_arn = NULL;
    int aws_provider_node = FLB_FALSE;
#endif

    /* Copy base configuration */
    *ec = *base;
    ec->own_index = FLB_FALSE;
    ec->own_type = FLB_FALSE;
    ec->own_cloud_user = FLB_FALSE;
    ec->own_cloud_passwd = FLB_FALSE;

#ifdef FLB_HAVE_AWS
    ec->own_base_aws_provider = FLB_FALSE;
    ec->own_aws_provider = FLB_FALSE;
    ec->own_aws_tls = FLB_FALSE;
    ec->own_aws_sts_tls = FLB_FALSE;
    ec->own_aws_unsigned_headers = FLB_FALSE;
#endif

    ec->own_logstash_prefix = FLB_FALSE;
    ec->own_logstash_prefix_separator = FLB_FALSE;
    ec->own_logstash_prefix_key = FLB_FALSE;
    ec->own_logstash_dateformat = FLB_FALSE;
    ec->own_time_key = FLB_FALSE;
    ec->own_time_key_format = FLB_FALSE;
    ec->own_write_operation = FLB_FALSE;
    ec->own_id_key = FLB_FALSE;
    ec->own_ra_id_key = FLB_FALSE;
    ec->own_ra_prefix_key = FLB_FALSE;
    ec->own_tag_key = FLB_FALSE;
    mk_list_entry_init(&ec->_head);

    /* Overwrite configuration from upstream node properties */

    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_INDEX, node);
    if (tmp) {
        ec->index = (char *)tmp;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_TYPE, node);
    if (tmp) {
        ec->type = (char *)tmp;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_SUPPRESS_TYPE_NAME, node);
    if (tmp && parse_bool_property(ctx, FLB_ES_CONFIG_PROPERTY_SUPPRESS_TYPE_NAME,
                                   tmp, &ec->suppress_type_name)) {
        return -1;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_HTTP_USER, node);
    if (tmp) {
        ec->http_user = (char *)tmp;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_HTTP_PASSWD, node);
    if (tmp) {
        ec->http_passwd = (char *)tmp;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_HTTP_API_KEY, node);
    if (tmp) {
        ec->http_api_key = (char *)tmp;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_GENERATE_ID, node);
    if (tmp && parse_bool_property(ctx, FLB_ES_CONFIG_PROPERTY_GENERATE_ID,
                                   tmp, &ec->generate_id)) {
        return -1;
    }

#ifdef FLB_HAVE_AWS
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_AWS_AUTH, node);
    if (tmp && parse_bool_property(ctx, FLB_ES_CONFIG_PROPERTY_AWS_AUTH,
                                   tmp, &ec->has_aws_auth)) {
        return -1;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_AWS_REGION, node);
    if (tmp) {
        ec->aws_region = (char *)tmp;
        aws_provider_node = FLB_TRUE;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_AWS_STS_ENDPOINT, node);
    if (tmp) {
        ec->aws_sts_endpoint = (char *)tmp;
        aws_provider_node = FLB_TRUE;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_AWS_SERVICE_NAME, node);
    if (tmp) {
        ec->aws_service_name = (char *)tmp;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_AWS_PROFILE, node);
    if (tmp) {
        ec->aws_profile = (char *)tmp;
        aws_provider_node = FLB_TRUE;
    }
    if (ec->has_aws_auth) {
        tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_AWS_EXTERNAL_ID,
                                             node);
        if (tmp) {
            aws_external_id = tmp;
            aws_provider_node = FLB_TRUE;
        }
        else {
            aws_external_id = flb_output_get_property(
                    FLB_ES_CONFIG_PROPERTY_AWS_EXTERNAL_ID, ctx->ins);
        }
        tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_AWS_ROLE_ARN, node);
        if (tmp) {
            aws_role_arn = tmp;
            aws_provider_node = FLB_TRUE;
        }
        else {
            aws_role_arn = flb_output_get_property(FLB_ES_CONFIG_PROPERTY_AWS_ROLE_ARN,
                                                   ctx->ins);
        }
    }
#endif

    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_LOGSTASH_FORMAT, node);
    if (tmp && parse_bool_property(ctx, FLB_ES_CONFIG_PROPERTY_LOGSTASH_FORMAT,
                                   tmp, &ec->logstash_format)) {
        return -1;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_LOGSTASH_PREFIX, node);
    if (tmp) {
        ec->logstash_prefix = flb_sds_create(tmp);
        if (ec->logstash_prefix == NULL) {
            return -1;
        }
        ec->own_logstash_prefix = FLB_TRUE;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_LOGSTASH_PREFIX_SEPARATOR,
                                         node);
    if (tmp) {
        ec->logstash_prefix_separator = flb_sds_create(tmp);
        if (ec->logstash_prefix_separator == NULL) {
            return -1;
        }
        ec->own_logstash_prefix_separator = FLB_TRUE;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_LOGSTASH_DATEFORMAT,
                                         node);
    if (tmp) {
        ec->logstash_dateformat = flb_sds_create(tmp);
        if (ec->logstash_dateformat == NULL) {
            return -1;
        }
        ec->own_logstash_dateformat = FLB_TRUE;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_TIME_KEY, node);
    if (tmp) {
        ec->time_key = flb_sds_create(tmp);
        if (ec->time_key == NULL) {
            return -1;
        }
        ec->own_time_key = FLB_TRUE;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_TIME_KEY_FORMAT, node);
    if (tmp) {
        ec->time_key_format = flb_sds_create(tmp);
        if (ec->time_key_format == NULL) {
            return -1;
        }
        ec->own_time_key_format = FLB_TRUE;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_TIME_KEY_NANOS, node);
    if (tmp && parse_bool_property(ctx, FLB_ES_CONFIG_PROPERTY_TIME_KEY_NANOS,
                                   tmp, &ec->time_key_nanos)) {
        return -1;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_INCLUDE_TAG_KEY, node);
    if (tmp && parse_bool_property(ctx, FLB_ES_CONFIG_PROPERTY_INCLUDE_TAG_KEY,
                                   tmp, &ec->include_tag_key)) {
        return -1;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_TAG_KEY, node);
    if (tmp) {
        ec->tag_key = flb_sds_create(tmp);
        if (ec->tag_key == NULL) {
            return -1;
        }
        ec->own_tag_key = FLB_TRUE;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_BUFFER_SIZE, node);
    if (tmp) {
        ec->buffer_size = config_adjust_buffer_size(flb_utils_size_to_bytes(tmp));
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_REPLACE_DOTS, node);
    if (tmp && parse_bool_property(ctx, FLB_ES_CONFIG_PROPERTY_REPLACE_DOTS,
                                   tmp, &ec->replace_dots)) {
        return -1;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_CURRENT_TIME_INDEX, node);
    if (tmp && parse_bool_property(ctx, FLB_ES_CONFIG_PROPERTY_CURRENT_TIME_INDEX,
                                   tmp, &ec->current_time_index)) {
        return -1;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_TRACE_OUTPUT, node);
    if (tmp && parse_bool_property(ctx, FLB_ES_CONFIG_PROPERTY_TRACE_OUTPUT,
                                   tmp, &ec->trace_output)) {
        return -1;
    }
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_TRACE_ERROR, node);
    if (tmp && parse_bool_property(ctx, FLB_ES_CONFIG_PROPERTY_TRACE_ERROR,
                                   tmp, &ec->trace_error)) {
        return -1;
    }

    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_LOGSTASH_PREFIX_KEY,
                                         node);
    if (tmp) {
        ec->logstash_prefix_key = flb_sds_create(tmp);
        if (ec->logstash_prefix_key == NULL) {
            return -1;
        }
        ec->own_logstash_prefix_key = FLB_TRUE;
        ret = config_set_ra_prefix_key(ec->logstash_prefix_key, ec, ctx);
        if (ret != 0) {
            return -1;
        }
    }

    /* handle cloud_auth */
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_CLOUD_AUTH, node);
    if (tmp) {
        ret = flb_es_conf_set_cloud_credentials(tmp, ec);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot configure cloud_auth");
            return -1;
        }
    }

    /* Compress (gzip) */
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_COMPRESS, node);
    if (tmp) {
        ec->compress_gzip = config_is_compressed_gzip(tmp);
    }

    /* Elasticsearch: path and pipeline */
    path = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_PATH, node);
    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_PIPELINE, node);
    if (path || tmp) {
        if (!path) {
            path = flb_output_get_property(FLB_ES_CONFIG_PROPERTY_PATH, ctx->ins);
        }
        if (!tmp) {
            tmp = flb_output_get_property(FLB_ES_CONFIG_PROPERTY_PIPELINE, ctx->ins);
        }
        ret = config_set_pipeline(path, tmp, ec);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot configure path and/or pipeline");
            return -1;
        }
    }

    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_ID_KEY, node);
    if (tmp) {
        ec->id_key = flb_sds_create(tmp);
        if (ec->id_key == NULL) {
            return -1;
        }
        ec->own_id_key = FLB_TRUE;
        ret = config_set_ra_id_key(ec->id_key, ec, ctx);
        if (ret != 0) {
            return -1;
        }
    }

    tmp = flb_upstream_node_get_property(FLB_ES_CONFIG_PROPERTY_WRITE_OPERATION, node);
    if (tmp) {
        ec->write_operation = flb_sds_create(tmp);
        if (ec->write_operation == NULL) {
            return -1;
        }
        ec->own_write_operation = FLB_TRUE;
    }

    ret = config_set_es_action(ec->write_operation, ec->ra_id_key,
                               ec->generate_id, ec, ctx);
    if (ret != 0) {
        return -1;
    }

#ifdef FLB_HAVE_AWS
    if ((base->has_aws_auth != ec->has_aws_auth)
        || (base->has_aws_auth == FLB_TRUE
            && ec->has_aws_auth == FLB_TRUE
            && aws_provider_node == FLB_TRUE)) {
        ret = flb_es_conf_set_aws_provider(aws_external_id, aws_role_arn, ec, ctx,
                                           config);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot configure AWS authentication");
            return -1;
        }
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
    if (ec->own_tag_key == FLB_TRUE) {
        flb_sds_destroy(ec->tag_key);
    }

    if (ec->ra_id_key && ec->own_ra_id_key == FLB_TRUE) {
        flb_ra_destroy(ec->ra_id_key);
        ec->ra_id_key = NULL;
    }

    if (ec->own_write_operation == FLB_TRUE) {
        flb_sds_destroy(ec->write_operation);
    }

    if (ec->own_id_key == FLB_TRUE) {
        flb_sds_destroy(ec->id_key);
    }

    if (ec->own_time_key_format == FLB_TRUE) {
        flb_sds_destroy(ec->time_key_format);
    }

    if (ec->own_time_key == FLB_TRUE) {
        flb_sds_destroy(ec->time_key);
    }

    if (ec->own_logstash_dateformat == FLB_TRUE) {
        flb_sds_destroy(ec->logstash_dateformat);
    }

    if (ec->own_logstash_prefix_key == FLB_TRUE) {
        flb_sds_destroy(ec->logstash_prefix_key);
    }

    if (ec->own_logstash_prefix_separator == FLB_TRUE) {
        flb_sds_destroy(ec->logstash_prefix_separator);
    }

    if (ec->own_logstash_prefix == FLB_TRUE) {
        flb_sds_destroy(ec->logstash_prefix);
    }

#ifdef FLB_HAVE_AWS
    if (ec->base_aws_provider && ec->own_base_aws_provider == FLB_TRUE) {
        flb_aws_provider_destroy(ec->base_aws_provider);
    }

    if (ec->aws_provider && ec->own_aws_provider == FLB_TRUE) {
        flb_aws_provider_destroy(ec->aws_provider);
    }

    if (ec->aws_tls && ec->own_aws_tls == FLB_TRUE) {
        flb_tls_destroy(ec->aws_tls);
    }

    if (ec->aws_sts_tls && ec->own_aws_sts_tls == FLB_TRUE) {
        flb_tls_destroy(ec->aws_sts_tls);
    }

    if (ec->aws_unsigned_headers && ec->own_aws_unsigned_headers == FLB_TRUE) {
        flb_slist_destroy(ec->aws_unsigned_headers);
        flb_free(ec->aws_unsigned_headers);
    }
#endif

    if (ec->ra_prefix_key && ec->own_ra_prefix_key == FLB_TRUE) {
        flb_ra_destroy(ec->ra_prefix_key);
    }

    if (ec->own_cloud_passwd == FLB_TRUE) {
        flb_free(ec->cloud_passwd);
    }
    if (ec->own_cloud_user == FLB_TRUE) {
        flb_free(ec->cloud_user);
    }

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
    struct mk_list *tmp;
    struct flb_upstream_node *node;
    struct flb_elasticsearch_config *ec;
    struct flb_elasticsearch_config *node_ec;

    /* Create main elasticsearch_config context */
    ec = flb_calloc(1, sizeof(struct flb_elasticsearch_config));
    if (!ec) {
        flb_errno();
        flb_plg_error(ctx->ins, "failed config allocation");
        return -1;
    }

    /* Read properties into main elasticsearch_config context */
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
     * Iterate over upstreams nodes and create elasticsearch_config context
     * for each node
     */
    mk_list_foreach(head, &ctx->ha->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);
        /* Create elasticsearch_config context for the upstream node */
        node_ec = flb_calloc(1, sizeof(struct flb_elasticsearch_config));
        if (!node_ec) {
            flb_errno();
            flb_plg_error(ctx->ins, "failed upstream node config allocation for %s node",
                          node->name);
            ret = -1;
            break;
        }

        /*
         * Fill elasticsearch_config context of the upstream node from:
         * 1. main elasticsearch_config context
         * 2. upstream node configuration section
         */
        ret = config_set_node_properties(node, node_ec, ec, ctx, config);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed upstream node configuration for %s node",
                          node->name);
            elasticsearch_config_destroy(node_ec);
            break;
        }

        /* Validate configuration of the upstream node */
        ret = config_validate(node_ec, ctx);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed upstream node configuration validation for %s node",
                          node->name);
            elasticsearch_config_destroy(node_ec);
            break;
        }

        /* Register allocated elasticsearch_config context for later cleanup */
        mk_list_add(&node_ec->_head, &ctx->configs);

        /* Set elasticsearch_config context into the node opaque data */
        flb_upstream_node_set_data(node_ec, node);
    }

    if (ret != 0) {
        /* Nullify each upstream node elasticsearch_config context */
        mk_list_foreach(head, &ctx->ha->nodes) {
            node = mk_list_entry(head, struct flb_upstream_node, _head);
            flb_upstream_node_set_data(NULL, node);
        }

        /* Cleanup elasticsearch_config contexts which were created */
        mk_list_foreach_safe(head, tmp, &ctx->configs) {
            node_ec = mk_list_entry(head, struct flb_elasticsearch_config, _head);
            mk_list_del(&node_ec->_head);
            elasticsearch_config_destroy(node_ec);
        }

        flb_upstream_ha_destroy(ctx->ha);
        elasticsearch_config_destroy(ec);
        return -1;
    }

    /* Register allocated elasticsearch_config context for later cleanup */
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
    upstream_file = flb_output_get_property(FLB_ES_CONFIG_PROPERTY_UPSTREAM, ins);
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
