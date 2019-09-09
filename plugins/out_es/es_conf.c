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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_ha.h>

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

    /* Allocate context */
    ec = flb_calloc(1, sizeof(struct flb_elasticsearch_config));
    if (!ec) {
        flb_errno();
        return -1;
    }

    ctx->ha_mode = FLB_TRUE;
    ctx->ha = flb_upstream_ha_from_file(upstream_file, config);
    if (!ctx->ha) {
        flb_error("[out_es] cannot load Upstream file");
        return -1;
    }

    /* Iterate nodes and create a forward_config context */
    mk_list_foreach(head, &ctx->ha->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);

        /* Is TLS enabled ? */
        if (node->tls_enabled == FLB_TRUE) {
            io_flags = FLB_IO_TLS;
        }
        else {
            io_flags = FLB_IO_TCP;
        }

        if (f_index) {
            ec->index = flb_strdup(f_index->value);
        }
        else {
            tmp = flb_upstream_node_get_property("index", node);
            if (!tmp) {
                ec->index = flb_strdup(FLB_ES_DEFAULT_INDEX);
            }
            else {
                ec->index = flb_strdup(tmp);
            }
        }

        if (f_type) {
            ec->type = flb_strdup(f_type->value);
        }
        else {
            tmp = flb_upstream_node_get_property("type", node);
            if (!tmp) {
                ec->type = flb_strdup(FLB_ES_DEFAULT_TYPE);
            }
            else {
                ec->type = flb_strdup(tmp);
            }
        }

        /* HTTP Auth */
        tmp = flb_upstream_node_get_property("http_user", node);
        if (tmp) {
            ec->http_user = flb_strdup(tmp);

            tmp = flb_upstream_node_get_property("http_passwd", node);
            if (tmp) {
                ec->http_passwd = flb_strdup(tmp);
            }
            else {
                ec->http_passwd = flb_strdup("");
            }
        }

        /*
         * Logstash compatibility options
         * ==============================
         */

        /* Logstash_Format */
        tmp = flb_upstream_node_get_property("logstash_format", node);
        if (tmp) {
            ec->logstash_format = flb_utils_bool(tmp);
        }
        else {
            ec->logstash_format = FLB_FALSE;
        }

        /* Logstash_Prefix */
        tmp = flb_upstream_node_get_property("logstash_prefix", node);
        if (tmp) {
            ec->logstash_prefix = flb_strdup(tmp);
            ec->logstash_prefix_len = strlen(tmp);
        }
        else if (ec->logstash_format == FLB_TRUE) {
            ec->logstash_prefix = flb_strdup(FLB_ES_DEFAULT_PREFIX);
            ec->logstash_prefix_len = sizeof(FLB_ES_DEFAULT_PREFIX) - 1;
        }

        /* Logstash_Prefix_Key */
        tmp = flb_upstream_node_get_property("logstash_prefix_key", node);
        if (tmp) {
            ec->logstash_prefix_key = flb_strdup(tmp);
            ec->logstash_prefix_key_len = strlen(tmp);
        }

        /* Logstash_DateFormat */
        tmp = flb_upstream_node_get_property("logstash_dateformat", node);
        if (tmp) {
            ec->logstash_dateformat = flb_strdup(tmp);
            ec->logstash_dateformat_len = strlen(tmp);
        }
        else if (ec->logstash_format == FLB_TRUE) {
            ec->logstash_dateformat = flb_strdup(FLB_ES_DEFAULT_TIME_FMT);
            ec->logstash_dateformat_len = sizeof(FLB_ES_DEFAULT_TIME_FMT) - 1;
        }

        /* Time Key */
        tmp = flb_upstream_node_get_property("time_key", node);
        if (tmp) {
            ec->time_key = flb_strdup(tmp);
            ec->time_key_len = strlen(tmp);
        }
        else {
            ec->time_key = flb_strdup(FLB_ES_DEFAULT_TIME_KEY);
            ec->time_key_len = sizeof(FLB_ES_DEFAULT_TIME_KEY) - 1;
        }

        /* Time Key Format */
        tmp = flb_upstream_node_get_property("time_key_format", node);
        if (tmp) {
            ec->time_key_format = flb_strdup(tmp);
            ec->time_key_format_len = strlen(tmp);
        }
        else {
            ec->time_key_format = flb_strdup(FLB_ES_DEFAULT_TIME_KEYF);
            ec->time_key_format_len = sizeof(FLB_ES_DEFAULT_TIME_KEYF) - 1;
        }

        /* Include Tag key */
        tmp = flb_upstream_node_get_property("include_tag_key", node);
        if (tmp) {
            ec->include_tag_key = flb_utils_bool(tmp);
        }
        else {
            ec->include_tag_key = FLB_FALSE;
        }

        /* Tag Key */
        if (ec->include_tag_key == FLB_TRUE) {
            tmp = flb_upstream_node_get_property("tag_key", node);
            if (tmp) {
                ec->tag_key = flb_strdup(tmp);
                ec->tag_key_len = strlen(tmp);
            }
            else {
                ec->tag_key = flb_strdup(FLB_ES_DEFAULT_TAG_KEY);
                ec->tag_key_len = sizeof(FLB_ES_DEFAULT_TAG_KEY) - 1;
            }
        }

        ec->buffer_size = FLB_HTTP_DATA_SIZE_MAX;
        tmp = flb_upstream_node_get_property("buffer_size", node);
        if (tmp) {
            if (*tmp == 'f' || *tmp == 'F' || *tmp == 'o' || *tmp == 'O') {
                /* unlimited size ? */
                if (flb_utils_bool(tmp) == FLB_FALSE) {
                    ec->buffer_size = 0;
                }
            }
            else {
                ret = flb_utils_size_to_bytes(tmp);
                if (ret == -1) {
                    flb_error("[out_es] invalid buffer_size=%s, using default", tmp);
                }
                else {
                    ec->buffer_size = (size_t) ret;
                }
            }
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

        /* Generate _id */
        tmp = flb_upstream_node_get_property("generate_id", node);
        if (tmp) {
            ec->generate_id = flb_utils_bool(tmp);
        } else {
            ec->generate_id = FLB_FALSE;
        }

        /* Replace dots */
        tmp = flb_upstream_node_get_property("replace_dots", node);
        if (tmp) {
            ec->replace_dots = flb_utils_bool(tmp);
        }
        else {
            ec->replace_dots = FLB_FALSE;
        }

        /* Use current time for index generation instead of message record */
        tmp = flb_upstream_node_get_property("current_time_index", node);
        if (tmp) {
            ec->current_time_index = flb_utils_bool(tmp);
        }
        else {
            ec->current_time_index = FLB_FALSE;
        }


        /* Trace output */
        tmp = flb_upstream_node_get_property("Trace_Output", node);
        if (tmp) {
            ec->trace_output = flb_utils_bool(tmp);
        }
        else {
            ec->trace_output = FLB_FALSE;
        }
        tmp = flb_upstream_node_get_property("Trace_Error", node);
        if (tmp) {
            ec->trace_error = flb_utils_bool(tmp);
        }
        else {
            ec->trace_error = FLB_FALSE;
        }

        /* Initialize and validate forward_config context */
        mk_list_add(&ec->_head, &ctx->configs);

        if (ret == -1) {
            if (ec) {
                flb_es_conf_destroy(ec);
            }
            return -1;
        }

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
        flb_error("[out_es] cannot create Upstream context");

        flb_es_conf_destroy(ec);
        flb_free(ctx);
        return -1;
    }

    /* Set manual Index and Type */
    ctx->u = upstream;
    if (f_index) {
        ec->index = flb_strdup(f_index->value);
    }
    else {
        tmp = flb_output_get_property("index", ins);
        if (!tmp) {
            ec->index = flb_strdup(FLB_ES_DEFAULT_INDEX);
        }
        else {
            ec->index = flb_strdup(tmp);
        }
    }

    if (f_type) {
        ec->type = flb_strdup(f_type->value);
    }
    else {
        tmp = flb_output_get_property("type", ins);
        if (!tmp) {
            ec->type = flb_strdup(FLB_ES_DEFAULT_TYPE);
        }
        else {
            ec->type = flb_strdup(tmp);
        }
    }

    /* HTTP Auth */
    tmp = flb_output_get_property("http_user", ins);
    if (tmp) {
        ec->http_user = flb_strdup(tmp);

        tmp = flb_output_get_property("http_passwd", ins);
        if (tmp) {
            ec->http_passwd = flb_strdup(tmp);
        }
        else {
            ec->http_passwd = flb_strdup("");
        }
    }

    /*
     * Logstash compatibility options
     * ==============================
     */

    /* Logstash_Format */
    tmp = flb_output_get_property("logstash_format", ins);
    if (tmp) {
        ec->logstash_format = flb_utils_bool(tmp);
    }
    else {
        ec->logstash_format = FLB_FALSE;
    }

    /* Logstash_Prefix */
    tmp = flb_output_get_property("logstash_prefix", ins);
    if (tmp) {
        ec->logstash_prefix = flb_strdup(tmp);
        ec->logstash_prefix_len = strlen(tmp);
    }
    else if (ec->logstash_format == FLB_TRUE) {
        ec->logstash_prefix = flb_strdup(FLB_ES_DEFAULT_PREFIX);
        ec->logstash_prefix_len = sizeof(FLB_ES_DEFAULT_PREFIX) - 1;
    }

    /* Logstash_Prefix_Key */
    tmp = flb_output_get_property("logstash_prefix_key", ins);
    if (tmp) {
        ec->logstash_prefix_key = flb_strdup(tmp);
        ec->logstash_prefix_key_len = strlen(tmp);
    }

    /* Logstash_DateFormat */
    tmp = flb_output_get_property("logstash_dateformat", ins);
    if (tmp) {
        ec->logstash_dateformat = flb_strdup(tmp);
        ec->logstash_dateformat_len = strlen(tmp);
    }
    else if (ec->logstash_format == FLB_TRUE) {
        ec->logstash_dateformat = flb_strdup(FLB_ES_DEFAULT_TIME_FMT);
        ec->logstash_dateformat_len = sizeof(FLB_ES_DEFAULT_TIME_FMT) - 1;
    }

    /* Time Key */
    tmp = flb_output_get_property("time_key", ins);
    if (tmp) {
        ec->time_key = flb_strdup(tmp);
        ec->time_key_len = strlen(tmp);
    }
    else {
        ec->time_key = flb_strdup(FLB_ES_DEFAULT_TIME_KEY);
        ec->time_key_len = sizeof(FLB_ES_DEFAULT_TIME_KEY) - 1;
    }

    /* Time Key Format */
    tmp = flb_output_get_property("time_key_format", ins);
    if (tmp) {
        ec->time_key_format = flb_strdup(tmp);
        ec->time_key_format_len = strlen(tmp);
    }
    else {
        ec->time_key_format = flb_strdup(FLB_ES_DEFAULT_TIME_KEYF);
        ec->time_key_format_len = sizeof(FLB_ES_DEFAULT_TIME_KEYF) - 1;
    }

    /* Include Tag key */
    tmp = flb_output_get_property("include_tag_key", ins);
    if (tmp) {
        ec->include_tag_key = flb_utils_bool(tmp);
    }
    else {
        ec->include_tag_key = FLB_FALSE;
    }

    /* Tag Key */
    if (ec->include_tag_key == FLB_TRUE) {
        tmp = flb_output_get_property("tag_key", ins);
        if (tmp) {
            ec->tag_key = flb_strdup(tmp);
            ec->tag_key_len = strlen(tmp);
        }
        else {
            ec->tag_key = flb_strdup(FLB_ES_DEFAULT_TAG_KEY);
            ec->tag_key_len = sizeof(FLB_ES_DEFAULT_TAG_KEY) - 1;
        }
    }

    ec->buffer_size = FLB_HTTP_DATA_SIZE_MAX;
    tmp = flb_output_get_property("buffer_size", ins);
    if (tmp) {
        if (*tmp == 'f' || *tmp == 'F' || *tmp == 'o' || *tmp == 'O') {
            /* unlimited size ? */
            if (flb_utils_bool(tmp) == FLB_FALSE) {
                ec->buffer_size = 0;
            }
        }
        else {
            ret = flb_utils_size_to_bytes(tmp);
            if (ret == -1) {
                flb_error("[out_es] invalid buffer_size=%s, using default", tmp);
            }
            else {
                ec->buffer_size = (size_t) ret;
            }
        }
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

    /* Generate _id */
    tmp = flb_output_get_property("generate_id", ins);
    if (tmp) {
        ec->generate_id = flb_utils_bool(tmp);
    } else {
        ec->generate_id = FLB_FALSE;
    }

    /* Replace dots */
    tmp = flb_output_get_property("replace_dots", ins);
    if (tmp) {
        ec->replace_dots = flb_utils_bool(tmp);
    }
    else {
        ec->replace_dots = FLB_FALSE;
    }

    /* Use current time for index generation instead of message record */
    tmp = flb_output_get_property("current_time_index", ins);
    if (tmp) {
        ec->current_time_index = flb_utils_bool(tmp);
    }
    else {
        ec->current_time_index = FLB_FALSE;
    }


    /* Trace output */
    tmp = flb_output_get_property("Trace_Output", ins);
    if (tmp) {
        ec->trace_output = flb_utils_bool(tmp);
    }
    else {
        ec->trace_output = FLB_FALSE;
    }
    tmp = flb_output_get_property("Trace_Error", ins);
    if (tmp) {
        ec->trace_error = flb_utils_bool(tmp);
    }
    else {
        ec->trace_error = FLB_FALSE;
    }

    mk_list_add(&ec->_head, &ctx->configs);

    flb_debug("[out_es] host=%s port=%i uri=%s index=%s type=%s",
              ins->host.name, ins->host.port, ec->uri,
              ec->index, ec->type);

    return 0;
}

int flb_es_conf_destroy(struct flb_elasticsearch_config *ec)
{
    flb_free(ec->index);
    flb_free(ec->type);

    flb_free(ec->http_user);
    flb_free(ec->http_passwd);

    flb_free(ec->logstash_prefix);
    flb_free(ec->logstash_dateformat);
    flb_free(ec->time_key);
    flb_free(ec->time_key_format);

    if (ec->include_tag_key) {
        flb_free(ec->tag_key);
    }

    if (ec->logstash_prefix_key) {
        flb_free(ec->logstash_prefix_key);
    }

    //flb_upstream_destroy(ec->u);
    flb_free(ec);

    return 0;
}
