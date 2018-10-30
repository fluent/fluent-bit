/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#include "es.h"
#include "es_conf.h"

struct flb_elasticsearch *flb_es_conf_create(struct flb_output_instance *ins,
                                             struct flb_config *config)
{

    int io_flags = 0;
    ssize_t ret;
    char *tmp;
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

    if (uri) {
        if (uri->count >= 2) {
            f_index = flb_uri_get(uri, 0);
            f_type  = flb_uri_get(uri, 1);
        }
    }

    /* Get network configuration */
    if (!ins->host.name) {
        ins->host.name = flb_strdup("127.0.0.1");
    }

    if (ins->host.port == 0) {
        ins->host.port = 9200;
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
        flb_error("[out_es] cannot create Upstream context");
        flb_es_conf_destroy(ctx);
        return NULL;
    }

    /* Set manual Index and Type */
    ctx->u = upstream;
    if (f_index) {
        ctx->index = flb_strdup(f_index->value);
    }
    else {
        tmp = flb_output_get_property("index", ins);
        if (!tmp) {
            ctx->index = flb_strdup(FLB_ES_DEFAULT_INDEX);
        }
        else {
            ctx->index = flb_strdup(tmp);
        }
    }

    if (f_type) {
        ctx->type = flb_strdup(f_type->value);
    }
    else {
        tmp = flb_output_get_property("type", ins);
        if (!tmp) {
            ctx->type = flb_strdup(FLB_ES_DEFAULT_TYPE);
        }
        else {
            ctx->type = flb_strdup(tmp);
        }
    }

    /* HTTP Auth */
    tmp = flb_output_get_property("http_user", ins);
    if (tmp) {
        ctx->http_user = flb_strdup(tmp);

        tmp = flb_output_get_property("http_passwd", ins);
        if (tmp) {
            ctx->http_passwd = flb_strdup(tmp);
        }
        else {
            ctx->http_passwd = flb_strdup("");
        }
    }

    /*
     * Logstash compatibility options
     * ==============================
     */

    /* Logstash_Format */
    tmp = flb_output_get_property("logstash_format", ins);
    if (tmp) {
        ctx->logstash_format = flb_utils_bool(tmp);
    }
    else {
        ctx->logstash_format = FLB_FALSE;
    }

    /* Logstash_Prefix */
    tmp = flb_output_get_property("logstash_prefix", ins);
    if (tmp) {
        ctx->logstash_prefix = flb_strdup(tmp);
        ctx->logstash_prefix_len = strlen(tmp);
    }
    else if (ctx->logstash_format == FLB_TRUE) {
        ctx->logstash_prefix = flb_strdup(FLB_ES_DEFAULT_PREFIX);
        ctx->logstash_prefix_len = sizeof(FLB_ES_DEFAULT_PREFIX) - 1;
    }

    /* Logstash_DateFormat */
    tmp = flb_output_get_property("logstash_dateformat", ins);
    if (tmp) {
        ctx->logstash_dateformat = flb_strdup(tmp);
        ctx->logstash_dateformat_len = strlen(tmp);
    }
    else if (ctx->logstash_format == FLB_TRUE) {
        ctx->logstash_dateformat = flb_strdup(FLB_ES_DEFAULT_TIME_FMT);
        ctx->logstash_dateformat_len = sizeof(FLB_ES_DEFAULT_TIME_FMT) - 1;
    }

    /* Time Key */
    tmp = flb_output_get_property("time_key", ins);
    if (tmp) {
        ctx->time_key = flb_strdup(tmp);
        ctx->time_key_len = strlen(tmp);
    }
    else {
        ctx->time_key = flb_strdup(FLB_ES_DEFAULT_TIME_KEY);
        ctx->time_key_len = sizeof(FLB_ES_DEFAULT_TIME_KEY) - 1;
    }

    /* Time Key Format */
    tmp = flb_output_get_property("time_key_format", ins);
    if (tmp) {
        ctx->time_key_format = flb_strdup(tmp);
        ctx->time_key_format_len = strlen(tmp);
    }
    else {
        ctx->time_key_format = flb_strdup(FLB_ES_DEFAULT_TIME_KEYF);
        ctx->time_key_format_len = sizeof(FLB_ES_DEFAULT_TIME_KEYF) - 1;
    }

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
        tmp = flb_output_get_property("tag_key", ins);
        if (tmp) {
            ctx->tag_key = flb_strdup(tmp);
            ctx->tag_key_len = strlen(tmp);
            if (tmp[0] != '_') {
                flb_warn("[out_es] consider use a tag_key that starts with '_'");
            }
        }
        else {
            ctx->tag_key = flb_strdup(FLB_ES_DEFAULT_TAG_KEY);
            ctx->tag_key_len = sizeof(FLB_ES_DEFAULT_TAG_KEY) - 1;
        }
    }

    ctx->buffer_size = FLB_HTTP_DATA_SIZE_MAX;
    tmp = flb_output_get_property("buffer_size", ins);
    if (tmp) {
        if (*tmp == 'f' || *tmp == 'F' || *tmp == 'o' || *tmp == 'O') {
            /* unlimited size ? */
            if (flb_utils_bool(tmp) == FLB_FALSE) {
                ctx->buffer_size = 0;
            }
        }
        else {
            ret = flb_utils_size_to_bytes(tmp);
            if (ret == -1) {
                flb_error("[out_es] invalid buffer_size=%s, using default", tmp);
            }
            else {
                ctx->buffer_size = (size_t) ret;
            }
        }
    }

    /* Elasticsearch: Pipeline */
    tmp = flb_output_get_property("pipeline", ins);
    if (tmp) {
        snprintf(ctx->uri, sizeof(ctx->uri) - 1, "/_bulk/?pipeline=%s", tmp);
    }
    else {
        snprintf(ctx->uri, sizeof(ctx->uri) - 1, "/_bulk");
    }

    /* Generate _id */
    tmp = flb_output_get_property("generate_id", ins);
    if (tmp) {
        ctx->generate_id = flb_utils_bool(tmp);
    } else {
        ctx->generate_id = FLB_FALSE;
    }

    /* Replace dots */
    tmp = flb_output_get_property("replace_dots", ins);
    if (tmp) {
        ctx->replace_dots = flb_utils_bool(tmp);
    }
    else {
        ctx->replace_dots = FLB_FALSE;
    }

    /* Trace output */
    tmp = flb_output_get_property("Trace_Output", ins);
    if (tmp) {
        ctx->trace_output = flb_utils_bool(tmp);
    }
    else {
        ctx->trace_output = FLB_FALSE;
    }

    return ctx;
}

int flb_es_conf_destroy(struct flb_elasticsearch *ctx)
{
    flb_free(ctx->index);
    flb_free(ctx->type);

    flb_free(ctx->http_user);
    flb_free(ctx->http_passwd);

    flb_free(ctx->logstash_prefix);
    flb_free(ctx->logstash_dateformat);
    flb_free(ctx->time_key);
    flb_free(ctx->time_key_format);

    if (ctx->include_tag_key) {
        flb_free(ctx->tag_key);
    }

    flb_upstream_destroy(ctx->u);
    flb_free(ctx);

    return 0;
}
