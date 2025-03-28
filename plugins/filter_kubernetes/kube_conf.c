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
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_hash_table.h>

#ifndef FLB_HAVE_TLS
#error "Fluent Bit was built without TLS support"
#endif

#include "kube_meta.h"
#include "kube_conf.h"

struct flb_kube *flb_kube_conf_create(struct flb_filter_instance *ins,
                                      struct flb_config *config)
{
    int off;
    int ret;
    const char *url;
    const char *tmp;
    const char *p;
    const char *cmd;
    struct flb_kube *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_kube));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->config = config;
    ctx->ins = ins;

    /* Set config_map properties in our local context */
    ret = flb_filter_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* K8s Token Command */
    cmd = flb_filter_get_property("kube_token_command", ins);
    if (cmd) {
        ctx->kube_token_command = cmd;
    }
    else {
        ctx->kube_token_command = NULL;
    }
    ctx->kube_token_create = 0;  

    /* Merge Parser */
    tmp = flb_filter_get_property("merge_parser", ins);
    if (tmp) {
        ctx->merge_parser = flb_parser_get(tmp, config);
        if (!ctx->merge_parser) {
            flb_plg_error(ctx->ins, "parser '%s' is not registered", tmp);
        }
    }
    else {
        ctx->merge_parser = NULL;
    }

    /* Get Kubernetes API server */
    url = flb_filter_get_property("kube_url", ins);

    if (ctx->use_tag_for_meta) {
        ctx->api_https = FLB_FALSE;
    }
    else if (!url) {
        ctx->api_host = flb_strdup(FLB_API_HOST);
        ctx->api_port = FLB_API_PORT;
        ctx->api_https = FLB_API_TLS;
    }
    else {
        tmp = url;

        /* Check the protocol */
        if (strncmp(tmp, "http://", 7) == 0) {
            off = 7;
            ctx->api_https = FLB_FALSE;
        }
        else if (strncmp(tmp, "https://", 8) == 0) {
            off = 8;
            ctx->api_https = FLB_TRUE;
        }
        else {
            flb_kube_conf_destroy(ctx);
            return NULL;
        }

        /* Get hostname and TCP port */
        p = url + off;
        tmp = strchr(p, ':');
        if (tmp) {
            ctx->api_host = flb_strndup(p, tmp - p);
            tmp++;
            ctx->api_port = atoi(tmp);
        }
        else {
            ctx->api_host = flb_strdup(p);
            ctx->api_port = FLB_API_PORT;
        }
    }

    if (ctx->kube_meta_cache_ttl > 0) {
        ctx->hash_table = flb_hash_table_create_with_ttl(ctx->kube_meta_cache_ttl,
                                                         FLB_HASH_TABLE_EVICT_OLDER,
                                                         FLB_HASH_TABLE_SIZE,
                                                         FLB_HASH_TABLE_SIZE);
    }
    else {
        ctx->hash_table = flb_hash_table_create(FLB_HASH_TABLE_EVICT_RANDOM,
                                                FLB_HASH_TABLE_SIZE,
                                                FLB_HASH_TABLE_SIZE);
    }

    if (ctx->kube_meta_namespace_cache_ttl > 0) {
        ctx->namespace_hash_table = flb_hash_table_create_with_ttl(
                                            ctx->kube_meta_namespace_cache_ttl,
                                            FLB_HASH_TABLE_EVICT_OLDER,
                                            FLB_HASH_TABLE_SIZE,
                                            FLB_HASH_TABLE_SIZE);
    }
    else {
        ctx->namespace_hash_table = flb_hash_table_create(
                                            FLB_HASH_TABLE_EVICT_RANDOM,
                                            FLB_HASH_TABLE_SIZE,
                                            FLB_HASH_TABLE_SIZE);
    }


    if (!ctx->hash_table || !ctx->namespace_hash_table) {
        flb_kube_conf_destroy(ctx);
        return NULL;
    }

    /* Merge log buffer */
    if (ctx->merge_log == FLB_TRUE) {
        ctx->unesc_buf = flb_malloc(FLB_MERGE_BUF_SIZE);
        ctx->unesc_buf_size = FLB_MERGE_BUF_SIZE;
    }

    /* Custom Regex */
    tmp = flb_filter_get_property("regex_parser", ins);
    if (tmp) {
        /* Get custom parser */
        ctx->parser = flb_parser_get(tmp, config);
        if (!ctx->parser) {
            flb_plg_error(ctx->ins, "invalid parser '%s'", tmp);
            flb_kube_conf_destroy(ctx);
            return NULL;
        }

        /* Force to regex parser */
        if (ctx->parser->type != FLB_PARSER_REGEX) {
            flb_plg_error(ctx->ins, "invalid parser type '%s'", tmp);
            flb_kube_conf_destroy(ctx);
            return NULL;
        }
        else {
            ctx->regex = ctx->parser->regex;
        }
    }

    if (!ctx->use_tag_for_meta) {
        flb_plg_info(ctx->ins, "https=%i host=%s port=%i",
                     ctx->api_https, ctx->api_host, ctx->api_port);
    }
    return ctx;
}

void flb_kube_conf_destroy(struct flb_kube *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->hash_table) {
        flb_hash_table_destroy(ctx->hash_table);
    }

    if (ctx->namespace_hash_table) {
        flb_hash_table_destroy(ctx->namespace_hash_table);
    }

    if (ctx->merge_log == FLB_TRUE) {
        flb_free(ctx->unesc_buf);
    }

    /* Destroy regex content only if a parser was not defined */
    if (ctx->parser == NULL && ctx->regex) {
        flb_regex_destroy(ctx->regex);
    }

    flb_free(ctx->api_host);
    flb_free(ctx->token);
    flb_free(ctx->namespace);
    flb_free(ctx->podname);
    flb_free(ctx->auth);

    if (ctx->kubelet_upstream) {
        flb_upstream_destroy(ctx->kubelet_upstream);
    }
    if (ctx->kube_api_upstream) {
        flb_upstream_destroy(ctx->kube_api_upstream);
    }

#ifdef FLB_HAVE_TLS
    if (ctx->tls) {
        flb_tls_destroy(ctx->tls);
    }
    if (ctx->kubelet_tls) {
        flb_tls_destroy(ctx->kubelet_tls);
    }
#endif

    flb_free(ctx);
}
