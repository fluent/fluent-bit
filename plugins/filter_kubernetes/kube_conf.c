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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_http_client.h>

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
    if (!url) {
        ctx->api_host = flb_strdup(FLB_KUBE_API_HOST);
        ctx->api_port = FLB_KUBE_API_PORT;
        ctx->api_https = FLB_KUBE_API_TLS;
        ctx->api_path = flb_strdup(FLB_KUBE_API_PATH);
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
            tmp = strchr(p, '/');
            if (tmp) {
                ctx->api_host = flb_strndup(p, tmp - p);
            }
            else {
                ctx->api_host = flb_strdup(p);
            }
            ctx->api_port = ctx->api_https ? 443 : 80;
        }
        /* Get optional API path or use default for backward compatibility */
        tmp = strchr(p, '/');
        if (tmp) {
            off = strlen(tmp);
            /* Remove trailing / if present e.g. if the API is proxied at root on some host
             * then you can prevent the path defaulting to '/api/v1' by specifying '/'.
             * It should be removed anyway because it will be added when used. */
            if (tmp[off - 1] == '/') {
                off--;
            }
            ctx->api_path = flb_strndup(tmp, off);
        }
        else {
            ctx->api_path = flb_strdup(FLB_KUBE_API_PATH);
        }
    }

    snprintf(ctx->kube_url, sizeof(ctx->kube_url) - 1,
             "%s://%s:%i%s",
             ctx->api_https ? "https" : "http",
             ctx->api_host, ctx->api_port,
             ctx->api_path);
    /* ctx->kube_url may not be used but a debug message enables us to see
     * if the above works (until unit tests somehow check that). */
    flb_plg_debug(ctx->ins, "Kube API endpoint %s/", ctx->kube_url);

    ctx->hash_table = flb_hash_create(FLB_HASH_EVICT_RANDOM,
                                      FLB_HASH_TABLE_SIZE,
                                      FLB_HASH_TABLE_SIZE);
    if (!ctx->hash_table) {
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

    flb_plg_info(ctx->ins, "https=%i host=%s port=%i",
                 ctx->api_https, ctx->api_host, ctx->api_port);
    return ctx;
}

void flb_kube_conf_destroy(struct flb_kube *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->hash_table) {
        flb_hash_destroy(ctx->hash_table);
    }

    if (ctx->merge_log == FLB_TRUE) {
        flb_free(ctx->unesc_buf);
    }

    /* Destroy regex content only if a parser was not defined */
    if (ctx->parser == NULL && ctx->regex) {
        flb_regex_destroy(ctx->regex);
    }

    flb_free(ctx->api_host);
    flb_free(ctx->api_path);
    flb_free(ctx->token);
    flb_free(ctx->namespace);
    flb_free(ctx->podname);
    flb_free(ctx->auth);

    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }

#ifdef FLB_HAVE_TLS
    if (ctx->tls.context) {
        flb_tls_context_destroy(ctx->tls.context);
    }
#endif

    flb_free(ctx);
}
