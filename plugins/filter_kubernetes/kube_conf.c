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

struct flb_kube *flb_kube_conf_create(struct flb_filter_instance *i,
                                      struct flb_config *config)
{
    int off;
    int ret;
    char *url;
    char *tmp;
    char *p;
    struct flb_kube *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_kube));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->config = config;
    ctx->merge_log = FLB_FALSE;
    ctx->annotations = FLB_TRUE;
    ctx->dummy_meta = FLB_FALSE;
    ctx->tls_debug = -1;
    ctx->tls_verify = FLB_TRUE;
    ctx->tls_ca_path = NULL;

    /* Buffer size for HTTP Client when reading responses from API Server */
    ctx->buffer_size = (FLB_HTTP_DATA_SIZE_MAX * 8);
    tmp = flb_filter_get_property("buffer_size", i);
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
                flb_error("[filter_kube] invalid buffer_size=%s, using default", tmp);
            }
            else {
                ctx->buffer_size = (size_t) ret;
            }
        }
    }

    tmp = flb_filter_get_property("tls.debug", i);
    if (tmp) {
        ctx->tls_debug = atoi(tmp);
    }

    tmp = flb_filter_get_property("tls.verify", i);
    if (tmp) {
        ctx->tls_verify = flb_utils_bool(tmp);
    }

    /* Merge [JSON] log */
    tmp = flb_filter_get_property("merge_json_log", i);
    if (tmp) {
        flb_warn("[filter_kube] merge_json_log is deprecated, "
                 "enabling 'merge_log' option instead");
        ctx->merge_log = flb_utils_bool(tmp);
    }
    tmp = flb_filter_get_property("merge_log", i);
    if (tmp) {
        ctx->merge_log = flb_utils_bool(tmp);
    }

    /* Merge processed log under a new key */
    tmp = flb_filter_get_property("merge_log_key", i);
    if (tmp) {
        ctx->merge_log_key = flb_strdup(tmp);
        ctx->merge_log_key_len = strlen(tmp);
    }

    /* On merge, trim field values (remove possible \n or \r) */
    tmp = flb_filter_get_property("merge_log_trim", i);
    if (tmp) {
        ctx->merge_log_trim = flb_utils_bool(tmp);
    }
    else {
        ctx->merge_log_trim = FLB_TRUE;
    }

    /* Get Kubernetes API server */
    url = flb_filter_get_property("kube_url", i);
    if (!url) {
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

    /* If set, meta-data load will be attempted from files in this dir,
       falling back to API if not existing.
    */
    tmp = flb_filter_get_property("kube_meta_preload_cache_dir", i);
    if (tmp) {
        ctx->meta_preload_cache_dir = flb_strdup(tmp);
    }

    /* Kubernetes TLS */
    if (ctx->api_https == FLB_TRUE) {
        /* CA file */
        tmp = flb_filter_get_property("kube_ca_file", i);
        if (!tmp) {
            ctx->tls_ca_file = flb_strdup(FLB_KUBE_CA);
        }
        else {
            ctx->tls_ca_file = flb_strdup(tmp);
        }

        /* CA certs path */
        tmp = flb_filter_get_property("kube_ca_path", i);
        if (tmp) {
            ctx->tls_ca_path = flb_strdup(tmp);
        }
    }

    /* Kubernetes Token file */
    tmp = flb_filter_get_property("kube_token_file", i);
    if (!tmp) {
        ctx->token_file = flb_strdup(FLB_KUBE_TOKEN);
    }
    else {
        ctx->token_file = flb_strdup(tmp);
    }

    snprintf(ctx->kube_url, sizeof(ctx->kube_url) - 1,
             "%s://%s:%i",
             ctx->api_https ? "https" : "http",
             ctx->api_host, ctx->api_port);

    ctx->hash_table = flb_hash_create(FLB_HASH_EVICT_RANDOM,
                                      FLB_HASH_TABLE_SIZE,
                                      FLB_HASH_TABLE_SIZE);
    if (!ctx->hash_table) {
        flb_kube_conf_destroy(ctx);
        return NULL;
    }

    /* Include Kubernetes Annotations in the final record */
    tmp = flb_filter_get_property("annotations", i);
    if (tmp) {
        ctx->annotations = flb_utils_bool(tmp);
    }

    /*
     * The Application may 'propose' special configuration keys
     * to the logging agent (Fluent Bit) through the annotations
     * set in the Pod definition, e.g:
     *
     *  "annotations": {
     *      "logging": {"parser": "apache"}
     *  }
     *
     * As of now, Fluent Bit/filter_kubernetes supports the following
     * options under the 'logging' map value:
     *
     * - k8s-logging.parser: propose Fluent Bit to parse the content
     *                       using the  pre-defined parser in the
     *                       value (e.g: apache).
     *
     * By default all options are disabled, so each option needs to
     * be enabled manually.
     */
    tmp = flb_filter_get_property("k8s-logging.parser", i);
    if (tmp) {
        ctx->k8s_logging_parser = flb_utils_bool(tmp);
    }
    else {
        ctx->k8s_logging_parser = FLB_FALSE;
    }

    tmp = flb_filter_get_property("k8s-logging.exclude", i);
    if (tmp) {
        ctx->k8s_logging_exclude = flb_utils_bool(tmp);
    }
    else {
        ctx->k8s_logging_exclude = FLB_FALSE;
    }

    /* Use Systemd Journal */
    tmp = flb_filter_get_property("use_journal", i);
    if (tmp) {
        ctx->use_journal = flb_utils_bool(tmp);
    }
    else {
        ctx->use_journal = FLB_FALSE;
    }

    /* Merge log buffer */
    if (ctx->merge_log == FLB_TRUE) {
        ctx->unesc_buf = flb_malloc(FLB_MERGE_BUF_SIZE);
        ctx->unesc_buf_size = FLB_MERGE_BUF_SIZE;
    }

    /* Custom Regex */
    tmp = flb_filter_get_property("regex_parser", i);
    if (tmp) {
        /* Get custom parser */
        ctx->parser = flb_parser_get(tmp, config);
        if (!ctx->parser) {
            flb_error("[filter_kube] invalid parser '%s'", tmp);
            flb_kube_conf_destroy(ctx);
            return NULL;
        }

        /* Force to regex parser */
        if (ctx->parser->type != FLB_PARSER_REGEX) {
            flb_error("[filter_kube] invalid parser type '%s'", tmp);
            flb_kube_conf_destroy(ctx);
            return NULL;
        }
        else {
            ctx->regex = ctx->parser->regex;
        }
    }

    /* Generate dummy metadata (only for test/dev purposes) */
    tmp = flb_filter_get_property("dummy_meta", i);
    if (tmp) {
        ctx->dummy_meta = flb_utils_bool(tmp);
    }

    flb_info("[filter_kube] https=%i host=%s port=%i",
              ctx->api_https, ctx->api_host, ctx->api_port);
    return ctx;
}

void flb_kube_conf_destroy(struct flb_kube *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->meta_preload_cache_dir) {
        flb_free(ctx->meta_preload_cache_dir);
    }
    if (ctx->hash_table) {
        flb_hash_destroy(ctx->hash_table);
    }

    if (ctx->merge_log == FLB_TRUE) {
        flb_free(ctx->unesc_buf);
    }

    if (ctx->merge_log_key) {
        flb_free(ctx->merge_log_key);
    }

    /* Destroy regex content only if a parser was not defined */
    if (ctx->parser == NULL && ctx->regex) {
        flb_regex_destroy(ctx->regex);
    }

    flb_free(ctx->api_host);
    flb_free(ctx->tls_ca_path);
    flb_free(ctx->tls_ca_file);
    flb_free(ctx->token_file);
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
