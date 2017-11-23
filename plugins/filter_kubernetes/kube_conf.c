/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
    ctx->merge_json_log = FLB_FALSE;
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

    /* Merge JSON log */
    tmp = flb_filter_get_property("merge_json_log", i);
    if (tmp) {
        ctx->merge_json_log = flb_utils_bool(tmp);
    }

    /* Merge JSON key */
    tmp = flb_filter_get_property("merge_json_key", i);
    if (tmp) {
        ctx->merge_json_key = flb_strdup(tmp);
        ctx->merge_json_key_len = strlen(tmp);
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

    /* Include Kubernetes Annotations */
    tmp = flb_filter_get_property("annotations", i);
    if (tmp) {
        ctx->annotations = flb_utils_bool(tmp);
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
    if (ctx->merge_json_log == FLB_TRUE) {
        ctx->merge_json_buf = flb_malloc(FLB_MERGE_BUF_SIZE);
        ctx->merge_json_buf_size = FLB_MERGE_BUF_SIZE;
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
    if (ctx->hash_table) {
        flb_hash_destroy(ctx->hash_table);
    }

    if (ctx->regex) {
        flb_regex_destroy(ctx->regex);
    }

    if (ctx->merge_json_log == FLB_TRUE) {
        flb_free(ctx->merge_json_buf);
    }

    if (ctx->merge_json_key) {
        flb_free(ctx->merge_json_key);
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
