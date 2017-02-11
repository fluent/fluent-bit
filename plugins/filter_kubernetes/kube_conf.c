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
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>

#include "kube_conf.h"

struct flb_kube *flb_kube_conf_create(struct flb_filter_instance *i,
                                      struct flb_config *config)
{
    int off;
    int io_type;
    char *tmp;
    char *p;
    struct flb_kube *ctx;

    ctx = flb_malloc(sizeof(struct flb_kube));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->config = config;

    /* Get Kubernetes API server */
    tmp = flb_filter_get_property("kubernetes_url", i);
    if (!tmp) {
        ctx->api_host = flb_strdup(FLB_API_HOST);
        ctx->api_port = FLB_API_PORT;
        ctx->api_https = FLB_FALSE;
    }
    else {
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
        p = tmp + off;
        tmp = strchr(p, ':');
        if (tmp) {
            ctx->api_host = flb_strndup(p, p - tmp);
            tmp++;
            ctx->api_port = atoi(tmp);
        }
        else {
            ctx->api_host = flb_strdup(p);
            ctx->api_port = FLB_API_PORT;
        }
    }

    if (ctx->api_https == FLB_FALSE) {
        io_type = FLB_IO_TCP;
    }
    else {
        io_type = FLB_IO_TLS;
    }

    /* Create an Upstream context */
    ctx->upstream = flb_upstream_create(config,
                                        ctx->api_host,
                                        ctx->api_port,
                                        io_type,
                                        NULL);

    flb_debug("[filter_kube] https=%i host=%s port=%i",
              ctx->api_https, ctx->api_host, ctx->api_port);
    return ctx;
}

void flb_kube_conf_destroy(struct flb_kube *ctx)
{
    if (ctx->api_host) {
        flb_free(ctx->api_host);
    }

}
