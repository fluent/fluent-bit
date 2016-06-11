/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_http_client.h>

#include "http.h"

struct flb_output_plugin out_http_plugin;

int cb_http_init(struct flb_output_instance *ins, struct flb_config *config,
               void *data)
{
    int ulen;
    char *uri = NULL;
    char *tmp;
    struct flb_upstream *upstream;
    struct flb_out_http_config *ctx = NULL;
    (void) data;

    /* Allocate plugin context */
    ctx = calloc(1, sizeof(struct flb_out_http_config));
    if (!ctx) {
        perror("malloc");
        return -1;
    }
    /*
     * Check if a Proxy have been set, if so the Upstream manager will use
     * the Proxy end-point and then we let the HTTP client know about it,
     * so it can adjust the HTTP requests.
     */
    tmp = flb_output_get_property("proxy", ins);
    if (tmp) {
        /*
         * Here we just want to lookup two things: host and port, we are
         * going to skip validations as most of them are handled by the
         * HTTP Client in a later stage.
         */
        char *p;
        char *addr;

        addr = strstr(tmp, "//");
        if (!addr) {
            free(ctx);
            return -1;
        }
        addr += 2; /* get right to the host section */
        if (*addr == '[') { /* IPv6 */
            p = strchr(addr, ']');
            if (!p) {
                free(ctx);
                return -1;
            }
            ctx->proxy_host = strndup(addr + 1, (p - addr - 1));
            p++;
            if (*p == ':') {
                p++;
                ctx->proxy_port = atoi(p);
            }
            else {
            }
        }
        else {
            /* Port lookup */
            p = strchr(addr, ':');
            if (p) {
                p++;
                ctx->proxy_port = atoi(p);
                ctx->proxy_host = strndup(addr, (p - addr) - 1);
            }
            else {
                ctx->proxy_host = strdup(addr);
                ctx->proxy_port = 80;
            }
        }
        ctx->proxy = tmp;
    }
    else {
        if (!ins->host.name) {
            ins->host.name = strdup("127.0.0.1");
        }
        if (ins->host.port == 0) {
            ins->host.port = 80;
        }
    }

    if (ctx->proxy) {
        flb_trace("[out_http] Upstream Proxy=%s:%i",
                  ctx->proxy_host, ctx->proxy_port);
        upstream = flb_upstream_create(config,
                                       ctx->proxy_host,
                                       ctx->proxy_port,
                                       FLB_IO_TCP, (void *) &ins->tls);
    }
    else {
        upstream = flb_upstream_create(config,
                                       ins->host.name,
                                       ins->host.port,
                                       FLB_IO_TCP, (void *) &ins->tls);
    }

    if (!upstream) {
        free(ctx);
        return -1;
    }

    if (ins->host.uri) {
        uri = strdup(ins->host.uri->full);
    }
    else {
        tmp = flb_output_get_property("uri", ins);
        if (tmp) {
            uri = strdup(tmp);
        }
    }

    if (!uri) {
        uri = strdup("/");
    }
    else if (uri[0] != '/') {
        ulen = strlen(uri);
        tmp = malloc(ulen + 2);
        tmp[0] = '/';
        memcpy(tmp + 1, uri, ulen);
        tmp[ulen + 1] = '\0';
        free(uri);
        uri = tmp;
    }

    ctx->u = upstream;
    ctx->uri  = uri;
    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

    flb_output_set_context(ins, ctx);
    return 0;
}

int cb_http_flush(void *data, size_t bytes,
                  char *tag, int tag_len,
                  struct flb_input_instance *i_ins,
                  void *out_context,
                  struct flb_config *config)
{
    int ret;
    size_t b_sent;
    struct flb_out_http_config *ctx = out_context;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    (void) i_ins;

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_error("[out_http] no upstream connections available");
        return -1;
    }

    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        data, bytes,
                        ctx->host, ctx->port,
                        ctx->proxy);

    ret = flb_http_do(c, &b_sent);
    flb_debug("[out_http] do=%i", ret);
    flb_http_client_destroy(c);

    /* Release the connection */
    flb_upstream_conn_release(u_conn);

    return ret;
}

int cb_http_exit(void *data, struct flb_config *config)
{
    struct flb_out_http_config *ctx = data;

    flb_upstream_destroy(ctx->u);

    free(ctx->proxy_host);
    free(ctx->uri);
    free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_http_plugin = {
    .name           = "http",
    .description    = "HTTP Output",
    .cb_init        = cb_http_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_http_flush,
    .cb_exit        = cb_http_exit,
    .flags          = FLB_OUTPUT_NET,
};
