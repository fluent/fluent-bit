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

struct flb_output_plugin out_http_plugin;

int cb_http_init(struct flb_output_instance *ins, struct flb_config *config,
               void *data)
{
    struct flb_upstream *upstream;
    (void) data;

    if (!ins->host.name) {
        ins->host.name = strdup("127.0.0.1");
    }
    if (ins->host.port == 0) {
        ins->host.port = 80;
    }

    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   FLB_IO_TCP, (void *) &ins->tls);
    if (!upstream) {
        return -1;
    }

    flb_output_set_context(ins, upstream);
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
    struct flb_upstream *u = out_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;
    (void) i_ins;

    /* Get an upstream connection */
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_error("[out_http] no upstream connections available");
        return -1;
    }

    c = flb_http_client(u_conn, FLB_HTTP_POST, "/",
                        data, bytes);
    ret = flb_http_do(c, &b_sent);
    flb_debug("[out_http] do=%i", ret);
    flb_http_client_destroy(c);

    /* Release the connection */
    flb_upstream_conn_release(u_conn);

    return ret;
}

int cb_http_exit(void *data, struct flb_config *config)
{
    struct flb_upstream *u = data;

    flb_upstream_destroy(u);
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
