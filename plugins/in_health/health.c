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
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define DEFAULT_INTERVAL_SEC  1
#define DEFAULT_INTERVAL_NSEC 0

/* Input configuration & context */
struct flb_in_health_config {
    /* Alert mode */
    int alert;

    /* Append Hostname */
    int add_host;
    int len_host;
    char* hostname;

    /* Append Port Number */
    int add_port;
    int port;

    /* Time interval check */
    int interval_sec;
    int interval_nsec;

    /* Networking */
    struct flb_upstream *u;
};

/* Collection aims to try to connect to the specified TCP server */
static int in_health_collect(struct flb_input_instance *i_ins,
                             struct flb_config *config, void *in_context)
{
    int map_num = 1;
    uint8_t alive;
    struct flb_in_health_config *ctx = in_context;
    struct flb_upstream_conn *u_conn;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        alive = FLB_FALSE;
    }
    else {
        alive = FLB_TRUE;
        flb_upstream_conn_release(u_conn);
    }

    if (alive == FLB_TRUE && ctx->alert == FLB_TRUE) {
        FLB_INPUT_RETURN();
    }

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Pack data */
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);

    /* extract map field */
    if (ctx->add_host) {
        map_num++;
    }
    if (ctx->add_port) {
        map_num++;
    }
    msgpack_pack_map(&mp_pck, map_num);

    /* Status */
    msgpack_pack_str(&mp_pck, 5);
    msgpack_pack_str_body(&mp_pck, "alive", 5);

    if (alive) {
        msgpack_pack_true(&mp_pck);
    }
    else {
        msgpack_pack_false(&mp_pck);
    }

    if (ctx->add_host) {
        /* append hostname */
        msgpack_pack_str(&mp_pck, strlen("hostname"));
        msgpack_pack_str_body(&mp_pck, "hostname", strlen("hostname"));
        msgpack_pack_str(&mp_pck, ctx->len_host);
        msgpack_pack_str_body(&mp_pck, ctx->hostname, ctx->len_host);
    }

    if (ctx->add_port) {
        /* append port number */
        msgpack_pack_str(&mp_pck, strlen("port"));
        msgpack_pack_str_body(&mp_pck, "port", strlen("port"));
        msgpack_pack_int32(&mp_pck, ctx->port);
    }

    flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    FLB_INPUT_RETURN();
    return 0;
}

static int in_health_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    char *pval;
    struct flb_in_health_config *ctx;
    (void) data;

    if (in->host.name == NULL) {
        flb_error("[in_health] no input 'Host' is given");
        return -1;
    }

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_in_health_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }
    ctx->alert = FLB_FALSE;
    ctx->add_host = FLB_FALSE;
    ctx->len_host = 0;
    ctx->hostname = NULL;

    ctx->add_port = FLB_FALSE;
    ctx->port     = -1;

    ctx->u = flb_upstream_create(config, in->host.name, in->host.port,
                                 FLB_IO_TCP, NULL);
    if (!ctx->u) {
        flb_free(ctx);
        flb_error("[in_health] could not initialize upstream");
        return -1;
    }

    /* interval settings */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        ctx->interval_sec = atoi(pval);
    }
    else {
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    }

    pval = flb_input_get_property("interval_nsec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        ctx->interval_nsec = atoi(pval);
    }
    else {
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    pval = flb_input_get_property("alert", in);
    if (pval) {
        if (strcasecmp(pval, "true") == 0 || strcasecmp(pval, "on") == 0) {
            ctx->alert = FLB_TRUE;
        }
    }

    pval = flb_input_get_property("add_host", in);
    if (pval) {
        if (strcasecmp(pval, "true") == 0 || strcasecmp(pval, "on") == 0) {
            ctx->add_host = FLB_TRUE;
            ctx->len_host = strlen(in->host.name);
            ctx->hostname = flb_strdup(in->host.name);
        }
    }

    pval = flb_input_get_property("add_port", in);
    if (pval) {
        if (strcasecmp(pval, "true") == 0 || strcasecmp(pval, "on") == 0) {
            ctx->add_port = FLB_TRUE;
            ctx->port = in->host.port;
        }
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set our collector based on time */
    ret = flb_input_set_collector_time(in,
                                       in_health_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_error("Could not set collector for Health input plugin");
        flb_free(ctx);
        return -1;
    }

    return 0;
}

int in_health_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_health_config *ctx = data;

    /* Remove msgpack buffer and destroy context */
    flb_upstream_destroy(ctx->u);
    flb_free(ctx->hostname);
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_health_plugin = {
    .name         = "health",
    .description  = "Check TCP server health",
    .cb_init      = in_health_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_health_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_health_exit,
    .flags        = FLB_INPUT_NET | FLB_INPUT_THREAD,
};
