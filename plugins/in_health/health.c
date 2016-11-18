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
#include <math.h>

#include <msgpack.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_utils.h>

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

    /* Time interval check */
    int interval_sec;
    int interval_nsec;

    /* Networking */
    struct flb_upstream *u;

    /* MessagePack buffers */
    msgpack_packer  mp_pck;
    msgpack_sbuffer mp_sbuf;
};

/* Collection aims to try to connect to the specified TCP server */
static int in_health_collect(struct flb_config *config, void *in_context)
{
    uint8_t alive;
    struct flb_in_health_config *ctx = in_context;
    struct flb_upstream_conn *u_conn;

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

    /*
     * Store the new data into the MessagePack buffer,
     */
    msgpack_pack_array(&ctx->mp_pck, 2);
    msgpack_pack_uint64(&ctx->mp_pck, time(NULL));
    
    if (ctx->add_host) {
        /* [ alive , hostname ]*/
        msgpack_pack_map(&ctx->mp_pck, 2);
    }
    else {
        /* [ alive ] */
        msgpack_pack_map(&ctx->mp_pck, 1);
    }

    /* Status */
    msgpack_pack_bin(&ctx->mp_pck, 5);
    msgpack_pack_bin_body(&ctx->mp_pck, "alive", 5);

    if (alive) {
        msgpack_pack_true(&ctx->mp_pck);
    }
    else {
        msgpack_pack_false(&ctx->mp_pck);
    }

    if (ctx->add_host) {
        /* append hostname */
        msgpack_pack_bin(&ctx->mp_pck, strlen("hostname"));
        msgpack_pack_bin_body(&ctx->mp_pck, "hostname", strlen("hostname"));
        msgpack_pack_bin(&ctx->mp_pck, ctx->len_host);
        msgpack_pack_bin_body(&ctx->mp_pck, ctx->hostname, ctx->len_host);
    }

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


    /* initialize MessagePack buffers */
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set our collector based on time */
    ret = flb_input_set_collector_time(in,
                                       in_health_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for Health input plugin");
    }

    return 0;
}

void *in_health_flush(void *in_context, size_t *size)
{
    char *buf;
    msgpack_sbuffer *sbuf;
    struct flb_in_health_config *ctx = in_context;

    sbuf = &ctx->mp_sbuf;
    *size = sbuf->size;
    buf = flb_malloc(sbuf->size);
    if (!buf) {
        return NULL;
    }

    /* set a new buffer and re-initialize our MessagePack context */
    memcpy(buf, sbuf->data, sbuf->size);
    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    return buf;
}

int in_health_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_health_config *ctx = data;

    /* Remove msgpack buffer and destroy context */
    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
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
    .cb_flush_buf = in_health_flush,
    .cb_exit      = in_health_exit,
    .flags        = FLB_INPUT_NET | FLB_INPUT_THREAD,
};
