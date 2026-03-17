/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>

#include <cmetrics/cmt_decode_prometheus.h>

#include "prom_scrape.h"

static struct prom_scrape *prom_scrape_create(struct flb_input_instance *ins,
                                              struct flb_config *config)
{
    int ret;
    int upstream_flags;
    struct prom_scrape *ctx;
    struct flb_upstream *upstream;

    if (ins->host.name == NULL) {
        ins->host.name = flb_sds_create("localhost");
    }
    if (ins->host.port == 0) {
        ins->host.port = 9100;
    }

    ctx = flb_calloc(1, sizeof(struct prom_scrape));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    upstream_flags = FLB_IO_TCP;

    if (ins->use_tls) {
        upstream_flags |= FLB_IO_TLS;
    }

    upstream = flb_upstream_create(config, ins->host.name, ins->host.port,
                                   upstream_flags, ins->tls);

    if (!upstream) {
        flb_plg_error(ins, "upstream initialization error");
        flb_free(ctx);
        return NULL;
    }
    ctx->upstream = upstream;

    return ctx;
}

static int collect_metrics(struct prom_scrape *ctx)
{
    int ret = -1;
    char errbuf[1024];
    size_t b_sent;
    struct flb_http_client *c;
    struct flb_connection *u_conn;
    struct cmt *cmt = NULL;
    struct cmt_decode_prometheus_parse_opts opts = {0};

    /* get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "could not get an upstream connection to %s:%u",
                      ctx->ins->host.name, ctx->ins->host.port);
        return -1;
    }

    c = flb_http_client(u_conn, FLB_HTTP_GET, ctx->metrics_path,
                        NULL, 0,
                        ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!c) {
        flb_plg_error(ctx->ins, "unable to create http client");
        goto client_error;
    }

    flb_http_buffer_size(c, ctx->buffer_max_size);

    /* Auth headers */
    if (ctx->http_user && ctx->http_passwd) { /* Basic */
        flb_http_basic_auth(c, ctx->http_user, ctx->http_passwd);
    } else if (ctx->bearer_token) { /* Bearer token */
        flb_http_bearer_auth(c, ctx->bearer_token);
    }

    /* Add User-Agent */
    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_error(ctx->ins, "http do error");
        goto http_error;
    }

    if (c->resp.status != 200) {
        flb_plg_error(ctx->ins, "http status code error: [%s] %d",
                      ctx->metrics_path, c->resp.status);
        goto http_error;
    }

    if (c->resp.payload_size <= 0) {
        flb_plg_error(ctx->ins, "empty response");
        goto http_error;
    }

    /* configure prometheus decoder options */
    opts.default_timestamp = cfl_time_now();
    opts.errbuf = errbuf;
    opts.errbuf_size = sizeof(errbuf);

    /* convert Prometheus Text to CMetrics */
    ret = cmt_decode_prometheus_create(&cmt,
                                       c->resp.payload,
                                       c->resp.payload_size,
                                       &opts);
    if (ret == 0) {
        /* Append the updated metrics */
        ret = flb_input_metrics_append(ctx->ins, NULL, 0, cmt);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "could not append metrics");
        }
        cmt_destroy(cmt);
    }
    else {
        flb_plg_error(ctx->ins, "error decoding Prometheus Text format");
    }

http_error:
    flb_http_client_destroy(c);
client_error:
    flb_upstream_conn_release(u_conn);

    return ret;
}

static int cb_prom_scrape_collect(struct flb_input_instance *ins,
                                  struct flb_config *config, void *in_context)
{
    int rc;
    struct prom_scrape *ctx = (struct prom_scrape *) in_context;

    rc = collect_metrics(ctx);
    FLB_INPUT_RETURN(rc);
}

static int cb_prom_scrape_init(struct flb_input_instance *ins,
                               struct flb_config *config, void *data)
{
    struct prom_scrape *ctx;

    /* Allocate space for the configuration */
    ctx = prom_scrape_create(ins, config);
    if (!ctx) {
        return -1;
    }

    flb_input_set_context(ins, ctx);
    ctx->coll_id = flb_input_set_collector_time(ins,
                                                cb_prom_scrape_collect,
                                                ctx->scrape_interval,
                                                0, config);
    return 0;
}

static int prom_scrape_destroy(struct prom_scrape *ctx)
{
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }
    flb_free(ctx);

    return 0;
}

static int cb_prom_scrape_exit(void *data, struct flb_config *config)
{
    struct prom_scrape *ctx = (struct prom_scrape *) data;

    if (!ctx) {
        return 0;
    }

    prom_scrape_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_TIME, "scrape_interval", "10s",
     0, FLB_TRUE, offsetof(struct prom_scrape, scrape_interval),
     "Scraping interval."
    },

    {
     FLB_CONFIG_MAP_SIZE, "buffer_max_size", HTTP_BUFFER_MAX_SIZE,
     0, FLB_TRUE, offsetof(struct prom_scrape, buffer_max_size),
     "Set the maximum buffer size for the HTTP response."
    },

    {
     FLB_CONFIG_MAP_STR, "metrics_path", DEFAULT_URI,
     0, FLB_TRUE, offsetof(struct prom_scrape, metrics_path),
     "Set the metrics URI endpoint, it must start with a forward slash."
    },

    {
     FLB_CONFIG_MAP_STR, "http_user", NULL,
     0, FLB_TRUE, offsetof(struct prom_scrape, http_user),
     "Set HTTP auth user"
    },

    {
     FLB_CONFIG_MAP_STR, "http_passwd", "",
     0, FLB_TRUE, offsetof(struct prom_scrape, http_passwd),
     "Set HTTP auth password"
    },

    {
     FLB_CONFIG_MAP_STR, "bearer_token", NULL,
     0, FLB_TRUE, offsetof(struct prom_scrape, bearer_token),
     "Set bearer token auth"
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_prometheus_scrape_plugin = {
    .name         = "prometheus_scrape",
    .description  = "Scrape metrics from Prometheus Endpoint",
    .cb_init      = cb_prom_scrape_init,
    .cb_pre_run   = NULL,
    .cb_collect   = cb_prom_scrape_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = cb_prom_scrape_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET | FLB_INPUT_CORO,
};
