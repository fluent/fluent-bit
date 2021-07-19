/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <msgpack.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "nginx.h"

/**
 * parse the output of the nginx stub_status module.
 * 
 * An example:
 *     Active connections: 1 
 *     server accepts handled requests
 *      10 10 10 
 *     Reading: 0 Writing: 1 Waiting: 0 
 */
static int nginx_parse_stub_status(flb_sds_t buf, struct nginx_status *status)
{
    struct mk_list *llines;
    struct mk_list *head = NULL;
    char *lines[4];
    int line = 0;
    int rc;
    struct flb_split_entry *cur = NULL;


    llines = flb_utils_split(buf, '\n', 4);
    if (lines == NULL) {
        return -1;
    }

    mk_list_foreach(head, llines) {
        cur = mk_list_entry(head, struct flb_split_entry, _head);
        lines[line] = cur->value;
        line++;
    }
    if (line < 4) {
        goto error;
    }
    
    rc = sscanf(lines[0], "Active connections: %lu \n", &status->active);
    if (rc != 1) {
        goto error;
    }
    rc = sscanf(lines[2], " %lu %lu %lu \n", 
           &status->accepts, &status->handled, &status->requests);
    if (rc != 3) {
        goto error;
    }
    rc = sscanf(lines[3], "Reading: %lu Writing: %lu Waiting: %lu \n",
            &status->reading, &status->writing, &status->waiting);
    if (rc != 3) {
        goto error;
    }

    flb_utils_split_free(llines);
    return 0;
error:
    flb_utils_split_free(llines);
    return -1;
}

static int nginx_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context);

/**
 * Callback function to gather statistics from the nginx
 * status module.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to
 *                      flb_in_de_config
 *
 * @return int Always returns success
 */
static int nginx_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    struct nginx_ctx *ctx = (struct nginx_ctx *)in_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *client;
    struct nginx_status status;
    flb_sds_t data;

    size_t b_sent;
    int ret = -1;
    uint64_t ts = cmt_time_now();
    

    u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_error("[nginx_stub_status] upstream connection initialization error");
        goto conn_error;
    }

    client = flb_http_client(u_conn, FLB_HTTP_GET, "/status", 
                             NULL, 0, ctx->ins->host.name, ctx->ins->host.port, NULL, 0);
    if (!client) {
        flb_error("[nginx_stub_status] unable to create http client");
        goto client_error;
    }

    ret = flb_http_do(client, &b_sent);
    if (ret != 0) {
        flb_error("[nginx_stub_status] http do error");
        goto http_error;
    }

    if (client->resp.status != 200) {
        flb_error("[nginx_stub_status] http status code error: %d", client->resp.status);
        goto http_error;
    }

    // look at using it directly...
    data = flb_sds_create_len(client->resp.payload,
                              client->resp.payload_size);
    /* work directly on the data here ... */
    if (nginx_parse_stub_status(data, &status) == -1) {
        flb_error("[nginx_stub_status] unable to parse stub status response");
        goto status_error;
    }

    cmt_counter_set(ctx->connections_accepted, ts, status.accepts, 0, NULL);
    cmt_counter_set(ctx->connections_handled, ts, status.handled, 0, NULL);
    cmt_counter_set(ctx->connections_total, ts, status.requests, 0, NULL);
    
    cmt_gauge_set(ctx->connections_active, ts, (double)status.active, 0, NULL);
    cmt_gauge_set(ctx->connections_reading, ts, (double)status.reading, 0, NULL);
    cmt_gauge_set(ctx->connections_writing, ts, (double)status.writing, 0, NULL);
    cmt_gauge_set(ctx->connections_waiting, ts, (double)status.waiting, 0, NULL);

    ret = flb_input_metrics_append(ins, NULL, 0, ctx->cmt);
    if (ret != 0) {
        flb_plg_error(ins, "could not append metrics");
    }

status_error:
    flb_sds_destroy(data);
http_error:
    flb_http_client_destroy(client);
client_error:
    flb_upstream_conn_release(u_conn);
conn_error:
    return ret;
}

/**
 * Function to initialize nginx_stub_status plugin.
 *
 * @param ins     Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 *
 * @return struct flb_in_nss_config* Pointer to the plugin's
 *         structure on success, NULL on failure.
 */
struct nginx_ctx *nginx_ctx_init(struct flb_input_instance *ins,
                                        struct flb_config *config)
{
    struct nginx_ctx *ctx;
    struct flb_upstream *upstream;
 
    if (ins->host.name == NULL) {
        ins->host.name = flb_sds_create("localhost");
    }
    if (ins->host.port == 0) {
        ins->host.port = 80;
    }

    ctx = flb_calloc(1, sizeof(struct nginx_ctx));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;

    ctx->cmt = cmt_create();
    if (!ctx->cmt) {
        flb_plg_error(ins, "could not initialize CMetrics");
        flb_free(ctx);
        return NULL;
    }
    
    upstream = flb_upstream_create(config, ins->host.name, ins->host.port,
                                 FLB_IO_TCP, NULL);
    if (!upstream) {
        flb_error("[nginx_stub_status] upstream initialization error");
        return NULL;
    }
    ctx->upstream = upstream;

    return ctx;
}

/**
 * Callback function to initialize docker events plugin
 *
 * @param ins     Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 * @param data    Unused
 *
 * @return int 0 on success, -1 on failure
 */
static int nginx_init(struct flb_input_instance *ins,
                      struct flb_config *config, void *data)
{
    struct nginx_ctx *ctx = NULL;
    
    /* Allocate space for the configuration */
    ctx = nginx_ctx_init(ins, config);
    if (!ctx) {
        return -1;
    }

    // https://github.com/nginxinc/nginx-prometheus-exporter#metrics-for-nginx-oss
    ctx->connections_accepted = cmt_counter_create(ctx->cmt, "nginx", "connections", 
        "accepted", "Accepted client connections", 0, NULL);
    if (ctx->connections_accepted == NULL) {
        return -1;
    }
    
    ctx->connections_handled = cmt_counter_create(ctx->cmt, "nginx", "connections", 
        "handled", "Handled client connections", 0, NULL);
    if (ctx->connections_handled == NULL) {
        return -1;
    }
    
    ctx->connections_total = cmt_counter_create(ctx->cmt, "nginx", "http_requests", 
        "total", "Total http requests", 0, NULL);
    if (ctx->connections_total == NULL) {
        return -1;
    }
    
    ctx->connections_active = cmt_gauge_create(ctx->cmt, "nginx", "connections", 
        "active", "active client connections", 0, NULL);
    if (ctx->connections_active == NULL) {
        return -1;
    }
    
    ctx->connections_reading = cmt_gauge_create(ctx->cmt, "nginx", "connections", 
        "reading", "reading client connections", 0, NULL);
    if (ctx->connections_reading == NULL) {
        return -1;
    }
    
    ctx->connections_writing = cmt_gauge_create(ctx->cmt, "nginx", "connections", 
        "writing", "writing client connections", 0, NULL);
    if (ctx->connections_writing == NULL) {
        return -1;
    }
    
    ctx->connections_waiting = cmt_gauge_create(ctx->cmt, "nginx", "connections", 
        "waiting", "waiting client connections", 0, NULL);
    if (ctx->connections_waiting == NULL) {
        return -1;
    }

    // when it fails keep the other values... but set JUST this value...
    // if they depend on the gauges and dont check active... MEH...
    ctx->connection_active = cmt_gauge_create(ctx->cmt, "nginx", "connections", "active", 
        "Shows the status of the last metric scrape: 1 for a successful scrape and 0 for a failed one", 
        0, NULL);
    
    /* Set the context */
    flb_input_set_context(ins, ctx);

    ctx->coll_id = flb_input_set_collector_time(ins, 
                                                nginx_collect,
                                                1, 
                                                0, config);
    return 0;
}

/**
 * Function to destroy nginx_stub_status plugin.
 *
 * @param ctx  Pointer to flb_in_nss_config
 *
 * @return int 0
 */
static int nginx_ctx_destroy(struct nginx_ctx *ctx)
{
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }
    flb_free(ctx);
    return 0;
}

/**
 * Callback exit function to cleanup plugin
 *
 * @param data    Pointer cast to flb_in_de_config
 * @param config  Unused
 *
 * @return int    Always returns 0
 */
static int nginx_exit(void *data, struct flb_config *config)
{
    struct nginx_ctx *ctx = (struct nginx_ctx *)data;

    if (!ctx) {
        return 0;
    }

    nginx_ctx_destroy(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_nginx_exporter_metrics_plugin = {
    .name         = "nginx_stub_status",
    .description  = "Nginx status metrics",
    .cb_init      = nginx_init,
    .cb_pre_run   = NULL,
    .cb_collect   = nginx_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = nginx_exit,
    .flags        = FLB_INPUT_NET,
    .event_type   = FLB_INPUT_METRICS
};
