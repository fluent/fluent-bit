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
#include <msgpack.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "nginx_stub_status.h"
#include "nginx_stub_status_config.h"


/**
 * parse the output of the nginx stub_status module.
 * 
 * An example:
 *     Active connections: 1 
 *     server accepts handled requests
 *      10 10 10 
 *     Reading: 0 Writing: 1 Waiting: 0 
 */
static int in_nss_parse_stub_status(flb_sds_t buf, struct flb_in_nss_status *status)
{
    struct mk_list *mk_lines;
    struct mk_list *mk_head = NULL;
    char *lines[4];
    int line = 0;
    int rc;
    struct flb_split_entry *cur = NULL;

    mk_lines = flb_utils_split(buf, '\n', 4);
    if (mk_lines == NULL) {
        return -1;
    }

    mk_list_foreach(mk_head, mk_lines) {
        cur = mk_list_entry(mk_head, struct flb_split_entry, _head);
        lines[line] = cur->value;
        line++;
    }
    if (line < 4) {
        goto error;
    }

    rc = sscanf(lines[0], "Active connections: %u \n", &status->active);
    if (rc != 1) {
        goto error;
    }
    rc = sscanf(lines[2], " %u %u %u \n", 
           &status->accepts, &status->handled, &status->requests);
    if (rc != 3) {
        goto error;
    }
    rc = sscanf(lines[3], "Reading: %u Writing: %u Waiting: %u \n",
            &status->reading, &status->writing, &status->waiting);
    if (rc != 3) {
        goto error;
    }

    flb_utils_split_free(mk_lines);
    return 0;
error:
    flb_utils_split_free(mk_lines);
    return -1;
}

static int in_nss_collect(struct flb_input_instance *ins,
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
static int in_nss_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    struct flb_in_nss_config *ctx = (struct flb_in_nss_config *)in_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *client;
    struct flb_in_nss_status status;
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

    data = flb_sds_create_len(client->resp.payload,
                              client->resp.payload_size);
    /* work directly on the data here ... */
    if (in_nss_parse_stub_status(data, &status) == -1) {
        flb_error("[nginx_stub_status] unable to parse stub status response");
        goto status_error;
    }

    cmt_counter_set(ctx->connections, ts, status.active, 
                    1, (char *[]) {"active"});
    cmt_counter_set(ctx->connections, ts, status.reading, 
                    1, (char *[]) {"reading"});
    cmt_counter_set(ctx->connections, ts, status.writing, 
                    1, (char *[]) {"writing"});
    cmt_counter_set(ctx->connections, ts, status.waiting, 
                    1, (char *[]) {"waiting"});
    
    cmt_counter_set(ctx->connection_totals, ts, status.accepts, 
                    1, (char *[]) {"accepts"});
    cmt_counter_set(ctx->connection_totals, ts, status.handled, 
                    1, (char *[]) {"handled"});
    cmt_counter_set(ctx->connection_totals, ts, status.requests, 
                    1, (char *[]) {"requests"});

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
 * Callback function to initialize docker events plugin
 *
 * @param ins     Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 * @param data    Unused
 *
 * @return int 0 on success, -1 on failure
 */
static int in_nss_init(struct flb_input_instance *ins,
                      struct flb_config *config, void *data)
{
    struct flb_in_nss_config *ctx = NULL;
    struct cmt_counter *c;


    /* Allocate space for the configuration */
    ctx = nss_config_init(ins, config);
    if (!ctx) {
        return -1;
    }
    
    c = cmt_counter_create(ctx->cmt, "node", "nginx", "connections", 
                                "Connections to Nginx",
                                1, (char *[]) {"status"});
    if (!c) {
        return -1;
    }
    ctx->connections = c;

    c = cmt_counter_create(ctx->cmt, "node", "nginx", "connection_totals", 
                                "Connection Totals for Nginx",
                                1, (char *[]) {"label"});
    if (!c) {
        return -1;
    }
    ctx->connection_totals = c;

    /* Set the context */
    flb_input_set_context(ins, ctx);

    ctx->coll_id = flb_input_set_collector_time(ins, 
                                                in_nss_collect,
                                                1, 
                                                0, config);
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
static int in_nss_exit(void *data, struct flb_config *config)
{
    struct flb_in_nss_config *ctx = (struct flb_in_nss_config *)data;

    if (!ctx) {
        return 0;
    }

    nss_config_destroy(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_nginx_stub_status_plugin = {
    .name         = "nginx_stub_status",
    .description  = "Nginx status metrics",
    .cb_init      = in_nss_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_nss_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_nss_exit,
    .flags        = FLB_INPUT_NET,
    .event_type   = FLB_INPUT_METRICS
};
