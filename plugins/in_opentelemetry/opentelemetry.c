/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>

#include "http_conn.h"
#include "opentelemetry.h"
#include "opentelemetry_config.h"

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new TCP instance which will wait for
 * JSON map messages.
 */
static int in_opentelemetry_collect(struct flb_input_instance *ins,
                                    struct flb_config *config, void *in_context)
{
    struct flb_connection    *connection;
    struct http_conn         *conn;
    struct flb_opentelemetry *ctx;

    ctx = in_context;

    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could not accept new connection");

        return -1;
    }

    flb_plg_trace(ctx->ins, "new TCP connection arrived FD=%i", connection->fd);

    conn = opentelemetry_conn_add(connection, ctx);

    if (conn == NULL) {
        return -1;
    }

    return 0;
}

static int in_opentelemetry_init(struct flb_input_instance *ins,
                                 struct flb_config *config, void *data)
{
    unsigned short int        port;
    int                       ret;
    struct flb_opentelemetry *ctx;

    (void) data;

    /* Create context and basic conf */
    ctx = opentelemetry_config_create(ins);
    if (!ctx) {
        return -1;
    }
    ctx->collector_id = -1;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        opentelemetry_config_destroy(ctx);
        return -1;
    }

    /* Set the context */
    flb_input_set_context(ins, ctx);

    port = (unsigned short int) strtoul(ctx->tcp_port, NULL, 10);

    ctx->downstream = flb_downstream_create(FLB_TRANSPORT_TCP,
                                            ins->flags,
                                            ctx->listen,
                                            port,
                                            ins->tls,
                                            config,
                                            &ins->net_setup);

    if (ctx->downstream == NULL) {
        flb_plg_error(ctx->ins,
                      "could not initialize downstream on %s:%s. Aborting",
                      ctx->listen, ctx->tcp_port);

        opentelemetry_config_destroy(ctx);

        return -1;
    }

    flb_input_downstream_set(ctx->downstream, ctx->ins);

    flb_plg_info(ctx->ins, "listening on %s:%s", ctx->listen, ctx->tcp_port);

    if (ctx->successful_response_code != 200 &&
        ctx->successful_response_code != 201 &&
        ctx->successful_response_code != 204) {
        flb_plg_error(ctx->ins, "%d is not supported response code. Use default 201",
                      ctx->successful_response_code);
        ctx->successful_response_code = 201;
    }

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(ins,
                                         in_opentelemetry_collect,
                                         ctx->downstream->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for IN_TCP input plugin");
        opentelemetry_config_destroy(ctx);
        return -1;
    }

    ctx->collector_id = ret;

    return 0;
}

static int in_opentelemetry_exit(void *data, struct flb_config *config)
{
    struct flb_opentelemetry *ctx;

    (void) config;

    ctx = data;

    if (ctx != NULL) {
        opentelemetry_config_destroy(ctx);
    }

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SIZE, "buffer_max_size", HTTP_BUFFER_MAX_SIZE,
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, buffer_max_size),
     ""
    },

    {
     FLB_CONFIG_MAP_SIZE, "buffer_chunk_size", HTTP_BUFFER_CHUNK_SIZE,
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, buffer_chunk_size),
     ""
    },

    {
     FLB_CONFIG_MAP_STR, "tag_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, tag_key),
     ""
    },
    {
     FLB_CONFIG_MAP_INT, "successful_response_code", "201",
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, successful_response_code),
     "Set successful response code. 200, 201 and 204 are supported."
    },
    {
     FLB_CONFIG_MAP_BOOL, "raw_traces", "false",
     0, FLB_TRUE, offsetof(struct flb_opentelemetry, raw_traces),
     "Forward traces without processing"
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_opentelemetry_plugin = {
    .name         = "opentelemetry",
    .description  = "OpenTelemetry",
    .cb_init      = in_opentelemetry_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_opentelemetry_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = in_opentelemetry_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_IO_OPT_TLS
};
