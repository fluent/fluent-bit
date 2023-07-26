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
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>

#include "splunk.h"
#include "splunk_conn.h"
#include "splunk_config.h"

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new TCP instance which will wait for
 * JSON map messages.
 */
static int in_splunk_collect(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    struct flb_connection *connection;
    struct splunk_conn      *conn;
    struct flb_splunk       *ctx;

    ctx = in_context;

    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could not accept new connection");

        return -1;
    }

    flb_plg_trace(ctx->ins, "new TCP connection arrived FD=%i",
                  connection->fd);

    conn = splunk_conn_add(connection, ctx);

    if (conn == NULL) {
        flb_downstream_conn_release(connection);

        return -1;
    }

    return 0;
}

static int in_splunk_init(struct flb_input_instance *ins,
                          struct flb_config *config, void *data)
{
    unsigned short int  port;
    int                 ret;
    struct flb_splunk    *ctx;

    (void) data;

    /* Create context and basic conf */
    ctx = splunk_config_create(ins);
    if (!ctx) {
        return -1;
    }

    ctx->collector_id = -1;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        splunk_config_destroy(ctx);
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

        splunk_config_destroy(ctx);

        return -1;
    }

    flb_input_downstream_set(ctx->downstream, ctx->ins);

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(ins,
                                         in_splunk_collect,
                                         ctx->downstream->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for IN_TCP input plugin");
        splunk_config_destroy(ctx);

        return -1;
    }

    ctx->collector_id = ret;

    return 0;
}

static int in_splunk_exit(void *data, struct flb_config *config)
{
    struct flb_splunk *ctx;

    (void) config;

    ctx = data;

    if (ctx != NULL) {
        splunk_config_destroy(ctx);
    }

    return 0;
}


static void in_splunk_pause(void *data, struct flb_config *config)
{
    struct flb_splunk *ctx = data;

    flb_input_collector_pause(ctx->collector_id, ctx->ins);

}

static void in_splunk_resume(void *data, struct flb_config *config)
{
    struct flb_splunk *ctx = data;

    flb_input_collector_resume(ctx->collector_id, ctx->ins);
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SIZE, "buffer_max_size", HTTP_BUFFER_MAX_SIZE,
     0, FLB_TRUE, offsetof(struct flb_splunk, buffer_max_size),
     ""
    },

    {
     FLB_CONFIG_MAP_SIZE, "buffer_chunk_size", HTTP_BUFFER_CHUNK_SIZE,
     0, FLB_TRUE, offsetof(struct flb_splunk, buffer_chunk_size),
     ""
    },

    {
     FLB_CONFIG_MAP_SLIST_1, "success_header", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_splunk, success_headers),
     "Add an HTTP header key/value pair on success. Multiple headers can be set"
    },

    {
     FLB_CONFIG_MAP_STR, "splunk_token", NULL,
     0, FLB_FALSE, 0,
     "Set valid Splunk HEC tokens for the requests"
    },

    {
     FLB_CONFIG_MAP_STR, "tag_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, tag_key),
     ""
    },


    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_splunk_plugin = {
    .name         = "splunk",
    .description  = "Input plugin for Splunk HEC payloads",
    .cb_init      = in_splunk_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_splunk_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_splunk_pause,
    .cb_resume    = in_splunk_resume,
    .cb_exit      = in_splunk_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_IO_OPT_TLS
};
