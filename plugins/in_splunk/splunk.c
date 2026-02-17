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
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_config.h>

#include "splunk.h"
#include "splunk_conn.h"
#include "splunk_prot.h"
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


    if (ctx->enable_http2) {
        ret = flb_http_server_init(&ctx->http_server,
                                    HTTP_PROTOCOL_VERSION_AUTODETECT,
                                    (FLB_HTTP_SERVER_FLAG_KEEPALIVE | FLB_HTTP_SERVER_FLAG_AUTO_INFLATE),
                                    NULL,
                                    ins->host.listen,
                                    ins->host.port,
                                    ins->tls,
                                    ins->flags,
                                    &ins->net_setup,
                                    flb_input_event_loop_get(ins),
                                    ins->config,
                                    (void *) ctx);

        if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "could not initialize http server on %s:%u. Aborting",
                          ins->host.listen, ins->host.port);

            splunk_config_destroy(ctx);

            return -1;
        }

        ret = flb_http_server_start(&ctx->http_server);

        if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "could not start http server on %s:%u. Aborting",
                          ins->host.listen, ins->host.port);

            splunk_config_destroy(ctx);

            return -1;
        }

        flb_http_server_set_buffer_max_size(&ctx->http_server, ctx->buffer_max_size);

        ctx->http_server.request_callback = splunk_prot_handle_ng;

        flb_input_downstream_set(ctx->http_server.downstream, ctx->ins);

        flb_plg_info(ctx->ins, "listening on %s:%u",
                     ins->host.listen, ins->host.port);
    }
    else {
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

        flb_plg_info(ctx->ins, "listening on %s:%s", ctx->listen, ctx->tcp_port);

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
    }


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
     FLB_CONFIG_MAP_BOOL, "http2", "true",
     0, FLB_TRUE, offsetof(struct flb_splunk, enable_http2),
     "Enable HTTP/2 support"
    },

    {
     FLB_CONFIG_MAP_SIZE, "buffer_max_size", HTTP_BUFFER_MAX_SIZE,
     0, FLB_TRUE, offsetof(struct flb_splunk, buffer_max_size),
     "Set the maximum size of buffer"
    },

    {
     FLB_CONFIG_MAP_SIZE, "buffer_chunk_size", HTTP_BUFFER_CHUNK_SIZE,
     0, FLB_TRUE, offsetof(struct flb_splunk, buffer_chunk_size),
     "Set the initial buffer size to store incoming data"
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
     FLB_CONFIG_MAP_BOOL, "store_token_in_metadata", "true",
     0, FLB_TRUE, offsetof(struct flb_splunk, store_token_in_metadata),
     "Store Splunk HEC tokens in metadata. If set as false, they will be stored into records."
    },

    {
     FLB_CONFIG_MAP_STR, "splunk_token_key", "@splunk_token",
     0, FLB_TRUE, offsetof(struct flb_splunk, store_token_key),
     "Set a record key for storing Splunk HEC token for the request"
    },

    {
     FLB_CONFIG_MAP_STR, "tag_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_splunk, tag_key),
     "Set a record key to specify the tag of the record"
    },

    {
     FLB_CONFIG_MAP_SLIST_2, "map_token_to_tag", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_splunk, token_to_tag_mappings),
     "Map input records from given Splunk HEC token to given tag. Multiple of these can be set to map different tokens to different tags."
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
