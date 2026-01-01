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
#include <fluent-bit/flb_random.h>

#include "in_elasticsearch.h"
#include "in_elasticsearch_config.h"
#include "in_elasticsearch_bulk_prot.h"
#include "in_elasticsearch_bulk_conn.h"

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new TCP instance which will wait for
 * JSON map messages.
 */
static int in_elasticsearch_bulk_collect(struct flb_input_instance *ins,
                                         struct flb_config *config, void *in_context)
{
    struct flb_connection *connection;
    struct in_elasticsearch_bulk_conn *conn;
    struct flb_in_elasticsearch    *ctx;

    ctx = in_context;

    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could not accept new connection");

        return -1;
    }

    flb_plg_trace(ctx->ins, "new TCP connection arrived FD=%i",
                  connection->fd);

    conn = in_elasticsearch_bulk_conn_add(connection, ctx);

    if (conn == NULL) {
        flb_downstream_conn_release(connection);

        return -1;
    }

    return 0;
}

static void bytes_to_groupname(unsigned char *data, char *buf, size_t len) {
    int index;
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (len-- > 0) {
        index = (int) data[len];
        index = index % (sizeof(charset) - 1);
        buf[len] = charset[index];
    }
}

static void bytes_to_nodename(unsigned char *data, char *buf, size_t len) {
    int index;
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz";

    while (len-- > 0) {
        index = (int) data[len];
        index = index % (sizeof(charset) - 1);
        buf[len] = charset[index];
    }
}

static int in_elasticsearch_bulk_init(struct flb_input_instance *ins,
                                      struct flb_config *config, void *data)
{
    unsigned short int  port;
    int                 ret;
    struct flb_in_elasticsearch    *ctx;
    unsigned char rand[16];

    (void) data;

    /* Create context and basic conf */
    ctx = in_elasticsearch_config_create(ins);
    if (!ctx) {
        return -1;
    }

    ctx->collector_id = -1;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        in_elasticsearch_config_destroy(ctx);
        return -1;
    }

    /* Set the context */
    flb_input_set_context(ins, ctx);

    port = (unsigned short int) strtoul(ctx->tcp_port, NULL, 10);

    if (flb_random_bytes(rand, 16)) {
        flb_plg_error(ctx->ins, "cannot generate cluster name");
        in_elasticsearch_config_destroy(ctx);
        return -1;
    }

    bytes_to_groupname(rand, ctx->cluster_name, 16);

    if (flb_random_bytes(rand, 12)) {
        flb_plg_error(ctx->ins, "cannot generate node name");
        in_elasticsearch_config_destroy(ctx);
        return -1;
    }

    bytes_to_nodename(rand, ctx->node_name, 12);

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

            in_elasticsearch_config_destroy(ctx);

            return -1;
        }

        ret = flb_http_server_start(&ctx->http_server);

        if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "could not start http server on %s:%u. Aborting",
                          ins->host.listen, ins->host.port);

            in_elasticsearch_config_destroy(ctx);

            return -1;
        }

        flb_http_server_set_buffer_max_size(&ctx->http_server, ctx->buffer_max_size);

        ctx->http_server.request_callback = in_elasticsearch_bulk_prot_handle_ng;

        flb_input_downstream_set(ctx->http_server.downstream, ctx->ins);
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

            in_elasticsearch_config_destroy(ctx);

            return -1;
        }

        flb_input_downstream_set(ctx->downstream, ctx->ins);

        /* Collect upon data available on the standard input */
        ret = flb_input_set_collector_socket(ins,
                                            in_elasticsearch_bulk_collect,
                                            ctx->downstream->server_fd,
                                            config);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Could not set collector for IN_ELASTICSEARCH input plugin");
            in_elasticsearch_config_destroy(ctx);

            return -1;
        }

        ctx->collector_id = ret;
    }

    return 0;
}

static int in_elasticsearch_bulk_exit(void *data, struct flb_config *config)
{
    struct flb_in_elasticsearch *ctx;

    (void) config;

    ctx = data;

    if (ctx != NULL) {
        in_elasticsearch_config_destroy(ctx);
    }

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "http2", "true",
     0, FLB_TRUE, offsetof(struct flb_in_elasticsearch, enable_http2),
     "Enable HTTP/2 support"
    },

    {
     FLB_CONFIG_MAP_SIZE, "buffer_max_size", HTTP_BUFFER_MAX_SIZE,
     0, FLB_TRUE, offsetof(struct flb_in_elasticsearch, buffer_max_size),
     "Set the maximum size of buffer"
    },

    {
     FLB_CONFIG_MAP_SIZE, "buffer_chunk_size", HTTP_BUFFER_CHUNK_SIZE,
     0, FLB_TRUE, offsetof(struct flb_in_elasticsearch, buffer_chunk_size),
     "Set the buffer chunk size"
    },

    {
     FLB_CONFIG_MAP_STR, "tag_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_elasticsearch, tag_key),
     "Specify a key name for extracting as a tag"
    },

    {
     FLB_CONFIG_MAP_STR, "meta_key", "@meta",
     0, FLB_TRUE, offsetof(struct flb_in_elasticsearch, meta_key),
     "Specify a key name for meta information"
    },

    {
     FLB_CONFIG_MAP_STR, "hostname", "localhost",
     0, FLB_TRUE, offsetof(struct flb_in_elasticsearch, hostname),
     "Specify hostname or FQDN. This parameter is effective for sniffering node information."
    },

    {
     FLB_CONFIG_MAP_STR, "version", "8.0.0",
     0, FLB_TRUE, offsetof(struct flb_in_elasticsearch, es_version),
     "Specify returning Elasticsearch server version."
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_elasticsearch_plugin = {
    .name         = "elasticsearch",
    .description  = "HTTP Endpoints for Elasticsearch (Bulk API)",
    .cb_init      = in_elasticsearch_bulk_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_elasticsearch_bulk_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = in_elasticsearch_bulk_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_IO_OPT_TLS
};
