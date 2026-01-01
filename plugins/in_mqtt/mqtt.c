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

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_config_map.h>

#include "mqtt.h"
#include "mqtt_conn.h"
#include "mqtt_config.h"

/* Initialize plugin */
static int in_mqtt_init(struct flb_input_instance *in,
                        struct flb_config *config, void *data)
{
    unsigned short int         port;
    int                        ret;
    struct flb_in_mqtt_config *ctx;

    (void) data;

    /* Allocate space for the configuration */
    ctx = mqtt_config_init(in);
    if (!ctx) {
        return -1;
    }
    ctx->ins = in;
    ctx->msgp_len = 0;

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Create downstream */
    port = (unsigned short int) strtoul(ctx->tcp_port, NULL, 10);

    ctx->downstream = flb_downstream_create(FLB_TRANSPORT_TCP,
                                            in->flags,
                                            ctx->listen,
                                            port,
                                            in->tls,
                                            config,
                                            &in->net_setup);

    if (ctx->downstream == NULL) {
        flb_plg_error(ctx->ins,
                      "could not initialize downstream on %s:%s. Aborting",
                      ctx->listen, ctx->tcp_port);

        mqtt_config_free(ctx);

        return -1;
    }

    flb_input_downstream_set(ctx->downstream, ctx->ins);

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_event(in,
                                        in_mqtt_collect,
                                        ctx->downstream->server_fd,
                                        config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set collector for MQTT input plugin");
        mqtt_config_free(ctx);
        return -1;
    }

    return 0;
}

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new MQTT instance which will wait for
 * events/data (MQTT control packages)
 */
int in_mqtt_collect(struct flb_input_instance *ins,
                    struct flb_config *config, void *in_context)
{
    struct flb_connection     *connection;
    struct mqtt_conn          *conn;
    struct flb_in_mqtt_config *ctx;

    ctx = in_context;

    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could not accept new connection");

        return -1;
    }

    flb_plg_debug(ctx->ins, "[fd=%i] new TCP connection", connection->fd);

    conn = mqtt_conn_add(connection, ctx);

    if (!conn) {
        flb_downstream_conn_release(connection);

        return -1;
    }

    return 0;
}

static int in_mqtt_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_mqtt_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    mqtt_conn_destroy_all(ctx);

    mqtt_config_free(ctx);

    return 0;
}

/* Configuration properties map */	
static struct flb_config_map config_map[] = {	
    {
     FLB_CONFIG_MAP_STR, "payload_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_mqtt_config, payload_key),
     "Key where the payload will be preserved"
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_size", MQTT_CONNECTION_DEFAULT_BUFFER_SIZE,
     0, FLB_TRUE, offsetof(struct flb_in_mqtt_config, buffer_size),
     "Maximum payload size"
    },
    /* EOF */	
    {0}	
};

/* Plugin reference */
struct flb_input_plugin in_mqtt_plugin = {
    .name         = "mqtt",
    .description  = "MQTT, listen for Publish messages",
    .cb_init      = in_mqtt_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_mqtt_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_mqtt_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_IO_OPT_TLS
};
