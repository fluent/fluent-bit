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

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>

#include "mqtt.h"
#include "mqtt_conn.h"
#include "mqtt_config.h"

/* Initialize plugin */
int in_mqtt_init(struct flb_config *config)
{
    int ret;
    struct flb_in_mqtt_config *ctx;

    /* Allocate space for the configuration */
    ctx = mqtt_config_init(config->file);
    if (!ctx) {
        return -1;
    }
    ctx->msgp_len = 0;

    /* Set the context */
    ret = flb_input_set_context("mqtt", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for MQTT input plugin");
    }

    /* Create TCP server */
    ctx->server_fd = flb_net_server(ctx->tcp_port, ctx->listen);
    if (ctx->server_fd > 0) {
        flb_debug("[mqtt] binding %s:%s", ctx->listen, ctx->tcp_port);
    }
    else {
        flb_error("[mqtt] could not bind address %s:%s. Aborting",
                  ctx->listen, ctx->tcp_port);
        exit(EXIT_FAILURE);
    }
    ctx->evl = config->evl;

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_event("mqtt",
                                        in_mqtt_collect,
                                        ctx->server_fd,
                                        config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for MQTT input plugin");
    }

    return 0;
}

void *in_mqtt_flush(void *in_context, int *size)
{
    char *buf;
    struct flb_in_mqtt_config *ctx = in_context;

    buf = malloc(ctx->msgp_len);
    memcpy(buf, ctx->msgp, ctx->msgp_len);
    *size = ctx->msgp_len;
    ctx->msgp_len = 0;

    return buf;
}

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new MQTT instance which will wait for
 * events/data (MQTT control packages)
 */
int in_mqtt_collect(struct flb_config *config, void *in_context)
{
    int fd;
    struct flb_in_mqtt_config *ctx = in_context;
    struct mqtt_conn *conn;

    /* Accept the new connection */
    fd = flb_net_accept(ctx->server_fd);
    if (fd == -1) {
        flb_error("[mqtt] could not accept new connection");
        return -1;
    }

    flb_debug("[mqtt] new TCP connection arrived FD=%i", fd);
    conn = mqtt_conn_add(fd, ctx);
    if (!conn) {
        return -1;
    }
    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_mqtt_plugin = {
    .name         = "mqtt",
    .description  = "MQTT, listen for Publish messages",
    .cb_init      = in_mqtt_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_mqtt_collect,
    .cb_flush_buf = in_mqtt_flush,
};
