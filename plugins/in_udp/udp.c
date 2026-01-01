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
#include <msgpack.h>

#include "udp.h"
#include "udp_conn.h"
#include "udp_config.h"

static int in_udp_collect(struct flb_input_instance *in,
                          struct flb_config *config,
                          void *in_context)
{
    struct flb_connection    *connection;
    struct flb_in_udp_config *ctx;

    ctx = in_context;

    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could get UDP server dummy connection");

        return -1;
    }

    return udp_conn_event(connection);
}

/* Initialize plugin */
static int in_udp_init(struct flb_input_instance *in,
                       struct flb_config *config, void *data)
{
    struct flb_connection    *connection;
    unsigned short int        port;
    int                       ret;
    struct flb_in_udp_config *ctx;

    (void) data;

    /* Allocate space for the configuration */
    ctx = udp_config_init(in);

    if (ctx == NULL) {
        return -1;
    }

    ctx->collector_id = -1;
    ctx->ins = in;

    /* Set the context */
    flb_input_set_context(in, ctx);

    port = (unsigned short int) strtoul(ctx->port, NULL, 10);

    ctx->downstream = flb_downstream_create(FLB_TRANSPORT_UDP,
                                            in->flags,
                                            ctx->listen,
                                            port,
                                            in->tls,
                                            config,
                                            &in->net_setup);

    if (ctx->downstream == NULL) {
        flb_plg_error(ctx->ins,
                      "could not initialize downstream on %s:%s. Aborting",
                      ctx->listen, ctx->port);

        udp_config_destroy(ctx);

        return -1;
    }

    flb_input_downstream_set(ctx->downstream, ctx->ins);

    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could not get UDP server dummy connection");

        udp_config_destroy(ctx);

        return -1;
    }

    ctx->dummy_conn = udp_conn_add(connection, ctx);

    if (ctx->dummy_conn == NULL) {
        flb_plg_error(ctx->ins, "could not track UDP server dummy connection");

        udp_config_destroy(ctx);

        return -1;
    }

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(in,
                                         in_udp_collect,
                                         ctx->downstream->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for IN_UDP input plugin");
        udp_config_destroy(ctx);

        return -1;
    }

    ctx->collector_id = ret;
    ctx->collector_event = flb_input_collector_get_event(ret, in);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not get collector event");
        udp_config_destroy(ctx);

        return -1;
    }

    return 0;
}

static int in_udp_exit(void *data, struct flb_config *config)
{
    struct flb_in_udp_config *ctx;

    (void) *config;

    ctx = data;

    if (ctx->dummy_conn != NULL) {
        udp_conn_del(ctx->dummy_conn);
    }

    udp_config_destroy(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_udp_config, format_name),
     "Set the format: json or none"
    },
    {
     FLB_CONFIG_MAP_STR, "separator", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_udp_config, raw_separator),
     "Set separator"
    },
    {
      FLB_CONFIG_MAP_STR, "chunk_size", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_udp_config, chunk_size_str),
      "Set the chunk size"
    },
    {
      FLB_CONFIG_MAP_STR, "buffer_size", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_udp_config, buffer_size_str),
      "Set the buffer size"
    },
    {
      FLB_CONFIG_MAP_STR, "source_address_key", (char *) NULL,
      0, FLB_TRUE, offsetof(struct flb_in_udp_config, source_address_key),
      "Key where the source address will be injected"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_udp_plugin = {
    .name         = "udp",
    .description  = "UDP",
    .cb_init      = in_udp_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_udp_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_udp_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER,
};
