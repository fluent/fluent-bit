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
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_downstream_worker.h>
#include <msgpack.h>

#include "udp.h"
#include "udp_conn.h"
#include "udp_config.h"

static int in_udp_collect_ctx(struct flb_in_udp_config *ctx);
static int in_udp_collect(struct flb_input_instance *in,
                          struct flb_config *config,
                          void *in_context);

static int in_udp_worker_listener_event(void *data)
{
    struct mk_event *event;

    event = data;

    return in_udp_collect_ctx(event->data);
}

static void in_udp_dummy_conn_destroy(struct flb_in_udp_config *ctx)
{
    if (ctx->dummy_conn != NULL) {
        udp_conn_del(ctx->dummy_conn);
        ctx->dummy_conn = NULL;
    }
}

static int in_udp_start_listener(struct flb_in_udp_config *ctx,
                                 struct flb_config *config,
                                 struct flb_net_setup *net_setup,
                                 struct mk_event_loop *event_loop,
                                 int use_collector)
{
    int ret;
    unsigned short int port;
    struct flb_connection *connection;

    port = (unsigned short int) strtoul(ctx->port, NULL, 10);

    ctx->downstream = flb_downstream_create(FLB_TRANSPORT_UDP,
                                            ctx->ins->flags,
                                            ctx->listen,
                                            port,
                                            ctx->ins->tls,
                                            config,
                                            net_setup);

    if (ctx->downstream == NULL) {
        flb_plg_error(ctx->ins,
                      "could not initialize downstream on %s:%s. Aborting",
                      ctx->listen, ctx->port);
        return -1;
    }

    flb_input_downstream_set(ctx->downstream, ctx->ins);

    connection = flb_downstream_conn_get(ctx->downstream);
    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could not get UDP server dummy connection");
        return -1;
    }

    ctx->dummy_conn = udp_conn_add(connection, ctx);
    if (ctx->dummy_conn == NULL) {
        flb_plg_error(ctx->ins, "could not track UDP server dummy connection");
        return -1;
    }

    if (use_collector == FLB_TRUE) {
        ret = flb_input_set_collector_socket(ctx->ins,
                                             in_udp_collect,
                                             ctx->downstream->server_fd,
                                             config);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "Could not set collector for IN_UDP input plugin");
            in_udp_dummy_conn_destroy(ctx);
            return -1;
        }

        ctx->collector_id = ret;
        ctx->collector_event = flb_input_collector_get_event(ret, ctx->ins);

        if (ctx->collector_event == NULL) {
            flb_plg_error(ctx->ins, "Could not get collector event");
            in_udp_dummy_conn_destroy(ctx);
            return -1;
        }
    }
    else {
        ctx->event_loop = event_loop;
        MK_EVENT_NEW(&ctx->listener_event);
        ctx->listener_event.type = FLB_ENGINE_EV_CUSTOM;
        ctx->listener_event.data = ctx;
        ctx->listener_event.handler = in_udp_worker_listener_event;

        ret = mk_event_add(event_loop,
                           ctx->downstream->server_fd,
                           FLB_ENGINE_EV_CUSTOM,
                           MK_EVENT_READ,
                           &ctx->listener_event);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not register UDP worker listener");
            in_udp_dummy_conn_destroy(ctx);
            return -1;
        }

        ctx->listener_registered = FLB_TRUE;
    }

    return 0;
}

static int in_udp_worker_init(struct flb_downstream_worker *worker,
                              void *parent,
                              void **worker_context)
{
    int ret;
    struct flb_in_udp_config *ctx;
    struct flb_in_udp_config *parent_ctx;

    parent_ctx = parent;

    ctx = udp_config_init(parent_ctx->ins);
    if (ctx == NULL) {
        return -1;
    }

    *worker_context = ctx;

    ctx->collector_id = -1;
    ctx->ins = parent_ctx->ins;
    ctx->workers = parent_ctx->workers;
    ctx->worker_id = worker->worker_id;
    ctx->use_ingress_queue = FLB_TRUE;
    ctx->net_setup = parent_ctx->ins->net_setup;
    ctx->net_setup.share_port = FLB_TRUE;

    ret = in_udp_start_listener(ctx,
                                parent_ctx->ins->config,
                                &ctx->net_setup,
                                worker->event_loop,
                                FLB_FALSE);
    if (ret == 0) {
        flb_downstream_thread_safe(ctx->downstream);
    }

    return ret;
}

static void in_udp_worker_exit(struct flb_downstream_worker *worker,
                               void *worker_context)
{
    struct flb_in_udp_config *ctx;

    (void) worker;

    ctx = worker_context;

    in_udp_dummy_conn_destroy(ctx);
    udp_config_destroy(ctx);
}

static void in_udp_worker_maintenance(struct flb_downstream_worker *worker,
                                      void *worker_context)
{
    struct flb_in_udp_config *ctx;

    (void) worker;

    ctx = worker_context;

    if (ctx->downstream != NULL) {
        flb_downstream_conn_pending_destroy(ctx->downstream);
    }
}

static int in_udp_workers_start(struct flb_in_udp_config *ctx)
{
    struct flb_downstream_worker_options options;

    memset(&options, 0, sizeof(struct flb_downstream_worker_options));
    options.workers = ctx->workers;
    options.config = ctx->ins->config;
    options.parent = ctx;
    options.cb_init = in_udp_worker_init;
    options.cb_exit = in_udp_worker_exit;
    options.cb_maintenance = in_udp_worker_maintenance;

    return flb_downstream_worker_runtime_start(&ctx->runtime, &options);
}

static void in_udp_workers_stop(struct flb_in_udp_config *ctx)
{
    flb_downstream_worker_runtime_stop(ctx->runtime);
    ctx->runtime = NULL;
}

static int in_udp_collect(struct flb_input_instance *in,
                          struct flb_config *config,
                          void *in_context)
{
    (void) in;
    (void) config;

    return in_udp_collect_ctx(in_context);
}

static int in_udp_collect_ctx(struct flb_in_udp_config *ctx)
{
    struct flb_connection    *connection;

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

    if (ctx->workers <= 0) {
        ctx->workers = 1;
    }

    if (ctx->workers > 1) {
        ret = flb_input_ingress_enable(in);
        if (ret != 0) {
            udp_config_destroy(ctx);
            return -1;
        }

        ret = in_udp_workers_start(ctx);
        if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "could not start UDP listener workers on %s:%s. Aborting",
                          ctx->listen, ctx->port);
            udp_config_destroy(ctx);
            return -1;
        }
    }
    else {
        ret = in_udp_start_listener(ctx, config, &in->net_setup, NULL, FLB_TRUE);
        if (ret != 0) {
            udp_config_destroy(ctx);
            return -1;
        }
    }

    flb_plg_info(ctx->ins,
                 "listening on %s:%s with %i worker%s",
                 ctx->listen, ctx->port, ctx->workers,
                 ctx->workers == 1 ? "" : "s");

    return 0;
}

static int in_udp_exit(void *data, struct flb_config *config)
{
    struct flb_in_udp_config *ctx;

    (void) *config;

    ctx = data;

    in_udp_workers_stop(ctx);
    in_udp_dummy_conn_destroy(ctx);

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
     FLB_CONFIG_MAP_STR, "parser", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_udp_config, parser_name),
     "Optional parser for line-delimited records"
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
    {
      FLB_CONFIG_MAP_INT, "workers", "1",
      0, FLB_TRUE, offsetof(struct flb_in_udp_config, workers),
      "Set the number of UDP listener workers"
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
