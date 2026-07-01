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
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>

#include "in_collectd.h"
#include "netprot.h"
#include "typesdb.h"

/*
 * Max payload size. By default, Collectd sends up to 1452 bytes
 * per a UDP packet, but the limit can be increased up to 65535
 * bytes through a configuration parameter.
 *
 * See network_config_set_buffer_size() in collectd/src/network.c.
 */
#define BUFFER_SIZE 65535

#define DEFAULT_LISTEN "0.0.0.0"
#define DEFAULT_PORT 25826

/* This is where most Linux systems places a default TypesDB */
#define DEFAULT_TYPESDB "/usr/share/collectd/types.db"

static int in_collectd_callback(struct flb_input_instance *i_ins,
                                struct flb_config *config, void *in_context);

static int in_collectd_init(struct flb_input_instance *in,
                            struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_collectd_config *ctx;
    struct mk_list *tdb;
    char *listen = DEFAULT_LISTEN;
    int port = DEFAULT_PORT;

    /* Initialize context */
    ctx = flb_calloc(1, sizeof(struct flb_in_collectd_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = in;

    ctx->bufsize = BUFFER_SIZE;
    ctx->buf = flb_malloc(ctx->bufsize);
    if (!ctx->buf) {
        flb_errno();
        flb_free(ctx);
        return -1;
    }
    
    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(in, "unable to load configuration");
        flb_free(ctx);
        return -1;
    }

    /* Listening address */
    if (in->host.listen) {
        listen = in->host.listen;
    }

    if (strlen(listen) > sizeof(ctx->listen) - 1) {
        flb_plg_error(ctx->ins, "too long address '%s'", listen);
        flb_free(ctx);
        return -1;
    }
    strcpy(ctx->listen, listen);

    /* Listening port */
    if (in->host.port) {
        port = in->host.port;
    }
    snprintf(ctx->port, sizeof(ctx->port), "%hu", (unsigned short) port);

    flb_plg_debug(ctx->ins, "Loading TypesDB from %s", ctx->types_db);

    tdb = typesdb_load_all(ctx, ctx->types_db);
    if (!tdb) {
        flb_plg_error(ctx->ins, "failed to load '%s'", ctx->types_db);
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }
    ctx->tdb = tdb;

    /* Set the context */
    flb_input_set_context(in, ctx);

    ctx->server_fd = flb_net_server_udp(ctx->port, ctx->listen, 
                                        in->net_setup.share_port);
    if (ctx->server_fd < 0) {
        flb_plg_error(ctx->ins, "failed to bind to %s:%s", ctx->listen,
                      ctx->port);
        typesdb_destroy(ctx->tdb);
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }

    /* Set the collector */
    ret = flb_input_set_collector_socket(in,
                                         in_collectd_callback,
                                         ctx->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed set up a collector");
        flb_socket_close(ctx->server_fd);
        typesdb_destroy(ctx->tdb);
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd = ret;

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "error initializing event encoder : %d", ret);

        flb_socket_close(ctx->server_fd);
        typesdb_destroy(ctx->tdb);
        flb_free(ctx->buf);
        flb_free(ctx);

        return -1;
    }

    flb_plg_info(ctx->ins, "start listening to %s:%s",
                 ctx->listen, ctx->port);

    return 0;
}

static int in_collectd_callback(struct flb_input_instance *i_ins,
                                struct flb_config *config, void *in_context)
{
    int len;
    struct flb_in_collectd_config *ctx = in_context;

    len = recv(ctx->server_fd, ctx->buf, ctx->bufsize, 0);
    if (len < 0) {
        flb_errno();
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    flb_log_event_encoder_reset(&ctx->log_encoder);

    if (netprot_to_msgpack(ctx->buf, len, ctx->tdb, &ctx->log_encoder)) {
        flb_plg_error(ctx->ins, "netprot_to_msgpack fails");

        return -1;
    }

    if (ctx->log_encoder.output_length > 0) {
        flb_input_log_append(i_ins, NULL, 0,
                             ctx->log_encoder.output_buffer,
                             ctx->log_encoder.output_length);
    }

    return 0;
}

static int in_collectd_exit(void *data, struct flb_config *config)
{
    struct flb_in_collectd_config *ctx = data;

    flb_log_event_encoder_destroy(&ctx->log_encoder);
    flb_socket_close(ctx->server_fd);
    flb_pipe_close(ctx->coll_fd);
    typesdb_destroy(ctx->tdb);
    flb_free(ctx->buf);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "typesdb", DEFAULT_TYPESDB,
     0, FLB_TRUE, offsetof(struct flb_in_collectd_config, types_db),
     "Set the types database filename"
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_collectd_plugin = {
    .name         = "collectd",
    .description  = "collectd input plugin",
    .cb_init      = in_collectd_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER,
    .cb_exit      = in_collectd_exit
};
