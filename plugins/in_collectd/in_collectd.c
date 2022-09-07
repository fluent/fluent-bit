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
    char                          *listen;
    unsigned short int             port;
    int                            ret;
    struct flb_in_collectd_config *ctx;
    struct mk_list                *tdb;

    listen = DEFAULT_LISTEN;
    port = DEFAULT_PORT;

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

    ctx->downstream = flb_downstream_create(FLB_TRANSPORT_UDP,
                                            in->flags,
                                            ctx->listen,
                                            port,
                                            NULL,
                                            config,
                                            &in->net_setup);

    if (ctx->downstream == NULL) {
        flb_plg_error(ctx->ins,
                      "could not initialize downstream on %s:%s. Aborting",
                      ctx->listen, ctx->port);

        typesdb_destroy(ctx->tdb);

        flb_free(ctx->buf);
        flb_free(ctx);

        return -1;
    }

    /* Set the collector */
    ret = flb_input_set_collector_socket(in,
                                         in_collectd_callback,
                                         ctx->downstream->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "failed set up a collector");

        flb_downstream_destroy(ctx->downstream);

        typesdb_destroy(ctx->tdb);

        flb_free(ctx->buf);
        flb_free(ctx);

        return -1;
    }

    ctx->coll_fd = ret;

    flb_plg_info(ctx->ins, "start listening to %s:%s",
                 ctx->listen, ctx->port);
    return 0;
}

static int in_collectd_callback(struct flb_input_instance *i_ins,
                                struct flb_config *config, void *in_context)
{
    struct flb_connection         *connection;
    msgpack_sbuffer                sbuf;
    msgpack_packer                 pck;
    int                            len;
    struct flb_in_collectd_config *ctx;

    ctx = in_context;

    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could get UDP server dummy connection");

        return -1;
    }

    /* Read data */
    len = flb_io_net_read(connection,
                          (void *) ctx->buf,
                          ctx->bufsize);

    if (len < 0) {
        flb_errno();
        return -1;
    }
    else if (len == 0) {
        return 0;
    }

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    if (netprot_to_msgpack(ctx->buf, len, ctx->tdb, &pck)) {
        flb_plg_error(ctx->ins, "netprot_to_msgpack fails");
        msgpack_sbuffer_destroy(&sbuf);
        return -1;
    }

    flb_input_chunk_append_raw(i_ins, NULL, 0, sbuf.data, sbuf.size);

    msgpack_sbuffer_destroy(&sbuf);

    return 0;
}

static int in_collectd_exit(void *data, struct flb_config *config)
{
    struct flb_in_collectd_config *ctx = data;

    if (ctx->downstream != NULL) {
        flb_downstream_destroy(ctx->downstream);
    }

    /* This seems wrong, probably some legacy remains but I
     * don't want to break stuff so I'll leave it as is.
     */
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
    .cb_exit      = in_collectd_exit
};
