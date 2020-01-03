/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>
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
#define DEFAULT_TYPESDB "/usr/share/collectd/types.db";

struct flb_in_collectd_config {
    char *buf;
    int bufsize;

    /* Server */
    char listen[256]; /* RFC-2181 */
    char port[6];     /* RFC-793 */

    /* Sockets */
    flb_sockfd_t server_fd;
    flb_pipefd_t coll_fd;

    struct mk_list *tdb;

    /* Plugin input instance */
    struct flb_input_instance *i_ins;
};

static int in_collectd_callback(struct flb_input_instance *i_ins,
                                struct flb_config *config, void *in_context);

static int in_collectd_init(struct flb_input_instance *in,
                            struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
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
    ctx->i_ins = in;

    ctx->bufsize = BUFFER_SIZE;
    ctx->buf = flb_malloc(ctx->bufsize);
    if (!ctx->buf) {
        flb_errno();
        flb_free(ctx);
        return -1;
    }

    /* Listening address */
    if (in->host.listen) {
        listen = in->host.listen;
    }

    if (strlen(listen) > sizeof(ctx->listen) - 1) {
        flb_error("[in_collectd] too long address '%s'", listen);
        flb_free(ctx);
        return -1;
    }
    strcpy(ctx->listen, listen);

    /* Listening port */
    if (in->host.port) {
        port = in->host.port;
    }
    snprintf(ctx->port, sizeof(ctx->port), "%hu", port);

    /* TypesDB */
    tmp = flb_input_get_property("typesdb", in);
    if (!tmp) {
        tmp = DEFAULT_TYPESDB;
    }

    flb_debug("[in_collectd] Loading TypesDB from %s", tmp);

    tdb = typesdb_load_all(tmp);
    if (!tdb) {
        flb_error("[in_collectd] failed to load '%s'", tmp);
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }
    ctx->tdb = tdb;

    /* Set the context */
    flb_input_set_context(in, ctx);

    ctx->server_fd = flb_net_server_udp(ctx->port, ctx->listen);
    if (ctx->server_fd < 0) {
        flb_error("[in_collectd] failed to bind to %s:%s", ctx->listen,
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
        flb_error("[in_collectd] failed set up a collector");
        flb_socket_close(ctx->server_fd);
        typesdb_destroy(ctx->tdb);
        flb_free(ctx->buf);
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd = ret;

    flb_info("[in_collectd] start listening to %s:%s", ctx->listen,
                                                       ctx->port);
    return 0;
}

static int in_collectd_callback(struct flb_input_instance *i_ins,
                                struct flb_config *config, void *in_context)
{
    struct flb_in_collectd_config *ctx = in_context;
    int len;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;

    len = recv(ctx->server_fd, ctx->buf, ctx->bufsize, 0);
    if (len < 0) {
        flb_errno();
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    if (netprot_to_msgpack(ctx->buf, len, ctx->tdb, &pck)) {
        flb_error("[in_collectd] netprot_to_msgpack fails");
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
    flb_socket_close(ctx->server_fd);
    flb_pipe_close(ctx->coll_fd);
    typesdb_destroy(ctx->tdb);
    flb_free(ctx->buf);
    flb_free(ctx);
    return 0;
}

struct flb_input_plugin in_collectd_plugin = {
    .name         = "collectd",
    .description  = "collectd input plugin",
    .cb_init      = in_collectd_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = in_collectd_exit
};
