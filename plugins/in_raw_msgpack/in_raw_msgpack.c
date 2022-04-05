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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_pack.h>

#include "in_raw_msgpack.h"
#include <sys/socket.h>
#include <sys/un.h>


int create_unix_sock(char *sock_path) {
    int socket_fd;
    struct sockaddr_un server_address;

    if ((socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
        printf("[Fluent Bit] [in_raw_msgpack] Failed to create client unix sock\n");
        return -1;
    }

    memset(&server_address, 0, sizeof(struct sockaddr_un));
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, sock_path);

    unlink(sock_path);
    if (bind(socket_fd, (const struct sockaddr *) &server_address, sizeof(struct sockaddr_un)) < 0) {
        close(socket_fd);
        printf("[Fluent Bit] [in_raw_msgpack] Failed to bind client unix sock\n");
        return -1;
    }
    return socket_fd;
}


int set_sock_fd(struct flb_raw_msgpack_config *ctx) {
    ctx->sock_fd = create_unix_sock(ctx->unix_sock_path);

    if (ctx->sock_fd < 0) {
        printf("[Fluent Bit] [in_raw_msgpack] Failed to create a socket\n");
        return -1;
    }
    return 0;
}


static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline int pack_regex(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                             struct flb_raw_msgpack_config *ctx,
                             struct flb_time *t, char *data, size_t data_size)
{
    msgpack_pack_array(mp_pck, 2);
    flb_time_append_to_msgpack(t, mp_pck, 0);
    msgpack_sbuffer_write(mp_sbuf, data, data_size);

    return 0;
}

/* cb_collect callback */
static int in_raw_msgpack_collect(struct flb_input_instance *ins,
                                  struct flb_config *config, void *in_context)
{
    int bytes = 0;
    struct flb_raw_msgpack_config *ctx = in_context;

    struct sockaddr_un client_address;
    socklen_t address_length  = sizeof(struct sockaddr_un);
    bytes = recvfrom(ctx->sock_fd,
                     (char *) &ctx->msg, sizeof(ctx->msg),
                     0, (struct sockaddr *) &client_address, &address_length);

    flb_plg_trace(ctx->ins, "stdin read() = %i", bytes);

    if (bytes == 0) {
        flb_plg_warn(ctx->ins, "end of file (stdin closed by remote end)");
    }

    if (bytes <= 0) {
        printf ("[Fluent Bit] [in_raw_msgpack] paused, cannot receive the data\n");
        flb_input_collector_pause(ctx->coll_fd, ctx->ins);
        flb_engine_exit(config);
        return -1;
    }

    flb_input_chunk_append_raw(ins, NULL, 0, ctx->msg.data_buf, ctx->msg.data_len);

    int bytes_sent = sendto(ctx->sock_fd,
                           (char *) &ctx->msg, sizeof(ctx->msg),
                           0, (struct sockaddr *) &client_address, address_length);

    return 0;
}

static int config_destroy(struct flb_raw_msgpack_config *ctx)
{
    close(ctx->sock_fd);
    unlink(ctx->unix_sock_path);
    flb_free(ctx);
    return 0;
}


/* Initialize plugin */
static int in_raw_msgpack_init(struct flb_input_instance *in,
                               struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    struct flb_raw_msgpack_config *ctx;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_raw_msgpack_config));
    if (!ctx) {
        return -1;
    }
    ctx->buf_len = 0;
    ctx->ins = in;

    // data pointer
    in_plugin_data_t *in_data = (in_plugin_data_t *)data;
    // ctx->ptr = in_data->buffer_ptr;

    strncpy(ctx->unix_sock_path, in_data->server_address, sizeof(ctx->unix_sock_path));
    set_sock_fd(ctx);


    tmp = flb_input_get_property("parser", in);
    if (tmp) {
        ctx->parser = flb_parser_get(tmp, config);
        if (!ctx->parser) {
            flb_plg_error(ctx->ins, "requested parser '%s' not found", tmp);
        }
    }
    else {
        ctx->parser = NULL;
    }

    /* Always initialize built-in JSON pack state */
    flb_pack_state_init(&ctx->pack_state);
    ctx->pack_state.multiple = FLB_TRUE;

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Collect data from buffer upon signal on socket */
    ret = flb_input_set_collector_event(in,
                                        in_raw_msgpack_collect,
                                        ctx->sock_fd,
                                        config);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for STDIN input plugin");
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

static int in_raw_msgpack_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_raw_msgpack_config *ctx = data;

    config_destroy(ctx);

    return 0;
}


struct flb_input_plugin in_raw_msgpack_plugin = {
    .name         = "raw_msgpack",
    .description  = "input raw Message Pack data",
    .cb_init      = in_raw_msgpack_init,
    .cb_pre_run   = NULL,
    // we do not need to set callback here, since we set flb_input_set_collector_event to listen to our socket
    .cb_collect   = NULL, //in_raw_msgpack_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_raw_msgpack_exit
};
