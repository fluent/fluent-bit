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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "docker_events.h"
#include "docker_events_config.h"


/**
 * Creates the connection to docker's unix socket and sends the
 * HTTP GET /events
 *
 * @param ctx  Pointer to flb_in_de_config
 *
 * @return int 0 on success, -1 on failure
 */
static int de_unix_create(struct flb_in_de_config *ctx)
{
    unsigned long len;
    size_t address_length;
    struct sockaddr_un address;
    char request[512];

    ctx->fd = flb_net_socket_create(AF_UNIX, FLB_FALSE);
    if (ctx->fd == -1) {
        return -1;
    }

    /* Prepare the unix socket path */
    len = strlen(ctx->unix_path);
    address.sun_family = AF_UNIX;
    sprintf(address.sun_path, "%s", ctx->unix_path);
    address_length = sizeof(address.sun_family) + len + 1;
    if (connect(ctx->fd, (struct sockaddr *)&address, address_length) == -1) {
        flb_errno();
        close(ctx->fd);
        return -1;
    }

    strcpy(request, "GET /events HTTP/1.0\r\n\r\n");
    flb_plg_trace(ctx->ins, "writing to socket %s", request);
    write(ctx->fd, request, strlen(request));

    /* Read the initial http response */
    read(ctx->fd, ctx->buf, ctx->buf_size - 1);

    return 0;
}

/**
 * Callback function to process events recieved on the unix
 * socket.
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to
 *                      flb_in_de_config
 *
 * @return int Always returns success
 */
static int in_de_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    struct flb_in_de_config *ctx = in_context;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    size_t str_len = 0;
    int ret = 0;

    /* variables for parser */
    int parser_ret = -1;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct flb_time out_time;

    if ((ret = read(ctx->fd, ctx->buf, ctx->buf_size - 1)) > 0) {
        str_len = ret;
        ctx->buf[str_len] = '\0';

        if (!ctx->parser) {
            /* Initialize local msgpack buffer */
            msgpack_sbuffer_init(&mp_sbuf);
            msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

            msgpack_pack_array(&mp_pck, 2);
            flb_pack_time_now(&mp_pck);
            msgpack_pack_map(&mp_pck, 1);

            msgpack_pack_str(&mp_pck, ctx->key_len);
            msgpack_pack_str_body(&mp_pck, ctx->key,
                                  ctx->key_len);
            msgpack_pack_str(&mp_pck, str_len);
            msgpack_pack_str_body(&mp_pck, ctx->buf, str_len);
            flb_input_chunk_append_raw(ins, NULL, 0, mp_sbuf.data,
                                       mp_sbuf.size);
            msgpack_sbuffer_destroy(&mp_sbuf);
        }
        else {
            flb_time_get(&out_time);
            parser_ret = flb_parser_do(ctx->parser, ctx->buf, str_len - 1,
                                       &out_buf, &out_size, &out_time);
            if (parser_ret >= 0) {
                if (flb_time_to_double(&out_time) == 0.0) {
                    flb_time_get(&out_time);
                }

                /* Initialize local msgpack buffer */
                msgpack_sbuffer_init(&mp_sbuf);
                msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

                msgpack_pack_array(&mp_pck, 2);
                flb_time_append_to_msgpack(&out_time, &mp_pck, 0);
                msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);

                flb_input_chunk_append_raw(ins, NULL, 0,
                                           mp_sbuf.data, mp_sbuf.size);
                msgpack_sbuffer_destroy(&mp_sbuf);
                flb_free(out_buf);
            }
            else {
                flb_plg_trace(ctx->ins, "tried to parse: %s", ctx->buf);
                flb_plg_trace(ctx->ins, "buf_size %zu", ctx->buf_size);
                flb_plg_error(ctx->ins, "parser returned an error: %d",
                              parser_ret);
            }
        }
    }
    else {
        int error = errno;
        flb_plg_error(ctx->ins, "read returned error: %d, %s", error,
                      strerror(error));
    }

    return 0;
}

/**
 * Callback function to initialize docker events plugin
 *
 * @param ins     Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 * @param data    Unused
 *
 * @return int 0 on success, -1 on failure
 */
static int in_de_init(struct flb_input_instance *ins,
                      struct flb_config *config, void *data)
{
    struct flb_in_de_config *ctx = NULL;
    (void)data;

    /* Allocate space for the configuration */
    ctx = de_config_init(ins, config);
    if (!ctx) {
        return -1;
    }
    ctx->ins = ins;

    /* Set the context */
    flb_input_set_context(ins, ctx);

    if (de_unix_create(ctx) != 0) {
        flb_plg_error(ctx->ins, "could not listen on unix://%s",
                      ctx->unix_path);
        de_config_destroy(ctx);
        return -1;
    }

    if (flb_input_set_collector_event(ins, in_de_collect,
                                      ctx->fd, config) == -1) {
        flb_plg_error(ctx->ins,
                      "could not set collector for IN_DOCKER_EVENTS plugin");
        de_config_destroy(ctx);
        return -1;
    }

    return 0;
}

/**
 * Callback exit function to cleanup plugin
 *
 * @param data    Pointer cast to flb_in_de_config
 * @param config  Unused
 *
 * @return int    Always returns 0
 */
static int in_de_exit(void *data, struct flb_config *config)
{
    (void)*config;
    struct flb_in_de_config *ctx = data;

    de_config_destroy(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_docker_events_plugin = {
    .name = "docker_events",
    .description = "Docker events",
    .cb_init = in_de_init,
    .cb_pre_run = NULL,
    .cb_collect = in_de_collect,
    .cb_flush_buf = NULL,
    .cb_exit = in_de_exit,
    .flags = FLB_INPUT_NET
};
