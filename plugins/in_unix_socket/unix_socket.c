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

#include <sys/stat.h>

#include "unix_socket.h"
#include "unix_socket_conn.h"
#include "unix_socket_config.h"

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new UNIX SOCKET instance which will wait for
 * JSON map messages.
 */
static int in_unix_socket_collect(struct flb_input_instance *in,
                                  struct flb_config *config, void *in_context)
{
    struct flb_connection            *connection;
    struct unix_socket_conn          *conn;
    struct flb_in_unix_socket_config *ctx;

    ctx = in_context;

    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could not accept new connection");

        return -1;
    }

    if (ctx->dgram_mode_flag) {
        return unix_socket_conn_event(connection);
    }
    else {
        flb_plg_trace(ctx->ins, "new UNIX SOCKET connection arrived FD=%i", connection->fd);

        conn = unix_socket_conn_add(connection, ctx);

        if (conn == NULL) {
            flb_plg_error(ctx->ins, "could not accept new connection");

            flb_downstream_conn_release(connection);

            return -1;
        }
    }

    return 0;
}

static int remove_existing_socket_file(char *socket_path)
{
    struct stat file_data;
    int         result;

    result = stat(socket_path, &file_data);

    if (result == -1) {
        if (errno == ENOENT) {
            return 0;
        }

        flb_errno();

        return -1;
    }

    if (S_ISSOCK(file_data.st_mode) == 0) {
        return -2;
    }

    result = unlink(socket_path);

    if (result != 0) {
        return -3;
    }

    return 0;
}

/* Initialize plugin */
static int in_unix_socket_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    struct flb_connection            *connection;
    int                               mode;
    struct flb_in_unix_socket_config *ctx;
    int                               ret;
    struct flb_tls                   *tls;

    (void) data;

    ctx = unix_socket_config_init(in);

    if (ctx == NULL) {
        return -1;
    }

    ctx->collector_id = -1;
    ctx->ins = in;

    mk_list_init(&ctx->connections);

    /* Set the context */
    flb_input_set_context(in, ctx);

    ret = remove_existing_socket_file(ctx->listen);

    if (ret != 0) {
        if (ret == -2) {
            flb_plg_error(ctx->ins,
                          "%s exists and it is not a unix socket. Aborting",
                          ctx->listen);
        }
        else {
            flb_plg_error(ctx->ins,
                          "could not remove existing unix socket %s. Aborting",
                          ctx->listen);
        }

        unix_socket_config_destroy(ctx);

        return -1;
    }

    mode = FLB_TRANSPORT_UNIX_STREAM;

    if (ctx->socket_mode != NULL &&
        strcasecmp(ctx->socket_mode, "DGRAM") == 0) {
        mode = FLB_TRANSPORT_UNIX_DGRAM;
        ctx->dgram_mode_flag = FLB_TRUE;
        tls = NULL;
    }
    else {
        tls = in->tls;
    }

    ctx->downstream = flb_downstream_create(mode,
                                            in->flags,
                                            ctx->listen,
                                            0,
                                            tls,
                                            config,
                                            &in->net_setup);

    if (ctx->downstream == NULL) {
        flb_plg_error(ctx->ins,
                      "could not initialize downstream on unix://%s. Aborting",
                      ctx->listen);

        unix_socket_config_destroy(ctx);

        return -1;
    }

    flb_input_downstream_set(ctx->downstream, ctx->ins);

    if (ctx->socket_permissions != NULL) {
        ret = chmod(ctx->listen, ctx->socket_acl);

        if (ret != 0) {
            flb_errno();

            flb_plg_error(ctx->ins, "cannot set permission on '%s' to %04o",
                          ctx->listen, ctx->socket_acl);

            unix_socket_config_destroy(ctx);

            return -1;
        }
    }

    if (ctx->dgram_mode_flag) {
        connection = flb_downstream_conn_get(ctx->downstream);

        if (connection == NULL) {
            flb_plg_error(ctx->ins, "could not get DGRAM server dummy "
                                    "connection");

            unix_socket_config_destroy(ctx);

            return -1;
        }

        ctx->dummy_conn = unix_socket_conn_add(connection, ctx);

        if (ctx->dummy_conn == NULL) {
            flb_plg_error(ctx->ins, "could not track DGRAM server dummy "
                                    "connection");

            unix_socket_config_destroy(ctx);

            return -1;
        }
    }

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(in,
                                         in_unix_socket_collect,
                                         ctx->downstream->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins,
                      "Could not set collector for IN_UNIX_SOCKET "
                      "input plugin");

        unix_socket_config_destroy(ctx);

        return -1;
    }

    ctx->collector_id = ret;
    ctx->collector_event = flb_input_collector_get_event(ret, in);

    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not get collector event");

        unix_socket_config_destroy(ctx);

        return -1;
    }

    return 0;
}

static int in_unix_socket_exit(void *data, struct flb_config *config)
{
    struct mk_list                   *head;
    struct unix_socket_conn          *conn;
    struct flb_in_unix_socket_config *ctx;
    struct mk_list                   *tmp;

    (void) *config;

    ctx = data;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct unix_socket_conn, _head);

        unix_socket_conn_del(conn);
    }

    unix_socket_config_destroy(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "socket_mode", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_unix_socket_config, socket_mode),
     "Unix socket mode : STREAM or DGRAM"
    },
    {
     FLB_CONFIG_MAP_STR, "socket_path", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_unix_socket_config, listen),
     "Unix socket path"
    },
    {
     FLB_CONFIG_MAP_STR, "socket_permissions", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_unix_socket_config, socket_permissions),
     "Set the permissions for the UNIX socket"
    },
    {
     FLB_CONFIG_MAP_STR, "format", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_unix_socket_config, format_name),
     "Set the format: json or none"
    },
    {
     FLB_CONFIG_MAP_STR, "separator", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_unix_socket_config, raw_separator),
     "Set separator"
    },
    {
      FLB_CONFIG_MAP_STR, "chunk_size", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_unix_socket_config, chunk_size_str),
      "Set the chunk size"
    },
    {
      FLB_CONFIG_MAP_STR, "buffer_size", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_unix_socket_config, buffer_size_str),
      "Set the buffer size"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_unix_socket_plugin = {
    .name         = "unix_socket",
    .description  = "UNIX_SOCKET",
    .cb_init      = in_unix_socket_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_unix_socket_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_unix_socket_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_IO_OPT_TLS
};
