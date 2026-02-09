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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_network.h>
#include <msgpack.h>

#ifdef FLB_HAVE_UNIX_SOCKET
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#endif

#include "fw.h"
#include "fw_conn.h"
#include "fw_config.h"

#ifdef FLB_HAVE_UNIX_SOCKET
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

static int fw_unix_create(struct flb_in_fw_config *ctx)
{
    int ret;

    ret = remove_existing_socket_file(ctx->unix_path);

    if (ret != 0) {
        if (ret == -2) {
            flb_plg_error(ctx->ins,
                          "%s exists and it is not a unix socket. Aborting",
                          ctx->unix_path);
        }
        else {
            flb_plg_error(ctx->ins,
                          "could not remove existing unix socket %s. Aborting",
                          ctx->unix_path);
        }

        return -1;
    }

    ctx->downstream = flb_downstream_create(FLB_TRANSPORT_UNIX_STREAM,
                                            ctx->ins->flags,
                                            ctx->unix_path,
                                            0,
                                            ctx->ins->tls,
                                            ctx->ins->config,
                                            &ctx->ins->net_setup);

    if (ctx->downstream == NULL) {
        return -1;
    }

    if (ctx->unix_perm_str) {
        if (chmod(ctx->unix_path, ctx->unix_perm)) {
            flb_errno();

            flb_plg_error(ctx->ins, "cannot set permission on '%s' to %04o",
                          ctx->unix_path, ctx->unix_perm);

            return -1;
        }
    }

    return 0;
}
#endif

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new FW instance which will wait for
 * MessagePack records.
 */
static int in_fw_collect(struct flb_input_instance *ins,
                         struct flb_config *config, void *in_context)
{
    int                      state_backup;
    struct flb_connection   *connection;
    struct fw_conn          *conn;
    struct flb_in_fw_config *ctx;

    ctx = in_context;

    state_backup = ctx->state;
    ctx->state = FW_INSTANCE_STATE_ACCEPTING_CLIENT;

    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could not accept new connection");
        ctx->state = state_backup;

        return -1;
    }

    if (!config->is_ingestion_active) {
        flb_downstream_conn_release(connection);
        ctx->state = state_backup;

        return -1;
    }

    if(ctx->is_paused) {
        flb_downstream_conn_release(connection);
        flb_plg_trace(ins, "TCP connection will be closed FD=%i", connection->fd);
        ctx->state = state_backup;

        return -1;
    }

    flb_plg_trace(ins, "new TCP connection arrived FD=%i", connection->fd);

    conn = fw_conn_add(connection, ctx);
    if (!conn) {
        flb_downstream_conn_release(connection);
        ctx->state = state_backup;

        return -1;
    }

    ctx->state = state_backup;

    if (ctx->state == FW_INSTANCE_STATE_PAUSED) {
        fw_conn_del_all(ctx);
    }

    return 0;
}

static void delete_users(struct flb_in_fw_config *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_in_fw_user *user;

    mk_list_foreach_safe(head, tmp, &ctx->users) {
        user = mk_list_entry(head, struct flb_in_fw_user, _head);
        flb_sds_destroy(user->name);
        flb_sds_destroy(user->password);
        mk_list_del(&user->_head);
        flb_free(user);
    }
}

static int setup_users(struct flb_in_fw_config *ctx,
                       struct flb_input_instance *ins)
{
    flb_sds_t tmp;
    struct mk_list *head;
    struct mk_list *split;
    struct flb_split_entry *sentry;
    struct flb_kv *kv;
    struct flb_in_fw_user *user;

    /* Iterate all input properties */
    mk_list_foreach(head, &ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        /* Create a new user */
        user = flb_malloc(sizeof(struct flb_in_fw_user));
        if (!user) {
            flb_errno();
            return -1;
        }

        /* Get the type */
        if (strcasecmp(kv->key, "security.users") != 0) {
            /* Other property. Skip */
            flb_free(user);
            continue;
        }

        /* As a value we expect a pair of a username and a passowrd */
        split = flb_utils_split(kv->val, ' ', 1);
        if (split == NULL) {
            flb_plg_error(ctx->ins,
                          "invalid value, expected username and password");
            delete_users(ctx);
            flb_free(user);
            return -1;
        }

        if (mk_list_size(split) != 2) {
            flb_plg_error(ctx->ins,
                          "invalid value, expected username and password");
            delete_users(ctx);
            flb_free(user);
            flb_utils_split_free(split);
            return -1;
        }

        /* Get first value (user's name) */
        sentry = mk_list_entry_first(split, struct flb_split_entry, _head);
        tmp = flb_sds_create_len(sentry->value, sentry->len);
        if (tmp == NULL) {
            delete_users(ctx);
            flb_free(user);
            flb_utils_split_free(split);
            return -1;
        }
        user->name = tmp;

        /* Get remaining content (password) */
        sentry = mk_list_entry_last(split, struct flb_split_entry, _head);
        tmp = flb_sds_create_len(sentry->value, sentry->len);
        if (tmp == NULL) {
            delete_users(ctx);
            flb_sds_destroy(user->name);
            flb_free(user);
            flb_utils_split_free(split);
            return -1;
        }
        user->password = tmp;

        /* Release split - only after both allocations succeed */
        flb_utils_split_free(split);

        /* Link to parent list */
        mk_list_add(&user->_head, &ctx->users);
    }

    return 0;
}

/* Initialize plugin */
static int in_fw_init(struct flb_input_instance *ins,
                      struct flb_config *config, void *data)
{
    unsigned short int       port;
    int                      ret;
    struct flb_in_fw_config *ctx;

    (void) data;

    /* Allocate space for the configuration */
    ctx = fw_config_init(ins);
    if (!ctx) {
        return -1;
    }

    ctx->state = FW_INSTANCE_STATE_RUNNING;
    ctx->coll_fd = -1;
    ctx->ins = ins;
    mk_list_init(&ctx->connections);
    mk_list_init(&ctx->users);

    /* Set the context */
    flb_input_set_context(ins, ctx);

    /* Set plugin ingestion to active */
    ctx->is_paused = FLB_FALSE;

    /* Unix Socket mode */
    if (ctx->unix_path) {
#ifndef FLB_HAVE_UNIX_SOCKET
        flb_plg_error(ctx->ins, "unix address is not supported %s:%s. Aborting",
                      ctx->listen, ctx->tcp_port);
        fw_config_destroy(ctx);
        return -1;
#else
        ret = fw_unix_create(ctx);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "could not listen on unix://%s",
                          ctx->unix_path);
            fw_config_destroy(ctx);
            return -1;
        }
        flb_plg_info(ctx->ins, "listening on unix://%s", ctx->unix_path);
#endif
    }
    else {
        port = (unsigned short int) strtoul(ctx->tcp_port, NULL, 10);

        ctx->downstream = flb_downstream_create(FLB_TRANSPORT_TCP,
                                                ctx->ins->flags,
                                                ctx->listen,
                                                port,
                                                ctx->ins->tls,
                                                config,
                                                &ctx->ins->net_setup);

        if (ctx->downstream == NULL) {
            flb_plg_error(ctx->ins,
                          "could not initialize downstream on unix://%s. Aborting",
                          ctx->listen);

            fw_config_destroy(ctx);

            return -1;
        }

        if (ctx->downstream != NULL) {
            flb_plg_info(ctx->ins, "listening on %s:%s",
                         ctx->listen, ctx->tcp_port);
        }
        else {
            flb_plg_error(ctx->ins, "could not bind address %s:%s. Aborting",
                          ctx->listen, ctx->tcp_port);

            fw_config_destroy(ctx);

            return -1;
        }
    }

    /* Load users */
    ret = setup_users(ctx, ins);
    if (ret == -1) {
        fw_config_destroy(ctx);
        return -1;
    }

    /* Users-only configuration must be rejected unless a (possibly empty) shared key is enabled. */
    if (mk_list_size(&ctx->users) > 0 &&
        ctx->shared_key == NULL &&
        ctx->empty_shared_key == FLB_FALSE) {
        flb_plg_error(ctx->ins, "security.users is set but no shared_key or empty_shared_key");
        delete_users(ctx);
        fw_config_destroy(ctx);
        return -1;
    }

    flb_input_downstream_set(ctx->downstream, ctx->ins);

    flb_net_socket_nonblocking(ctx->downstream->server_fd);

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(ins,
                                         in_fw_collect,
                                         ctx->downstream->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set server socket collector");
        fw_config_destroy(ctx);
        return -1;
    }

    ctx->coll_fd = ret;

    pthread_mutex_init(&ctx->conn_mutex, NULL);

    return 0;
}

static void in_fw_pause(void *data, struct flb_config *config)
{
    int ret;
    struct flb_in_fw_config *ctx = data;

    if (config->is_running == FLB_TRUE) {
        /*
         * This is the case when we are not in a shutdown phase, but
         * backpressure built up, and the plugin needs to
         * pause the ingestion. The plugin should close all the connections
         * and wait for the ingestion to resume.
         */
        flb_input_collector_pause(ctx->coll_fd, ctx->ins);

        ret = pthread_mutex_lock(&ctx->conn_mutex);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot lock collector mutex");
            return;
        }

        if (ctx->state == FW_INSTANCE_STATE_RUNNING) {
            fw_conn_del_all(ctx);
        }

        ctx->is_paused = FLB_TRUE;
        ret = pthread_mutex_unlock(&ctx->conn_mutex);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot unlock collector mutex");
            return;
        }
    }

    /*
     * If the plugin is paused AND the ingestion not longer active,
     * it means we are in a shutdown phase. This plugin can safetly
     * close the socket server collector.
     *
     * This socket stop is a workaround since the server API will be
     * refactored shortly.
     */
    if (config->is_ingestion_active == FLB_FALSE) {
        fw_conn_del_all(ctx);
    }

    ctx->state = FW_INSTANCE_STATE_PAUSED;
}

static void in_fw_resume(void *data, struct flb_config *config) {
    int ret;
    struct flb_in_fw_config *ctx = data;

    if (config->is_running == FLB_TRUE) {
        flb_input_collector_resume(ctx->coll_fd, ctx->ins);

        ret = pthread_mutex_lock(&ctx->conn_mutex);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot lock collector mutex");
            return;
        }

        ctx->is_paused = FLB_FALSE;
        ret = pthread_mutex_unlock(&ctx->conn_mutex);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "cannot unlock collector mutex");
            return;
        }

        ctx->state = FW_INSTANCE_STATE_RUNNING;
    }
}


static int in_fw_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_fw_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    delete_users(ctx);
    fw_conn_del_all(ctx);
    fw_config_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
   {
    FLB_CONFIG_MAP_STR, "tag_prefix", NULL,
    0, FLB_TRUE, offsetof(struct flb_in_fw_config, tag_prefix),
    "Prefix incoming tag with the defined value."
   },
   {
    FLB_CONFIG_MAP_STR, "shared_key", NULL,
    0, FLB_TRUE, offsetof(struct flb_in_fw_config, shared_key),
    "Shared key for secure forward authentication."
   },
   {
    FLB_CONFIG_MAP_STR, "self_hostname", NULL,
    0, FLB_FALSE, 0,
    "Hostname used in the handshake process for secure forward authentication."
   },
   {
    FLB_CONFIG_MAP_STR, "security.users", NULL,
    FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
    "Specify username and password pairs."
   },
   {
    FLB_CONFIG_MAP_STR, "unix_path", NULL,
    0, FLB_TRUE, offsetof(struct flb_in_fw_config, unix_path),
    "The path to unix socket to receive a Forward message."
   },
   {
    FLB_CONFIG_MAP_STR, "unix_perm", (char *)NULL,
    0, FLB_TRUE, offsetof(struct flb_in_fw_config, unix_perm_str),
    "Set the permissions for the UNIX socket."
   },
   {
    FLB_CONFIG_MAP_SIZE, "buffer_chunk_size", FLB_IN_FW_CHUNK_SIZE,
    0, FLB_TRUE, offsetof(struct flb_in_fw_config, buffer_chunk_size),
    "The buffer memory size used to receive a Forward message."
   },
   {
    FLB_CONFIG_MAP_SIZE, "buffer_max_size", FLB_IN_FW_CHUNK_MAX_SIZE,
    0, FLB_TRUE, offsetof(struct flb_in_fw_config, buffer_max_size),
    "The maximum buffer memory size used to receive a Forward message."
   },
   {
    FLB_CONFIG_MAP_BOOL, "empty_shared_key", "false",
    0, FLB_TRUE, offsetof(struct flb_in_fw_config, empty_shared_key),
    "Enable an empty string as the shared key for authentication."
   },
   {0}
};

/* Plugin reference */
struct flb_input_plugin in_forward_plugin = {
    .name         = "forward",
    .description  = "Fluentd in-forward",
    .cb_init      = in_fw_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_fw_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_fw_pause,
    .cb_resume    = in_fw_resume,
    .cb_exit      = in_fw_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_IO_OPT_TLS
};
