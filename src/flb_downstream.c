/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_connection.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_thread_storage.h>

/* Config map for Downstream networking setup */
struct flb_config_map downstream_net[] = {
    { 
     FLB_CONFIG_MAP_BOOL, "net.share_port", "false",
     0, FLB_TRUE, offsetof(struct flb_net_setup, share_port),
     "Allow multiple plugins to bind to the same port"
    },

    {
     FLB_CONFIG_MAP_INT, "net.backlog", STR(FLB_NETWORK_DEFAULT_BACKLOG_SIZE),
     0, FLB_TRUE, offsetof(struct flb_net_setup, backlog),
     "Set the backlog size for listening sockets"
    },

    {
     FLB_CONFIG_MAP_TIME, "net.io_timeout", "0s",
     0, FLB_TRUE, offsetof(struct flb_net_setup, io_timeout),
     "Set maximum time a connection can stay idle"
    },

    {
     FLB_CONFIG_MAP_TIME, "net.accept_timeout", "10s",
     0, FLB_TRUE, offsetof(struct flb_net_setup, accept_timeout),
     "Set maximum time allowed to establish an incoming connection, this time "
     "includes the TLS handshake"
    },

    {
     FLB_CONFIG_MAP_BOOL, "net.accept_timeout_log_error", "true",
     0, FLB_TRUE, offsetof(struct flb_net_setup, accept_timeout_log_error),
     "On client accept timeout, specify if it should log an error. When "
     "disabled, the timeout is logged as a debug message"
    },

    {
     FLB_CONFIG_MAP_BOOL, "net.keepalive", "true",
     0, FLB_TRUE, offsetof(struct flb_net_setup, keepalive),
     "Enable or disable Keepalive support"
    },

    /* EOF */
    {0}
};

/* Enable thread-safe mode for downstream connection */
void flb_downstream_thread_safe(struct flb_downstream *stream)
{
    flb_stream_enable_thread_safety(&stream->base);
}

struct mk_list *flb_downstream_get_config_map(struct flb_config *config)
{
    return flb_config_map_create(config, downstream_net);
}

/* Initialize any downstream environment context */
void flb_downstream_init()
{
    /* There's nothing to do here yet */
}

int flb_downstream_setup(struct flb_downstream *stream,
                         int transport, int flags,
                         const char *host,
                         unsigned short int port,
                         struct flb_tls *tls,
                         struct flb_config *config,
                         struct flb_net_setup *net_setup)
{
    char port_string[8];

    flb_stream_setup(&stream->base,
                     FLB_DOWNSTREAM,
                     transport,
                     flags,
                     tls,
                     config,
                     net_setup);

    stream->server_fd = FLB_INVALID_SOCKET;
    stream->host = flb_strdup(host);
    stream->port = port;

    if (stream->host == NULL) {
        return -1;
    }

    /* map the net_setup config map coming from the caller */
    stream->net_setup = net_setup;

    mk_list_init(&stream->busy_queue);
    mk_list_init(&stream->destroy_queue);

    snprintf(port_string, sizeof(port_string), "%u", port);

    if (transport == FLB_TRANSPORT_TCP) {
        stream->server_fd = flb_net_server(port_string, host,
                                           net_setup->backlog,
                                           net_setup->share_port);
    }
    else if (transport == FLB_TRANSPORT_UDP) {
        stream->server_fd = flb_net_server_udp(port_string, host, net_setup->share_port);
    }
    else if (transport == FLB_TRANSPORT_UNIX_STREAM) {
        stream->server_fd = flb_net_server_unix(host,
                                                FLB_TRUE,
                                                net_setup->backlog,
                                                net_setup->share_port);
    }
    else if (transport == FLB_TRANSPORT_UNIX_DGRAM) {
        stream->server_fd = flb_net_server_unix(host,
                                                FLB_FALSE,
                                                net_setup->backlog,
                                                net_setup->share_port);
    }

    if (stream->server_fd != -1) {
        flb_debug("[downstream] listening on %s:%s", host, port_string);
    }
    else {
        flb_error("[downstream] could not bind address %s:%s. Aborting",
                  host, port_string);

        return -2;
    }

    mk_list_add(&stream->base._head, &config->downstreams);

    return 0;
}

/* Creates a new downstream context */
struct flb_downstream *flb_downstream_create(int transport, int flags,
                                             const char *host,
                                             unsigned short int port,
                                             struct flb_tls *tls,
                                             struct flb_config *config,
                                             struct flb_net_setup *net_setup)
{
    struct flb_downstream *stream;
    int                    result;

    stream = flb_calloc(1, sizeof(struct flb_downstream));

    if (stream == NULL) {
        flb_errno();
    }
    else {
        stream->base.dynamically_allocated = FLB_TRUE;

        result = flb_downstream_setup(stream,
                                      transport, flags,
                                      host, port,
                                      tls,
                                      config,
                                      net_setup);

        if (result != 0) {
            flb_downstream_destroy(stream);

            stream = NULL;
        }
    }

    return stream;
}

/*
 * This function moves the 'downstream connection' into the queue to be
 * destroyed. Note that the caller is responsible to validate and check
 * required mutex if this is being used in multi-worker mode.
 */
static int prepare_destroy_conn(struct flb_connection *connection)
{
    flb_trace("[downstream] destroy connection #%i to %s",
              connection->fd, flb_connection_get_remote_address(connection));

    if (MK_EVENT_IS_REGISTERED((&connection->event))) {
        mk_event_del(connection->evl, &connection->event);
    }

    /* This should be != -1 to cover those use cases where stdin, stdout
     * and stderr are closed.
     */

    if (connection->fd != FLB_INVALID_SOCKET) {
        flb_socket_close(connection->fd);

        connection->fd = FLB_INVALID_SOCKET;
        connection->event.fd = FLB_INVALID_SOCKET;
    }

    /* remove connection from the queue */
    mk_list_del(&connection->_head);

    /* Add node to destroy queue */
    mk_list_add(&connection->_head, &connection->downstream->destroy_queue);

    /*
     * note: the connection context is destroyed by the engine once all events
     * have been processed.
     */
    return 0;
}

/* 'safe' version of prepare_destroy_conn. It set locks if necessary */
static inline int prepare_destroy_conn_safe(struct flb_connection *connection)
{
    int result;

    /* This used to not wait for the lock in thread safe mode but it makes
     * no sense so I'm changing it (08/28/22) leo
     */

    flb_stream_acquire_lock(connection->stream, FLB_TRUE);

    result = prepare_destroy_conn(connection);

    flb_stream_release_lock(connection->stream);

    return result;
}

static int destroy_conn(struct flb_connection *connection)
{
    /* Delay the destruction of busy connections */
    if (connection->busy_flag) {
        return 0;
    }

    if (connection->tls_session != NULL) {
        flb_tls_session_destroy(connection->tls_session);
    }

    mk_list_del(&connection->_head);

    flb_connection_destroy(connection);

    return 0;
}

struct flb_connection *flb_downstream_conn_get(struct flb_downstream *stream)
{
    flb_sockfd_t           connection_fd;
    struct flb_connection *connection;
    int                    transport;
    struct flb_coro       *coroutine;
    int                    result;

    transport = stream->base.transport;

    if (transport == FLB_TRANSPORT_UDP ||
        transport == FLB_TRANSPORT_UNIX_DGRAM ) {
        if (stream->dgram_connection != NULL) {
            return stream->dgram_connection;
        }

        connection_fd = stream->server_fd;
    }
    else {
        connection_fd = FLB_INVALID_SOCKET;
    }

    if (flb_downstream_is_async(stream)) {
        coroutine = flb_coro_get();
    }
    else {
        coroutine = NULL;
    }

    connection = flb_connection_create(connection_fd,
                                       FLB_DOWNSTREAM_CONNECTION,
                                       (void *) stream,
                                       flb_engine_evl_get(),
                                       coroutine);

    if (connection == NULL) {
        return NULL;
    }

    connection->busy_flag = FLB_TRUE;

    flb_stream_acquire_lock(&stream->base, FLB_TRUE);

    /* Link new connection to the busy queue */
    mk_list_add(&connection->_head, &stream->busy_queue);

    flb_stream_release_lock(&stream->base);

    if (transport != FLB_TRANSPORT_UDP &&
        transport != FLB_TRANSPORT_UNIX_DGRAM ) {
        flb_connection_reset_connection_timeout(connection);

        result = flb_io_net_accept(connection, coroutine);

        if (result != 0) {
            flb_connection_reset_connection_timeout(connection);

            flb_debug("[downstream] connection #%i failed",
                      connection->fd);

            prepare_destroy_conn_safe(connection);

            connection->busy_flag = FLB_FALSE;

            return NULL;
        }

        flb_connection_unset_connection_timeout(connection);
    }

    connection->busy_flag = FLB_FALSE;

    flb_connection_reset_io_timeout(connection);

    if (transport == FLB_TRANSPORT_UDP ||
        transport == FLB_TRANSPORT_UNIX_DGRAM) {
        if (stream->dgram_connection == NULL) {
            stream->dgram_connection = connection;
        }
    }

    return connection;
}

void flb_downstream_destroy(struct flb_downstream *stream)
{
    struct flb_connection *connection;
    struct mk_list        *head;
    struct mk_list        *tmp;

    if (stream != NULL) {
        mk_list_foreach_safe(head, tmp, &stream->busy_queue) {
            connection = mk_list_entry(head, struct flb_connection, _head);

            prepare_destroy_conn(connection);
        }

        mk_list_foreach_safe(head, tmp, &stream->destroy_queue) {
            connection = mk_list_entry(head, struct flb_connection, _head);

            destroy_conn(connection);
        }

        /* If the simulated UDP connection reference is set then
         * it means that connection was already cleaned up by the
         * preceding code which means server_fd holds a socket
         * reference that has already been closed and we need to
         * honor that.
         */

        if (stream->dgram_connection != NULL) {
            stream->dgram_connection = NULL;
            stream->server_fd = FLB_INVALID_SOCKET;
        }

        if (stream->host != NULL) {
            flb_free(stream->host);
        }

        if (stream->server_fd != FLB_INVALID_SOCKET) {
            flb_socket_close(stream->server_fd);
        }

        if (mk_list_entry_orphan(&stream->base._head) == 0) {
            mk_list_del(&stream->base._head);
        }

        if (stream->base.dynamically_allocated) {
            flb_free(stream);
        }
    }
}

int flb_downstream_conn_release(struct flb_connection *connection)
{
    return prepare_destroy_conn_safe(connection);
}

int flb_downstream_conn_timeouts(struct mk_list *list)
{
    int                    elapsed_time;
    struct flb_connection *connection;
    const char            *reason;
    struct flb_downstream *stream;
    struct mk_list        *s_head;
    struct mk_list        *head;
    int                    drop;
    int                  inject;
    struct mk_list        *tmp;
    time_t                 now;

    now = time(NULL);

    /* Iterate all downstream contexts */
    mk_list_foreach(head, list) {
        stream = mk_list_entry(head, struct flb_downstream, base._head);

        if (stream->base.transport == FLB_TRANSPORT_UDP) {
            continue;
        }

        flb_stream_acquire_lock(&stream->base, FLB_TRUE);

        /* Iterate every busy connection */
        mk_list_foreach_safe(s_head, tmp, &stream->busy_queue) {
            connection = mk_list_entry(s_head, struct flb_connection, _head);

            drop = FLB_FALSE;

            /* Connect timeouts */
            if (connection->net->connect_timeout > 0 &&
                connection->ts_connect_timeout > 0 &&
                connection->ts_connect_timeout <= now) {
                drop = FLB_TRUE;
                reason = "connection timeout";
                elapsed_time = connection->net->accept_timeout;
            }
            else if (connection->net->io_timeout > 0 &&
                     connection->ts_io_timeout > 0 &&
                     connection->ts_io_timeout <= now) {
                drop = FLB_TRUE;
                reason = "IO timeout";
                elapsed_time = connection->net->io_timeout;
            }

            if (drop) {
                if (!flb_downstream_is_shutting_down(stream)) {
                    if (connection->net->accept_timeout_log_error) {
                        flb_error("[downstream] connection #%i from %s timed "
                                  "out after %i seconds (%s)",
                                  connection->fd,
                                  connection->user_friendly_remote_host,
                                  elapsed_time,
                                  reason);
                    }
                    else {
                        flb_debug("[downstream] connection #%i from %s timed "
                                  "out after %i seconds (%s)",
                                  connection->fd,
                                  connection->user_friendly_remote_host,
                                  elapsed_time,
                                  reason);
                    }
                }

                inject = FLB_FALSE;
                if (connection->event.status != MK_EVENT_NONE) {
                    inject = FLB_TRUE;
                }
                connection->net_error = ETIMEDOUT;
                prepare_destroy_conn(connection);
                if (inject == FLB_TRUE) {
                    mk_event_inject(connection->evl,
                                    &connection->event,
                                    connection->event.mask,
                                    FLB_TRUE);
                }
            }
        }

        flb_stream_release_lock(&stream->base);
    }

    return 0;
}

int flb_downstream_conn_pending_destroy(struct flb_downstream *stream)
{
    struct flb_connection *connection;
    struct mk_list        *head;
    struct mk_list        *tmp;

    flb_stream_acquire_lock(&stream->base, FLB_TRUE);

    mk_list_foreach_safe(head, tmp, &stream->destroy_queue) {
        connection = mk_list_entry(head, struct flb_connection, _head);

        destroy_conn(connection);
    }

    flb_stream_release_lock(&stream->base);

    return 0;
}

int flb_downstream_conn_pending_destroy_list(struct mk_list *list)
{
    struct flb_downstream *stream;
    struct mk_list        *head;

    /* Iterate all downstream contexts */
    mk_list_foreach(head, list) {
         stream = mk_list_entry(head, struct flb_downstream, base._head);

        flb_downstream_conn_pending_destroy(stream);
    }

    return 0;
}

int flb_downstream_is_async(struct flb_downstream *stream)
{
    return flb_stream_is_async(&stream->base);
}
