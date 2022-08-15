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

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_downstream_conn.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_thread_storage.h>

/* Config map for Downstream networking setup */
struct flb_config_map downstream_net[] = {
    {
     FLB_CONFIG_MAP_TIME, "net.connect_timeout", "10s",
     0, FLB_TRUE, offsetof(struct flb_net_setup, connect_timeout),
     "Set maximum time allowed to establish a connection, this time "
     "includes the TLS handshake"
    },

    {
     FLB_CONFIG_MAP_BOOL, "net.connect_timeout_log_error", "true",
     0, FLB_TRUE, offsetof(struct flb_net_setup, connect_timeout_log_error),
     "On connection timeout, specify if it should log an error. When disabled, "
     "the timeout is logged as a debug message"
    },

    /* EOF */
    {0}
};

struct mk_list *flb_downstream_get_config_map(struct flb_config *config)
{
    struct mk_list *config_map;

    config_map = flb_config_map_create(config, downstream_net);

    return config_map;
}

/* Initialize any downstream environment context */
void flb_downstream_init()
{
    /* There's nothing to do here yet */
}

/* Creates a new downstream context */
struct flb_downstream *flb_downstream_create(struct flb_config *config,
                                             const char *host, int port, int flags,
                                             struct flb_tls *tls)
{
    struct flb_downstream *stream;

    stream = flb_calloc(1, sizeof(struct flb_downstream));

    if (stream == NULL) {
        flb_errno();

        return NULL;
    }

    stream->config = config;

    /* Set default networking setup values */
    flb_net_setup_init(&stream->net);

    /* Set upstream to the http_proxy if it is specified. */
    stream->host = flb_strdup(host);
    stream->port = port;

    if (stream->host == NULL) {
        flb_free(stream);

        return NULL;
    }

    stream->flags  = flags;
    stream->flags |= FLB_IO_ASYNC;

    stream->thread_safe = FLB_FALSE;

#ifdef FLB_HAVE_TLS
    stream->tls = tls;
#endif

    mk_list_init(&stream->busy_queue);
    mk_list_init(&stream->destroy_queue);

    mk_list_add(&stream->_head, &config->downstreams);

    return stream;
}

/*
 * This function moves the 'downstream connection' into the queue to be
 * destroyed. Note that the caller is responsible to validate and check
 * required mutex if this is being used in multi-worker mode.
 */
static int prepare_destroy_conn(struct flb_downstream_conn *connection)
{
    struct flb_downstream *stream;

    stream = connection->stream;

    flb_trace("[downstream] destroy connection #%i to %s:%i",
              connection->fd, connection->host, connection->port);

    if (stream->flags & FLB_IO_ASYNC) {
        mk_event_del(connection->evl, &connection->event);
    }

    /* This should be != -1 to cover those use cases where stdin, stdout
     * and stderr are closed.
     */

    if (connection->fd > 0) {
        flb_socket_close(connection->fd);

        connection->fd = -1;
        connection->event.fd = -1;
    }

    /* remove connection from the queue */
    mk_list_del(&connection->_head);

    /* Add node to destroy queue */
    mk_list_add(&connection->_head, &stream->destroy_queue);

    /*
     * note: the connection context is destroyed by the engine once all events
     * have been processed.
     */
    return 0;
}

/* 'safe' version of prepare_destroy_conn. It set locks if necessary */
static inline int prepare_destroy_conn_safe(struct flb_downstream_conn *connection)
{
    struct flb_downstream *stream;
    int                    locked;
    int                    result;

    locked = FLB_FALSE;
    stream = connection->stream;

    if (stream->thread_safe) {
        result = pthread_mutex_trylock(&stream->mutex_lists);

        if (result == 0) {
            locked = FLB_TRUE;
        }
    }

    result = prepare_destroy_conn(connection);

    if (locked) {
        pthread_mutex_unlock(&stream->mutex_lists);
    }

    return result;
}

static int destroy_conn(struct flb_downstream_conn *connection)
{
    /* Delay the destruction of busy connections */
    if (connection->busy_flag) {
        return 0;
    }

#ifdef FLB_HAVE_TLS
    if (connection->tls_session != NULL) {
        flb_tls_session_destroy(connection->tls_session);
    }
#endif

    mk_list_del(&connection->_head);
    flb_free(connection);

    return 0;
}

struct flb_downstream_conn *flb_downstream_conn_get(struct flb_downstream *stream)
{
    struct flb_downstream_conn *connection;
    time_t                      now;

    now = time(NULL);

    connection = flb_calloc(1, sizeof(struct flb_downstream_conn));
    if (connection == NULL) {
        flb_errno();

        return NULL;
    }

    connection->stream        = stream;
    connection->fd            = -1;
    connection->net_error     = -1;
    connection->busy_flag     = FLB_TRUE;

    /* retrieve the event loop */
    connection->evl = flb_engine_evl_get();

    if (stream->net.connect_timeout > 0) {
        connection->ts_connect_timeout = now + stream->net.connect_timeout;
    }
    else {
        connection->ts_connect_timeout = -1;
    }

#ifdef FLB_HAVE_TLS
    connection->tls = NULL;
    connection->tls_session   = NULL;
#endif

    connection->coro = flb_coro_get();

    MK_EVENT_ZERO(&connection->event);

    if (stream->thread_safe == FLB_TRUE) {
        pthread_mutex_lock(&stream->mutex_lists);
    }

    /* Link new connection to the busy queue */
    mk_list_add(&connection->_head, &stream->busy_queue);

    if (stream->thread_safe == FLB_TRUE) {
        pthread_mutex_unlock(&stream->mutex_lists);
    }

    return connection;
}

int flb_downstream_destroy(struct flb_downstream *stream)
{
    struct flb_downstream_conn *connection;
    struct mk_list             *head;
    struct mk_list             *tmp;

    mk_list_foreach_safe(head, tmp, &stream->busy_queue) {
        connection = mk_list_entry(head, struct flb_downstream_conn, _head);
        prepare_destroy_conn(connection);
    }

    mk_list_foreach_safe(head, tmp, &stream->destroy_queue) {
        connection = mk_list_entry(head, struct flb_downstream_conn, _head);
        destroy_conn(connection);
    }

    flb_free(stream->host);
    flb_free(stream);

    return 0;
}

int flb_downstream_conn_release(struct flb_downstream_conn *connection)
{
    return prepare_destroy_conn_safe(connection);
}

int flb_downstream_conn_timeouts(struct mk_list *list)
{
    return 0;
}

int flb_downstream_conn_pending_destroy(struct flb_downstream *stream)
{
     struct flb_downstream_conn *connection;
    struct mk_list             *head;
    struct mk_list             *tmp;

    if (stream->thread_safe == FLB_TRUE) {
        pthread_mutex_lock(&stream->mutex_lists);
    }

    mk_list_foreach_safe(head, tmp, &stream->destroy_queue) {
        connection = mk_list_entry(head, struct flb_downstream_conn, _head);

        destroy_conn(connection);
    }

    if (stream->thread_safe == FLB_TRUE) {
        pthread_mutex_unlock(&stream->mutex_lists);
    }

    return 0;
}

int flb_downstream_is_async(struct flb_downstream *stream)
{
    if (stream->flags & FLB_IO_ASYNC) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}
