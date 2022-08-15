/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_socket.h>

#include "openssl.c"

/* Config map for Upstream networking setup */
struct flb_config_map tls_configmap[] = {
    {
     FLB_CONFIG_MAP_BOOL, "tls", "off",
     0, FLB_FALSE, 0,
     "Enable or disable TLS/SSL support",
    },
    {
     FLB_CONFIG_MAP_BOOL, "tls.verify", "on",
     0, FLB_FALSE, 0,
     "Force certificate validation",
    },
    {
     FLB_CONFIG_MAP_INT, "tls.debug", "1",
     0, FLB_FALSE, 0,
     "Set TLS debug verbosity level. It accept the following "
     "values: 0 (No debug), 1 (Error), 2 (State change), 3 "
     "(Informational) and 4 Verbose"
    },
    {
     FLB_CONFIG_MAP_STR, "tls.ca_file", NULL,
     0, FLB_FALSE, 0,
     "Absolute path to CA certificate file"
    },
    {
     FLB_CONFIG_MAP_STR, "tls.ca_path", NULL,
     0, FLB_FALSE, 0,
     "Absolute path to scan for certificate files"
    },
    {
     FLB_CONFIG_MAP_STR, "tls.crt_file", NULL,
     0, FLB_FALSE, 0,
     "Absolute path to Certificate file"
    },
    {
     FLB_CONFIG_MAP_STR, "tls.key_file", NULL,
     0, FLB_FALSE, 0,
     "Absolute path to private Key file"
    },
    {
     FLB_CONFIG_MAP_STR, "tls.key_passwd", NULL,
     0, FLB_FALSE, 0,
     "Optional password for tls.key_file file"
    },

    {
     FLB_CONFIG_MAP_STR, "tls.vhost", NULL,
     0, FLB_FALSE, 0,
     "Hostname to be used for TLS SNI extension"
    },

    /* EOF */
    {0}
};

struct mk_list *flb_tls_get_config_map(struct flb_config *config)
{
    struct mk_list *config_map;

    config_map = flb_config_map_create(config, tls_configmap);
    return config_map;
}

static inline unsigned short int flb_tls_get_remote_port(struct flb_tls_session *session)
{
    struct flb_upstream_conn   *u_conn;
    struct flb_downstream_conn *d_conn;

    if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        u_conn = (struct flb_upstream_conn *) session->connection;

        return u_conn->u->tcp_port;
    }
    else if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        d_conn = (struct flb_downstream_conn *) session->connection;

        return d_conn->port;
    }

    return 0;
}

static inline char *flb_tls_get_remote_host(struct flb_tls_session *session)
{
    struct flb_upstream_conn   *u_conn;
    struct flb_downstream_conn *d_conn;

    if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        u_conn = (struct flb_upstream_conn *) session->connection;

        return u_conn->u->tcp_host;
    }
    else if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        d_conn = (struct flb_downstream_conn *) session->connection;

        return d_conn->host;
    }

    return NULL;
}

static inline int flb_tls_get_stream_connect_timeout(struct flb_tls_session *session)
{
    struct flb_upstream_conn   *u_conn;
    struct flb_downstream_conn *d_conn;

    if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        u_conn = (struct flb_upstream_conn *) session->connection;

        return u_conn->u->net.connect_timeout;
    }
    else if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        d_conn = (struct flb_downstream_conn *) session->connection;

        return d_conn->stream->net.connect_timeout;
    }

    return 0;
}

static inline int flb_tls_get_connection_connect_timeout(struct flb_tls_session *session)
{
    struct flb_upstream_conn   *u_conn;
    struct flb_downstream_conn *d_conn;

    if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        u_conn = (struct flb_upstream_conn *) session->connection;

        return u_conn->ts_connect_timeout;
    }
    else if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        d_conn = (struct flb_downstream_conn *) session->connection;

        return d_conn->ts_connect_timeout;
    }

    return 0;
}

static inline flb_sockfd_t flb_tls_get_connection_socket(struct flb_tls_session *session)
{
    struct flb_upstream_conn   *u_conn;
    struct flb_downstream_conn *d_conn;

    if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        u_conn = (struct flb_upstream_conn *) session->connection;

        return u_conn->fd;
    }
    else if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        d_conn = (struct flb_downstream_conn *) session->connection;

        return d_conn->fd;
    }

    return (flb_sockfd_t) -1;
}

static inline struct mk_event *flb_tls_get_event(struct flb_tls_session *session)
{
    struct flb_upstream_conn   *u_conn;
    struct flb_downstream_conn *d_conn;

    if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        u_conn = (struct flb_upstream_conn *) session->connection;

        return &u_conn->event;
    }
    else if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        d_conn = (struct flb_downstream_conn *) session->connection;

        return &d_conn->event;
    }

    return NULL;
}

static inline struct mk_event_loop *flb_tls_get_event_loop(struct flb_tls_session *session)
{
    struct flb_upstream_conn   *u_conn;
    struct flb_downstream_conn *d_conn;

    if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        u_conn = (struct flb_upstream_conn *) session->connection;

        return u_conn->evl;
    }
    else if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        d_conn = (struct flb_downstream_conn *) session->connection;

        return d_conn->evl;
    }

    return NULL;
}

static inline void flb_tls_set_connection_coroutine(struct flb_tls_session *session,
                                                    struct flb_coro *coroutine)
{
    struct flb_upstream_conn   *u_conn;
    struct flb_downstream_conn *d_conn;

    if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        u_conn = (struct flb_upstream_conn *) session->connection;

        u_conn->coro = coroutine;
    }
    else if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        d_conn = (struct flb_downstream_conn *) session->connection;

        d_conn->coro = coroutine;
    }
}

static inline void flb_tls_set_connection_priority(struct flb_tls_session *session,
                                                   int priority)
{
    struct mk_event *event;

    event = flb_tls_get_event(session);

    if (event != NULL) {
        event->priority = priority;
    }
}

static inline int io_tls_event_switch(struct flb_tls_session *session,
                                      int mask)
{
    struct mk_event_loop *event_loop;
    struct mk_event      *event;
    int                   ret;

    event = flb_tls_get_event(session);
    event_loop = flb_tls_get_event_loop(session);

    if ((event->mask & mask) == 0) {
        ret = mk_event_add(event_loop,
                           event->fd,
                           FLB_ENGINE_EV_THREAD,
                           mask, event);

        event->priority = FLB_ENGINE_PRIORITY_CONNECT;

        if (ret == -1) {
            flb_error("[io_tls] error changing mask to %i", mask);

            return -1;
        }
    }

    return 0;
}

struct flb_tls *flb_tls_create(int verify,
                               int debug,
                               const char *vhost,
                               const char *ca_path,
                               const char *ca_file, const char *crt_file,
                               const char *key_file, const char *key_passwd)
{
    void *backend;
    struct flb_tls *tls;

    backend = tls_context_create(verify, debug, vhost, ca_path, ca_file,
                                 crt_file, key_file, key_passwd);
    if (!backend) {
        flb_error("[tls] could not create TLS backend");
        return NULL;
    }

    tls = flb_calloc(1, sizeof(struct flb_tls));
    if (!tls) {
        flb_errno();
        tls_context_destroy(backend);
        return NULL;
    }

    tls->verify = verify;
    tls->debug = debug;

    if (vhost) {
        tls->vhost = flb_strdup(vhost);
    }
    tls->ctx = backend;

    tls->api = &tls_openssl;

    return tls;
}

int flb_tls_init()
{
    return tls_init();
}

int flb_tls_destroy(struct flb_tls *tls)
{
    if (tls->ctx) {
        tls->api->context_destroy(tls->ctx);
    }
    if (tls->vhost) {
        flb_free(tls->vhost);
    }
    flb_free(tls);
    return 0;
}

int flb_tls_net_read(struct flb_tls_session *session, void *buf, size_t len)
{
    struct flb_tls *tls;
    int             ret;

    tls = session->tls;

 retry_read:
    ret = tls->api->net_read(session, buf, len);

    if (ret == FLB_TLS_WANT_READ) {
        goto retry_read;
    }
    else if (ret == FLB_TLS_WANT_WRITE) {
        goto retry_read;
    }
    else if (ret < 0) {
        return -1;
    }
    else if (ret == 0) {
        return -1;
    }

    return ret;
}

int flb_tls_net_read_async(struct flb_coro *co,
                           struct flb_tls_session *session,
                           void *buf, size_t len)
{
    int ret;
    struct flb_tls *tls;

    tls = session->tls;

 retry_read:
    ret = tls->api->net_read(session, buf, len);

    if (ret == FLB_TLS_WANT_READ) {
        flb_tls_set_connection_coroutine(session, co);

        io_tls_event_switch(session, MK_EVENT_READ);
        flb_coro_yield(co, FLB_FALSE);

        goto retry_read;
    }
    else if (ret == FLB_TLS_WANT_WRITE) {
        flb_tls_set_connection_coroutine(session, co);

        io_tls_event_switch(session, MK_EVENT_WRITE);
        flb_coro_yield(co, FLB_FALSE);
        
        goto retry_read;
    }
    else
    {
        /* We want this field to hold NULL at all times unless we are explicitly
         * waiting to be resumed.
         */
        flb_tls_set_connection_coroutine(session, NULL);

        if (ret < 0) {
            return -1;
        }
        else if (ret == 0) {
            return -1;
        }
    }

    return ret;
}

int flb_tls_net_write(struct flb_tls_session *session,
                      const void *data, size_t len, size_t *out_len)
{
    size_t          total;
    int             ret;
    struct flb_tls *tls;

    total = 0;
    tls = session->tls;

retry_write:
    ret = tls->api->net_write(session,
                              (unsigned char *) data + total,
                              len - total);

    if (ret == FLB_TLS_WANT_WRITE) {
        goto retry_write;
    }
    else if (ret == FLB_TLS_WANT_READ) {
        goto retry_write;
    }
    else if (ret < 0) {
        return -1;
    }

    /* Update counter and check if we need to continue writing */
    total += ret;

    if (total < len) {
        goto retry_write;
    }

    *out_len = total;

    return 0;
}

int flb_tls_net_write_async(struct flb_coro *co,
                           struct flb_tls_session *session,
                            const void *data, size_t len, size_t *out_len)
{
    size_t          total;
    int             ret;
    struct flb_tls *tls;

    total = 0;
    tls = session->tls;

retry_write:
    flb_tls_set_connection_coroutine(session, co);

    ret = tls->api->net_write(session,
                              (unsigned char *) data + total,
                              len - total);

    if (ret == FLB_TLS_WANT_WRITE) {
        io_tls_event_switch(session, MK_EVENT_WRITE);

        flb_coro_yield(co, FLB_FALSE);

        goto retry_write;
    }
    else if (ret == FLB_TLS_WANT_READ) {
        io_tls_event_switch(session, MK_EVENT_READ);

        flb_coro_yield(co, FLB_FALSE);

        goto retry_write;
    }
    else if (ret < 0) {
        /* We want this field to hold NULL at all times unless we are explicitly
         * waiting to be resumed.
         */

        flb_tls_set_connection_coroutine(session, NULL);

        return -1;
    }

    /* Update counter and check if we need to continue writing */
    total += ret;

    if (total < len) {
        io_tls_event_switch(session, MK_EVENT_WRITE);

        flb_coro_yield(co, FLB_FALSE);

        goto retry_write;
    }

    /* We want this field to hold NULL at all times unless we are explicitly
     * waiting to be resumed.
     */

    flb_tls_set_connection_coroutine(session, NULL);

    *out_len = total;

    mk_event_del(flb_tls_get_event_loop(session),
                 flb_tls_get_event(session));

    return 0;
}


/* Create a TLS session (+handshake) */
int flb_tls_client_session_create(struct flb_tls *tls,
                                  struct flb_upstream_conn *u_conn,
                                  struct flb_coro *co)
{
    struct flb_tls_session *session;
    int                     flag;
    int                     ret;
    struct flb_upstream     *u;

    u = u_conn->u;

    session = flb_calloc(1, sizeof(struct flb_tls_session));

    if (session == NULL) {
        return -1;
    }

    /* Create TLS session */
    session->ptr = tls->api->session_create(tls, u_conn->fd);
    if (session->ptr == NULL) {
        flb_error("[tls] could not create TLS session for %s:%i",
                  u->tcp_host, u->tcp_port);

        flb_tls_session_destroy(session);

        return -1;
    }

    session->connection = (void *) u_conn;
    session->connection_type = FLB_TLS_UPSTREAM_CONNECTION;

    /* Configure virtual host */
    if (!u->tls->vhost) {
        u->tls->vhost = flb_strdup(u->tcp_host);
        if (u->proxied_host) {
            u->tls->vhost = flb_strdup(u->proxied_host);
        }
    }

    /* Reference TLS context and session */
    u_conn->tls = tls;
    u_conn->tls_session = session;

 retry_handshake:
    ret = tls->api->net_client_handshake(tls, session->ptr);
    if (ret != 0) {
        if (ret != FLB_TLS_WANT_READ && ret != FLB_TLS_WANT_WRITE) {
            goto error;
        }

        flag = 0;
        if (ret == FLB_TLS_WANT_WRITE) {
            flag = MK_EVENT_WRITE;
        }
        else if (ret == FLB_TLS_WANT_READ) {
            flag = MK_EVENT_READ;
        }

        /*
         * If there are no coroutine thread context (th == NULL) it means this
         * TLS handshake is happening from a blocking code. Just sleep a bit
         * and retry.
         *
         * In the other case for an async socket 'th' is NOT NULL so the code
         * is under a coroutine context and it can yield.
         */
        if (!co) {
            flb_trace("[io_tls] handshake connection #%i in process to %s:%i",
                      u_conn->fd, u->tcp_host, u->tcp_port);

            /* Connect timeout */
            if (u->net.connect_timeout > 0 &&
                u_conn->ts_connect_timeout > 0 &&
                u_conn->ts_connect_timeout <= time(NULL)) {
                flb_error("[io_tls] handshake connection #%i to %s:%i timed out after "
                          "%i seconds",
                          u_conn->fd,
                          u->tcp_host, u->tcp_port, u->net.connect_timeout);
                goto error;
            }

            flb_time_msleep(500);

            goto retry_handshake;
        }

        /*
         * FIXME: if we need multiple reads we are invoking the same
         * system call multiple times.
         */
        ret = mk_event_add(u_conn->evl,
                           u_conn->event.fd,
                           FLB_ENGINE_EV_THREAD,
                           flag, &u_conn->event);

        u_conn->event.priority = FLB_ENGINE_PRIORITY_CONNECT;

        if (ret == -1) {
            goto error;
        }

        u_conn->coro = co;

        flb_coro_yield(co, FLB_FALSE);

        /* We want this field to hold NULL at all times unless we are explicitly
         * waiting to be resumed.
         */
        u_conn->coro = NULL;

        goto retry_handshake;
    }

    if (u_conn->event.status & MK_EVENT_REGISTERED) {
        mk_event_del(u_conn->evl, &u_conn->event);
    }
    return 0;

 error:
    if (u_conn->event.status & MK_EVENT_REGISTERED) {
        mk_event_del(u_conn->evl, &u_conn->event);
    }

    flb_tls_session_destroy(session);

    return -1;
}

/* Create a TLS session (server) */
int flb_tls_server_session_create(struct flb_tls *tls,
                                  struct flb_downstream_conn *connection,
                                  struct flb_coro *co)
{
    struct flb_tls_session *session;
    int                     result;
    int                     flag;

    session = flb_calloc(1, sizeof(struct flb_tls_session));

    if (session == NULL) {
        return -1;
    }

    /* Create TLS session */
    session->ptr = tls->api->session_create(tls, connection->fd);

    if (session == NULL) {
        flb_error("[tls] could not create TLS session for %s:%i",
                  connection->host, connection->port);

        return -1;
    }

    session->tls = tls;
    session->connection = (void *) connection;
    session->connection_type = FLB_TLS_DOWNSTREAM_CONNECTION;

    /* Configure virtual host */
    if (connection->tls->vhost == NULL) {
        connection->tls->vhost = flb_strdup(connection->host);
    }

    /* Reference TLS context and session */
    connection->tls = tls;
    connection->tls_session = session;

    result = 0;

 retry_handshake:
    result = tls->api->net_server_handshake(tls, session->ptr);

    if (result != 0) {
        if (result != FLB_TLS_WANT_READ && result != FLB_TLS_WANT_WRITE) {
            result = -1;

            goto cleanup;
        }

        flag = 0;

        if (result == FLB_TLS_WANT_WRITE) {
            flag = MK_EVENT_WRITE;
        }
        else if (result == FLB_TLS_WANT_READ) {
            flag = MK_EVENT_READ;
        }

        /*
         * If there are no coroutine thread context (th == NULL) it means this
         * TLS handshake is happening from a blocking code. Just sleep a bit
         * and retry.
         *
         * In the other case for an async socket 'th' is NOT NULL so the code
         * is under a coroutine context and it can yield.
         */
        if (co == NULL) {
            flb_trace("[io_tls] server handshake connection #%i in process to %s:%i",
                      flb_tls_get_connection_socket(session),
                      flb_tls_get_remote_host(session),
                      flb_tls_get_remote_port(session));

            /* Connect timeout */
            if (flb_tls_get_stream_connect_timeout(session) > 0 &&
                flb_tls_get_connection_connect_timeout(session) > 0 &&
                flb_tls_get_connection_connect_timeout(session) <= time(NULL)) {
                flb_error("[io_tls] handshake connection #%i to %s:%i timed out after "
                          "%i seconds",
                          flb_tls_get_connection_socket(session),
                          flb_tls_get_remote_host(session),
                          flb_tls_get_remote_port(session),
                          flb_tls_get_stream_connect_timeout(session));

                result = -1;

                goto cleanup;
            }

            flb_time_msleep(500);

            goto retry_handshake;
        }

        /*
         * FIXME: if we need multiple reads we are invoking the same
         * system call multiple times.
         */

        result = mk_event_add(flb_tls_get_event_loop(session),
                              flb_tls_get_connection_socket(session),
                              FLB_ENGINE_EV_THREAD,
                              flag,
                              flb_tls_get_event(session));

        flb_tls_set_connection_priority(session, FLB_ENGINE_PRIORITY_CONNECT);

        if (result == -1) {
            goto cleanup;
        }

        flb_tls_set_connection_coroutine(session, co);

        flb_coro_yield(co, FLB_FALSE);

        /* We want this field to hold NULL at all times unless we are explicitly
         * waiting to be resumed.
         */

        flb_tls_set_connection_coroutine(session, NULL);

        goto retry_handshake;
    }

cleanup:
    if (connection->event.status & MK_EVENT_REGISTERED) {
        mk_event_del(flb_tls_get_event_loop(session),
                     flb_tls_get_event(session));
    }

    if (result != 0) {
        flb_tls_session_destroy(session);
    }

    return result;
}

int flb_tls_session_destroy(struct flb_tls_session *session)
{
    struct flb_upstream_conn   *u_conn;
    struct flb_downstream_conn *d_conn;
    int                         ret;

    if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        u_conn = (struct flb_upstream_conn *) session->connection;

        u_conn->tls = NULL;
        u_conn->tls_session = NULL;
    }
    else if (session->connection_type == FLB_TLS_UPSTREAM_CONNECTION) {
        d_conn = (struct flb_downstream_conn *) session->connection;

        d_conn->tls = NULL;
        d_conn->tls_session = NULL;
    }

    if (session->ptr != NULL) {
        ret = session->tls->api->session_destroy(session->ptr);

        if (ret == -1) {
            return -1;
        }

        flb_free(session);
    }

    return 0;
}
