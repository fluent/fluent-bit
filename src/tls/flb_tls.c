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

    {
     FLB_CONFIG_MAP_BOOL, "tls.verify_hostname", "off",
     0, FLB_FALSE, 0,
     "Enable or disable to verify hostname"
    },

    {
     FLB_CONFIG_MAP_STR, "tls.min_version", NULL,
     0, FLB_FALSE, 0,
     "Specify the minimum version of TLS"
    },

    {
     FLB_CONFIG_MAP_STR, "tls.max_version", NULL,
     0, FLB_FALSE, 0,
     "Specify the maximum version of TLS"
    },

    {
     FLB_CONFIG_MAP_STR, "tls.ciphers", NULL,
     0, FLB_FALSE, 0,
     "Specify TLS ciphers up to TLSv1.2"
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


static inline void io_tls_backup_event(struct flb_connection *connection,
                                       struct mk_event *backup)
{
    if (connection != NULL && backup != NULL) {
        memcpy(backup, &connection->event, sizeof(struct mk_event));
    }
}

static inline void io_tls_restore_event(struct flb_connection *connection,
                                        struct mk_event *backup)
{
    int result;

    if (connection != NULL && backup != NULL) {
        if (MK_EVENT_IS_REGISTERED((&connection->event))) {
            result = mk_event_del(connection->evl, &connection->event);

            assert(result == 0);
        }

        if (MK_EVENT_IS_REGISTERED(backup)) {
            connection->event.priority = backup->priority;
            connection->event.handler = backup->handler;

            result = mk_event_add(connection->evl,
                                  connection->fd,
                                  backup->type,
                                  backup->mask,
                                  &connection->event);

            assert(result == 0);
        }
    }
}


static inline int io_tls_event_switch(struct flb_tls_session *session,
                                      int mask)
{
    struct mk_event_loop *event_loop;
    struct mk_event      *event;
    int                   ret;

    event = &session->connection->event;
    event_loop = session->connection->evl;

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

int flb_tls_load_system_certificates(struct flb_tls *tls)
{
    return load_system_certificates(tls->ctx);
}

struct flb_tls *flb_tls_create(int mode,
                               int verify,
                               int debug,
                               const char *vhost,
                               const char *ca_path,
                               const char *ca_file,
                               const char *crt_file,
                               const char *key_file,
                               const char *key_passwd)
{
    void *backend;
    struct flb_tls *tls;

    /* Assuming the TLS role based on the connection direction is wrong
     * but it's something we'll accept for the moment.
     */

    backend = tls_context_create(verify, debug, mode,
                                 vhost, ca_path, ca_file,
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
    tls->mode = mode;
    tls->verify_hostname = FLB_FALSE;
#if defined(FLB_SYSTEM_WINDOWS)
    tls->certstore_name = NULL;
    tls->use_enterprise_store = FLB_FALSE;
#endif

    if (vhost != NULL) {
        tls->vhost = flb_strdup(vhost);
    }
    tls->ctx = backend;

    tls->api = &tls_openssl;

    return tls;
}

int flb_tls_set_minmax_proto(struct flb_tls *tls,
                             const char *min_version, const char *max_version)
{
    if (tls->ctx) {
        return tls->api->set_minmax_proto(tls, min_version, max_version);
    }

    return 0;
}

int flb_tls_set_ciphers(struct flb_tls *tls, const char *ciphers)
{
    if (tls->ctx) {
        return tls->api->set_ciphers(tls, ciphers);
    }

    return 0;
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

    if (tls->vhost != NULL) {
        flb_free(tls->vhost);
    }

#if defined(FLB_SYSTEM_WINDOWS)
    if (tls->certstore_name) {
        flb_free(tls->certstore_name);
    }
#endif

    flb_free(tls);

    return 0;
}

int flb_tls_set_alpn(struct flb_tls *tls, const char *alpn)
{
    if (tls->ctx) {
        return tls->api->context_alpn_set(tls->ctx, alpn);
    }

    return 0;
}

int flb_tls_set_verify_hostname(struct flb_tls *tls, int verify_hostname)
{
    if (!tls) {
        return -1;
    }

    tls->verify_hostname = !!verify_hostname;

    return 0;
}

#if defined(FLB_SYSTEM_WINDOWS)
int flb_tls_set_certstore_name(struct flb_tls *tls, const char *certstore_name)
{
    if (!tls) {
        return -1;
    }

    if (tls->certstore_name) {
        flb_free(tls->certstore_name);
    }

    tls->certstore_name = flb_strdup(certstore_name);

    return 0;
}

int flb_tls_set_use_enterprise_store(struct flb_tls *tls, int use_enterprise)
{
    if (!tls) {
        return -1;
    }

    tls->use_enterprise_store = !!use_enterprise;

    return 0;
}
#endif

int flb_tls_net_read(struct flb_tls_session *session, void *buf, size_t len)
{
    time_t          timeout_timestamp;
    time_t          current_timestamp;
    struct flb_tls *tls;
    int             ret;

    tls = session->tls;

    if (session->connection->net->io_timeout > 0) {
        timeout_timestamp = time(NULL) + session->connection->net->io_timeout;
    }
    else {
        timeout_timestamp = 0;
    }

 retry_read:
    ret = tls->api->net_read(session, buf, len);

    current_timestamp = time(NULL);

    if (ret == FLB_TLS_WANT_READ) {
        if (timeout_timestamp > 0 &&
            timeout_timestamp <= current_timestamp) {
            return ret;
        }

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
    int             event_restore_needed;
    struct mk_event event_backup;
    struct flb_tls *tls;
    int             ret;

    tls = session->tls;

    event_restore_needed = FLB_FALSE;

    io_tls_backup_event(session->connection, &event_backup);

 retry_read:
    ret = tls->api->net_read(session, buf, len);

    if (ret == FLB_TLS_WANT_READ) {
        event_restore_needed = FLB_TRUE;

        session->connection->coroutine = co;

        io_tls_event_switch(session, MK_EVENT_READ);
        flb_coro_yield(co, FLB_FALSE);

        goto retry_read;
    }
    else if (ret == FLB_TLS_WANT_WRITE) {
        event_restore_needed = FLB_TRUE;

        session->connection->coroutine = co;

        io_tls_event_switch(session, MK_EVENT_WRITE);
        flb_coro_yield(co, FLB_FALSE);

        goto retry_read;
    }
    else
    {
        /* We want this field to hold NULL at all times unless we are explicitly
         * waiting to be resumed.
         */
        session->connection->coroutine = NULL;

        if (ret <= 0) {
            ret = -1;
        }
    }

    if (event_restore_needed) {
        /* If we enter here it means we registered this connection
         * in the event loop, in which case we need to unregister it
         * and restore the original registration if there was one.
         *
         * We do it conditionally because in those cases in which
         * send succeeds on the first try we don't touch the event
         * and it wouldn't make sense to unregister and register for
         * the same event.
         */

        io_tls_restore_event(session->connection, &event_backup);
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
        *out_len = total;

        return -1;
    }

    /* Update counter and check if we need to continue writing */
    total += ret;

    if (total < len) {
        goto retry_write;
    }

    *out_len = total;

    return ret;
}

int flb_tls_net_write_async(struct flb_coro *co,
                            struct flb_tls_session *session,
                            const void *data, size_t len, size_t *out_len)
{
    int             event_restore_needed;
    struct mk_event event_backup;
    size_t          total;
    int             ret;
    struct flb_tls *tls;

    total = 0;
    tls = session->tls;

    event_restore_needed = FLB_FALSE;

    io_tls_backup_event(session->connection, &event_backup);

retry_write:
    session->connection->coroutine = co;

    ret = tls->api->net_write(session,
                              (unsigned char *) data + total,
                              len - total);

    if (ret == FLB_TLS_WANT_WRITE) {
        event_restore_needed = FLB_TRUE;

        io_tls_event_switch(session, MK_EVENT_WRITE);

        flb_coro_yield(co, FLB_FALSE);

        goto retry_write;
    }
    else if (ret == FLB_TLS_WANT_READ) {
        event_restore_needed = FLB_TRUE;

        io_tls_event_switch(session, MK_EVENT_READ);

        flb_coro_yield(co, FLB_FALSE);

        goto retry_write;
    }
    else if (ret < 0) {
        /* We want this field to hold NULL at all times unless we are explicitly
         * waiting to be resumed.
         */

        session->connection->coroutine = NULL;
        *out_len = total;

        io_tls_restore_event(session->connection, &event_backup);

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

    session->connection->coroutine = NULL;

    *out_len = total;

    if (event_restore_needed) {
        /* If we enter here it means we registered this connection
         * in the event loop, in which case we need to unregister it
         * and restore the original registration if there was one.
         *
         * We do it conditionally because in those cases in which
         * send succeeds on the first try we don't touch the event
         * and it wouldn't make sense to unregister and register for
         * the same event.
         */

        io_tls_restore_event(session->connection, &event_backup);
    }

    return total;
}

int flb_tls_client_session_create(struct flb_tls *tls,
                                  struct flb_connection *u_conn,
                                  struct flb_coro *co)
{
    return flb_tls_session_create(tls, u_conn, co);
}

int flb_tls_server_session_create(struct flb_tls *tls,
                                  struct flb_connection *connection,
                                  struct flb_coro *co)
{
    return flb_tls_session_create(tls, connection, co);
}

/* Create a TLS session (server) */
int flb_tls_session_create(struct flb_tls *tls,
                           struct flb_connection *connection,
                           struct flb_coro *co)
{
    int                     event_restore_needed;
    struct mk_event         event_backup;
    struct flb_tls_session *session;
    int                     result;
    char                   *vhost;
    int                     flag;

    session = flb_calloc(1, sizeof(struct flb_tls_session));

    if (session == NULL) {
        return -1;
    }

    vhost = NULL;

    if (connection->type == FLB_UPSTREAM_CONNECTION) {
        if (connection->upstream->proxied_host != NULL) {
            vhost = flb_rtrim(connection->upstream->proxied_host, '.');
        }
        else {
            if (tls->vhost == NULL) {
                vhost = flb_rtrim(connection->upstream->tcp_host, '.');
            }
        }
    }

    /* Create TLS session */
    session->ptr = tls->api->session_create(tls, connection->fd);

    if (session == NULL) {
        flb_error("[tls] could not create TLS session for %s",
                  flb_connection_get_remote_address(connection));

        return -1;
    }

    session->tls = tls;
    session->connection = connection;

    result = 0;

    event_restore_needed = FLB_FALSE;

    io_tls_backup_event(session->connection, &event_backup);

 retry_handshake:
    result = tls->api->net_handshake(tls, vhost, session->ptr);

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
        if (co == NULL || !flb_upstream_is_async(connection->upstream)) {
            flb_trace("[io_tls] server handshake connection #%i in process to %s",
                      connection->fd,
                      flb_connection_get_remote_address(connection));

            /* Connect timeout */
            if (connection->net->connect_timeout > 0 &&
                connection->ts_connect_timeout > 0 &&
                connection->ts_connect_timeout <= time(NULL)) {
                flb_error("[io_tls] handshake connection #%i to %s timed out after "
                          "%i seconds",
                          connection->fd,
                          flb_connection_get_remote_address(connection),
                          connection->net->connect_timeout);

                result = -1;

                goto cleanup;
            }

            flb_time_msleep(500);

            goto retry_handshake;
        }

        event_restore_needed = FLB_TRUE;

        /*
         * FIXME: if we need multiple reads we are invoking the same
         * system call multiple times.
         */

        result = mk_event_add(connection->evl,
                              connection->fd,
                              FLB_ENGINE_EV_THREAD,
                              flag,
                              &connection->event);

        connection->event.priority = FLB_ENGINE_PRIORITY_CONNECT;

        if (result == -1) {
            goto cleanup;
        }

        connection->coroutine = co;

        flb_coro_yield(co, FLB_FALSE);

        /* We want this field to hold NULL at all times unless we are explicitly
         * waiting to be resumed.
         */

        connection->coroutine = NULL;

        /* This check's purpose is to abort when a timeout is detected.
         */
        if (connection->net_error == -1) {
            goto retry_handshake;
        }
        else {
            result = -1;
        }
    }

cleanup:
    if (event_restore_needed) {
        /* If we enter here it means we registered this connection
         * in the event loop, in which case we need to unregister it
         * and restore the original registration if there was one.
         *
         * We do it conditionally because in those cases in which
         * send succeeds on the first try we don't touch the event
         * and it wouldn't make sense to unregister and register for
         * the same event.
         */

        io_tls_restore_event(session->connection, &event_backup);
    }

    if (result != 0) {
        flb_tls_session_destroy(session);
    }
    else {
        connection->tls_session = session;
    }

    if (vhost != NULL) {
        flb_free(vhost);
    }

    return result;
}

const char *flb_tls_session_get_alpn(struct flb_tls_session *session)
{
    if (session->ptr != NULL) {
        return session->tls->api->session_alpn_get(session);
    }

    return NULL;
}

int flb_tls_session_destroy(struct flb_tls_session *session)
{
    int ret;

    session->connection->tls_session = NULL;

    if (session->ptr != NULL) {
        ret = session->tls->api->session_destroy(session->ptr);

        if (ret == -1) {
            return -1;
        }

        flb_free(session);
    }

    return 0;
}
