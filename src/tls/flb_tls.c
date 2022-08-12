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


static inline int io_tls_event_switch(struct flb_upstream_conn *u_conn,
                                      int mask)
{
    int ret;
    struct mk_event *event;

    event = &u_conn->event;
    if ((event->mask & mask) == 0) {
        ret = mk_event_add(u_conn->evl,
                           event->fd,
                           FLB_ENGINE_EV_THREAD,
                           mask, &u_conn->event);
        u_conn->event.priority = FLB_ENGINE_PRIORITY_CONNECT;
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

int flb_tls_net_read(struct flb_upstream_conn *u_conn, void *buf, size_t len)
{
    int ret;
    struct flb_tls *tls = u_conn->tls;

 retry_read:
    ret = tls->api->net_read(u_conn, buf, len);
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

int flb_tls_net_read_async(struct flb_coro *co, struct flb_upstream_conn *u_conn,
                           void *buf, size_t len)
{
    int ret;
    struct flb_tls *tls = u_conn->tls;

 retry_read:
    ret = tls->api->net_read(u_conn, buf, len);
    if (ret == FLB_TLS_WANT_READ) {
        u_conn->coro = co;

        io_tls_event_switch(u_conn, MK_EVENT_READ);
        flb_coro_yield(co, FLB_FALSE);

        goto retry_read;
    }
    else if (ret == FLB_TLS_WANT_WRITE) {
        u_conn->coro = co;

        io_tls_event_switch(u_conn, MK_EVENT_WRITE);
        flb_coro_yield(co, FLB_FALSE);
        
        goto retry_read;
    }
    else
    {
        /* We want this field to hold NULL at all times unless we are explicitly
         * waiting to be resumed.
         */
        u_conn->coro = NULL;

        if (ret < 0) {
            return -1;
        }
        else if (ret == 0) {
            return -1;
        }
    }

    return ret;
}

int flb_tls_net_write(struct flb_upstream_conn *u_conn,
                      const void *data, size_t len, size_t *out_len)
{
    int ret;
    size_t total = 0;
    struct flb_tls *tls = u_conn->tls;

retry_write:
    ret = tls->api->net_write(u_conn, (unsigned char *) data + total,
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

int flb_tls_net_write_async(struct flb_coro *co, struct flb_upstream_conn *u_conn,
                            const void *data, size_t len, size_t *out_len)
{
    int ret;
    size_t total = 0;
    struct flb_tls *tls = u_conn->tls;

 retry_write:
    u_conn->coro = co;

    ret = tls->api->net_write(u_conn, (unsigned char *) data + total,
                              len - total);
    if (ret == FLB_TLS_WANT_WRITE) {
        io_tls_event_switch(u_conn, MK_EVENT_WRITE);
        flb_coro_yield(co, FLB_FALSE);

        goto retry_write;
    }
    else if (ret == FLB_TLS_WANT_READ) {
        io_tls_event_switch(u_conn, MK_EVENT_READ);
        flb_coro_yield(co, FLB_FALSE);

        goto retry_write;
    }
    else if (ret < 0) {
        /* We want this field to hold NULL at all times unless we are explicitly
         * waiting to be resumed.
         */

        u_conn->coro = NULL;

        return -1;
    }

    /* Update counter and check if we need to continue writing */
    total += ret;
    if (total < len) {
        io_tls_event_switch(u_conn, MK_EVENT_WRITE);
        flb_coro_yield(co, FLB_FALSE);

        goto retry_write;
    }

    /* We want this field to hold NULL at all times unless we are explicitly
     * waiting to be resumed.
     */

    u_conn->coro = NULL;

    *out_len = total;
    mk_event_del(u_conn->evl, &u_conn->event);
    return 0;
}


/* Create a TLS session (+handshake) */
int flb_tls_session_create(struct flb_tls *tls,
                           struct flb_upstream_conn *u_conn,
                           struct flb_coro *co)
{
    int ret;
    int flag;
    struct flb_tls_session *session;
    struct flb_upstream *u = u_conn->u;

    /* Create TLS session */
    session = tls->api->session_create(tls, u_conn);
    if (!session) {
        flb_error("[tls] could not create TLS session for %s:%i",
                  u->tcp_host, u->tcp_port);
        return -1;
    }

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
    ret = tls->api->net_handshake(tls, session);
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
    flb_tls_session_destroy(tls, u_conn);
    u_conn->tls_session = NULL;

    return -1;
}

int flb_tls_session_destroy(struct flb_tls *tls, struct flb_upstream_conn *u_conn)
{
    int ret;

    ret = tls->api->session_destroy(u_conn->tls_session);
    if (ret == -1) {
        return -1;
    }

    u_conn->tls = NULL;
    u_conn->tls_session = NULL;

    return 0;
}
