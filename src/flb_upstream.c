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

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_io_tls.h>
#include <fluent-bit/flb_tls.h>
#include <fluent-bit/flb_utils.h>

/* Creates a new upstream context */
struct flb_upstream *flb_upstream_create(struct flb_config *config,
                                         const char *host, int port, int flags,
                                         void *tls)
{
    struct flb_upstream *u;

    u = flb_calloc(1, sizeof(struct flb_upstream));
    if (!u) {
        flb_errno();
        return NULL;
    }

    u->tcp_host      = flb_strdup(host);
    u->tcp_port      = port;
    u->flags         = flags;
    u->evl           = config->evl;
    u->n_connections = 0;
    u->flags |= FLB_IO_ASYNC;

    mk_list_init(&u->av_queue);
    mk_list_init(&u->busy_queue);

#ifdef FLB_HAVE_TLS
    u->tls      = (struct flb_tls *) tls;
#endif

    mk_list_add(&u->_head, &config->upstreams);
    return u;
}

/* Create an upstream context using a valid URL (protocol, host and port) */
struct flb_upstream *flb_upstream_create_url(struct flb_config *config,
                                             const char *url, int flags,
                                             void *tls)
{
    int ret;
    int tmp_port = 0;
    char *prot = NULL;
    char *host = NULL;
    char *port = NULL;
    char *uri = NULL;
    struct flb_upstream *u = NULL;

    /* Parse and split URL */
    ret = flb_utils_url_split(url, &prot, &host, &port, &uri);
    if (ret == -1) {
        flb_error("[upstream] invalid URL: %s", url);
        return NULL;
    }

    if (!prot) {
        flb_error("[upstream] unknown protocol type from URL: %s", url);
        goto out;
    }

    /* Manage some default ports */
    if (!port) {
        if (strcasecmp(prot, "http") == 0) {
            tmp_port = 80;
        }
        else if (strcasecmp(prot, "https") == 0) {
            tmp_port = 443;
        }
    }
    else {
        tmp_port = atoi(port);
    }

    if (tmp_port <= 0) {
        flb_error("[upstream] unknown TCP port in URL: %s", url);
        goto out;
    }

    u = flb_upstream_create(config, host, tmp_port, flags, tls);
    if (!u) {
        flb_error("[upstream] error creating context from URL: %s", url);
    }

 out:
    if (prot) {
        flb_free(prot);
    }
    if (host) {
        flb_free(host);
    }
    if (port) {
        flb_free(port);
    }
    if (uri) {
        flb_free(uri);
    }

    return u;
}

static struct flb_upstream_conn *create_conn(struct flb_upstream *u)
{
    int ret;
    struct flb_upstream_conn *conn;
    struct flb_thread *th = pthread_getspecific(flb_thread_key);

    conn = flb_malloc(sizeof(struct flb_upstream_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }
    conn->u             = u;
    conn->fd            = -1;
#ifdef FLB_HAVE_TLS
    conn->tls_session   = NULL;

    /* TLS handshake */
    conn->tls_handshake_start = -1;
    conn->tls_handshake_timeout = -1;
#endif
    conn->ts_created = time(NULL);
    conn->ts_available = 0;
    conn->ka_count = 0;

    MK_EVENT_ZERO(&conn->event);

    /* Link new connection to the busy queue */
    mk_list_add(&conn->_head, &u->busy_queue);
    u->n_connections++;

    /* Start connection */
    ret = flb_io_net_connect(conn, th);
    if (ret == -1) {
        mk_list_del(&conn->_head);
        flb_free(conn);
        return NULL;
    }

    if (conn->u->flags & FLB_IO_TCP_KA) {
        flb_debug("[upstream] KA connection #%i to %s:%i is connected",
                  conn->fd, u->tcp_host, u->tcp_port);
    }

    return conn;
}

static int destroy_conn(struct flb_upstream_conn *u_conn)
{
    struct flb_upstream *u = u_conn->u;

    flb_trace("[upstream] destroy connection #%i to %s:%i",
              u_conn->fd, u->tcp_host, u->tcp_port);

    if (u->flags & FLB_IO_ASYNC) {
        mk_event_del(u->evl, &u_conn->event);
    }

#ifdef FLB_HAVE_TLS
    if (u_conn->tls_session) {
        flb_tls_session_destroy(u_conn->tls_session);
        u_conn->tls_session = NULL;
    }
#endif

    if (u_conn->fd > 0) {
        flb_socket_close(u_conn->fd);
    }

    /* remove connection from the queue */
    mk_list_del(&u_conn->_head);

    u->n_connections--;
    flb_free(u_conn);

    return 0;
}

int flb_upstream_destroy(struct flb_upstream *u)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_upstream_conn *u_conn;

    mk_list_foreach_safe(head, tmp, &u->av_queue) {
        u_conn = mk_list_entry(head, struct flb_upstream_conn, _head);
        destroy_conn(u_conn);
    }

    mk_list_foreach_safe(head, tmp, &u->busy_queue) {
        u_conn = mk_list_entry(head, struct flb_upstream_conn, _head);
        destroy_conn(u_conn);
    }

    flb_free(u->tcp_host);
    mk_list_del(&u->_head);
    flb_free(u);

    return 0;
}

struct flb_upstream_conn *flb_upstream_conn_get(struct flb_upstream *u)
{
    time_t ts;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_upstream_conn *conn = NULL;

    /* On non Keepalive mode, always create a new TCP connection */
    if ((u->flags & FLB_IO_TCP_KA) == 0) {
        return create_conn(u);
    }

    /*
     * If we are in keepalive mode, iterate list of available connections,
     * take a little of time to do some cleanup and assign a connection. If no
     * entries exists, just create a new one.
     */

    ts = time(NULL);
    mk_list_foreach_safe(head, tmp, &u->av_queue) {
        conn = mk_list_entry(head, struct flb_upstream_conn, _head);

        /* Check if is time to destroy this connection */
        if ((ts - conn->ts_created) > u->ka_timeout) {
            flb_debug("[upstream] KA connection #%i to %s:%i timed out, closing.",
                      conn->fd, u->tcp_host, u->tcp_port);
            destroy_conn(conn);
            conn = NULL;
            continue;
        }

        /* This connection works, let's move it to the busy queue */
        mk_list_del(&conn->_head);
        mk_list_add(&conn->_head, &u->busy_queue);

        /* I/O Timeouts */
        conn->tls_handshake_start = -1;
        conn->tls_handshake_timeout = -1;

        flb_debug("[upstream] KA connection #%i to %s:%i has been assigned (recycled)",
                  conn->fd, u->tcp_host, u->tcp_port);

        /*
         * Note: since we are in a keepalive connection, the socket is already being
         * monitored for possible disconnections while idle. Upon re-use by the caller
         * when it try to send some data, the I/O interface (flb_io.c) will put the
         * proper event mask and reuse, there is no need to remove the socket from
         * the event loop and re-add it again.
         *
         * So... just return the connection context.
         */
        return conn;
    }

    /* No keepalive connection available, create a new one */
    if (!conn) {
        return create_conn(u);
    }

    return conn;
}

/*
 * An 'idle' and keepalive might be disconnected, if so, this callback will perform
 * the proper connection cleanup.
 */
static int cb_upstream_conn_ka_dropped(void *data)
{
    struct flb_upstream_conn *conn;

    conn = (struct flb_upstream_conn *) data;

    flb_debug("[upstream] KA connection #%i to %s:%i has been disconnected "
              "by the remote service",
              conn->fd, conn->u->tcp_host, conn->u->tcp_port);
    return destroy_conn(conn);
}

int flb_upstream_conn_release(struct flb_upstream_conn *conn)
{
    int ret;
    time_t ts;
    struct flb_upstream *u;

    /* Upstream context */
    u = conn->u;

    /* If this is a valid KA connection just recycle */
    if (conn->u->flags & FLB_IO_TCP_KA) {
        /* check keepalive timeout */
        ts = time(NULL);
        if ((ts - conn->ts_created) > conn->u->ka_timeout) {
            /* this connection must be dropped */
            flb_debug("[upstream] KA connection #%i to %s:%i timed out, closing.",
                      conn->fd, conn->u->tcp_host, conn->u->tcp_port);
            return destroy_conn(conn);
        }

        /*
         * This connection is still useful, move it to the 'available' queue and
         * initialize variables.
         */
        mk_list_del(&conn->_head);
        mk_list_add(&conn->_head, &conn->u->av_queue);
        conn->ts_available = time(NULL);

        /*
         * The socket at this point is not longer monitored, so if we want to be
         * notified if the 'available keepalive connection' gets disconnected by
         * the remote endpoint we need to add it again.
         */
        conn->event.handler = cb_upstream_conn_ka_dropped;
        conn->event.data    = &conn;

        ret = mk_event_add(u->evl, conn->fd,
                           FLB_ENGINE_EV_CUSTOM,
                           MK_EVENT_CLOSE, &conn->event);
        if (ret == -1) {
            /* We failed the registration, for safety just destroy the connection */
            flb_debug("[upstream] KA connection #%i to %s:%i could not be "
                      "registered, closing.",
                      conn->fd, conn->u->tcp_host, conn->u->tcp_port);
            return destroy_conn(conn);
        }

        flb_debug("[upstream] KA connection #%i to %s:%i is now available",
                  conn->fd, conn->u->tcp_host, conn->u->tcp_port);
        conn->ka_count++;
        return 0;
    }

    /* No keepalive connections must be destroyed */
    return destroy_conn(conn);
}

int flb_upstream_conn_timeouts(struct flb_config *ctx)
{
    time_t now;
    struct mk_list *head;
    struct mk_list *u_head;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;

    now = time(NULL);
    mk_list_foreach(head, &ctx->upstreams) {
        u = mk_list_entry(head, struct flb_upstream, _head);
#ifdef FLB_HAVE_TLS
        /* Iterate every connection */
        mk_list_foreach(u_head, &u->busy_queue) {
            u_conn = mk_list_entry(u_head, struct flb_upstream_conn, _head);
            if (u_conn->tls_handshake_timeout != -1 &&
                u_conn->tls_handshake_timeout <= now) {
                /*
                 * Shutdown the connection, this is the safest way to indicate
                 * that the socket cannot longer work and any co-routine on
                 * waiting for I/O will receive the notification and trigger
                 * the error to it caller.
                 */
                shutdown(u_conn->fd, SHUT_RDWR);

                /* Notify the user */
                flb_error("[upstream] TLS handshake to %s:%i timeout after "
                          "%i seconds",
                          u->tcp_host, u->tcp_port, u->tls->handshake_timeout);
            }
        }
#endif
    }

    return 0;
}
