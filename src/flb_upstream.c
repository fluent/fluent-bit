/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_thread_storage.h>

FLB_TLS_DEFINE(struct mk_list, flb_upstream_list_key);

/* Config map for Upstream networking setup */
struct flb_config_map upstream_net[] = {
    {
     FLB_CONFIG_MAP_BOOL, "net.keepalive", "true",
     0, FLB_TRUE, offsetof(struct flb_net_setup, keepalive),
     "Enable or disable Keepalive support"
    },

    {
     FLB_CONFIG_MAP_TIME, "net.keepalive_idle_timeout", "30s",
     0, FLB_TRUE, offsetof(struct flb_net_setup, keepalive_idle_timeout),
     "Set maximum time allowed for an idle Keepalive connection"
    },

    {
     FLB_CONFIG_MAP_TIME, "net.connect_timeout", "10s",
     0, FLB_TRUE, offsetof(struct flb_net_setup, connect_timeout),
     "Set maximum time allowed to establish a connection, this time "
     "includes the TLS handshake"
    },

    {
     FLB_CONFIG_MAP_STR, "net.source_address", NULL,
     0, FLB_TRUE, offsetof(struct flb_net_setup, source_address),
     "Specify network address to bind for data traffic"
    },

    {
     FLB_CONFIG_MAP_INT, "net.keepalive_max_recycle", "2000",
     0, FLB_TRUE, offsetof(struct flb_net_setup, keepalive_max_recycle),
     "Set maximum number of times a keepalive connection can be used "
     "before it is retired."
    },

    /* EOF */
    {0}
};

/* Enable thread-safe mode for upstream connection */
void flb_upstream_thread_safe(struct flb_upstream *u)
{
    u->thread_safe = FLB_TRUE;
    pthread_mutex_init(&u->mutex_lists, NULL);

    /*
     * Upon upstream creation, automatically the upstream is linked into
     * the main Fluent Bit context (struct flb_config *)->upstreams. We
     * have to avoid any access to this context outside of the worker
     * thread.
     */
    mk_list_del(&u->_head);
}

struct mk_list *flb_upstream_get_config_map(struct flb_config *config)
{
    struct mk_list *config_map;

    config_map = flb_config_map_create(config, upstream_net);
    return config_map;
}

void flb_upstream_queue_init(struct flb_upstream_queue *uq)
{
    mk_list_init(&uq->av_queue);
    mk_list_init(&uq->busy_queue);
    mk_list_init(&uq->destroy_queue);
}

struct flb_upstream_queue *flb_upstream_queue_get(struct flb_upstream *u)
{
    struct mk_list *head;
    struct mk_list *list;
    struct flb_upstream *th_u;
    struct flb_upstream_queue *uq;

    /*
     * Get the upstream queue, this might be different if the upstream is running
     * in single-thread or multi-thread mode.
     */
    if (u->thread_safe == FLB_TRUE) {
        list = flb_upstream_list_get();
        if (!list) {
            /*
             * Here is the issue: a plugin enabled in multiworker mode in the
             * initialization callback might wanted to use an upstream
             * connection, but the init callback does not run in threaded mode
             * so we hit this problem.
             *
             * As a fallback mechanism: just cross our fingers and return the
             * principal upstream queue.
             */
            return (struct flb_upstream_queue *) &u->queue;
        }

        mk_list_foreach(head, list) {
            th_u = mk_list_entry(head, struct flb_upstream, _head);
            if (th_u->parent_upstream == u) {
                break;
            }
            th_u = NULL;
        }

        if (!th_u) {
            return NULL;
        }
        uq = &th_u->queue;
    }
    else {
        uq = &u->queue;
    }

    return uq;
}

void flb_upstream_list_set(struct mk_list *list)
{
    FLB_TLS_SET(flb_upstream_list_key, list);
}

struct mk_list *flb_upstream_list_get()
{
    return FLB_TLS_GET(flb_upstream_list_key);
}

/* Initialize any upstream environment context */
void flb_upstream_init()
{
    /* Initialize the upstream queue thread local storage */
    FLB_TLS_INIT(flb_upstream_list_key);
}

/* Creates a new upstream context */
struct flb_upstream *flb_upstream_create(struct flb_config *config,
                                         const char *host, int port, int flags,
                                         struct flb_tls *tls)
{
    int ret;
    char *proxy_protocol = NULL;
    char *proxy_host = NULL;
    char *proxy_port = NULL;
    char *proxy_username = NULL;
    char *proxy_password = NULL;
    struct flb_upstream *u;

    u = flb_calloc(1, sizeof(struct flb_upstream));
    if (!u) {
        flb_errno();
        return NULL;
    }

    /* Set default networking setup values */
    flb_net_setup_init(&u->net);

    /* Set upstream to the http_proxy if it is specified. */
    if (config->http_proxy) {
        flb_debug("[upstream] config->http_proxy: %s", config->http_proxy);
        ret = flb_utils_proxy_url_split(config->http_proxy, &proxy_protocol,
                                        &proxy_username, &proxy_password,
                                        &proxy_host, &proxy_port);
        if (ret == -1) {
            flb_errno();
            flb_free(u);
            return NULL;
        }

        u->tcp_host = flb_strdup(proxy_host);
        u->tcp_port = atoi(proxy_port);
        u->proxied_host = flb_strdup(host);
        u->proxied_port = port;
        if (proxy_username && proxy_password) {
            u->proxy_username = flb_strdup(proxy_username);
            u->proxy_password = flb_strdup(proxy_password);
        }

        flb_free(proxy_protocol);
        flb_free(proxy_host);
        flb_free(proxy_port);
        flb_free(proxy_username);
        flb_free(proxy_password);
    }
    else {
        u->tcp_host = flb_strdup(host);
        u->tcp_port = port;
    }

    if (!u->tcp_host) {
        flb_free(u);
        return NULL;
    }

    u->flags          = flags;
    u->flags         |= FLB_IO_ASYNC;
    u->thread_safe    = FLB_FALSE;


    /* Initialize queues */
    flb_upstream_queue_init(&u->queue);

#ifdef FLB_HAVE_TLS
    u->tls = tls;
#endif

    mk_list_add(&u->_head, &config->upstreams);
    return u;
}


/* Create an upstream context using a valid URL (protocol, host and port) */
struct flb_upstream *flb_upstream_create_url(struct flb_config *config,
                                             const char *url, int flags,
                                             struct flb_tls *tls)
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
            if ((flags & FLB_IO_TLS) == 0) {
                flags |= FLB_IO_TLS;
            }
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

/*
 * This function moves the 'upstream connection' into the queue to be
 * destroyed. Note that the caller is responsible to validate and check
 * required mutex if this is being used in multi-worker mode.
 */
static int prepare_destroy_conn(struct flb_upstream_conn *u_conn)
{
    struct flb_upstream *u = u_conn->u;
    struct flb_upstream_queue *uq;

    uq = flb_upstream_queue_get(u);

    flb_trace("[upstream] destroy connection #%i to %s:%i",
              u_conn->fd, u->tcp_host, u->tcp_port);

    if (u->flags & FLB_IO_ASYNC) {
        mk_event_del(u_conn->evl, &u_conn->event);
    }

    if (u_conn->fd > 0) {
        flb_socket_close(u_conn->fd);
        u_conn->fd = -1;
        u_conn->event.fd = -1;
    }

    /* remove connection from the queue */
    mk_list_del(&u_conn->_head);

    /* Add node to destroy queue */
    mk_list_add(&u_conn->_head, &uq->destroy_queue);

    /*
     * note: the connection context is destroyed by the engine once all events
     * have been processed.
     */
    return 0;
}

/* 'safe' version of prepare_destroy_conn. It set locks if necessary */
static inline int prepare_destroy_conn_safe(struct flb_upstream_conn *u_conn)
{
    int ret;
    struct flb_upstream *u = u_conn->u;

    if (u->thread_safe == FLB_TRUE) {
        pthread_mutex_lock(&u->mutex_lists);
    }

    ret = prepare_destroy_conn(u_conn);

    if (u->thread_safe == FLB_TRUE) {
        pthread_mutex_unlock(&u->mutex_lists);
    }

    return ret;
}

static int destroy_conn(struct flb_upstream_conn *u_conn)
{
#ifdef FLB_HAVE_TLS
    if (u_conn->tls_session) {
        flb_tls_session_destroy(u_conn->tls, u_conn);
    }
#endif
    mk_list_del(&u_conn->_head);
    flb_free(u_conn);

    return 0;
}

static struct flb_upstream_conn *create_conn(struct flb_upstream *u)
{
    int ret;
    time_t now;
    struct mk_event_loop *evl;
    struct flb_coro *coro = flb_coro_get();
    struct flb_upstream_conn *conn;
    struct flb_upstream_queue *uq;

    now = time(NULL);

    conn = flb_calloc(1, sizeof(struct flb_upstream_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }
    conn->u             = u;
    conn->fd            = -1;
    conn->net_error     = -1;

    /* retrieve the event loop */
    evl = flb_engine_evl_get();
    conn->evl = evl;

    if (u->net.connect_timeout > 0) {
        conn->ts_connect_timeout = now + u->net.connect_timeout;
    }
    else {
        conn->ts_connect_timeout = -1;
    }

#ifdef FLB_HAVE_TLS
    conn->tls = NULL;
    conn->tls_session   = NULL;
#endif
    conn->ts_created = time(NULL);
    conn->ts_assigned = time(NULL);
    conn->ts_available = 0;
    conn->ka_count = 0;
    conn->coro = coro;

    if (u->net.keepalive == FLB_TRUE) {
        flb_upstream_conn_recycle(conn, FLB_TRUE);
    }
    else {
        flb_upstream_conn_recycle(conn, FLB_FALSE);
    }

    MK_EVENT_ZERO(&conn->event);

    if (u->thread_safe == FLB_TRUE) {
        pthread_mutex_lock(&u->mutex_lists);
    }

    /* Link new connection to the busy queue */
    uq = flb_upstream_queue_get(u);
    mk_list_add(&conn->_head, &uq->busy_queue);

    if (u->thread_safe == FLB_TRUE) {
        pthread_mutex_unlock(&u->mutex_lists);
    }

    /* Start connection */
    ret = flb_io_net_connect(conn, coro);
    if (ret == -1) {
        flb_debug("[upstream] connection #%i failed to %s:%i",
                  conn->fd, u->tcp_host, u->tcp_port);
        prepare_destroy_conn_safe(conn);
        return NULL;
    }

    if (conn->u->flags & FLB_IO_TCP_KA) {
        flb_debug("[upstream] KA connection #%i to %s:%i is connected",
                  conn->fd, u->tcp_host, u->tcp_port);
    }

    /* Invalidate timeout for connection */
    conn->ts_connect_timeout = -1;

    return conn;
}

int flb_upstream_destroy(struct flb_upstream *u)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_upstream_conn *u_conn;
    struct flb_upstream_queue *uq;

    uq = flb_upstream_queue_get(u);
    if (!uq) {
        uq = &u->queue;
    }

    mk_list_foreach_safe(head, tmp, &uq->av_queue) {
        u_conn = mk_list_entry(head, struct flb_upstream_conn, _head);
        prepare_destroy_conn(u_conn);
    }

    mk_list_foreach_safe(head, tmp, &uq->busy_queue) {
        u_conn = mk_list_entry(head, struct flb_upstream_conn, _head);
        prepare_destroy_conn(u_conn);
    }

    mk_list_foreach_safe(head, tmp, &uq->destroy_queue) {
        u_conn = mk_list_entry(head, struct flb_upstream_conn, _head);
        destroy_conn(u_conn);
    }

    flb_free(u->tcp_host);
    flb_free(u->proxied_host);
    flb_free(u->proxy_username);
    flb_free(u->proxy_password);
    mk_list_del(&u->_head);
    flb_free(u);

    return 0;
}

/* Enable or disable 'recycle' flag for the connection */
int flb_upstream_conn_recycle(struct flb_upstream_conn *conn, int val)
{
    if (val == FLB_TRUE || val == FLB_FALSE) {
        conn->recycle = val;
    }

    return -1;
}

struct flb_upstream_conn *flb_upstream_conn_get(struct flb_upstream *u)
{
    int err;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_upstream_conn *conn = NULL;
    struct flb_upstream_queue *uq;

    uq = flb_upstream_queue_get(u);

    flb_trace("[upstream] get new connection for %s:%i, net setup:\n"
              "net.connect_timeout        = %i seconds\n"
              "net.source_address         = %s\n"
              "net.keepalive              = %s\n"
              "net.keepalive_idle_timeout = %i seconds",
              u->tcp_host, u->tcp_port,
              u->net.connect_timeout,
              u->net.source_address ? u->net.source_address: "any",
              u->net.keepalive ? "enabled": "disabled",
              u->net.keepalive_idle_timeout);

    /* On non Keepalive mode, always create a new TCP connection */
    if (u->net.keepalive == FLB_FALSE) {
        return create_conn(u);
    }

    /*
     * If we are in keepalive mode, iterate list of available connections,
     * take a little of time to do some cleanup and assign a connection. If no
     * entries exists, just create a new one.
     */
    mk_list_foreach_safe(head, tmp, &uq->av_queue) {
        conn = mk_list_entry(head, struct flb_upstream_conn, _head);

        if (u->thread_safe == FLB_TRUE) {
            pthread_mutex_lock(&u->mutex_lists);
        }

        /* This connection works, let's move it to the busy queue */
        mk_list_del(&conn->_head);
        mk_list_add(&conn->_head, &uq->busy_queue);

        if (u->thread_safe == FLB_TRUE) {
            pthread_mutex_unlock(&u->mutex_lists);
        }

        /* Reset errno */
        conn->net_error = -1;

        err = flb_socket_error(conn->fd);
        if (!FLB_EINPROGRESS(err) && err != 0) {
            flb_debug("[upstream] KA connection #%i is in a failed state "
                      "to: %s:%i, cleaning up",
                      conn->fd, u->tcp_host, u->tcp_port);
            prepare_destroy_conn_safe(conn);
            conn = NULL;
            continue;
        }

        /* Connect timeout */
        conn->ts_assigned = time(NULL);
        flb_debug("[upstream] KA connection #%i to %s:%i has been assigned (recycled)",
                  conn->fd, u->tcp_host, u->tcp_port);
        /*
         * Note: since we are in a keepalive connection, the socket is already being
         * monitored for possible disconnections while idle. Upon re-use by the caller
         * when it try to send some data, the I/O interface (flb_io.c) will put the
         * proper event mask and reuse, there is no need to remove the socket from
         * the event loop and re-add it again.
         *
         * So just return the connection context.
         */
        return conn;
    }

    /* No keepalive connection available, create a new one */
    if (!conn) {
        conn = create_conn(u);
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
    return prepare_destroy_conn_safe(conn);
}

int flb_upstream_conn_release(struct flb_upstream_conn *conn)
{
    int ret;
    struct flb_upstream *u = conn->u;
    struct flb_upstream_queue *uq;

    uq = flb_upstream_queue_get(u);

    /* If this is a valid KA connection just recycle */
    if (conn->u->net.keepalive == FLB_TRUE && conn->recycle == FLB_TRUE && conn->fd > -1) {
        /*
         * This connection is still useful, move it to the 'available' queue and
         * initialize variables.
         */
        if (u->thread_safe == FLB_TRUE) {
            pthread_mutex_lock(&u->mutex_lists);
        }

        mk_list_del(&conn->_head);
        mk_list_add(&conn->_head, &uq->av_queue);

        if (u->thread_safe == FLB_TRUE) {
            pthread_mutex_unlock(&u->mutex_lists);
        }

        conn->ts_available = time(NULL);

        /*
         * The socket at this point is not longer monitored, so if we want to be
         * notified if the 'available keepalive connection' gets disconnected by
         * the remote endpoint we need to add it again.
         */
        conn->event.handler = cb_upstream_conn_ka_dropped;

        ret = mk_event_add(conn->evl, conn->fd,
                           FLB_ENGINE_EV_CUSTOM,
                           MK_EVENT_CLOSE, &conn->event);
        if (ret == -1) {
            /* We failed the registration, for safety just destroy the connection */
            flb_debug("[upstream] KA connection #%i to %s:%i could not be "
                      "registered, closing.",
                      conn->fd, conn->u->tcp_host, conn->u->tcp_port);
            return prepare_destroy_conn_safe(conn);
        }

        flb_debug("[upstream] KA connection #%i to %s:%i is now available",
                  conn->fd, conn->u->tcp_host, conn->u->tcp_port);
        conn->ka_count++;

        /* if we have exceeded our max number of uses of this connection, destroy it */
        if (conn->u->net.keepalive_max_recycle > 0 &&
            conn->ka_count > conn->u->net.keepalive_max_recycle) {
            flb_debug("[upstream] KA count %i exceeded configured limit "
                      "of %i: closing.",
                      conn->ka_count, conn->u->net.keepalive_max_recycle);
            return prepare_destroy_conn(conn);
        }

        return 0;
    }

    /* No keepalive connections must be destroyed */
    return prepare_destroy_conn_safe(conn);
}

int flb_upstream_conn_timeouts(struct mk_list *list)
{
    time_t now;
    int drop;
    struct mk_list *head;
    struct mk_list *u_head;
    struct mk_list *tmp;
    struct flb_upstream *u;
    struct flb_upstream_conn *u_conn;
    struct flb_upstream_queue *uq;

    now = time(NULL);

    /* Iterate all upstream contexts */
    mk_list_foreach(head, list) {
        u = mk_list_entry(head, struct flb_upstream, _head);
        uq = flb_upstream_queue_get(u);

        if (u->thread_safe == FLB_TRUE) {
            pthread_mutex_lock(&u->mutex_lists);
        }

        /* Iterate every busy connection */
        mk_list_foreach_safe(u_head, tmp, &uq->busy_queue) {
            u_conn = mk_list_entry(u_head, struct flb_upstream_conn, _head);

            drop = FLB_FALSE;

            /* Connect timeouts */
            if (u->net.connect_timeout > 0 &&
                u_conn->ts_connect_timeout > 0 &&
                u_conn->ts_connect_timeout <= now) {
                drop = FLB_TRUE;
                flb_error("[upstream] connection #%i to %s:%i timed out after "
                          "%i seconds",
                          u_conn->fd,
                          u->tcp_host, u->tcp_port, u->net.connect_timeout);
            }

            if (drop == FLB_TRUE) {
                /*
                 * Shutdown the connection, this is the safest way to indicate
                 * that the socket cannot longer work and any co-routine on
                 * waiting for I/O will receive the notification and trigger
                 * the error to it caller.
                 */
                shutdown(u_conn->fd, SHUT_RDWR);
                u_conn->net_error = ETIMEDOUT;
                prepare_destroy_conn(u_conn);
            }
        }

        /* Check every available Keepalive connection */
        mk_list_foreach_safe(u_head, tmp, &uq->av_queue) {
            u_conn = mk_list_entry(u_head, struct flb_upstream_conn, _head);
            if ((now - u_conn->ts_available) >= u->net.keepalive_idle_timeout) {
                shutdown(u_conn->fd, SHUT_RDWR);
                prepare_destroy_conn(u_conn);
                flb_debug("[upstream] drop keepalive connection #%i to %s:%i "
                          "(keepalive idle timeout)",
                          u_conn->fd, u->tcp_host, u->tcp_port);
            }
        }

        if (u->thread_safe == FLB_TRUE) {
            pthread_mutex_unlock(&u->mutex_lists);
        }
    }

    return 0;
}

int flb_upstream_conn_pending_destroy(struct flb_upstream *u)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_upstream_conn *u_conn;
    struct flb_upstream_queue *uq;

    uq = flb_upstream_queue_get(u);

    if (u->thread_safe == FLB_TRUE) {
        pthread_mutex_lock(&u->mutex_lists);
    }

    /* Real destroy of connections context */
    mk_list_foreach_safe(head, tmp, &uq->destroy_queue) {
        u_conn = mk_list_entry(head, struct flb_upstream_conn, _head);
        destroy_conn(u_conn);
    }

    if (u->thread_safe == FLB_TRUE) {
        pthread_mutex_lock(&u->mutex_lists);
    }

    return 0;
}

int flb_upstream_conn_active_destroy(struct flb_upstream *u)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_upstream_conn *u_conn;
    struct flb_upstream_queue *uq;

    uq = flb_upstream_queue_get(u);

    /* Real destroy of connections context */
    mk_list_foreach_safe(head, tmp, &uq->av_queue) {
        u_conn = mk_list_entry(head, struct flb_upstream_conn, _head);
        destroy_conn(u_conn);
    }

    return 0;
}

int flb_upstream_conn_active_destroy_list(struct mk_list *list)
{
    struct mk_list *head;
    struct flb_upstream *u;

    /* Iterate all upstream contexts */
    mk_list_foreach(head, list) {
        u = mk_list_entry(head, struct flb_upstream, _head);
        flb_upstream_conn_active_destroy(u);
    }

    return 0;
}

int flb_upstream_conn_pending_destroy_list(struct mk_list *list)
{
    struct mk_list *head;
    struct flb_upstream *u;

    /* Iterate all upstream contexts */
    mk_list_foreach(head, list) {
        u = mk_list_entry(head, struct flb_upstream, _head);
        flb_upstream_conn_pending_destroy(u);
    }

    return 0;
}

int flb_upstream_is_async(struct flb_upstream *u)
{
    if (u->flags & FLB_IO_ASYNC) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}
