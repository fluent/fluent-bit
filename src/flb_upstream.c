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
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_thread_storage.h>

FLB_TLS_DEFINE(struct mk_list, flb_upstream_list_key);

/* Config map for Upstream networking setup */
struct flb_config_map upstream_net[] = {
    {
     FLB_CONFIG_MAP_STR, "net.dns.mode", NULL,
     0, FLB_TRUE, offsetof(struct flb_net_setup, dns_mode),
     "Select the primary DNS connection type (TCP or UDP)"
    },

    {
     FLB_CONFIG_MAP_STR, "net.dns.resolver", NULL,
     0, FLB_TRUE, offsetof(struct flb_net_setup, dns_resolver),
     "Select the primary DNS resolver type (LEGACY or ASYNC)"
    },

    {
     FLB_CONFIG_MAP_BOOL, "net.dns.prefer_ipv4", "false",
     0, FLB_TRUE, offsetof(struct flb_net_setup, dns_prefer_ipv4),
     "Prioritize IPv4 DNS results when trying to establish a connection"
    },

    {
     FLB_CONFIG_MAP_BOOL, "net.dns.prefer_ipv6", "false",
     0, FLB_TRUE, offsetof(struct flb_net_setup, dns_prefer_ipv6),
     "Prioritize IPv6 DNS results when trying to establish a connection"
    },

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
     FLB_CONFIG_MAP_BOOL, "net.tcp_keepalive", "off",
     0, FLB_TRUE, offsetof(struct flb_net_setup, tcp_keepalive),
     "Enable or disable the use of TCP keepalive probes"
    },

    {
     FLB_CONFIG_MAP_INT, "net.tcp_keepalive_time", "-1",
     0, FLB_TRUE, offsetof(struct flb_net_setup, tcp_keepalive_time),
     "interval between the last data packet sent and the first "
     "TCP keepalive probe"
    },

    {
     FLB_CONFIG_MAP_INT, "net.tcp_keepalive_interval", "-1",
     0, FLB_TRUE, offsetof(struct flb_net_setup, tcp_keepalive_interval),
     "interval between TCP keepalive probes when no response is"
     "received on a keepidle probe"
    },

    {
     FLB_CONFIG_MAP_INT, "net.tcp_keepalive_probes", "-1",
     0, FLB_TRUE, offsetof(struct flb_net_setup, tcp_keepalive_probes),
     "number of unacknowledged probes to consider a connection dead"
    },

    {
     FLB_CONFIG_MAP_TIME, "net.io_timeout", "0s",
     0, FLB_TRUE, offsetof(struct flb_net_setup, io_timeout),
     "Set maximum time a connection can stay idle while assigned"
    },

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

    {
     FLB_CONFIG_MAP_STR, "net.source_address", NULL,
     0, FLB_TRUE, offsetof(struct flb_net_setup, source_address),
     "Specify network address to bind for data traffic"
    },

    {
     FLB_CONFIG_MAP_INT, "net.keepalive_max_recycle", "2000",
     0, FLB_TRUE, offsetof(struct flb_net_setup, keepalive_max_recycle),
     "Set maximum number of times a keepalive connection can be used "
     "before it is retried."
    },

    {
     FLB_CONFIG_MAP_INT, "net.max_worker_connections", "0",
     0, FLB_TRUE, offsetof(struct flb_net_setup, max_worker_connections),
     "Set the maximum number of active TCP connections that can be used per worker thread."
    },

    {
     FLB_CONFIG_MAP_BOOL, "net.proxy_env_ignore", "false",
     0, FLB_TRUE, offsetof(struct flb_net_setup, proxy_env_ignore),
     "Ignore proxy environment variables when connecting"
    },

    /* EOF */
    {0}
};

int flb_upstream_needs_proxy(const char *host, const char *proxy,
                             const char *no_proxy);

static void flb_upstream_increment_busy_connections_count(
                struct flb_upstream *stream);

static void flb_upstream_decrement_busy_connections_count(
                struct flb_upstream *stream);

static void flb_upstream_increment_total_connections_count(
                struct flb_upstream *stream);

static void flb_upstream_decrement_total_connections_count(
                struct flb_upstream *stream);

/* Enable thread-safe mode for upstream connection */
void flb_upstream_thread_safe(struct flb_upstream *u)
{
    /*
     * Upon upstream creation, automatically the upstream is linked into
     * the main Fluent Bit context (struct flb_config *)->upstreams. We
     * have to avoid any access to this context outside of the worker
     * thread.
     */

    flb_stream_enable_thread_safety(&u->base);
}

struct mk_list *flb_upstream_get_config_map(struct flb_config *config)
{
    size_t          config_index;
    struct mk_list *config_map;

    /* If a global dns mode was provided in the SERVICE category then we set it as
     * the default value for net.dns_mode, that way the user can set a global value and
     * override it on a per plugin basis, however, it's not because of this flexibility
     * that it was done but because in order to be able to save the value in the
     * flb_net_setup structure (and not lose it when flb_output_upstream_set overwrites
     * the structure) we need to do it this way (or at least that's what I think)
     */
    for (config_index = 0 ; upstream_net[config_index].name != NULL ; config_index++) {
        if (config->dns_mode != NULL) {
            if (strcmp(upstream_net[config_index].name, "net.dns.mode") == 0) {
                upstream_net[config_index].def_value = config->dns_mode;
            }
        }
        if (config->dns_resolver != NULL) {
            if (strcmp(upstream_net[config_index].name, "net.dns.resolver") == 0) {
                upstream_net[config_index].def_value = config->dns_resolver;
            }
        }
        if (config->dns_prefer_ipv4) {
            if (strcmp(upstream_net[config_index].name,
                       "net.dns.prefer_ipv4") == 0) {
                upstream_net[config_index].def_value = "true";
            }
        }
        if (config->dns_prefer_ipv6) {
            if (strcmp(upstream_net[config_index].name,
                       "net.dns.prefer_ipv6") == 0) {
                upstream_net[config_index].def_value = "true";
            }
        }
    }

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
    if (flb_stream_is_thread_safe(&u->base) == FLB_TRUE) {
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
            th_u = mk_list_entry(head, struct flb_upstream, base._head);
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

    u->base.dynamically_allocated = FLB_TRUE;

    flb_stream_setup(&u->base,
                     FLB_UPSTREAM,
                     FLB_TRANSPORT_TCP,
                     flags,
                     tls,
                     config,
                     NULL);

    /* Set upstream to the http_proxy if it is specified. */
    if (flb_upstream_needs_proxy(host, config->http_proxy, config->no_proxy) == FLB_TRUE) {
        flb_debug("[upstream] config->http_proxy: %s", config->http_proxy);
        ret = flb_utils_proxy_url_split(config->http_proxy, &proxy_protocol,
                                        &proxy_username, &proxy_password,
                                        &proxy_host, &proxy_port);
        if (ret == -1) {
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

    flb_stream_enable_flags(&u->base, FLB_IO_ASYNC);

    /* Initialize queues */
    flb_upstream_queue_init(&u->queue);

    mk_list_add(&u->base._head, &config->upstreams);

    return u;
}

/*
 * Checks whehter a destinate URL should be proxied.
 */
int flb_upstream_needs_proxy(const char *host, const char *proxy,
                             const char *no_proxy)
{
    int ret;
    struct mk_list no_proxy_list;
    struct mk_list *head;
    struct flb_slist_entry *e = NULL;

    /* No HTTP_PROXY, should not set up proxy for the upstream `host`. */
    if (proxy == NULL) {
        return FLB_FALSE;
    }

    /* No NO_PROXY with HTTP_PROXY set, should set up proxy for the upstream `host`. */
    if (no_proxy == NULL) {
        return FLB_TRUE;
    }

    /* NO_PROXY=`*`, it matches all hosts. */
    if (strcmp(no_proxy, "*") == 0) {
        return FLB_FALSE;
    }

    /* check the URL list in the NO_PROXY  */
    ret = flb_slist_create(&no_proxy_list);
    if (ret != 0) {
        return FLB_TRUE;
    }
    ret = flb_slist_split_string(&no_proxy_list, no_proxy, ',', -1);
    if (ret <= 0) {
        return FLB_TRUE;
    }
    ret = FLB_TRUE;
    mk_list_foreach(head, &no_proxy_list) {
        e = mk_list_entry(head, struct flb_slist_entry, _head);
         if (strcmp(host, e->str) == 0) {
            ret = FLB_FALSE;
            break;
        }
    }

    /* clean up the resources. */
    flb_slist_destroy(&no_proxy_list);

    return ret;
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

/* This function shuts the connection down in order to cause
 * any client code trying to read or write from it to fail.
 */
static void shutdown_connection(struct flb_connection *u_conn)
{
    if (u_conn->fd > 0 &&
        !u_conn->shutdown_flag) {
        shutdown(u_conn->fd, SHUT_RDWR);

        u_conn->shutdown_flag = FLB_TRUE;
    }
}

/*
 * This function moves the 'upstream connection' into the queue to be
 * destroyed. Note that the caller is responsible to validate and check
 * required mutex if this is being used in multi-worker mode.
 */
static int prepare_destroy_conn(struct flb_connection *u_conn)
{
    struct flb_upstream *u;
    struct flb_upstream_queue *uq;

    u = u_conn->upstream;

    uq = flb_upstream_queue_get(u);

    flb_trace("[upstream] destroy connection #%i to %s:%i",
              u_conn->fd, u->tcp_host, u->tcp_port);

    if (MK_EVENT_IS_REGISTERED((&u_conn->event))) {
        mk_event_del(u_conn->evl, &u_conn->event);
    }

    if (u_conn->fd > 0) {
#ifdef FLB_HAVE_TLS
        if (u_conn->tls_session != NULL) {
            flb_tls_session_destroy(u_conn->tls_session);

            u_conn->tls_session = NULL;
        }
#endif
        shutdown_connection(u_conn);

        flb_socket_close(u_conn->fd);

        u_conn->fd = -1;
        u_conn->event.fd = -1;
    }

    /* remove connection from the queue */
    mk_list_del(&u_conn->_head);

    /* Add node to destroy queue */
    mk_list_add(&u_conn->_head, &uq->destroy_queue);

    flb_upstream_decrement_total_connections_count(u);

    /*
     * note: the connection context is destroyed by the engine once all events
     * have been processed.
     */
    return 0;
}

/* 'safe' version of prepare_destroy_conn. It set locks if necessary */
static inline int prepare_destroy_conn_safe(struct flb_connection *u_conn)
{
    int ret;

    flb_stream_acquire_lock(u_conn->stream, FLB_TRUE);

    ret = prepare_destroy_conn(u_conn);

    flb_stream_release_lock(u_conn->stream);

    return ret;
}

static int destroy_conn(struct flb_connection *u_conn)
{
    /* Delay the destruction of busy connections */
    if (u_conn->busy_flag) {
        return 0;
    }

    mk_list_del(&u_conn->_head);

    flb_connection_destroy(u_conn);

    return 0;
}

static struct flb_connection *create_conn(struct flb_upstream *u)
{
    struct flb_coro           *coro;
    struct flb_connection     *conn;
    int                        ret;
    struct flb_upstream_queue *uq;

    coro = flb_coro_get();

    conn = flb_connection_create(FLB_INVALID_SOCKET,
                                 FLB_UPSTREAM_CONNECTION,
                                 (void *) u,
                                 flb_engine_evl_get(),
                                 flb_coro_get());
    if (conn == NULL) {
        return NULL;
    }

    conn->busy_flag = FLB_TRUE;

    if (flb_stream_is_keepalive(&u->base)) {
        flb_upstream_conn_recycle(conn, FLB_TRUE);
    }
    else {
        flb_upstream_conn_recycle(conn, FLB_FALSE);
    }

    flb_stream_acquire_lock(&u->base, FLB_TRUE);

    /* Link new connection to the busy queue */
    uq = flb_upstream_queue_get(u);
    mk_list_add(&conn->_head, &uq->busy_queue);

    flb_upstream_increment_total_connections_count(u);

    flb_stream_release_lock(&u->base);

    flb_connection_reset_connection_timeout(conn);

    /* Start connection */
    ret = flb_io_net_connect(conn, coro);
    if (ret == -1) {
        flb_connection_unset_connection_timeout(conn);

        flb_debug("[upstream] connection #%i failed to %s:%i",
                  conn->fd, u->tcp_host, u->tcp_port);

        prepare_destroy_conn_safe(conn);
        conn->busy_flag = FLB_FALSE;

        return NULL;
    }

    flb_connection_unset_connection_timeout(conn);

    if (flb_stream_is_keepalive(&u->base)) {
        flb_debug("[upstream] KA connection #%i to %s:%i is connected",
                  conn->fd, u->tcp_host, u->tcp_port);
    }

    /* Invalidate timeout for connection */
    conn->busy_flag = FLB_FALSE;

    return conn;
}

int flb_upstream_destroy(struct flb_upstream *u)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_connection *u_conn;
    struct flb_upstream_queue *uq;

    uq = flb_upstream_queue_get(u);
    if (!uq) {
        uq = &u->queue;
    }

    mk_list_foreach_safe(head, tmp, &uq->av_queue) {
        u_conn = mk_list_entry(head, struct flb_connection, _head);
        prepare_destroy_conn(u_conn);
    }

    mk_list_foreach_safe(head, tmp, &uq->busy_queue) {
        u_conn = mk_list_entry(head, struct flb_connection, _head);
        prepare_destroy_conn(u_conn);
    }

    mk_list_foreach_safe(head, tmp, &uq->destroy_queue) {
        u_conn = mk_list_entry(head, struct flb_connection, _head);
        destroy_conn(u_conn);
    }

    flb_free(u->tcp_host);
    flb_free(u->proxied_host);
    flb_free(u->proxy_username);
    flb_free(u->proxy_password);
    mk_list_del(&u->base._head);
    flb_free(u);

    return 0;
}

/* Enable or disable 'recycle' flag for the connection */
int flb_upstream_conn_recycle(struct flb_connection *conn, int val)
{
    if (val == FLB_TRUE || val == FLB_FALSE) {
        conn->recycle = val;
    }

    return -1;
}

struct flb_connection *flb_upstream_conn_get(struct flb_upstream *u)
{
    int err;
    int total_connections = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_connection *conn;
    struct flb_upstream_queue *uq;

    uq = flb_upstream_queue_get(u);

    flb_trace("[upstream] get new connection for %s:%i, net setup:\n"
              "net.connect_timeout        = %i seconds\n"
              "net.source_address         = %s\n"
              "net.keepalive              = %s\n"
              "net.keepalive_idle_timeout = %i seconds\n"
              "net.max_worker_connections = %i",
              u->tcp_host, u->tcp_port,
              u->base.net.connect_timeout,
              u->base.net.source_address ? u->base.net.source_address: "any",
              u->base.net.keepalive ? "enabled": "disabled",
              u->base.net.keepalive_idle_timeout,
              u->base.net.max_worker_connections);


    /* If the upstream is limited by max connections, check current state */
    if (u->base.net.max_worker_connections > 0) {
        /*
         * Connections are linked to one of these lists:
         *
         *  - av_queue  : connections ready to be used (available)
         *  - busy_queue: connections that are busy (someone is using them)
         *  - drop_queue: connections in the cleanup phase (to be drop)
         *
         * Fluent Bit don't create connections ahead of time, just on demand. When
         * a connection is created is placed into the busy_queue, when is not longer
         * needed one of these things happen:
         *
         *   - if keepalive is enabled (default), the connection is moved to the 'av_queue'.
         *   - if keepalive is disabled, the connection is moved to 'drop_queue' then is
         *     closed and destroyed.
         *
         * Based on the logic described above, to limit the number of total connections
         * in the worker, we only need to count the number of connections linked into
         * the 'busy_queue' list because if there are connections available 'av_queue' it
         * won't create a one.
         */

        /* Count the number of relevant connections */
        flb_stream_acquire_lock(&u->base, FLB_TRUE);
        total_connections = mk_list_size(&uq->busy_queue);
        flb_stream_release_lock(&u->base);

        if (total_connections >= u->base.net.max_worker_connections) {
            flb_debug("[upstream] max worker connections=%i reached to: %s:%i, cannot connect",
                      u->base.net.max_worker_connections, u->tcp_host, u->tcp_port);
            return NULL;
        }
    }

    conn = NULL;

    /*
     * If we are in keepalive mode, iterate list of available connections,
     * take a little of time to do some cleanup and assign a connection. If no
     * entries exists, just create a new one.
     */
    if (u->base.net.keepalive) {
        mk_list_foreach_safe(head, tmp, &uq->av_queue) {
            conn = mk_list_entry(head, struct flb_connection, _head);

            flb_stream_acquire_lock(&u->base, FLB_TRUE);

            /* This connection works, let's move it to the busy queue */
            mk_list_del(&conn->_head);
            mk_list_add(&conn->_head, &uq->busy_queue);

            flb_stream_release_lock(&u->base);

            err = flb_socket_error(conn->fd);

            if (!FLB_EINPROGRESS(err) && err != 0) {
                flb_debug("[upstream] KA connection #%i is in a failed state "
                          "to: %s:%i, cleaning up",
                          conn->fd, u->tcp_host, u->tcp_port);
                prepare_destroy_conn_safe(conn);
                conn = NULL;
                continue;
            }

            /* Reset errno */
            conn->net_error = -1;

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

            break;
        }
    }

    /*
     * There are no keepalive connections available or keepalive is disabled
     * so we need to create a new one.
     */
    if (conn == NULL) {
        conn = create_conn(u);
    }

    if (conn != NULL) {
        flb_connection_reset_io_timeout(conn);
        flb_upstream_increment_busy_connections_count(u);
    }

    return conn;
}

/*
 * An 'idle' and keepalive might be disconnected, if so, this callback will perform
 * the proper connection cleanup.
 */
static int cb_upstream_conn_ka_dropped(void *data)
{
    struct flb_connection *conn;

    conn = (struct flb_connection *) data;

    flb_debug("[upstream] KA connection #%i to %s:%i has been disconnected "
              "by the remote service",
              conn->fd, conn->upstream->tcp_host, conn->upstream->tcp_port);
    return prepare_destroy_conn_safe(conn);
}

int flb_upstream_conn_release(struct flb_connection *conn)
{
    int ret;
    struct flb_upstream *u = conn->upstream;
    struct flb_upstream_queue *uq;

    flb_upstream_decrement_busy_connections_count(u);

    uq = flb_upstream_queue_get(u);

    /* If this is a valid KA connection just recycle */
    if (u->base.net.keepalive == FLB_TRUE &&
        conn->recycle == FLB_TRUE &&
        conn->fd > -1 &&
        conn->net_error == -1) {
        /*
         * This connection is still useful, move it to the 'available' queue and
         * initialize variables.
         */
        flb_stream_acquire_lock(&u->base, FLB_TRUE);

        mk_list_del(&conn->_head);
        mk_list_add(&conn->_head, &uq->av_queue);

        flb_stream_release_lock(&u->base);

        conn->ts_available = time(NULL);

        /*
         * The socket at this point is not longer monitored, so if we want to be
         * notified if the 'available keepalive connection' gets disconnected by
         * the remote endpoint we need to add it again.
         */
        conn->event.handler = cb_upstream_conn_ka_dropped;

        ret = mk_event_add(conn->evl,
                           conn->fd,
                           FLB_ENGINE_EV_CUSTOM,
                           MK_EVENT_CLOSE,
                           &conn->event);

        conn->event.priority = FLB_ENGINE_PRIORITY_CONNECT;
        if (ret == -1) {
            /* We failed the registration, for safety just destroy the connection */
            flb_debug("[upstream] KA connection #%i to %s:%i could not be "
                      "registered, closing.",
                      conn->fd, u->tcp_host, u->tcp_port);
            return prepare_destroy_conn_safe(conn);
        }

        flb_debug("[upstream] KA connection #%i to %s:%i is now available",
                  conn->fd, u->tcp_host, u->tcp_port);
        conn->ka_count++;

        /* if we have exceeded our max number of uses of this connection, destroy it */
        if (conn->net->keepalive_max_recycle > 0 &&
            conn->ka_count > conn->net->keepalive_max_recycle) {
            flb_debug("[upstream] KA count %i exceeded configured limit "
                      "of %i: closing.",
                      conn->ka_count,
                      conn->net->keepalive_max_recycle);

            return prepare_destroy_conn_safe(conn);
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
    const char *reason;
    struct mk_list *head;
    struct mk_list *u_head;
    struct mk_list *tmp;
    struct flb_upstream *u;
    struct flb_connection *u_conn;
    struct flb_upstream_queue *uq;
    int elapsed_time;

    now = time(NULL);

    /* Iterate all upstream contexts */
    mk_list_foreach(head, list) {
        u = mk_list_entry(head, struct flb_upstream, base._head);
        uq = flb_upstream_queue_get(u);

        flb_stream_acquire_lock(&u->base, FLB_TRUE);

        /* Iterate every busy connection */
        mk_list_foreach_safe(u_head, tmp, &uq->busy_queue) {
            u_conn = mk_list_entry(u_head, struct flb_connection, _head);

            drop = FLB_FALSE;

            /* Connect timeouts */
            if (u_conn->net->connect_timeout > 0 &&
                u_conn->ts_connect_timeout > 0 &&
                u_conn->ts_connect_timeout <= now) {
                drop = FLB_TRUE;
                reason = "connection timeout";
                elapsed_time = u_conn->net->connect_timeout;
            }
            else if (u_conn->net->io_timeout > 0 &&
                     u_conn->ts_io_timeout > 0 &&
                     u_conn->ts_io_timeout <= now) {
                drop = FLB_TRUE;
                reason = "IO timeout";
                elapsed_time = u_conn->net->io_timeout;
            }

            if (drop) {
                if (!flb_upstream_is_shutting_down(u)) {
                    if (u->base.net.connect_timeout_log_error) {
                        flb_error("[upstream] connection #%i to %s timed "
                                  "out after %i seconds (%s)",
                                  u_conn->fd,
                                  flb_connection_get_remote_address(u_conn),
                                  elapsed_time,
                                  reason);
                    }
                    else {
                        flb_debug("[upstream] connection #%i to %s timed "
                                  "out after %i seconds (%s)",
                                  u_conn->fd,
                                  flb_connection_get_remote_address(u_conn),
                                  elapsed_time,
                                  reason);
                    }
                }

                u_conn->net_error = ETIMEDOUT;

                /* We need to shut the connection down
                 * in order to cause some functions that are not
                 * aware of the connection error signaling
                 * mechanism to fail and abort.
                 *
                 * These functions do not check the net_error field
                 * in the connection instance upon being awakened
                 * so we need to ensure that any read/write
                 * operations on the socket generate an error.
                 *
                 * net_io_write_async
                 * net_io_read_async
                 * flb_tls_net_write_async
                 * flb_tls_net_read_async
                 *
                 * This operation could be selectively performed for
                 * connections that have already been established
                 * with no side effects because the connection
                 * establishment code honors `net_error` but
                 * taking in account that the previous version of
                 * the code did it unconditionally with no noticeable
                 * side effects leaving it that way is the safest
                 * choice at the moment.
                 */

                if (MK_EVENT_IS_REGISTERED((&u_conn->event))) {
                    shutdown_connection(u_conn);

                    mk_event_inject(u_conn->evl,
                                    &u_conn->event,
                                    u_conn->event.mask,
                                    FLB_TRUE);
                }
                else {
                    /* I can't think of a valid reason for this code path
                     * to be taken but considering that it was previously
                     * possible for it to happen (maybe wesley can shed
                     * some light on it if he remembers) I'll leave this
                     * for the moment.
                     * In any case, it's proven not to interfere with the
                     * coroutine awakening issue this change addresses.
                     */

                    prepare_destroy_conn(u_conn);
                }

                flb_upstream_decrement_busy_connections_count(u);
            }
        }

        /* Check every available Keepalive connection */
        mk_list_foreach_safe(u_head, tmp, &uq->av_queue) {
            u_conn = mk_list_entry(u_head, struct flb_connection, _head);

            if ((now - u_conn->ts_available) >= u->base.net.keepalive_idle_timeout) {
                prepare_destroy_conn(u_conn);
                flb_debug("[upstream] drop keepalive connection #%i to %s:%i "
                          "(keepalive idle timeout)",
                          u_conn->fd, u->tcp_host, u->tcp_port);
            }
        }

        flb_stream_release_lock(&u->base);
    }

    return 0;
}

int flb_upstream_conn_pending_destroy(struct flb_upstream *u)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_connection *u_conn;
    struct flb_upstream_queue *uq;

    uq = flb_upstream_queue_get(u);

    flb_stream_acquire_lock(&u->base, FLB_TRUE);

    /* Real destroy of connections context */
    mk_list_foreach_safe(head, tmp, &uq->destroy_queue) {
        u_conn = mk_list_entry(head, struct flb_connection, _head);

        destroy_conn(u_conn);
    }

    flb_stream_release_lock(&u->base);

    return 0;
}

int flb_upstream_conn_active_destroy(struct flb_upstream *u)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_connection *u_conn;
    struct flb_upstream_queue *uq;

    uq = flb_upstream_queue_get(u);

    /* Real destroy of connections context */
    mk_list_foreach_safe(head, tmp, &uq->av_queue) {
        u_conn = mk_list_entry(head, struct flb_connection, _head);

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
        u = mk_list_entry(head, struct flb_upstream, base._head);

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
        u = mk_list_entry(head, struct flb_upstream, base._head);

        flb_upstream_conn_pending_destroy(u);
    }

    return 0;
}

int flb_upstream_is_async(struct flb_upstream *u)
{
    return flb_stream_is_async(&u->base);
}

void flb_upstream_set_total_connections_label(
        struct flb_upstream *stream,
        const char *label_value)
{
    stream->cmt_total_connections_label = label_value;
}

void flb_upstream_set_total_connections_gauge(
        struct flb_upstream *stream,
        struct cmt_gauge *gauge_instance)
{
    stream->cmt_total_connections = gauge_instance;
}

static void flb_upstream_increment_total_connections_count(
                struct flb_upstream *stream)
{
    if (stream->parent_upstream != NULL) {
        stream = (struct flb_upstream *) stream->parent_upstream;

        flb_upstream_increment_total_connections_count(stream);
    }
    if (stream->cmt_total_connections != NULL) {
        if (stream->cmt_total_connections_label != NULL) {
            cmt_gauge_inc(
                stream->cmt_total_connections,
                cfl_time_now(),
                1,
                (char *[]) {
                    (char *) stream->cmt_total_connections_label
                });
        }
        else {
            cmt_gauge_inc(stream->cmt_total_connections,
                          cfl_time_now(),
                          0, NULL);
        }
    }
}

static void flb_upstream_decrement_total_connections_count(
                struct flb_upstream *stream)
{
    if (stream->parent_upstream != NULL) {
        stream = (struct flb_upstream *) stream->parent_upstream;

        flb_upstream_decrement_total_connections_count(stream);
    }
    else if (stream->cmt_total_connections != NULL) {
        if (stream->cmt_total_connections_label != NULL) {
            cmt_gauge_dec(
                stream->cmt_total_connections,
                cfl_time_now(),
                1,
                (char *[]) {
                    (char *) stream->cmt_total_connections_label
                });
        }
        else {
            cmt_gauge_dec(stream->cmt_total_connections,
                          cfl_time_now(),
                          0, NULL);
        }
    }
}

void flb_upstream_set_busy_connections_label(
        struct flb_upstream *stream,
        const char *label_value)
{
    stream->cmt_busy_connections_label = label_value;
}

void flb_upstream_set_busy_connections_gauge(
        struct flb_upstream *stream,
        struct cmt_gauge *gauge_instance)
{
    stream->cmt_busy_connections = gauge_instance;
}

static void flb_upstream_increment_busy_connections_count(
                struct flb_upstream *stream)
{
    if (stream->parent_upstream != NULL) {
        stream = (struct flb_upstream *) stream->parent_upstream;

        flb_upstream_increment_busy_connections_count(stream);
    }
    else if (stream->cmt_busy_connections != NULL) {
        if (stream->cmt_busy_connections_label != NULL) {
            cmt_gauge_inc(
                stream->cmt_busy_connections,
                cfl_time_now(),
                1,
                (char *[]) {
                    (char *) stream->cmt_busy_connections_label
                });
        }
        else {
            cmt_gauge_inc(stream->cmt_busy_connections,
                          cfl_time_now(),
                          0, NULL);
        }
    }
}

static void flb_upstream_decrement_busy_connections_count(
                struct flb_upstream *stream)
{
    if (stream->parent_upstream != NULL) {
        stream = (struct flb_upstream *) stream->parent_upstream;

        flb_upstream_decrement_busy_connections_count(stream);
    }
    else if (stream->cmt_busy_connections != NULL) {
        if (stream->cmt_busy_connections_label != NULL) {
            cmt_gauge_dec(
                stream->cmt_busy_connections,
                cfl_time_now(),
                1,
                (char *[]) {
                    (char *) stream->cmt_busy_connections_label
                });
        }
        else {
            cmt_gauge_dec(stream->cmt_busy_connections,
                          cfl_time_now(),
                          0, NULL);
        }
    }
}
