/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
                                         char *host, int port, int flags,
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

    return u;
}

/* Create an upstream context using a valid URL (protocol, host and port) */
struct flb_upstream *flb_upstream_create_url(struct flb_config *config,
                                             char *url, int flags, void *tls)
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

int flb_upstream_destroy(struct flb_upstream *u)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_upstream_conn *u_conn;

    mk_list_foreach_safe(head, tmp, &u->av_queue) {
        u_conn = mk_list_entry(head, struct flb_upstream_conn, _head);
        flb_upstream_conn_release(u_conn);
    }

    mk_list_foreach_safe(head, tmp, &u->busy_queue) {
        u_conn = mk_list_entry(head, struct flb_upstream_conn, _head);
        flb_upstream_conn_release(u_conn);
    }

    flb_free(u->tcp_host);
    flb_free(u);

    return 0;
}

static struct flb_upstream_conn *create_conn(struct flb_upstream *u)
{
    int ret;
    struct flb_upstream_conn *conn;
#if defined (FLB_HAVE_FLUSH_LIBCO)
    struct flb_thread *th = pthread_getspecific(flb_thread_key);
#else
    void *th = NULL;
#endif

    conn = flb_malloc(sizeof(struct flb_upstream_conn));
    if (!conn) {
        perror("malloc");
        return NULL;
    }
    conn->u             = u;
    conn->fd            = -1;
    conn->connect_count = 0;
#ifdef FLB_HAVE_TLS
    conn->tls_session   = NULL;
#endif

    MK_EVENT_NEW(&conn->event);

    /* Start connection */
    ret = flb_io_net_connect(conn, th);
    if (ret == -1) {
        flb_free(conn);
        return NULL;
    }

    /* Link new connection to the busy queue */
    mk_list_add(&conn->_head, &u->busy_queue);
    u->n_connections++;

    return conn;
}

static struct flb_upstream_conn *get_conn(struct flb_upstream *u)
{
    struct flb_upstream_conn *conn;

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_lock(&u->mutex_queue);
#endif
    /* Get the first available connection and increase the counter */
    conn = mk_list_entry_first(&u->av_queue,
                               struct flb_upstream_conn, _head);
    u->n_connections++;

    /* Move it to the busy queue */
    mk_list_del(&conn->_head);
    mk_list_add(&conn->_head, &u->busy_queue);

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_unlock(&u->mutex_queue);
#endif

    return conn;
}

struct flb_upstream_conn *flb_upstream_conn_get(struct flb_upstream *u)
{
    struct flb_upstream_conn *u_conn = NULL;

    /*
     * FIXME: for 0.9 series the keep alive mode will be enabled, useless
     * check now as the available queue is always empty.
     */
    if (mk_list_is_empty(&u->av_queue) == 0) {

        if (u->max_connections <= 0) {
            u_conn = create_conn(u);
        }
        else if (u->n_connections < u->max_connections) {
            u_conn = create_conn(u);
        }
        else {
            return NULL;
        }
    }
    else {
        /* Get an available connection */
        u_conn = get_conn(u);
    }

    if (!u_conn) {
        return NULL;
    }

    return u_conn;
}

int flb_upstream_conn_release(struct flb_upstream_conn *u_conn)
{
    struct flb_upstream *u = u_conn->u;

    flb_trace("[upstream] [fd=%i] releasing connection %p",
              u_conn->fd, u_conn);

    if (u->flags & FLB_IO_ASYNC) {
        mk_event_del(u->evl, &u_conn->event);
    }

    if (u_conn->fd > 0) {
        flb_socket_close(u_conn->fd);
    }

#ifdef FLB_HAVE_TLS
    if (u_conn->tls_session) {
        flb_tls_session_destroy(u_conn->tls_session);
        u_conn->tls_session = NULL;
    }
#endif

    /* remove connection from the queue */
    mk_list_del(&u_conn->_head);

    u->n_connections--;
    flb_free(u_conn);

    return 0;
}
