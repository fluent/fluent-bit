/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <unistd.h>

#include <mk_core.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_io_tls.h>
#include <fluent-bit/flb_tls.h>

/* Creates a new upstream context */
struct flb_upstream *flb_upstream_create(struct flb_config *config,
                                         char *host, int port, int flags,
                                         void *tls)
{
    struct flb_upstream *u;

    u = calloc(1, sizeof(struct flb_upstream));
    if (!u) {
        perror("malloc");
        return NULL;
    }

    u->tcp_host      = strdup(host);
    u->tcp_port      = port;
    u->flags         = flags;
    u->evl           = config->evl;
    u->n_connections = 0;
    mk_list_init(&u->av_queue);
    mk_list_init(&u->busy_queue);

#ifdef FLB_HAVE_TLS
    u->tls      = (struct flb_tls *) tls;
#endif

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

    free(u->tcp_host);
    free(u);

    return 0;
}

static struct flb_upstream_conn *create_conn(struct flb_upstream *u)
{
    struct flb_upstream_conn *conn;

    conn = malloc(sizeof(struct flb_upstream_conn));
    if (!conn) {
        return NULL;
    }
    conn->u           = u;
    conn->fd          = -1;
#ifdef FLB_HAVE_TLS
    conn->tls_session = NULL;
#endif

    MK_EVENT_NEW(&conn->event);
    mk_list_add(&conn->_head, &u->busy_queue);
    u->n_connections++;

    return conn;
}

static struct flb_upstream_conn *get_conn(struct flb_upstream *u)
{
    struct flb_upstream_conn *conn;

    /* Get the first available connection and increase the counter */
    conn = mk_list_entry_first(&u->av_queue,
                               struct flb_upstream_conn, _head);
    u->n_connections++;

    /* Move it to the busy queue */
    mk_list_del(&conn->_head);
    mk_list_add(&conn->_head, &u->busy_queue);

    return conn;
}

struct flb_upstream_conn *flb_upstream_conn_get(struct flb_upstream *u)
{
    struct flb_upstream_conn *u_conn = NULL;

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

    flb_trace("[upstream] releasing connection %p", u_conn);

    if (u_conn->fd > 0) {
        close(u_conn->fd);
    }
    mk_event_del(u->evl, &u_conn->event);
    mk_list_del(&u_conn->_head);

    u->n_connections--;
    free(u_conn);

    return 0;
}
