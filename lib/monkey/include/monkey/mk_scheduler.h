/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#define _GNU_SOURCE

#include <monkey/mk_info.h>
#include <monkey/mk_tls.h>

#include <monkey/mk_core.h>
#include <monkey/mk_server.h>
#include <monkey/mk_stream.h>
#include <monkey/mk_net.h>

#ifndef MK_SCHEDULER_H
#define MK_SCHEDULER_H

#define MK_SCHED_CONN_TIMEOUT    -1
#define MK_SCHED_CONN_CLOSED     -2

#define MK_SCHED_SIGNAL_DEADBEEF         0xDEADBEEF
#define MK_SCHED_SIGNAL_FREE_ALL         0xFFEE0000
#define MK_SCHED_SIGNAL_EVENT_LOOP_BREAK 0xEEFFAACC

#ifdef _WIN32
    /* The pid field in the mk_sched_worker structure is ignored in platforms other than
     * linux and mac os so it can be safely plugged in this meaningless way
     */
    typedef uint64_t pid_t;
#endif

/*
 * Scheduler balancing mode:
 *
 * - Fair Balancing: use a single socket and upon accept
 *   new connections, lookup the less loaded thread and
 *   assign the socket to that specific epoll queue.
 *
 * - ReusePort: Use new Linux Kernel 3.9 feature that
 *   allows thread to share binded address on a lister
 *   socket. We let the Kernel to decide how to balance.
 */
#define MK_SCHEDULER_FAIR_BALANCING   0
#define MK_SCHEDULER_REUSEPORT        1

/*
 * Thread-scope structure/variable that holds the Scheduler context for the
 * worker (or thread) in question.
 */
struct mk_sched_worker
{
    /* The event loop on this scheduler thread */
    struct mk_event_loop *loop;

    unsigned long long accepted_connections;
    unsigned long long closed_connections;
    unsigned long long over_capacity;

    /*
     * The timeout queue represents client connections that
     * have not initiated it requests or the request status
     * is incomplete. This linear lists allows the scheduler
     * to perform a fast check upon every timeout.
     */
    struct mk_list timeout_queue;

    short int idx;
    unsigned char initialized;

    pthread_t tid;

    pid_t pid;

    /* store the memory page size (_SC_PAGESIZE) */
    unsigned int mem_pagesize;

    struct mk_http_session *request_handler;


    struct mk_list event_free_queue;

    /*
     * This variable is used to signal the active workers,
     * just available because of ULONG_MAX bug described
     * on mk_scheduler.c .
     */
    int signal_channel_r;
    int signal_channel_w;

    /* If using REUSEPORT, this points to the list of listeners */
    struct mk_list *listeners;

    /*
     * List head for finished requests that need to be cleared after each
     * event loop round.
     */
    struct mk_list requests_done;

    /* List of co-routine threads */
    struct mk_list threads;
    struct mk_list threads_purge;

};


/* Every connection in the server is represented by this structure */
struct mk_sched_conn
{
    struct mk_event event;             /* event loop context           */
    int status;                        /* connection status            */
    uint32_t properties;
    char is_timeout_on;                /* registered to timeout queue? */
    time_t arrive_time;                /* arrive time                  */
    struct mk_sched_handler *protocol; /* protocol handler             */
    struct mk_server_listen *server_listen;
    struct mk_plugin_network *net;     /* I/O network layer            */
    struct mk_channel channel;         /* stream channel               */
    struct mk_list timeout_head;       /* link to the timeout queue    */
    void *data;                        /* optional ref for protocols   */
};

/* Protocol capabilities */
#define MK_SCHED_CONN_CAP(conn)  conn->protocol->capabilities

/* Connection properties */
#define MK_SCHED_CONN_PROP(conn) conn->server_listen->listen->flags

/*
 * It defines a Handler for a connection in questions. This struct
 * is used inside mk_sched_conn to define which protocol/handler
 * needs to take care of every action.
 */
struct mk_sched_handler
{
    /*
     * Protocol definition and callbacks:
     *
     * - name    : the protocol handler name.
     * - cb_read : callback triggered when there is data on the socket to read.
     * - cb_close: callback triggered when the socket channel have been closed.
     * - cb_done : callback triggered when the whole channel data have been
     *             written. This callback is optional. The return value of this
     *             callback indicate to the scheduler of the channel should be
     *             closed or not: -1 = close, 0 = leave it open and wait for more
     *             data.
     */
    const char *name;
    int (*cb_read)  (struct mk_sched_conn *, struct mk_sched_worker *,
                     struct mk_server *);
    int (*cb_close) (struct mk_sched_conn *, struct mk_sched_worker *, int,
                     struct mk_server *);
    int (*cb_done)  (struct mk_sched_conn *, struct mk_sched_worker *,
                     struct mk_server *);
    int (*cb_upgrade) (void *, void *, struct mk_server *);

    /*
     * This extra field is a small hack. The scheduler connection context
     * contains information about the connection, and setting this field
     * will let the scheduler allocate some extra memory bytes on the
     * context memory reference:
     *
     * e.g:
     *
     * t_size = (sizeof(struct mk_sched_conn) + sched_extra_size);
     * struct sched_conn *conn = malloc(t_size);
     *
     * This is useful for protocol or handlers where a socket connection
     * represents one unique instance, the use case is HTTP, e.g:
     *
     * HTTP : 1 connection = 1 client (one request at a time)
     * HTTP2: 1 connection = 1 client with multiple-framed requests
     *
     * The purpose is to avoid protocol handlers to perform more memory
     * allocations and connection lookups the sched context is good enough
     * to help on this, e.g:
     *
     *  t_size = (sizeof(struct mk_sched_conn) + (sizeof(struct mk_http_session);
     *  conn = malloc(t_size);
     */
    int sched_extra_size;
    char capabilities;
};

struct mk_sched_notif {
    struct mk_event event;
};

/* Struct under thread context */
struct mk_sched_thread_conf {
    struct mk_server *server;
};

struct mk_sched_worker_cb {
    void (*cb_func) (void *);
    void *data;
    struct mk_list _head;
};

/*
 * All data required by the Scheduler interface is mapped inside this
 * struct which is later linked into config->scheduler_ctx.
 */
struct mk_sched_ctx {
    /* Array of sched_worker */
    struct mk_sched_worker *workers;
};


struct mk_sched_worker *mk_sched_next_target(struct mk_server *server);
int mk_sched_init(struct mk_server *server);
int mk_sched_exit(struct mk_server *server);

int mk_sched_launch_thread(struct mk_server *server, pthread_t *tout);

void *mk_sched_launch_epoll_loop(void *thread_conf);
struct mk_sched_worker *mk_sched_get_handler_owner(void);

static inline struct rb_root *mk_sched_get_request_list()
{
    return MK_TLS_GET(mk_tls_sched_cs);
}

static inline struct mk_sched_worker *mk_sched_get_thread_conf()
{
    return MK_TLS_GET(mk_tls_sched_worker_node);
}

static inline struct mk_event_loop *mk_sched_loop()
{
    struct mk_sched_worker *w;

    w = MK_TLS_GET(mk_tls_sched_worker_node);
    return w->loop;
}

void mk_sched_update_thread_status(struct mk_sched_worker *sched,
                                   int active, int closed);

int mk_sched_drop_connection(struct mk_sched_conn *conn,
                             struct mk_sched_worker *sched,
                             struct mk_server *server);

int mk_sched_check_timeouts(struct mk_sched_worker *sched,
                            struct mk_server *server);


struct mk_sched_conn *mk_sched_add_connection(int remote_fd,
                                              struct mk_server_listen *listener,
                                              struct mk_sched_worker *sched,
                                              struct mk_server *server);

int mk_sched_remove_client(struct mk_sched_conn *conn,
                           struct mk_sched_worker *sched,
                           struct mk_server *server);

struct mk_sched_conn *mk_sched_get_connection(struct mk_sched_worker
                                                     *sched, int remote_fd);
int mk_sched_update_conn_status(struct mk_sched_worker *sched, int remote_fd,
                                int status);
int mk_sched_sync_counters();
void mk_sched_worker_free(struct mk_server *server);

struct mk_sched_handler *mk_sched_handler_cap(char cap);

/* Event handlers */
int mk_sched_event_read(struct mk_sched_conn *conn,
                        struct mk_sched_worker *sched,
                        struct mk_server *server);

int mk_sched_event_write(struct mk_sched_conn *conn,
                         struct mk_sched_worker *sched,
                         struct mk_server *server);


int mk_sched_event_close(struct mk_sched_conn *conn,
                         struct mk_sched_worker *sched,
                         int type, struct mk_server *server);

void mk_sched_event_free(struct mk_event *event);


static inline void mk_sched_event_free_all(struct mk_sched_worker *sched)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_event *event;

    mk_list_foreach_safe(head, tmp, &sched->event_free_queue) {
        event = mk_list_entry(head, struct mk_event, _head);
        mk_list_del(&event->_head);
        mk_mem_free(event);
    }
}

static inline void mk_sched_conn_timeout_add(struct mk_sched_conn *conn,
                                             struct mk_sched_worker *sched)
{
    if (conn->is_timeout_on == MK_FALSE) {
        mk_list_add(&conn->timeout_head, &sched->timeout_queue);
        conn->is_timeout_on = MK_TRUE;
    }
}

static inline void mk_sched_conn_timeout_del(struct mk_sched_conn *conn)
{
    if (conn->is_timeout_on == MK_TRUE) {
        mk_list_del(&conn->timeout_head);
        conn->is_timeout_on = MK_FALSE;
    }
}


#define mk_sched_conn_read(conn, buf, s)                \
    conn->net->read(conn->event.fd, buf, s)
#define mk_sched_conn_write(ch, buf, s)         \
    mk_net_conn_write(ch, buf, s)
#define mk_sched_conn_writev(ch, iov)           \
    ch->io->writev(ch->fd, iov)
#define mk_sched_conn_sendfile(ch, f_fd, f_offs, f_count)   \
    ch->io->send_file(ch->fd, f_fd, f_offs, f_count)

#define mk_sched_switch_protocol(conn, cap)     \
    conn->protocol = mk_sched_handler_cap(cap)

int mk_sched_worker_cb_add(struct mk_server *server,
                           void (*cb_func) (void *),
                           void *data);

void mk_sched_worker_cb_free(struct mk_server *server);
int mk_sched_send_signal(struct mk_sched_worker *worker, uint64_t val);
int mk_sched_broadcast_signal(struct mk_server *server, uint64_t val);
int mk_sched_workers_join(struct mk_server *server);
int mk_sched_threads_purge(struct mk_sched_worker *sched);
int mk_sched_threads_destroy_all(struct mk_sched_worker *sched);
int mk_sched_threads_destroy_conn(struct mk_sched_worker *sched,
                                  struct mk_sched_conn *conn);

#endif
