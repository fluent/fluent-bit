/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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
#include <monkey/mk_server.h>
#include <monkey/mk_stream.h>

#ifndef MK_SCHEDULER_H
#define MK_SCHEDULER_H

#define MK_SCHED_CONN_TIMEOUT    -1
#define MK_SCHED_CONN_CLOSED     -2

#define MK_SCHED_SIGNAL_DEADBEEF  0xDEADBEEF
#define MK_SCHED_SIGNAL_FREE_ALL  0xFFEE0000

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

extern __thread struct rb_root *cs_list;
extern __thread struct mk_list *cs_incomplete;

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
     * Red-Black tree queue to perform fast lookup over
     * the scheduler busy queue
     */
    struct rb_root rb_queue;

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

    /*
     * This variable is used to signal the active workers,
     * just available because of ULONG_MAX bug described
     * on mk_scheduler.c .
     */
    int signal_channel_r;
    int signal_channel_w;
};


/* Every connection in the server is represented by this structure */
struct mk_sched_conn
{
    struct mk_event event;             /* event loop context           */
    int status;                        /* connection status            */
    char is_timeout_on;                /* registered to timeout queue? */
    time_t arrive_time;                /* arrive time                  */
    struct mk_sched_handler *protocol; /* protocol handler             */
    struct mk_plugin_network *net;     /* I/O network layer            */
    struct mk_channel channel;         /* stream channel               */
    struct mk_list timeout_head;       /* link to the timeout queue    */
    struct rb_node _rb_head;           /* red-black tree head          */
};

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
    int (*cb_read)  (struct mk_sched_conn *, struct mk_sched_worker *);
    int (*cb_close) (struct mk_sched_conn *, struct mk_sched_worker *, int);
    int (*cb_done)  (struct mk_sched_conn *, struct mk_sched_worker *);

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

extern __thread struct mk_sched_notif  *worker_sched_notif;
extern __thread struct mk_sched_worker *worker_sched_node;

/* global scheduler list */
struct mk_sched_worker *sched_list;

/* Struct under thread context */
typedef struct
{
} sched_thread_conf;

extern pthread_mutex_t mutex_worker_init;
extern pthread_mutex_t mutex_worker_exit;
pthread_mutex_t mutex_port_init;

struct mk_sched_worker *mk_sched_next_target();
void mk_sched_init();
int mk_sched_launch_thread(int max_events, pthread_t *tout);
void *mk_sched_launch_epoll_loop(void *thread_conf);
struct mk_sched_worker *mk_sched_get_handler_owner(void);

static inline struct rb_root *mk_sched_get_request_list()
{
    return cs_list;
}

static inline struct mk_sched_worker *mk_sched_get_thread_conf()
{
    return worker_sched_node;
}

static inline struct mk_event_loop *mk_sched_loop()
{
    return worker_sched_node->loop;
}

void mk_sched_update_thread_status(struct mk_sched_worker *sched,
                                   int active, int closed);

int mk_sched_drop_connection(struct mk_sched_conn *conn,
                             struct mk_sched_worker *sched);

int mk_sched_check_timeouts(struct mk_sched_worker *sched);
struct mk_sched_conn *mk_sched_add_connection(int remote_fd,
                                              struct mk_server_listen *listener,
                                              struct mk_sched_worker *sched);
int mk_sched_remove_client(struct mk_sched_conn *conn,
                           struct mk_sched_worker *sched);

struct mk_sched_conn *mk_sched_get_connection(struct mk_sched_worker
                                                     *sched, int remote_fd);
int mk_sched_update_conn_status(struct mk_sched_worker *sched, int remote_fd,
                                int status);
int mk_sched_sync_counters();
void mk_sched_worker_free();

struct mk_sched_handler *mk_sched_handler_cap(char cap);

/* Event handlers */
int mk_sched_event_read(struct mk_sched_conn *conn,
                        struct mk_sched_worker *sched);
int mk_sched_event_write(struct mk_sched_conn *conn,
                         struct mk_sched_worker *sched);
int mk_sched_event_close(struct mk_sched_conn *conn,
                         struct mk_sched_worker *sched,
                         int type);

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

#define mk_sched_conn_read(conn, buf, s)        \
    conn->net->read(conn->event.fd, buf, s)
#define mk_sched_conn_write(ch, buf, s)         \
    ch->io->write(ch->fd, buf, s)
#define mk_sched_conn_writev(ch, iov)           \
    ch->io->writev(ch->fd, iov)
#define mk_sched_conn_sendfile(ch, f_fd, f_offs, f_count)   \
    ch->io->send_file(ch->fd, f_fd, f_offs, f_count)

#endif
