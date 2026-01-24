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

#include <monkey/monkey.h>
#include <monkey/mk_info.h>
#include <monkey/mk_core.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_scheduler_tls.h>
#include <monkey/mk_server.h>
#include <monkey/mk_thread.h>
#include <monkey/mk_cache.h>
#include <monkey/mk_config.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_linuxtrace.h>
#include <monkey/mk_server.h>
#include <monkey/mk_plugin_stage.h>
#include <monkey/mk_http_thread.h>

#include <signal.h>

#ifndef _WIN32
#include <sys/syscall.h>
#endif

extern struct mk_sched_handler mk_http_handler;
extern struct mk_sched_handler mk_http2_handler;

pthread_mutex_t mutex_worker_init = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_worker_exit = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_conn_timeout = PTHREAD_MUTEX_INITIALIZER;

/*
 * Returns the worker id which should take a new incomming connection,
 * it returns the worker id with less active connections. Just used
 * if config->scheduler_mode is MK_SCHEDULER_FAIR_BALANCING.
 */
static inline int _next_target(struct mk_server *server)
{
    int i;
    int target = 0;
    unsigned long long tmp = 0, cur = 0;
    struct mk_sched_ctx *ctx = server->sched_ctx;
    struct mk_sched_worker *worker;

    cur = (ctx->workers[0].accepted_connections -
           ctx->workers[0].closed_connections);
    if (cur == 0) {
        return 0;
    }

    /* Finds the lowest load worker */
    for (i = 1; i < server->workers; i++) {
        worker = &ctx->workers[i];
        tmp = worker->accepted_connections - worker->closed_connections;
        if (tmp < cur) {
            target = i;
            cur = tmp;

            if (cur == 0)
                break;
        }
    }

    /*
     * If sched_ctx->workers[target] worker is full then the whole server too,
     * because it has the lowest load.
     */
    if (mk_unlikely(server->server_capacity > 0 &&
                    server->server_capacity <= cur)) {
        MK_TRACE("Too many clients: %i", server->server_capacity);

        /* Instruct to close the connection anyways, we lie, it will die */
        return -1;
    }

    return target;
}

struct mk_sched_worker *mk_sched_next_target(struct mk_server *server)
{
    int t;
    struct mk_sched_ctx *ctx = server->sched_ctx;

    t = _next_target(server);
    if (mk_likely(t != -1)) {
        return &ctx->workers[t];
    }

    return NULL;
}

/*
 * This function is invoked when the core triggers a MK_SCHED_SIGNAL_FREE_ALL
 * event through the signal channels, it means the server will stop working
 * so this is the last call to release all memory resources in use. Of course
 * this takes place in a thread context.
 */
void mk_sched_worker_free(struct mk_server *server)
{
    int i;
    pthread_t tid;
    struct mk_sched_ctx *ctx = server->sched_ctx;
    struct mk_sched_worker *worker = NULL;

    pthread_mutex_lock(&mutex_worker_exit);

    /*
     * Fix Me: needs to implement API to make plugins release
     * their resources first at WORKER LEVEL
     */

    /* External */
    mk_plugin_exit_worker();
    mk_vhost_fdt_worker_exit(server);
    mk_cache_worker_exit();

    /* Scheduler stuff */
    tid = pthread_self();
    for (i = 0; i < server->workers; i++) {
        worker = &ctx->workers[i];
        if (worker->tid == tid) {
            break;
        }
        worker = NULL;
    }

    mk_bug(!worker);

    /* FIXME!: there is nothing done here with the worker context */

    /* Free master array (av queue & busy queue) */
    mk_mem_free(MK_TLS_GET(mk_tls_sched_cs));
    mk_mem_free(MK_TLS_GET(mk_tls_sched_cs_incomplete));
    mk_mem_free(MK_TLS_GET(mk_tls_sched_worker_notif));
    pthread_mutex_unlock(&mutex_worker_exit);
}

struct mk_sched_handler *mk_sched_handler_cap(char cap)
{
    if (cap == MK_CAP_HTTP) {
        return &mk_http_handler;
    }

#ifdef MK_HAVE_HTTP2
    else if (cap == MK_CAP_HTTP2) {
        return &mk_http2_handler;
    }
#endif

    return NULL;
}

/*
 * Register a new client connection into the scheduler, this call takes place
 * inside the worker/thread context.
 */
struct mk_sched_conn *mk_sched_add_connection(int remote_fd,
                                              struct mk_server_listen *listener,
                                              struct mk_sched_worker *sched,
                                              struct mk_server *server)
{
    int ret;
    int size;
    struct mk_sched_handler *handler;
    struct mk_sched_conn *conn;
    struct mk_event *event;

    /* Before to continue, we need to run plugin stage 10 */
    ret = mk_plugin_stage_run_10(remote_fd, server);

    /* Close connection, otherwise continue */
    if (ret == MK_PLUGIN_RET_CLOSE_CONX) {
        listener->network->network->close(listener->network, remote_fd);
        MK_LT_SCHED(remote_fd, "PLUGIN_CLOSE");
        return NULL;
    }

    handler = listener->protocol;
    if (handler->sched_extra_size > 0) {
        void *data;
        size = (sizeof(struct mk_sched_conn) + handler->sched_extra_size);
        data = mk_mem_alloc_z(size);
        conn = (struct mk_sched_conn *) data;
    }
    else {
        conn = mk_mem_alloc_z(sizeof(struct mk_sched_conn));
    }

    if (!conn) {
        mk_err("[server] Could not register client");
        return NULL;
    }

    event = &conn->event;
    event->fd           = remote_fd;
    event->type         = MK_EVENT_CONNECTION;
    event->mask         = MK_EVENT_EMPTY;
    event->status       = MK_EVENT_NONE;
    conn->arrive_time   = server->clock_context->log_current_utime;
    conn->protocol      = handler;
    conn->net           = listener->network->network;
    conn->is_timeout_on = MK_FALSE;
    conn->server_listen = listener;

    /* Stream channel */
    conn->channel.type  = MK_CHANNEL_SOCKET;    /* channel type     */
    conn->channel.fd    = remote_fd;            /* socket conn      */
    conn->channel.io    = conn->net;            /* network layer    */
    conn->channel.event = event;                /* parent event ref */
    mk_list_init(&conn->channel.streams);

    /*
     * Register the connections into the timeout_queue:
     *
     * When a new connection arrives, we cannot assume it contains some data
     * to read, meaning the event loop may not get notifications and the protocol
     * handler will never be called. So in order to avoid DDoS we always register
     * this session in the timeout_queue for further lookup.
     *
     * The protocol handler is in charge to remove the session from the
     * timeout_queue.
     */
    pthread_mutex_lock(&mutex_conn_timeout);
    mk_sched_conn_timeout_add(conn, sched);
    pthread_mutex_unlock(&mutex_conn_timeout);

    /* Linux trace message */
    MK_LT_SCHED(remote_fd, "REGISTERED");

    return conn;
}

static void mk_sched_thread_lists_init()
{
    struct mk_list *sched_cs_incomplete;

    /* mk_tls_sched_cs_incomplete */
    sched_cs_incomplete = mk_mem_alloc(sizeof(struct mk_list));
    mk_list_init(sched_cs_incomplete);
    MK_TLS_SET(mk_tls_sched_cs_incomplete, sched_cs_incomplete);
}

/* Register thread information. The caller thread is the thread information's owner */
static int mk_sched_register_thread(struct mk_server *server)
{
    struct mk_sched_ctx *ctx = server->sched_ctx;
    struct mk_sched_worker *worker;

    /*
     * If this thread slept inside this section, some other thread may touch
     * server->worker_id.
     * So protect it with a mutex, only one thread may handle server->worker_id.
     *
     * Note : Let's use the platform agnostic atomics we implemented in cmetrics here
     * instead of a lock.
     */
    worker = &ctx->workers[server->worker_id];
    worker->idx = server->worker_id++;
    worker->tid = pthread_self();

#if defined(__linux__)
    /*
     * Under Linux does not exists the difference between process and
     * threads, everything is a thread in the kernel task struct, and each
     * one has it's own numerical identificator: PID .
     *
     * Here we want to know what's the PID associated to this running
     * task (which is different from parent Monkey PID), it can be
     * retrieved with gettid() but Glibc does not export to userspace
     * the syscall, we need to call it directly through syscall(2).
     */
    worker->pid = syscall(__NR_gettid);
#elif defined(__APPLE__)
    uint64_t tid;
    pthread_threadid_np(NULL, &tid);
    worker->pid = tid;
#else
    worker->pid = 0xdeadbeef;
#endif

    /* Initialize lists */
    mk_list_init(&worker->timeout_queue);
    worker->request_handler = NULL;

    return worker->idx;
}

static void mk_signal_thread_sigpipe_safe()
{
#ifndef _WIN32
    sigset_t old;
    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, &old);
#endif
}

/* created thread, all these calls are in the thread context */
void *mk_sched_launch_worker_loop(void *data)
{
    int ret;
    int wid;
    unsigned long len;
    char *thread_name = 0;
    struct mk_list *head;
    struct mk_sched_worker_cb *wcb;
    struct mk_sched_worker *sched = NULL;
    struct mk_sched_notif *notif = NULL;
    struct mk_sched_thread_conf *thinfo = data;
    struct mk_sched_ctx *ctx;
    struct mk_server *server;

    server = thinfo->server;
    ctx = server->sched_ctx;

    /* Avoid SIGPIPE signals on this thread */
    mk_signal_thread_sigpipe_safe();

    /* Init specific thread cache */
    mk_sched_thread_lists_init();
    mk_cache_worker_init();

    /* Virtual hosts: initialize per thread-vhost data */
    mk_vhost_fdt_worker_init(server);

    /* Register working thread */
    wid = mk_sched_register_thread(server);
    sched = &ctx->workers[wid];
    sched->loop = mk_event_loop_create(MK_EVENT_QUEUE_SIZE);
    if (!sched->loop) {
        mk_err("Error creating Scheduler loop");
        exit(EXIT_FAILURE);
    }


    sched->mem_pagesize = mk_utils_get_system_page_size();

    /*
     * Create the notification instance and link it to the worker
     * thread-scope list.
     */
    notif = mk_mem_alloc_z(sizeof(struct mk_sched_notif));
    MK_TLS_SET(mk_tls_sched_worker_notif, notif);

    /* Register the scheduler channel to signal active workers */
    ret = mk_event_channel_create(sched->loop,
                                  &sched->signal_channel_r,
                                  &sched->signal_channel_w,
                                  notif);
    if (ret < 0) {
        exit(EXIT_FAILURE);
    }

    mk_list_init(&sched->event_free_queue);
    mk_list_init(&sched->threads);
    mk_list_init(&sched->threads_purge);

    /*
     * ULONG_MAX BUG test only
     * =======================
     * to test the workaround we can use the following value:
     *
     *  thinfo->closed_connections = 1000;
     */

    //thinfo->ctx = thconf->ctx;

    /* Rename worker */
    mk_string_build(&thread_name, &len, "monkey: wrk/%i", sched->idx);
    mk_utils_worker_rename(thread_name);
    mk_mem_free(thread_name);

    /* Export known scheduler node to context thread */
    MK_TLS_SET(mk_tls_sched_worker_node, sched);
    mk_plugin_core_thread(server);

    if (server->scheduler_mode == MK_SCHEDULER_REUSEPORT) {
        sched->listeners = mk_server_listen_init(server);
        if (!sched->listeners) {
            exit(EXIT_FAILURE);
        }
    }

    /* Unlock the conditional initializator */
    pthread_mutex_lock(&server->pth_mutex);
    server->pth_init = MK_TRUE;
    pthread_cond_signal(&server->pth_cond);
    pthread_mutex_unlock(&server->pth_mutex);

    /* Invoke custom worker-callbacks defined by the scheduler (lib) */
    mk_list_foreach(head, &server->sched_worker_callbacks) {
        wcb = mk_list_entry(head, struct mk_sched_worker_cb, _head);
        wcb->cb_func(wcb->data);
    }

    mk_mem_free(thinfo);

    /* init server thread loop */
    mk_server_worker_loop(server);

    return 0;
}

/* Create thread which will be listening for incomings requests */
int mk_sched_launch_thread(struct mk_server *server, pthread_t *tout)
{
    pthread_t tid;
    pthread_attr_t attr;
    struct mk_sched_thread_conf *thconf;

    server->pth_init = MK_FALSE;

    /*
     * This lock is used for the 'pth_cond' conditional. Once the worker
     * thread is ready it will signal the condition.
     */
    pthread_mutex_lock(&server->pth_mutex);

    /* Thread data */
    thconf = mk_mem_alloc_z(sizeof(struct mk_sched_thread_conf));
    thconf->server = server;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    if (pthread_create(&tid, &attr, mk_sched_launch_worker_loop,
                       (void *) thconf) != 0) {
        mk_libc_error("pthread_create");
        pthread_mutex_unlock(&server->pth_mutex);
        return -1;
    }

    *tout = tid;

    /* Block until the child thread is ready */
    while (!server->pth_init) {
        pthread_cond_wait(&server->pth_cond, &server->pth_mutex);
    }

    pthread_mutex_unlock(&server->pth_mutex);

    return 0;
}

/*
 * The scheduler nodes are an array of struct mk_sched_worker type,
 * each worker thread belongs to a scheduler node, on this function we
 * allocate a scheduler node per number of workers defined.
 */
int mk_sched_init(struct mk_server *server)
{
    int size;
    struct mk_sched_ctx *ctx;

    ctx = mk_mem_alloc_z(sizeof(struct mk_sched_ctx));
    if (!ctx) {
        mk_libc_error("malloc");
        return -1;
    }

    size = (sizeof(struct mk_sched_worker) * server->workers);
    ctx->workers = mk_mem_alloc(size);
    if (!ctx->workers) {
        mk_libc_error("malloc");
        mk_mem_free(ctx);
        return -1;
    }
    memset(ctx->workers, '\0', size);

    /* Initialize helpers */
    pthread_mutex_init(&server->pth_mutex, NULL);
    pthread_cond_init(&server->pth_cond, NULL);
    server->pth_init = MK_FALSE;

    /* Map context into server context */
    server->sched_ctx = ctx;

    /* The mk_thread_prepare call was replaced by mk_http_thread_initialize_tls
     * which is called earlier.
     */

    return 0;
}

int mk_sched_exit(struct mk_server *server)
{
    struct mk_sched_ctx *ctx;

    ctx = server->sched_ctx;
    mk_sched_worker_cb_free(server);
    mk_mem_free(ctx->workers);
    mk_mem_free(ctx);

    return 0;
}

void mk_sched_set_request_list(struct rb_root *list)
{
    MK_TLS_SET(mk_tls_sched_cs, list);
}

int mk_sched_remove_client(struct mk_sched_conn *conn,
                           struct mk_sched_worker *sched,
                           struct mk_server *server)
{
    struct mk_event *event;

    /*
     * Close socket and change status: we must invoke mk_epoll_del()
     * because when the socket is closed is cleaned from the queue by
     * the Kernel at its leisure, and we may get false events if we rely
     * on that.
     */
    event = &conn->event;
    MK_TRACE("[FD %i] Scheduler remove", event->fd);

    mk_event_del(sched->loop, event);

    /* Invoke plugins in stage 50 */
    mk_plugin_stage_run_50(event->fd, server);

    sched->closed_connections++;

    /* Unlink from the red-black tree */
    //rb_erase(&conn->_rb_head, &sched->rb_queue);
    pthread_mutex_lock(&mutex_conn_timeout);
    mk_sched_conn_timeout_del(conn);
    pthread_mutex_unlock(&mutex_conn_timeout);

    /* Close at network layer level */
    conn->net->close(conn->net->plugin, event->fd);

    /* Release and return */
    mk_channel_clean(&conn->channel);
    mk_sched_event_free(&conn->event);
    conn->status = MK_SCHED_CONN_CLOSED;

    MK_LT_SCHED(remote_fd, "DELETE_CLIENT");
    return 0;
}

/* FIXME: nobody is using this function, check back later */
struct mk_sched_conn *mk_sched_get_connection(struct mk_sched_worker *sched,
                                                 int remote_fd)
{
    (void) sched;
    (void) remote_fd;
    return NULL;
}

/*
 * For a given connection number, remove all resources associated: it can be
 * used on any context such as: timeout, I/O errors, request finished,
 * exceptions, etc.
 */
int mk_sched_drop_connection(struct mk_sched_conn *conn,
                             struct mk_sched_worker *sched,
                             struct mk_server *server)
{
    mk_sched_threads_destroy_conn(sched, conn);
    return mk_sched_remove_client(conn, sched, server);
}

int mk_sched_check_timeouts(struct mk_sched_worker *sched,
                            struct mk_server *server)
{
    int client_timeout;
    struct mk_sched_conn *conn;
    struct mk_list *head;
    struct mk_list *temp;

    /* PENDING CONN TIMEOUT */
    mk_list_foreach_safe(head, temp, &sched->timeout_queue) {
        conn = mk_list_entry(head, struct mk_sched_conn, timeout_head);
        if (conn->event.type & MK_EVENT_IDLE) {
            continue;
        }

        client_timeout = conn->arrive_time + server->timeout;

        /* Check timeout */
        if (client_timeout <= server->clock_context->log_current_utime) {
            MK_TRACE("Scheduler, closing fd %i due TIMEOUT",
                     conn->event.fd);
            MK_LT_SCHED(conn->event.fd, "TIMEOUT_CONN_PENDING");
            conn->protocol->cb_close(conn, sched, MK_SCHED_CONN_TIMEOUT,
                                     server);
            mk_sched_drop_connection(conn, sched, server);
        }
    }

    return 0;
}

static int sched_thread_cleanup(struct mk_sched_worker *sched,
                                struct mk_list *list)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_http_thread *mth;
    (void) sched;

    mk_list_foreach_safe(head, tmp, list) {
        mth = mk_list_entry(head, struct mk_http_thread, _head);
        mk_http_thread_destroy(mth);
        c++;
    }

    return c;

}

int mk_sched_threads_purge(struct mk_sched_worker *sched)
{
    int c = 0;

    c = sched_thread_cleanup(sched, &sched->threads_purge);
    return c;
}

int mk_sched_threads_destroy_all(struct mk_sched_worker *sched)
{
    int c = 0;

    c = sched_thread_cleanup(sched, &sched->threads_purge);
    c += sched_thread_cleanup(sched, &sched->threads);

    return c;
}

/*
 * Destroy the thread contexts associated to the particular
 * connection.
 *
 * Return the number of contexts destroyed.
 */
int mk_sched_threads_destroy_conn(struct mk_sched_worker *sched,
                                  struct mk_sched_conn *conn)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_http_thread *mth;
    (void) sched;

    mk_list_foreach_safe(head, tmp, &sched->threads) {
        mth = mk_list_entry(head, struct mk_http_thread, _head);
        if (mth->session->conn == conn) {
            mk_http_thread_destroy(mth);
            c++;
        }
    }
    return c;
}

/*
 * Scheduler events handler: lookup for event handler and invoke
 * proper callbacks.
 */
int mk_sched_event_read(struct mk_sched_conn *conn,
                        struct mk_sched_worker *sched,
                        struct mk_server *server)
{
    int ret = 0;

#ifdef MK_HAVE_TRACE
    MK_TRACE("[FD %i] Connection Handler / read", conn->event.fd);
#endif

    /*
     * When the event loop notify that there is some readable information
     * from the socket, we need to invoke the protocol handler associated
     * to this connection and also pass as a reference the 'read()' function
     * that handle 'read I/O' operations, e.g:
     *
     *  - plain sockets through liana will use just read(2)
     *  - ssl though mbedtls should use mk_mbedtls_read(..)
     */
    ret = conn->protocol->cb_read(conn, sched, server);
    if (ret == -1) {
        if (errno == EAGAIN) {
            MK_TRACE("[FD %i] EAGAIN: need to read more data", conn->event.fd);
            return 1;
        }
        return -1;
    }

    return ret;
}

int mk_sched_event_write(struct mk_sched_conn *conn,
                         struct mk_sched_worker *sched,
                         struct mk_server *server)
{
    int ret = -1;
    size_t count;
    struct mk_event *event;

    MK_TRACE("[FD %i] Connection Handler / write", conn->event.fd);

    ret = mk_channel_write(&conn->channel, &count);
    if (ret == MK_CHANNEL_FLUSH || ret == MK_CHANNEL_BUSY) {
        return 0;
    }
    else if (ret == MK_CHANNEL_DONE || ret == MK_CHANNEL_EMPTY) {
        if (conn->protocol->cb_done) {
            ret = conn->protocol->cb_done(conn, sched, server);
        }
        if (ret == -1) {
            return -1;
        }
        else if (ret == 0) {
            event = &conn->event;
            mk_event_add(sched->loop, event->fd,
                         MK_EVENT_CONNECTION,
                         MK_EVENT_READ,
                         conn);
        }
        return 0;
    }
    else if (ret & MK_CHANNEL_ERROR) {
        return -1;
    }

    /* avoid to make gcc cry :_( */
    return -1;
}

int mk_sched_event_close(struct mk_sched_conn *conn,
                         struct mk_sched_worker *sched,
                         int type, struct mk_server *server)
{
    MK_TRACE("[FD %i] Connection Handler, closed", conn->event.fd);
    mk_event_del(sched->loop, &conn->event);

    if (type != MK_EP_SOCKET_DONE) {
        conn->protocol->cb_close(conn, sched, type, server);
    }
    /*
     * Remove the socket from the scheduler and make sure
     * to disable all notifications.
     */
    mk_sched_drop_connection(conn, sched, server);
    return 0;
}

void mk_sched_event_free(struct mk_event *event)
{
    struct mk_sched_worker *sched = mk_sched_get_thread_conf();

    if ((event->type & MK_EVENT_IDLE) != 0) {
        return;
    }

    event->type |= MK_EVENT_IDLE;
    mk_list_add(&event->_head, &sched->event_free_queue);
}

/* Register a new callback function to invoke when a worker is created */
int mk_sched_worker_cb_add(struct mk_server *server,
                           void (*cb_func) (void *),
                           void *data)
{
    struct mk_sched_worker_cb *wcb;

    wcb = mk_mem_alloc(sizeof(struct mk_sched_worker_cb));
    if (!wcb) {
        return -1;
    }

    wcb->cb_func = cb_func;
    wcb->data    = data;
    mk_list_add(&wcb->_head, &server->sched_worker_callbacks);
    return 0;
}

void mk_sched_worker_cb_free(struct mk_server *server)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_sched_worker_cb *wcb;

    mk_list_foreach_safe(head, tmp, &server->sched_worker_callbacks) {
        wcb = mk_list_entry(head, struct mk_sched_worker_cb, _head);
        mk_list_del(&wcb->_head);
        mk_mem_free(wcb);
    }
}

int mk_sched_send_signal(struct mk_sched_worker *worker, uint64_t val)
{
    ssize_t n;

    /* When using libevent _mk_event_channel_create creates a unix socket
     * instead of a pipe and windows doesn't us calling read / write on a
     * socket instead of recv / send
     */

#ifdef _WIN32
    n = send(worker->signal_channel_w, &val, sizeof(uint64_t), 0);
#else
    n = write(worker->signal_channel_w, &val, sizeof(uint64_t));
#endif

    if (n < 0) {
        mk_libc_error("write");

        return 0;
    }

    return 1;
}

int mk_sched_broadcast_signal(struct mk_server *server, uint64_t val)
{
    int i;
    int count = 0;
    struct mk_sched_ctx *ctx;
    struct mk_sched_worker *worker;

    ctx = server->sched_ctx;
    for (i = 0; i < server->workers; i++) {
        worker = &ctx->workers[i];

        count += mk_sched_send_signal(worker, val);
    }

    return count;
}

/*
 * Wait for all workers to finish: this function assumes that previously a
 * MK_SCHED_SIGNAL_FREE_ALL was sent to the worker channels.
 */
int mk_sched_workers_join(struct mk_server *server)
{
    int i;
    int count = 0;
    struct mk_sched_ctx *ctx;
    struct mk_sched_worker *worker;

    ctx = server->sched_ctx;
    for (i = 0; i < server->workers; i++) {
        worker = &ctx->workers[i];
        pthread_join(worker->tid, NULL);
        count++;
    }

    return count;
}
