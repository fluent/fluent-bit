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

#include <monkey/mk_info.h>
#include <monkey/monkey.h>
#include <monkey/mk_config.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_server.h>
#include <monkey/mk_server_tls.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_core.h>
#include <monkey/mk_fifo.h>
#include <monkey/mk_http_thread.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#ifndef _WIN32
#include <sys/time.h>
#include <sys/resource.h>
#endif

pthread_key_t mk_server_fifo_key;

static int mk_server_lib_notify_event_loop_break(struct mk_sched_worker *sched);

/* Return the number of clients that can be attended  */
unsigned int mk_server_capacity(struct mk_server *server)
{
    int ret;
    int cur;

#ifndef _WIN32
    struct rlimit lim;

    /* Limit by system */
    getrlimit(RLIMIT_NOFILE, &lim);
    cur = lim.rlim_cur;

    if (server->fd_limit > cur) {
        lim.rlim_cur = server->fd_limit;
        lim.rlim_max = server->fd_limit;

        ret = setrlimit(RLIMIT_NOFILE, &lim);
        if (ret == -1) {
            mk_warn("Could not increase FDLimit to %i.", server->fd_limit);
        }
        else {
            cur = server->fd_limit;
        }
    }
    else if (server->fd_limit > 0) {
        cur = server->fd_limit;
    }

#else
    ret = 0;
    cur = INT_MAX; 

    /* This is not the right way to plug this, according to raymond chen the only limit
     * to fd count is free memory in their winsock provider and there are no other limits
     * that I know of but I should still look for a more elegant solution. (even if it
     * was just ignoring the server_capacity limit in scheduler.c: _next_target)
    */
#endif

    return cur;
}

static inline
struct mk_sched_conn *mk_server_listen_handler(struct mk_sched_worker *sched,
                                               void *data,
                                               struct mk_server *server)
{
    int ret;
    int client_fd = -1;
    struct mk_sched_conn *conn;
    struct mk_server_listen *listener = data;

    client_fd = mk_socket_accept(listener->server_fd);
    if (mk_unlikely(client_fd == -1)) {
        MK_TRACE("[server] Accept connection failed: %s", strerror(errno));
        goto error;
    }

    conn = mk_sched_add_connection(client_fd, listener, sched, server);
    if (mk_unlikely(!conn)) {
        goto error;
    }

    ret = mk_event_add(sched->loop, client_fd,
                       MK_EVENT_CONNECTION, MK_EVENT_READ, conn);
    if (mk_unlikely(ret != 0)) {
        mk_err("[server] Error registering file descriptor: %s",
               strerror(errno));
        goto error;
    }

    sched->accepted_connections++;
    MK_TRACE("[server] New connection arrived: FD %i", client_fd);
    return conn;

error:
    if (client_fd != -1) {
        listener->network->network->close(client_fd);
    }

    return NULL;
}

void mk_server_listen_free()
{
    struct mk_list *list;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_server_listen *listener;

    list = MK_TLS_GET(mk_tls_server_listen);
    mk_list_foreach_safe(head, tmp, list) {
        listener = mk_list_entry(head, struct mk_server_listen, _head);
        mk_list_del(&listener->_head);
        mk_mem_free(listener);
    }
}

void mk_server_listen_exit(struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_server_listen *listen;

    if (!list) {
        return;
    }

    mk_list_foreach_safe(head, tmp, list) {
        listen = mk_list_entry(head, struct mk_server_listen, _head);
        close(listen->server_fd);
        mk_list_del(&listen->_head);
        mk_mem_free(listen);
    }

    mk_mem_free(list);
}

struct mk_list *mk_server_listen_init(struct mk_server *server)
{
    int i = 0;
    int server_fd;
    int reuse_port = MK_FALSE;
    struct mk_list *head;
    struct mk_list *listeners;
    struct mk_event *event;
    struct mk_server_listen *listener;
    struct mk_sched_handler *protocol;
    struct mk_plugin *plugin;
    struct mk_config_listener *listen;

    if (!server) {
        goto error;
    }

    listeners = mk_mem_alloc(sizeof(struct mk_list));
    mk_list_init(listeners);

    if (server->scheduler_mode == MK_SCHEDULER_REUSEPORT) {
        reuse_port = MK_TRUE;
    }

    mk_list_foreach(head, &server->listeners) {
        listen = mk_list_entry(head, struct mk_config_listener, _head);

        server_fd = mk_socket_server(listen->port,
                                     listen->address,
                                     reuse_port,
                                     server);
        if (server_fd >= 0) {
            if (mk_socket_set_tcp_defer_accept(server_fd) != 0) {
#if defined (__linux__)
                mk_warn("[server] Could not set TCP_DEFER_ACCEPT");
#endif
            }

            listener = mk_mem_alloc(sizeof(struct mk_server_listen));

            /* configure the internal event_state */
            event = &listener->event;
            event->fd   = server_fd;
            event->type = MK_EVENT_LISTENER;
            event->mask = MK_EVENT_EMPTY;
            event->status = MK_EVENT_NONE;

            /* continue with listener setup and linking */
            listener->server_fd = server_fd;
            listener->listen    = listen;

            if (listen->flags & MK_CAP_HTTP) {
                protocol = mk_sched_handler_cap(MK_CAP_HTTP);
                if (!protocol) {
                    mk_err("HTTP protocol not supported");
                    exit(EXIT_FAILURE);
                }
                listener->protocol = protocol;
            }

#ifdef MK_HAVE_HTTP2
            if (listen->flags & MK_CAP_HTTP2) {
                protocol = mk_sched_handler_cap(MK_CAP_HTTP2);
                if (!protocol) {
                    mk_err("HTTP2 protocol not supported");
                    exit(EXIT_FAILURE);
                }
                listener->protocol = protocol;
            }
#endif
            listener->network = mk_plugin_cap(MK_CAP_SOCK_PLAIN, server);

            if (listen->flags & MK_CAP_SOCK_TLS) {
                plugin = mk_plugin_cap(MK_CAP_SOCK_TLS, server);
                if (!plugin) {
                    mk_err("SSL/TLS not supported");
                    exit(EXIT_FAILURE);
                }
                listener->network = plugin;
            }

            mk_list_add(&listener->_head, listeners);
        }
        else {
            mk_err("[server] Failed to bind server socket to %s:%s.",
                   listen->address,
                   listen->port);
            return NULL;
        }
        i += 1;
    }

    if (reuse_port == MK_TRUE) {
        MK_TLS_SET(mk_tls_server_listen, listeners);
    }

    return listeners;

error:
    return NULL;
}

/* Here we launch the worker threads to attend clients */
void mk_server_launch_workers(struct mk_server *server)
{
    int i;
    pthread_t skip;

    /* Launch workers */
    for (i = 0; i < server->workers; i++) {
        /* Spawn the thread */
        mk_sched_launch_thread(server, &skip);
    }
}

/*
 * When using the FIFO interface, this function get's the FIFO worker
 * context and register the pipe file descriptor into the main event
 * loop.
 *
 * note: this function is invoked by each worker thread.
 */
static int mk_server_fifo_worker_setup(struct mk_event_loop *evl)
{
    int ret;
    struct mk_fifo_worker *fw;

    fw = pthread_getspecific(mk_server_fifo_key);
    if (!fw) {
        return -1;
    }

    ret = mk_event_add(evl, fw->channel[0],
                       MK_EVENT_FIFO, MK_EVENT_READ,
                       fw);
    if (ret != 0) {
        mk_err("[server] Error registering fifo worker channel: %s",
               strerror(errno));
        return -1;
    }

    return 0;
}

/*
 * The loop_balancer() runs in the main process context and is considered
 * the old-fashion way to handle connections. It have an event queue waiting
 * for connections, once one arrives, it decides which worker (thread) may
 * handle it registering the accept(2)ed file descriptor on the worker
 * event monitored queue.
 */
void mk_server_loop_balancer(struct mk_server *server)
{
    struct mk_list *head;
    struct mk_list *listeners;
    struct mk_server_listen *listener;
    struct mk_event *event;
    struct mk_event_loop *evl;
    struct mk_sched_worker *sched;

    /* Init the listeners */
    listeners = mk_server_listen_init(server);
    if (!listeners) {
        mk_err("Failed to initialize listen sockets.");
        return;
    }

    /* Create an event loop context */
    evl = mk_event_loop_create(MK_EVENT_QUEUE_SIZE);
    if (!evl) {
        mk_err("Could not initialize event loop");
        exit(EXIT_FAILURE);
    }

    /* Register the listeners */
    mk_list_foreach(head, listeners) {
        listener = mk_list_entry(head, struct mk_server_listen, _head);
        mk_event_add(evl, listener->server_fd,
                     MK_EVENT_LISTENER, MK_EVENT_READ,
                     listener);
    }

    while (1) {
        mk_event_wait(evl);
        mk_event_foreach(event, evl) {
            if (event->mask & MK_EVENT_READ) {
                /*
                 * Accept connection: determinate which thread may work on this
                 * new connection.
                 */
                sched = mk_sched_next_target(server);
                if (sched != NULL) {
                    mk_server_listen_handler(sched, event, server);

                    mk_server_lib_notify_event_loop_break(sched);

#ifdef MK_HAVE_TRACE
                    int i;
                    struct mk_sched_ctx *ctx = server->sched_ctx;

                    for (i = 0; i < server->workers; i++) {
                        MK_TRACE("Worker Status");
                        MK_TRACE(" WID %i / conx = %llu",
                                 ctx->workers[i].idx,
                                 ctx->workers[i].accepted_connections -
                                 ctx->workers[i].closed_connections);
                    }
#endif
                }
                else {
                    mk_warn("[server] Over capacity.");
                }
            }
            else if (event->mask & MK_EVENT_CLOSE) {
                mk_err("[server] Error on socket %d: %s",
                       event->fd, strerror(errno));
            }
        }
    }
}

/*
 * This function is called when the scheduler is running in the REUSEPORT
 * mode. That means that each worker is listening on shared TCP ports.
 *
 * When using shared TCP ports the Kernel decides to which worker the
 * connection will be assigned.
 */
void mk_server_worker_loop(struct mk_server *server)
{
    int ret = -1;
    int timeout_fd;
    uint64_t val;
    struct mk_event *event;
    struct mk_event_loop *evl;
    struct mk_list *list;
    struct mk_list *head;
    struct mk_sched_conn *conn;
    struct mk_sched_worker *sched;
    struct mk_server_listen *listener;
    struct mk_server_timeout *server_timeout;

    /* Get thread conf */
    sched = mk_sched_get_thread_conf();
    evl = sched->loop;

    /*
     * The worker will NOT process any connection until the master
     * process through mk_server_loop() send us the green light
     * signal MK_SERVER_SIGNAL_START.
     */
    mk_event_wait(evl);
    mk_event_foreach(event, evl) {
        if ((event->mask & MK_EVENT_READ) &&
            event->type == MK_EVENT_NOTIFICATION) {
            if (event->fd == sched->signal_channel_r) {
        /* When using libevent _mk_event_channel_create creates a unix socket
         * instead of a pipe and windows doesn't us calling read / write on a
         * socket instead of recv / send
         */
#ifdef _WIN32
                ret = recv(event->fd, &val, sizeof(val), MSG_WAITALL);
#else
                ret = read(event->fd, &val, sizeof(val));
#endif
                if (ret < 0) {
                    mk_libc_error("read");
                    continue;
                }
                if (val == MK_SERVER_SIGNAL_START) {
                    MK_TRACE("Worker %i started (SIGNAL_START)", sched->idx);
                    break;
                }
            }
        }
    }

    if (server->scheduler_mode == MK_SCHEDULER_REUSEPORT) {
        /* Register listeners */
        list = MK_TLS_GET(mk_tls_server_listen);
        mk_list_foreach(head, list) {
            listener = mk_list_entry(head, struct mk_server_listen, _head);
            mk_event_add(sched->loop, listener->server_fd,
                         MK_EVENT_LISTENER, MK_EVENT_READ,
                         listener);
        }
    }

    /*
     * If running in library mode, register the FIFO pipe file descriptors
     * into the main event loop.
     */
    if (server->lib_mode == MK_TRUE) {
        mk_server_fifo_worker_setup(evl);
    }

    /* create a new timeout file descriptor */
    server_timeout = mk_mem_alloc(sizeof(struct mk_server_timeout));
    MK_TLS_SET(mk_tls_server_timeout, server_timeout);
    timeout_fd = mk_event_timeout_create(evl, server->timeout, 0, server_timeout);

    while (1) {
        mk_event_wait(evl);
        mk_event_foreach(event, evl) {
            ret = 0;
            if (event->type & MK_EVENT_IDLE) {
                continue;
            }

            if (event->type == MK_EVENT_CONNECTION) {
                conn = (struct mk_sched_conn *) event;

                if (event->mask & MK_EVENT_WRITE) {
                    MK_TRACE("[FD %i] Event WRITE", event->fd);
                    ret = mk_sched_event_write(conn, sched, server);
                }

                if (event->mask & MK_EVENT_READ) {
                    MK_TRACE("[FD %i] Event READ", event->fd);
                    ret = mk_sched_event_read(conn, sched, server);
                }


                if (event->mask & MK_EVENT_CLOSE && ret != -1) {
                    MK_TRACE("[FD %i] Event CLOSE", event->fd);
                    ret = -1;
                }

                if (ret < 0 && conn->status != MK_SCHED_CONN_CLOSED) {
                    MK_TRACE("[FD %i] Event FORCE CLOSE | ret = %i",
                             event->fd, ret);
                    mk_sched_event_close(conn, sched, MK_EP_SOCKET_CLOSED,
                                         server);
                }
            }
            else if (event->type == MK_EVENT_LISTENER) {
                /*
                 * A new connection have been accepted..or failed, despite
                 * the result, we let the loop continue processing the other
                 * events triggered.
                 */
                conn = mk_server_listen_handler(sched, event, server);
                if (conn) {
                    //conn->event.mask = MK_EVENT_READ
                    //goto speed;
                }
                continue;
            }
            else if (event->type == MK_EVENT_CUSTOM) {
                /*
                 * We got an event associated to a custom interface, that
                 * means a plugin registered some file descriptor on this
                 * event loop and an event was triggered. We pass the control
                 * to the defined event handler.
                 */
                event->handler(event);
            }
            else if (event->type == MK_EVENT_NOTIFICATION) {
#ifdef _WIN32
                ret = recv(event->fd, &val, sizeof(val), MSG_WAITALL);
#else
                ret = read(event->fd, &val, sizeof(val));
#endif
                if (ret < 0) {
                    mk_libc_error("read");
                    continue;
                }

                if (event->fd == sched->signal_channel_r) {
                    if (val == MK_SCHED_SIGNAL_DEADBEEF) {
                        //FIXME:mk_sched_sync_counters();
                        continue;
                    }
                    else if (val == MK_SCHED_SIGNAL_FREE_ALL) {
                        if (timeout_fd > 0) {
                            close(timeout_fd);
                        }
                        mk_mem_free(MK_TLS_GET(mk_tls_server_timeout));
                        mk_server_listen_exit(sched->listeners);
                        mk_event_loop_destroy(evl);
                        mk_sched_worker_free(server);
                        return;
                    }
                    else if (val == MK_SCHED_SIGNAL_EVENT_LOOP_BREAK) {
                        /* NOTE: This is just a notification that's sent to break out
                         *       of the libevent loop in windows after accepting a new
                         *       client
                        */
                        MK_TRACE("New client accepted, awesome!");
                    }
                }
                else if (event->fd == timeout_fd) {
                    mk_sched_check_timeouts(sched, server);
                }
                continue;
            }
            else if (event->type == MK_EVENT_THREAD) {
                mk_http_thread_event(event);
                continue;
            }
            else if (event->type == MK_EVENT_FIFO) {
                mk_fifo_worker_read(event);
                continue;
            }
        }
        mk_sched_threads_purge(sched);
        mk_sched_event_free_all(sched);
    }
}

static int mk_server_lib_notify_event_loop_break(struct mk_sched_worker *sched)
{
    uint64_t val;

    /* Check the channel is valid (enabled by library mode) */
    if (sched->signal_channel_w <= 0) {
        return -1;
    }

    val = MK_SCHED_SIGNAL_EVENT_LOOP_BREAK;

#ifdef _WIN32
    return send(sched->signal_channel_w, &val, sizeof(uint64_t), 0);
#else
    return write(sched->signal_channel_w, &val, sizeof(uint64_t));
#endif
}

static int mk_server_lib_notify_started(struct mk_server *server)
{
    uint64_t val;

    /* Check the channel is valid (enabled by library mode) */
    if (server->lib_ch_manager[1] <= 0) {
        return -1;
    }

    val = MK_SERVER_SIGNAL_START;

#ifdef _WIN32
    return send(server->lib_ch_manager[1], &val, sizeof(uint64_t), 0);
#else
    return write(server->lib_ch_manager[1], &val, sizeof(uint64_t));
#endif
}


void mk_server_loop(struct mk_server *server)
{
    uint64_t val;

    /* Rename worker */
    mk_utils_worker_rename("monkey: server");

    if (server->lib_mode == MK_FALSE) {
        mk_info("HTTP Server started");
    }

    /* Wake up workers */
    val = MK_SERVER_SIGNAL_START;
    mk_sched_broadcast_signal(server, val);

    /* Signal lib caller (if any) */
    mk_server_lib_notify_started(server);

    /*
     * When using REUSEPORT mode on the Scheduler, we need to signal
     * them so they can start processing connections.
     */
    if (server->scheduler_mode == MK_SCHEDULER_REUSEPORT) {
        /* do thing :) */
    }
    else {
        /* FIXME!: this old mode needs some checks on library mode */
        mk_server_loop_balancer(server);
    }
}
