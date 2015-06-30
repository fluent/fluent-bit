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

#include <monkey/monkey.h>
#include <monkey/mk_config.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_server.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_core.h>

#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/resource.h>

__thread struct mk_list *server_listen;
__thread struct mk_server_timeout *server_timeout;

/* Return the number of clients that can be attended  */
unsigned int mk_server_capacity()
{
    int ret;
    int cur;
    struct rlimit lim;

    /* Limit by system */
    getrlimit(RLIMIT_NOFILE, &lim);
    cur = lim.rlim_cur;

    if (mk_config->fd_limit > cur) {
        lim.rlim_cur = mk_config->fd_limit;
        lim.rlim_max = mk_config->fd_limit;

        ret = setrlimit(RLIMIT_NOFILE, &lim);
        if (ret == -1) {
            mk_warn("Could not increase FDLimit to %i.", mk_config->fd_limit);
        }
        else {
            cur = mk_config->fd_limit;
        }
    }
    else if (mk_config->fd_limit > 0) {
        cur = mk_config->fd_limit;
    }

    return cur;
}

static inline
struct mk_sched_conn *mk_server_listen_handler(struct mk_sched_worker *sched,
                                               void *data)
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

    conn = mk_sched_add_connection(client_fd, listener, sched);
    if (mk_unlikely(!conn)) {
        mk_err("[server] Failed to register client.");
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
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_server_listen *listener;

    mk_list_foreach_safe(head, tmp, server_listen) {
        listener = mk_list_entry(head, struct mk_server_listen, _head);
        mk_list_del(&listener->_head);
        mk_mem_free(listener);
    }
}

struct mk_list *mk_server_listen_init(struct mk_server_config *config)
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

    if (config == NULL) {
        goto error;
    }

    listeners = malloc(sizeof(struct mk_list));
    mk_list_init(listeners);

    if (config->scheduler_mode == MK_SCHEDULER_REUSEPORT) {
        reuse_port = MK_TRUE;
    }

    mk_list_foreach(head, &config->listeners) {
        listen = mk_list_entry(head, struct mk_config_listener, _head);

        server_fd = mk_socket_server(listen->port,
                                     listen->address,
                                     reuse_port,
                                     config);
        if (server_fd >= 0) {
            if (mk_socket_set_tcp_defer_accept(server_fd) != 0) {
#if defined (__linux__)
                mk_warn("[server] Could not set TCP_DEFER_ACCEPT");
#endif
            }

            listener = mk_mem_malloc(sizeof(struct mk_server_listen));

            /* configure the internal event_state */
            event = &listener->event;
            event->fd   = server_fd;
            event->type = MK_EVENT_LISTENER;
            event->mask = MK_EVENT_EMPTY;

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

            if (listen->flags & MK_CAP_HTTP2) {
                mk_err("HTTP/2 not supported");
                exit(EXIT_FAILURE);
            }

            listener->network = mk_plugin_cap(MK_CAP_SOCK_PLAIN, config);

            if (listen->flags & MK_CAP_SOCK_SSL) {
                plugin = mk_plugin_cap(MK_CAP_SOCK_SSL, config);
                if (!plugin) {
                    mk_err("SSL/TLS not supported");
                    exit(EXIT_FAILURE);
                }
                listener->network = plugin;
            }

            mk_list_add(&listener->_head, listeners);
        }
        else {
            mk_warn("[server] Failed to bind server socket to %s:%s.",
                    listen->address,
                    listen->port);
        }
        i += 1;
    }

    if (reuse_port == MK_TRUE) {
        server_listen = listeners;
    }

    return listeners;

error:
    return NULL;
}

/* Here we launch the worker threads to attend clients */
void mk_server_launch_workers()
{
    int i;
    pthread_t skip;

    /* Launch workers */
    for (i = 0; i < mk_config->workers; i++) {
        mk_sched_launch_thread(mk_config->server_capacity, &skip);
    }

    /* Wait until all workers report as ready */
    while (1) {
        int ready = 0;

        pthread_mutex_lock(&mutex_worker_init);
        for (i = 0; i < mk_config->workers; i++) {
            if (sched_list[i].initialized)
                ready++;
        }
        pthread_mutex_unlock(&mutex_worker_init);

        if (ready == mk_config->workers) break;
        usleep(10000);
    }
}


/*
 * The loop_balancer() runs in the main process context and is considered
 * the old-fashion way to handle connections. It have an event queue waiting
 * for connections, once one arrives, it decides which worker (thread) may
 * handle it registering the accept(2)ed file descriptor on the worker
 * event monitored queue.
 */
void mk_server_loop_balancer()
{
    struct mk_list *head;
    struct mk_list *listeners;
    struct mk_server_listen *listener;
    struct mk_event *event;
    struct mk_event_loop *evl;
    struct mk_sched_worker *sched;

    /* Init the listeners */
    listeners = mk_server_listen_init(mk_config);
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
                sched = mk_sched_next_target();
                if (sched != NULL) {
                    mk_server_listen_handler(sched, event);
#ifdef TRACE
                    int i;
                    struct mk_sched_worker *node;

                    node = sched_list;
                    for (i = 0; i < mk_config->workers; i++) {
                        MK_TRACE("Worker Status");
                        MK_TRACE(" WID %i / conx = %llu",
                                 node[i].idx,
                                 node[i].accepted_connections -
                                 node[i].closed_connections);
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
void mk_server_worker_loop()
{
    int ret = -1;
    int timeout_fd;
    uint64_t val;
    struct mk_event *event;
    struct mk_event_loop *evl;
    struct mk_list *head;
    struct mk_sched_conn *conn;
    struct mk_sched_worker *sched;
    struct mk_server_listen *listener;

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
                ret = read(event->fd, &val, sizeof(val));
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
        else {
            /* FIXME */
        }
    }

    if (mk_config->scheduler_mode == MK_SCHEDULER_REUSEPORT) {
        /* Register listeners */
        mk_list_foreach(head, server_listen) {
            listener = mk_list_entry(head, struct mk_server_listen, _head);
            mk_event_add(sched->loop, listener->server_fd,
                         MK_EVENT_LISTENER, MK_EVENT_READ,
                         listener);
        }
    }

    /* create a new timeout file descriptor */
    server_timeout = mk_mem_malloc(sizeof(struct mk_server_timeout));
    timeout_fd = mk_event_timeout_create(evl, mk_config->timeout, server_timeout);

    while (1) {
        mk_event_wait(evl);
        mk_event_foreach(event, evl) {
            if (event->type == MK_EVENT_CONNECTION) {
                conn = (struct mk_sched_conn *) event;

                if (event->mask & MK_EVENT_WRITE) {
                    MK_TRACE("[FD %i] Event WRITE", event->fd);
                    ret = mk_sched_event_write(conn, sched);
                    //printf("event write ret=%i\n", ret);

                }

                if (event->mask & MK_EVENT_READ) {
                    MK_TRACE("[FD %i] Event READ", event->fd);
                    ret = mk_sched_event_read(conn, sched);
                }


                if (event->mask & MK_EVENT_CLOSE && ret != -1) {
                    MK_TRACE("[FD %i] Event CLOSE", event->fd);
                    ret = -1;
                }

                if (ret < 0) {
                    MK_TRACE("[FD %i] Event FORCE CLOSE | ret = %i",
                             event->fd, ret);
                    mk_sched_event_close(conn, sched, MK_EP_SOCKET_CLOSED);
                }
            }
            else if (event->type == MK_EVENT_LISTENER) {
                /*
                 * A new connection have been accepted..or failed, despite
                 * the result, we let the loop continue processing the other
                 * events triggered.
                 */
                conn = mk_server_listen_handler(sched, event);
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
                ret = read(event->fd, &val, sizeof(val));
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
                        mk_event_loop_destroy(evl);
                        mk_sched_worker_free();
                        return;
                    }
                }
                else if (event->fd == timeout_fd) {
                    mk_sched_check_timeouts(sched);
                }
                continue;
            }
        }
    }
}

void mk_server_loop(void)
{
    int n;
    int i;
    uint64_t val;

    /* Rename worker */
    mk_utils_worker_rename("monkey: server");

    mk_info("HTTP Server started");

    /* Wake up workers */
    val = MK_SERVER_SIGNAL_START;
    for (i = 0; i < mk_config->workers; i++) {
        n = write(sched_list[i].signal_channel_w, &val, sizeof(val));
        if (n < 0) {
            perror("write");
        }
    }

    /*
     * When using REUSEPORT mode on the Scheduler, we need to signal
     * them so they can start processing connections.
     */
    if (mk_config->scheduler_mode == MK_SCHEDULER_REUSEPORT) {
        /* Hang here, basically do nothing as threads are doing the job  */
        sigset_t mask;
        sigprocmask(0, NULL, &mask);
        sigsuspend(&mask);
        return;
    }
    else {
        mk_server_loop_balancer();
    }
}
