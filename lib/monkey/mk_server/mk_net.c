/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2016 Monkey Software LLC <eduardo@monkey.io>
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
#include <monkey/mk_net.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_thread.h>

#ifdef _WIN32
#include <winsock2.h>
#include <afunix.h>
#else
#include <sys/socket.h>
#include <netinet/tcp.h>
#endif

/* Initialize the network stack*/
int mk_net_init()
{
#ifdef _WIN32
    int result;
    WSADATA wsa_data;
    static int initialized = 0;

    if(0 != initialized) {
        return 0;
    }

    result = WSAStartup(MAKEWORD(2, 2), &wsa_data);

    if(0 != result) {
        if(WSAEINPROGRESS == result)
        {
            Sleep(100); /* Let the other thread finish initializing the stack */

            return 0;
        }

        return -1;
    }

    initialized = 1;    
#endif

    return 0;
}

/* Connect to a TCP socket server */
static int mk_net_fd_connect(int fd, char *host, unsigned long port)
{
    int ret;
    struct addrinfo hints;
    struct addrinfo *res;
    char _port[6];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(_port, sizeof(_port), "%lu", port);
    ret = getaddrinfo(host, _port, &hints, &res);
    if (ret != 0) {
        return -1;
    }

    ret = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    return ret;
}

struct mk_net_connection *mk_net_conn_create(char *addr, int port)
{
    int fd;
    int ret;
    int error = 0;
    socklen_t len = sizeof(error);
    struct mk_sched_worker *sched;
    struct mk_net_connection *conn;

    /* Allocate connection context */
    conn = mk_mem_alloc(sizeof(struct mk_net_connection));
    if (!conn) {
        return NULL;
    }

    /* Create socket */
    fd = mk_socket_create(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        mk_mem_free(conn);
        return NULL;
    }

    /* Make socket async */
    mk_socket_set_nonblocking(fd);
    conn->fd = fd;

    ret = mk_net_fd_connect(conn->fd, addr, port);
    if (ret == -1) {
        if (errno != EINPROGRESS) {
            close(fd);
            mk_mem_free(conn);
            return NULL;
        }

        MK_EVENT_NEW(&conn->event);

        sched = mk_sched_get_thread_conf();
        // FIXME: not including the thread
        //conn->thread = mk_thread_get();
        ret = mk_event_add(sched->loop, conn->fd, MK_EVENT_THREAD,
                           MK_EVENT_WRITE, &conn->event);
        if (ret == -1) {
            close(fd);
            mk_mem_free(conn);
            return NULL;
        }

        /*
         * Return the control to the parent caller, we need to wait for
         * the event loop to get back to us.
         */
        mk_thread_yield(conn->thread);

        /* We got a notification, remove the event registered */
        ret = mk_event_del(sched->loop, &conn->event);

        /* Check the connection status */
        if (conn->event.mask & MK_EVENT_WRITE) {
            ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
            if (ret == -1) {
                close(fd);
                mk_mem_free(conn);
                return NULL;
            }

            if (error != 0) {
                /* Connection is broken, not much to do here */
                fprintf(stderr, "Async connection failed %s:%i\n",
                        conn->host, conn->port);
                close(fd);
                mk_mem_free(conn);
                return NULL;
            }
            MK_EVENT_NEW(&conn->event);
            return conn;
        }
        else {
            close(fd);
            mk_mem_free(conn);
            return NULL;
        }
    }

    return NULL;
}

int mk_net_conn_write(struct mk_channel *channel,
                      void *data, size_t len)
{
    int ret = 0;
    int error;
    ssize_t bytes;
    size_t total = 0;
    size_t send;
    socklen_t slen = sizeof(error);
    struct mk_thread *th = pthread_getspecific(mk_thread_key);
    struct mk_sched_worker *sched;

    sched = mk_sched_get_thread_conf();
    if (!sched) {
        return -1;
    }

 retry:
    error = 0;

    if (len - total > 524288) {
        send = 524288;
    }
    else {
        send = (len - total);
    }

    send = len - total;
    bytes = channel->io->write(channel->fd, (uint8_t *)data + total, send);
    if (bytes == -1) {
        if (errno == EAGAIN) {
            MK_EVENT_NEW(channel->event);
            channel->thread = th;
            ret = mk_event_add(sched->loop,
                               channel->fd,
                               MK_EVENT_THREAD,
                               MK_EVENT_WRITE, channel->event);
            if (ret == -1) {
                /*
                 * If we failed here there no much that we can do, just
                 * let the caller we failed
                 */
                return -1;
            }

            /*
             * Return the control to the parent caller, we need to wait for
             * the event loop to get back to us.
             */
            mk_thread_yield(th);

            /* We got a notification, remove the event registered */
            ret = mk_event_del(sched->loop, channel->event);
            if (ret == -1) {
                return -1;
            }

            /* Check the connection status */
            if (channel->event->mask & MK_EVENT_WRITE) {
                ret = getsockopt(channel->fd, SOL_SOCKET, SO_ERROR, &error, &slen);
                if (ret == -1) {
                    fprintf(stderr, "[io] could not validate socket status");
                    return -1;
                }

                if (error != 0) {
                    return -1;
                }

                MK_EVENT_NEW(channel->event);
                goto retry;
            }
            else {
                return -1;
            }

        }
        else {
            return -1;
        }
    }

    /* Update counters */
    total += bytes;
    if (total < len) {
        channel->thread = th;
        ret = mk_event_add(sched->loop,
                           channel->fd,
                           MK_EVENT_THREAD,
                           MK_EVENT_WRITE, channel->event);
        if (ret == -1) {
            /*
             * If we failed here there no much that we can do, just
             * let the caller we failed
             */
            return -1;
        }

        mk_thread_yield(th);
        goto retry;
    }

    if (channel->event->status & MK_EVENT_REGISTERED) {
        /* We got a notification, remove the event registered */
        ret = mk_event_del(sched->loop, channel->event);
    }

    return total;
}
