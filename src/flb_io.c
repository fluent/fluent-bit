/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

/*
 * FLB_IO
 * ======
 * This interface is used by the output plugins which needs to write over
 * the network in plain communication or through the TLS support. When dealing
 * with network operation there are a few things to keep in mind:
 *
 * - TCP hosts can be down.
 * - Network can be slow.
 * - If the amount of data to flush requires multiple 'write' operations, we
 *   should not block the main thread, instead use event-driven mechanism to
 *   write when is possible.
 *
 * Output plugins that flag themselves with FLB_OUTPUT_TCP or FLB_OUTPUT_TLS
 * can take advantage of this interface.
 *
 * The workflow to use this is the following:
 *
 * - A connection and data flow requires an flb_io_upstream context.
 * - We write/read data through the flb_io_write()/flb_io_read() interfaces.
 *
 * Note that Upstreams context may define how network operations will work,
 * basically synchronous or asynchronous (non-blocking).
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_io_tls.h>
#include <fluent-bit/flb_io_tls_rw.h>
#include <fluent-bit/flb_tls.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_upstream.h>

#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_thread.h>

FLB_INLINE int flb_io_net_connect(struct flb_upstream_conn *u_conn,
                                  struct flb_thread *th)
{
    int ret;
    int err;
    int error = 0;
    int async = FLB_FALSE;
    uint32_t mask;
    char so_error_buf[256];
    fd_set wait_set;
    flb_sockfd_t fd = -1;
    socklen_t len = sizeof(error);
    struct timeval timeout;
    struct flb_upstream *u = u_conn->u;
    struct sockaddr_storage addr;
    struct addrinfo hint;
    struct addrinfo *res = NULL;

    if (u_conn->fd > 0) {
        flb_socket_close(u_conn->fd);
    }

    /*
     * If the net.source_address was set, we need to determinate the address
     * type (for socket type creation) and bind it.
     *
     * Note that this routine overrides the behavior of the 'ipv6' configuration
     * property.
     */
    if (u->net.source_address) {
        memset(&hint, '\0', sizeof hint);

        hint.ai_family = PF_UNSPEC;
        hint.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

        ret = getaddrinfo(u->net.source_address, NULL, &hint, &res);
        if (ret == -1) {
            flb_errno();
            flb_error("[io] cannot parse source_address=%s",
                      u->net.source_address);
            return -1;
        }

        if (res->ai_family == AF_INET) {
            fd = flb_net_socket_create(AF_INET, FLB_FALSE);
        }
        else if (res->ai_family == AF_INET6) {
            fd = flb_net_socket_create(AF_INET6, FLB_FALSE);
        }
        else {
            flb_error("[io] could not create socket for "
                      "source_address=%s, unknown ai_family",
                      u->net.source_address);
            freeaddrinfo(res);
            return -1;
        }

        if (fd == -1) {
            flb_error("[io] could not create an %s socket for "
                      "source_address=%s",
                      res->ai_family == AF_INET ? "IPv4": "IPv6",
                      u->net.source_address);
            freeaddrinfo(res);
            return -1;
        }

        /* Bind the address */
        memcpy(&addr, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
        ret = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
        if (ret == -1) {
            flb_errno();
            flb_socket_close(fd);
            flb_error("[io] could not bind source_address=%s",
                      u->net.source_address);
            return -1;
        }
    }
    else {
        /* Create the socket */
        if (u_conn->u->flags & FLB_IO_IPV6) {
            fd = flb_net_socket_create(AF_INET6, FLB_FALSE);
        }
        else {
            fd = flb_net_socket_create(AF_INET, FLB_FALSE);
        }
        if (fd == -1) {
            flb_error("[io] could not create socket");
            return -1;
        }
    }

    u_conn->fd = fd;
    u_conn->event.fd = fd;

    /* Disable Nagle's algorithm */
    flb_net_socket_tcp_nodelay(fd);

    /*
     * If the socket is asynchronous or we need a timeout for connect(2) on a
     * blocking socket set the 'async' flag,
     */
    if ((u->flags & FLB_IO_ASYNC) || u->net.connect_timeout > 0) {
        async = FLB_TRUE;
        flb_net_socket_nonblocking(u_conn->fd);
    }

    /* Start the connection */
    ret = flb_net_tcp_fd_connect(fd, u->tcp_host, u->tcp_port);
    if (ret == -1) {
        /*
         * We got an exception, depending on the blocking mode we must
         * check the 'errno' status of the socket.
         *
         * If no asynchronous mode was set, just fail right away.
         */
        if (async == FLB_FALSE) {
            flb_errno();
            flb_error("[io] TCP failed connecting to: %s:%i",
                      u->tcp_host, u->tcp_port);
            flb_socket_close(fd);
            return -1;
        }

        /*
         * If the asynchronous mode is enabled and the connection is still in
         * progress, check under which condition the non-blocking socket was
         * set, the options are:
         *
         *  1. Native asynchronous socket connection set by the caller
         *  2. Blocking socket that needs a timeout for connect(2)
         */
        err = flb_socket_error(fd);
        if (!FLB_EINPROGRESS(err)) {
            flb_errno();
            flb_error("[io] TCP failed connecting to: %s:%i",
                      u->tcp_host, u->tcp_port);
            flb_socket_close(fd);
            return -1;
        }

        /* FYI: The connection is in progress... */
        flb_trace("[io] connection in process to %s:%i",
                  u->tcp_host, u->tcp_port);

        /*
         * Timeout for blocking socket. Check if the 'original' socket
         * mode is 'blocking'
         */
        if ((u->flags & FLB_IO_ASYNC) == 0) {
            /*
             * Prepare a timeout using select(2): we could use our own
             * event loop mechanism for this, but it will require an
             * extra file descriptor, the select(2) call is straightforward
             * for this use case.
             */
            FD_ZERO(&wait_set);
            FD_SET(u_conn->fd, &wait_set);

            /* Wait 'connect_timeout' seconds for an event */
            timeout.tv_sec = u->net.connect_timeout;
            timeout.tv_usec = 0;
            ret = select(u_conn->fd + 1, NULL, &wait_set, NULL, &timeout);
            if (ret == 0) {
                /* Timeout */
                flb_error("[io] TCP connect timeout after %i seconds to: "
                          "%s:%i",
                          u->net.connect_timeout,
                          u->tcp_host, u->tcp_port);
                flb_socket_close(fd);
                return -1;
            }
            else if (ret < 0) {
                /* Generic error */
                flb_errno();
                flb_error("[io] TCP failed connecting to: %s:%i",
                          u->tcp_host, u->tcp_port);
                flb_socket_close(fd);
                return -1;
            }

            /*
             * No exception, the connection succeeded, return the normal
             * blocking mode to the socket.
             */
            flb_net_socket_blocking(u_conn->fd);

            /* Finalize last steps for connection like TLS and return */
            goto connected;
        }

        MK_EVENT_ZERO(&u_conn->event);
        u_conn->thread = th;
        ret = mk_event_add(u->evl,
                           fd,
                           FLB_ENGINE_EV_THREAD,
                           MK_EVENT_WRITE, &u_conn->event);
        if (ret == -1) {
            /*
             * If we failed here there no much that we can do, just
             * let the caller we failed
             */
            flb_socket_close(fd);
            return -1;
        }

        /*
         * Return the control to the parent caller, we need to wait for
         * the event loop to get back to us.
         */
        flb_thread_yield(th, FLB_FALSE);

        /* Save the mask before the event handler do a reset */
        mask = u_conn->event.mask;

        /* We got a notification, remove the event registered */
        ret = mk_event_del(u->evl, &u_conn->event);
        if (ret == -1) {
            flb_error("[io] connect event handler error");
            flb_socket_close(fd);
            return -1;
        }

        /* Check the connection status */
        if (mask & MK_EVENT_WRITE) {
            ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
            if (ret == -1) {
                flb_error("[io] could not validate socket status");
                flb_socket_close(fd);
                return -1;
            }

            /* Check the exception */
            if (error != 0) {
                /*
                 * The upstream connection might want to override the
                 * exception (mostly used for local timeouts: ETIMEDOUT.
                 */
                if (u_conn->net_error > 0) {
                    error = u_conn->net_error;
                }

                /* Connection is broken, not much to do here */
                strerror_r(error, so_error_buf, sizeof(so_error_buf) - 1);
                flb_error("[io] TCP connection failed: %s:%i (%s)",
                          u->tcp_host, u->tcp_port, so_error_buf);
                flb_socket_close(fd);
                return -1;
            }
        }
        else {
            flb_error("[io] TCP connection, unexpected error: %s:%i",
                      u->tcp_host, u->tcp_port);
            flb_socket_close(fd);
            return -1;
        }
    }

connected:

#ifdef FLB_HAVE_TLS
    /* Check if TLS was enabled, if so perform the handshake */
    if (u_conn->u->flags & FLB_IO_TLS) {
        ret = net_io_tls_handshake(u_conn, th);
        if (ret != 0) {
            flb_socket_close(fd);
            return -1;
        }
    }
#endif

    flb_trace("[io] connection OK");

    return 0;
}

static int net_io_write(struct flb_upstream_conn *u_conn,
                        const void *data, size_t len, size_t *out_len)
{
    int ret;
    int tries = 0;
    size_t total = 0;

    if (u_conn->fd <= 0) {
        struct flb_thread *th;
        th = (struct flb_thread *) pthread_getspecific(flb_thread_key);
        ret = flb_io_net_connect(u_conn, th);
        if (ret == -1) {
            return -1;
        }
    }

    while (total < len) {
        ret = send(u_conn->fd, (char *) data + total, len - total, 0);
        if (ret == -1) {
            if (FLB_WOULDBLOCK()) {
                /*
                 * FIXME: for now we are handling this in a very lazy way,
                 * just sleep for a second and retry (for a max of 30 tries).
                 */
                sleep(1);
                tries++;

                if (tries == 30) {
                    return -1;
                }
                continue;
            }
            return -1;
        }
        tries = 0;
        total += ret;
    }

    *out_len = total;
    return total;
}

/*
 * Perform Async socket write(2) operations. This function depends on a main
 * event-loop and the co-routines interface to yield/resume once sockets are
 * ready to continue.
 *
 * Intentionally we register/de-register the socket file descriptor from
 * the event loop each time when we require to do some work.
 */
static FLB_INLINE int net_io_write_async(struct flb_thread *th,
                                         struct flb_upstream_conn *u_conn,
                                         const void *data, size_t len, size_t *out_len)
{
    int ret = 0;
    int error;
    uint32_t mask;
    ssize_t bytes;
    size_t total = 0;
    size_t to_send;
    socklen_t slen = sizeof(error);
    char so_error_buf[256];
    struct flb_upstream *u = u_conn->u;

 retry:
    error = 0;

    if (len - total > 524288) {
        to_send = 524288;
    }
    else {
        to_send = (len - total);
    }
    bytes = send(u_conn->fd, (char *) data + total, to_send, 0);

#ifdef FLB_HAVE_TRACE
    if (bytes > 0) {
        flb_trace("[io thread=%p] [fd %i] write_async(2)=%d (%lu/%lu)",
                  th, u_conn->fd, bytes, total + bytes, len);
    }
    else {
        flb_trace("[io thread=%p] [fd %i] write_async(2)=%d (%lu/%lu)",
                  th, u_conn->fd, bytes, total, len);
    }
#endif

    if (bytes == -1) {
        if (FLB_WOULDBLOCK()) {
            u_conn->thread = th;
            ret = mk_event_add(u->evl,
                               u_conn->fd,
                               FLB_ENGINE_EV_THREAD,
                               MK_EVENT_WRITE, &u_conn->event);
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
            flb_thread_yield(th, FLB_FALSE);

            /* Save events mask since mk_event_del() will reset it */
            mask = u_conn->event.mask;

            /* We got a notification, remove the event registered */
            ret = mk_event_del(u->evl, &u_conn->event);
            if (ret == -1) {
                return -1;
            }

            /* Check the connection status */
            if (mask & MK_EVENT_WRITE) {
                ret = getsockopt(u_conn->fd, SOL_SOCKET, SO_ERROR, &error, &slen);
                if (ret == -1) {
                    flb_error("[io] could not validate socket status");
                    return -1;
                }

                if (error != 0) {
                    /* Connection is broken, not much to do here */
                    strerror_r(error, so_error_buf, sizeof(so_error_buf) - 1);
                    flb_error("[io fd=%i] error sending data to: %s:%i (%s)",
                              u_conn->fd,
                              u->tcp_host, u->tcp_port, so_error_buf);

                    return -1;
                }

                MK_EVENT_NEW(&u_conn->event);
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
        if (u_conn->event.status == MK_EVENT_NONE) {
            u_conn->event.mask = MK_EVENT_EMPTY;
            u_conn->thread = th;
            ret = mk_event_add(u->evl,
                               u_conn->fd,
                               FLB_ENGINE_EV_THREAD,
                               MK_EVENT_WRITE, &u_conn->event);
            if (ret == -1) {
                /*
                 * If we failed here there no much that we can do, just
                 * let the caller we failed
                 */
                return -1;
            }
        }
        flb_thread_yield(th, MK_FALSE);
        goto retry;
    }

    if (u_conn->event.status & MK_EVENT_REGISTERED) {
        /* We got a notification, remove the event registered */
        ret = mk_event_del(u->evl, &u_conn->event);
        assert(ret == 0);
    }

    *out_len = total;
    return bytes;
}

static ssize_t net_io_read(struct flb_upstream_conn *u_conn,
                           void *buf, size_t len)
{
    int ret;

    ret = recv(u_conn->fd, buf, len, 0);
    if (ret == -1) {
        return -1;
    }

    return ret;
}

static FLB_INLINE ssize_t net_io_read_async(struct flb_thread *th,
                                            struct flb_upstream_conn *u_conn,
                                            void *buf, size_t len)
{
    int ret;
    struct flb_upstream *u = u_conn->u;

 retry_read:

    ret = recv(u_conn->fd, buf, len, 0);
    if (ret == -1) {
        if (FLB_WOULDBLOCK()) {
            u_conn->thread = th;
            ret = mk_event_add(u->evl,
                               u_conn->fd,
                               FLB_ENGINE_EV_THREAD,
                               MK_EVENT_READ, &u_conn->event);
            if (ret == -1) {
                /*
                 * If we failed here there no much that we can do, just
                 * let the caller we failed
                 */
                flb_socket_close(u_conn->fd);
                return -1;
            }
            flb_thread_yield(th, MK_FALSE);
            goto retry_read;
        }
        return -1;
    }
    else if (ret <= 0) {
        return -1;
    }

    return ret;
}

/* Write data to an upstream connection/server */
int flb_io_net_write(struct flb_upstream_conn *u_conn, const void *data,
                     size_t len, size_t *out_len)
{
    int ret = -1;
    struct flb_upstream *u = u_conn->u;
    struct flb_thread *th = pthread_getspecific(flb_thread_key);

    flb_trace("[io thread=%p] [net_write] trying %zd bytes",
              th, len);

    if (u->flags & FLB_IO_TCP) {
        if (u->flags & FLB_IO_ASYNC) {
            ret = net_io_write_async(th, u_conn, data, len, out_len);
        }
        else {
            ret = net_io_write(u_conn, data, len, out_len);
        }
    }
#ifdef FLB_HAVE_TLS
    else if (u->flags & FLB_IO_TLS) {
        ret = flb_io_tls_net_write(th, u_conn, data, len, out_len);
    }
#endif

    if (ret == -1 && u_conn->fd > 0) {
        flb_socket_close(u_conn->fd);
        u_conn->fd = -1;
        u_conn->event.fd = -1;
    }

    flb_trace("[io thread=%p] [net_write] ret=%i total=%lu/%lu",
              th, ret, *out_len, len);
    return ret;
}

ssize_t flb_io_net_read(struct flb_upstream_conn *u_conn, void *buf, size_t len)
{
    int ret = -1;
    struct flb_upstream *u = u_conn->u;
    struct flb_thread *th = pthread_getspecific(flb_thread_key);

    flb_trace("[io thread=%p] [net_read] try up to %zd bytes",
              th, len);

    if (u->flags & FLB_IO_TCP) {
        if (u->flags & FLB_IO_ASYNC) {
            ret = net_io_read_async(th, u_conn, buf, len);
        }
        else {
            ret = net_io_read(u_conn, buf, len);
        }
    }
#ifdef FLB_HAVE_TLS
    else if (u->flags & FLB_IO_TLS) {
        ret = flb_io_tls_net_read(th, u_conn, buf, len);
    }
#endif

    flb_trace("[io thread=%p] [net_read] ret=%i", th, ret);
    return ret;
}
