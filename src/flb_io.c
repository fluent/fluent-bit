/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_upstream.h>

#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_http_client.h>

int flb_io_net_connect(struct flb_upstream_conn *u_conn,
                       struct flb_coro *coro)
{
    int ret;
    int async = FLB_FALSE;
    flb_sockfd_t fd = -1;
    struct flb_upstream *u = u_conn->u;

    if (u_conn->fd > 0) {
        flb_socket_close(u_conn->fd);
        u_conn->fd = -1;
        u_conn->event.fd = -1;
    }

    /* Check which connection mode must be done */
    if (coro) {
        async = flb_upstream_is_async(u);
    }
    else {
        async = FLB_FALSE;
    }

    /* Perform TCP connection */
    fd = flb_net_tcp_connect(u->tcp_host, u->tcp_port, u->net.source_address,
                             u->net.connect_timeout, async, coro, u_conn);
    if (fd == -1) {
        return -1;
    }

    if (u->proxied_host) {
        ret = flb_http_client_proxy_connect(u_conn);
        if (ret == -1) {
            flb_debug("[http_client] flb_http_client_proxy_connect connection #%i failed to %s:%i.",
                      u_conn->fd, u->tcp_host, u->tcp_port);
          flb_socket_close(fd);
          return -1;
        }
        flb_debug("[http_client] flb_http_client_proxy_connect connection #%i connected to %s:%i.",
                  u_conn->fd, u->tcp_host, u->tcp_port);
    }

#ifdef FLB_HAVE_TLS
    /* Check if TLS was enabled, if so perform the handshake */
    if (u->flags & FLB_IO_TLS) {
        ret = flb_tls_session_create(u->tls, u_conn, coro);
        if (ret != 0) {
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
    struct flb_coro *coro;

    if (u_conn->fd <= 0) {
        coro = flb_coro_get();
        ret = flb_io_net_connect(u_conn, coro);
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
static FLB_INLINE int net_io_write_async(struct flb_coro *co,
                                         struct flb_upstream_conn *u_conn,
                                         const void *data, size_t len, size_t *out_len)
{
    int ret = 0;
    int error;
    uint32_t mask;
    ssize_t bytes;
    size_t total = 0;
    size_t to_send;
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
        flb_trace("[io coro=%p] [fd %i] write_async(2)=%d (%lu/%lu)",
                  co, u_conn->fd, bytes, total + bytes, len);
    }
    else {
        flb_trace("[io coro=%p] [fd %i] write_async(2)=%d (%lu/%lu)",
                  co, u_conn->fd, bytes, total, len);
    }
#endif

    if (bytes == -1) {
        if (FLB_WOULDBLOCK()) {
            u_conn->coro = co;
            ret = mk_event_add(u_conn->evl,
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
            flb_coro_yield(co, FLB_FALSE);

            /* Save events mask since mk_event_del() will reset it */
            mask = u_conn->event.mask;

            /* We got a notification, remove the event registered */
            ret = mk_event_del(u_conn->evl, &u_conn->event);
            if (ret == -1) {
                return -1;
            }

            /* Check the connection status */
            if (mask & MK_EVENT_WRITE) {
                error = flb_socket_error(u_conn->fd);
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
            u_conn->coro = co;
            ret = mk_event_add(u_conn->evl,
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
        flb_coro_yield(co, MK_FALSE);
        goto retry;
    }

    if (u_conn->event.status & MK_EVENT_REGISTERED) {
        /* We got a notification, remove the event registered */
        ret = mk_event_del(u_conn->evl, &u_conn->event);
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

static FLB_INLINE ssize_t net_io_read_async(struct flb_coro *co,
                                            struct flb_upstream_conn *u_conn,
                                            void *buf, size_t len)
{
    int ret;

 retry_read:
    ret = recv(u_conn->fd, buf, len, 0);
    if (ret == -1) {
        if (FLB_WOULDBLOCK()) {
            u_conn->coro = co;
            ret = mk_event_add(u_conn->evl,
                               u_conn->fd,
                               FLB_ENGINE_EV_THREAD,
                               MK_EVENT_READ, &u_conn->event);
            if (ret == -1) {
                /*
                 * If we failed here there no much that we can do, just
                 * let the caller we failed
                 */
                return -1;
            }
            flb_coro_yield(co, MK_FALSE);
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
    struct flb_coro *coro = flb_coro_get();

    flb_trace("[io coro=%p] [net_write] trying %zd bytes", coro, len);

    if (!u_conn->tls_session) {
        if (u->flags & FLB_IO_ASYNC) {
            ret = net_io_write_async(coro, u_conn, data, len, out_len);
        }
        else {
            ret = net_io_write(u_conn, data, len, out_len);
        }
    }
#ifdef FLB_HAVE_TLS
    else if (u->flags & FLB_IO_TLS) {
        if (u->flags & FLB_IO_ASYNC) {
            ret = flb_tls_net_write_async(coro, u_conn, data, len, out_len);
        }
        else {
            ret = flb_tls_net_write(u_conn, data, len, out_len);
        }
    }
#endif

    if (ret == -1 && u_conn->fd > 0) {
        flb_socket_close(u_conn->fd);
        u_conn->fd = -1;
        u_conn->event.fd = -1;
    }

    flb_trace("[io coro=%p] [net_write] ret=%i total=%lu/%lu",
              coro, ret, *out_len, len);
    return ret;
}

ssize_t flb_io_net_read(struct flb_upstream_conn *u_conn, void *buf, size_t len)
{
    int ret = -1;
    struct flb_upstream *u = u_conn->u;
    struct flb_coro *coro = flb_coro_get();

    flb_trace("[io coro=%p] [net_read] try up to %zd bytes", coro, len);

    if (!u_conn->tls_session) {
        if (u->flags & FLB_IO_ASYNC) {
            ret = net_io_read_async(coro, u_conn, buf, len);
        }
        else {
            ret = net_io_read(u_conn, buf, len);
        }
    }
#ifdef FLB_HAVE_TLS
    else if (u->flags & FLB_IO_TLS) {
        if (u->flags & FLB_IO_ASYNC) {
            ret = flb_tls_net_read_async(coro, u_conn, buf, len);
        }
        else {
            ret = flb_tls_net_read(u_conn, buf, len);
        }
    }
#endif

    flb_trace("[io coro=%p] [net_read] ret=%i", coro, ret);
    return ret;
}
