/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <string.h>
#include <errno.h>
#ifndef FLB_SYSTEM_WINDOWS
#include <unistd.h>
#endif

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_downstream.h>

#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_http_client.h>


static int flb_io_get_iov_max()
{
    long limit;

#ifdef IOV_MAX
    limit = IOV_MAX;
#else
    limit = -1;
#endif

#ifdef _SC_IOV_MAX
    {
        long sys_limit;

        sys_limit = sysconf(_SC_IOV_MAX);

        if (sys_limit > 0) {
            limit = sys_limit;
        }
    }
#endif

    if (limit <= 0 || limit > INT_MAX) {
        limit = 1024;
    }

    return (int) limit;
}

int flb_io_net_accept(struct flb_connection *connection,
                       struct flb_coro *coro)
{
    int ret;

    if (connection->fd != FLB_INVALID_SOCKET) {
        flb_socket_close(connection->fd);

        connection->fd = FLB_INVALID_SOCKET;
        connection->event.fd = FLB_INVALID_SOCKET;
    }

    /* Accept the new connection */
    connection->fd = flb_net_accept(connection->downstream->server_fd);

    if (connection->fd == -1) {
        connection->fd = FLB_INVALID_SOCKET;

        return -1;
    }

#ifdef FLB_HAVE_TLS
    /* Check if TLS was enabled, if so perform the handshake */
    if (flb_stream_is_secure(connection->stream) &&
        connection->stream->tls_context != NULL) {
        ret = flb_tls_session_create(connection->stream->tls_context,
                                     connection,
                                     coro);

        if (ret != 0) {
            return -1;
        }
    }
#endif

    flb_trace("[io] connection OK");

    return 0;
}

int flb_io_net_connect(struct flb_connection *connection,
                       struct flb_coro *coro)
{
    int ret;
    int async = FLB_FALSE;
    flb_sockfd_t fd = -1;
    int flags = flb_connection_get_flags(connection);

    if (connection->fd > 0) {
        flb_socket_close(connection->fd);
        connection->fd = -1;
        connection->event.fd = -1;
    }

    /* Check which connection mode must be done */
    if (coro && (flags & FLB_IO_ASYNC)) {
        async = flb_upstream_is_async(connection->upstream);
    }
    else {
        async = FLB_FALSE;
    }

    /* Perform TCP connection */
    fd = flb_net_tcp_connect(connection->upstream->tcp_host,
                             connection->upstream->tcp_port,
                             connection->stream->net.source_address,
                             connection->stream->net.connect_timeout,
                             async, coro, connection);
    if (fd == -1) {
        return -1;
    }

    if (connection->upstream->proxied_host) {
        ret = flb_http_client_proxy_connect(connection);

        if (ret == -1) {
            flb_debug("[http_client] flb_http_client_proxy_connect connection #%i failed to %s:%i.",
                      connection->fd,
                      connection->upstream->tcp_host,
                      connection->upstream->tcp_port);

            flb_socket_close(fd);
            connection->fd = -1;
            connection->event.fd = -1;
            return -1;
        }
        flb_debug("[http_client] flb_http_client_proxy_connect connection #%i connected to %s:%i.",
                  connection->fd,
                  connection->upstream->tcp_host,
                  connection->upstream->tcp_port);
    }

    /* set TCP keepalive and it's options */
    if (connection->net->tcp_keepalive) {
        ret = flb_net_socket_tcp_keepalive(connection->fd,
                                           connection->net);

        if (ret == -1) {
            flb_socket_close(fd);
            connection->fd = -1;
            connection->event.fd = -1;
            return -1;
        }
    }

#ifdef FLB_HAVE_TLS
    /* Check if TLS was enabled, if so perform the handshake */
    if (flb_stream_is_secure(connection->stream) &&
        connection->stream->tls_context != NULL) {
        ret = flb_tls_session_create(connection->stream->tls_context,
                                     connection,
                                     coro);

        if (ret != 0) {
            return -1;
        }
    }
#endif

    flb_trace("[io] connection OK");

    return 0;
}

static void net_io_propagate_critical_error(
                struct flb_connection *connection)
{
    switch (errno) {
    case EBADF:
    case ECONNRESET:
    case EDESTADDRREQ:
    case ENOTCONN:
    case EPIPE:
    case EACCES:
    case ENOTTY:
    case ENETDOWN:
    case ENETUNREACH:
        connection->net_error = errno;
    }
}

static int fd_io_write(int fd, struct sockaddr_storage *address,
                       const void *data, size_t len, size_t *out_len);
static int net_io_write(struct flb_connection *connection,
                        const void *data, size_t len, size_t *out_len)
{
    struct sockaddr_storage *address;
    int                      ret;

    if (connection->fd <= 0) {
        if (connection->type != FLB_UPSTREAM_CONNECTION) {
            return -1;
        }

        ret = flb_io_net_connect((struct flb_connection *) connection,
                                 flb_coro_get());

        if (ret == -1) {
            return -1;
        }
    }

    address = NULL;

    if (connection->type == FLB_DOWNSTREAM_CONNECTION) {
        if (connection->stream->transport == FLB_TRANSPORT_UDP ||
            connection->stream->transport == FLB_TRANSPORT_UNIX_DGRAM) {
            address = &connection->raw_remote_host;
        }
    }

    ret = fd_io_write(connection->fd, address, data, len, out_len);

    if (ret == -1) {
        net_io_propagate_critical_error(connection);
    }

    return ret;
}

static int fd_io_write(int fd, struct sockaddr_storage *address,
                       const void *data, size_t len, size_t *out_len)
{
    int ret;
    int tries = 0;
    size_t total = 0;

    while (total < len) {
        if (address != NULL) {
            ret = sendto(fd, (char *) data + total, len - total, 0,
                         (struct sockaddr *) address,
                         flb_network_address_size(address));
        }
        else {
            ret = send(fd, (char *) data + total, len - total, 0);
        }

        if (ret == -1) {
            if (FLB_WOULDBLOCK()) {
                /*
                 * FIXME: for now we are handling this in a very lazy way,
                 * just sleep for a second and retry (for a max of 30 tries).
                 */
                sleep(1);
                tries++;

                if (tries == 30) {
                    /* Since we're aborting after 30 failures we want the
                     * caller to know how much data we were able to send
                     */

                    *out_len = total;

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

static FLB_INLINE void net_io_backup_event(struct flb_connection *connection,
                                           struct mk_event *backup)
{
    if (connection != NULL && backup != NULL) {
        memcpy(backup, &connection->event, sizeof(struct mk_event));
    }
}

static FLB_INLINE void net_io_restore_event(struct flb_connection *connection,
                                            struct mk_event *backup)
{
    int result;

    if (connection != NULL && backup != NULL) {
        if (MK_EVENT_IS_REGISTERED((&connection->event))) {
            result = mk_event_del(connection->evl, &connection->event);

            assert(result == 0);
        }

        if (MK_EVENT_IS_REGISTERED(backup)) {
            connection->event.priority = backup->priority;
            connection->event.handler = backup->handler;

            result = mk_event_add(connection->evl,
                                  connection->fd,
                                  backup->type,
                                  backup->mask,
                                  &connection->event);

            assert(result == 0);
        }
    }
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
                                         struct flb_connection *connection,
                                         const void *data, size_t len, size_t *out_len)
{
    int ret = 0;
    int error;
    uint32_t mask;
    ssize_t bytes;
    size_t total = 0;
    size_t to_send;
    char so_error_buf[256];
    struct mk_event event_backup;
    int event_restore_needed;

    event_restore_needed = FLB_FALSE;

    net_io_backup_event(connection, &event_backup);

retry:
    error = 0;

    if (len - total > 524288) {
        to_send = 524288;
    }
    else {
        to_send = (len - total);
    }

    bytes = send(connection->fd, (char *) data + total, to_send, 0);

#ifdef FLB_HAVE_TRACE
    if (bytes > 0) {
        flb_trace("[io coro=%p] [fd %i] write_async(2)=%zd (%lu/%lu)",
                  co, connection->fd, bytes, total + bytes, len);
    }
    else {
        flb_trace("[io coro=%p] [fd %i] write_async(2)=%zd (%lu/%lu)",
                  co, connection->fd, bytes, total, len);
    }
#endif

    if (bytes == -1) {
        if (FLB_WOULDBLOCK()) {
            event_restore_needed = FLB_TRUE;

            ret = mk_event_add(connection->evl,
                               connection->fd,
                               FLB_ENGINE_EV_THREAD,
                               MK_EVENT_WRITE,
                               &connection->event);

            connection->event.priority = FLB_ENGINE_PRIORITY_SEND_RECV;

            if (ret == -1) {
                /*
                 * If we failed here there no much that we can do, just
                 * let the caller we failed
                 */
                *out_len = total;

                net_io_restore_event(connection, &event_backup);

                return -1;
            }

            connection->coroutine = co;

            /*
             * Return the control to the parent caller, we need to wait for
             * the event loop to get back to us.
             */
            flb_coro_yield(co, FLB_FALSE);

            /* We want this field to hold NULL at all times unless we are explicitly
             * waiting to be resumed.
             */
            connection->coroutine = NULL;

            /* Save events mask since mk_event_del() will reset it */
            mask = connection->event.mask;

            /* We got a notification, remove the event registered */
            ret = mk_event_del(connection->evl, &connection->event);

            if (ret == -1) {
                *out_len = total;

                net_io_restore_event(connection, &event_backup);

                return -1;
            }

            /* Check the connection status */
            if (mask & MK_EVENT_WRITE) {
                error = flb_socket_error(connection->fd);

                if (error != 0) {
                    /* Connection is broken, not much to do here */
                    strerror_r(error, so_error_buf, sizeof(so_error_buf) - 1);

                    flb_error("[io fd=%i] error sending data to: %s (%s)",
                              connection->fd,
                              flb_connection_get_remote_address(connection),
                              so_error_buf);

                    *out_len = total;

                    net_io_restore_event(connection, &event_backup);

                    return -1;
                }

                MK_EVENT_NEW(&connection->event);

                goto retry;
            }
            else {
                *out_len = total;

                net_io_restore_event(connection, &event_backup);

                return -1;
            }

        }
        else {
            *out_len = total;

            net_io_restore_event(connection, &event_backup);
            net_io_propagate_critical_error(connection);

            return -1;
        }
    }

    /* Update counters */
    total += bytes;
    if (total < len) {
        if ((connection->event.mask & MK_EVENT_WRITE) == 0) {
            ret = mk_event_add(connection->evl,
                               connection->fd,
                               FLB_ENGINE_EV_THREAD,
                               MK_EVENT_WRITE,
                               &connection->event);

            connection->event.priority = FLB_ENGINE_PRIORITY_SEND_RECV;

            if (ret == -1) {
                /*
                 * If we failed here there no much that we can do, just
                 * let the caller we failed
                 */
                *out_len = total;

                net_io_restore_event(connection, &event_backup);

                return -1;
            }
        }

        connection->coroutine = co;

        flb_coro_yield(co, MK_FALSE);

        /* We want this field to hold NULL at all times unless we are explicitly
         * waiting to be resumed.
         */
        connection->coroutine = NULL;

        goto retry;
    }

    if (event_restore_needed) {
        /* If we enter here it means we registered this connection
         * in the event loop, in which case we need to unregister it
         * and restore the original registration if there was one.
         *
         * We do it conditionally because in those cases in which
         * send succeeds on the first try we don't touch the event
         * and it wouldn't make sense to unregister and register for
         * the same event.
         */

        net_io_restore_event(connection, &event_backup);
    }

    *out_len = total;

    return bytes;
}

static ssize_t fd_io_read(int fd, struct sockaddr_storage *address,
                          void *buf, size_t len);
static ssize_t net_io_read(struct flb_connection *connection,
                           void *buf, size_t len)
{
    struct sockaddr_storage *address;
    int                      ret;

    address = NULL;

    if (connection->type == FLB_DOWNSTREAM_CONNECTION) {
        if (connection->stream->transport == FLB_TRANSPORT_UDP ||
            connection->stream->transport == FLB_TRANSPORT_UNIX_DGRAM) {
            address = &connection->raw_remote_host;
        }
    }

    ret = fd_io_read(connection->fd, address, buf, len);

    if (ret == -1) {
        ret = FLB_WOULDBLOCK();
        if (ret) {
            /* timeout caused error */
            flb_warn("[net] sync io_read #%i timeout after %i seconds from: %s",
                     connection->fd,
                     connection->net->io_timeout,
                     flb_connection_get_remote_address(connection));
        }
        else {
            net_io_propagate_critical_error(connection);
        }

        return -1;
    }

    return ret;
}

static ssize_t fd_io_read(int fd, struct sockaddr_storage *address,
                          void *buf, size_t len)
{
    socklen_t address_size;
    int       ret;

    if (address != NULL) {
        address_size = sizeof(struct sockaddr_storage);
        ret = recvfrom(fd, buf, len, 0,
                       (struct sockaddr *) address,
                       &address_size);
    }
    else {
        ret = recv(fd, buf, len, 0);
    }

    if (ret == -1) {
        return -1;
    }

    return ret;
}

static FLB_INLINE ssize_t net_io_read_async(struct flb_coro *co,
                                            struct flb_connection *connection,
                                            void *buf, size_t len)
{
    struct mk_event event_backup;
    int event_restore_needed;
    int ret;

    event_restore_needed = FLB_FALSE;

    net_io_backup_event(connection, &event_backup);

 retry_read:
    ret = recv(connection->fd, buf, len, 0);

    if (ret == -1) {
        if (FLB_WOULDBLOCK()) {
            event_restore_needed = FLB_TRUE;

            ret = mk_event_add(connection->evl,
                               connection->fd,
                               FLB_ENGINE_EV_THREAD,
                               MK_EVENT_READ,
                               &connection->event);

            connection->event.priority = FLB_ENGINE_PRIORITY_SEND_RECV;

            if (ret == -1) {
                /*
                 * If we failed here there no much that we can do, just
                 * let the caller we failed
                 */
                net_io_restore_event(connection, &event_backup);

                return -1;
            }

            connection->coroutine = co;

            flb_coro_yield(co, MK_FALSE);

            /* We want this field to hold NULL at all times unless we are explicitly
             * waiting to be resumed.
             */
            connection->coroutine = NULL;

            goto retry_read;
        }
        else {
            net_io_propagate_critical_error(connection);
        }

        ret = -1;
    }
    else if (ret <= 0) {
        ret = -1;
    }

    if (event_restore_needed) {
        /* If we enter here it means we registered this connection
         * in the event loop, in which case we need to unregister it
         * and restore the original registration if there was one.
         *
         * We do it conditionally because in those cases in which
         * send succeeds on the first try we don't touch the event
         * and it wouldn't make sense to unregister and register for
         * the same event.
         */

        net_io_restore_event(connection, &event_backup);
    }

    return ret;
}


int flb_io_net_writev(struct flb_connection *connection,
                      const struct flb_iovec *iov,
                      int iovcnt,
                      size_t *out_len)
{
    int    result;
    int    index;
    size_t total;
    size_t total_length;
    char  *temporary_buffer;

    if (iov == NULL || iovcnt <= 0 || out_len == NULL) {
        errno = EINVAL;

        return -1;
    }

    if (iovcnt > flb_io_get_iov_max()) {
        errno = EINVAL;

        return -1;
    }

    total_length = 0;

    for (index = 0 ; index < iovcnt ; index++) {
        /* Overflow guard */
        if (iov[index].iov_len > SIZE_MAX - total_length) {
            errno = EOVERFLOW;
            return -1;
        }

        if (iov[index].iov_len > 0 && iov[index].iov_base == NULL) {
            errno = EINVAL;
            return -1;
        }

        total_length += iov[index].iov_len;
    }

    if (total_length == 0) {
        *out_len = 0;

        return 0;
    }

    temporary_buffer = flb_malloc(total_length);

    if (temporary_buffer == NULL) {
        flb_errno();

        return -1;
    }

    total = 0;

    for (index = 0 ; index < iovcnt ; index++) {
        if (iov[index].iov_len > 0) {
            memcpy(&temporary_buffer[total], iov[index].iov_base, iov[index].iov_len);
        }
        total += iov[index].iov_len;
    }

    result = flb_io_net_write(connection, temporary_buffer, total_length, out_len);

    flb_free(temporary_buffer);

    return result;
}

/* Write data to fd. For unix socket. */
int flb_io_fd_write(int fd, const void *data, size_t len, size_t *out_len)
{
    /* TODO: support async mode */
    return fd_io_write(fd, NULL, data, len, out_len);
}

/* Write data to an upstream connection/server */
int flb_io_net_write(struct flb_connection *connection, const void *data,
                     size_t len, size_t *out_len)
{
    int              flags;
    struct flb_coro *coro;
    int              ret;

    ret  = -1;
    coro = flb_coro_get();
    flags = flb_connection_get_flags(connection);

    flb_trace("[io coro=%p] [net_write] trying %zd bytes", coro, len);

    if (connection->tls_session == NULL) {
        if (flags & FLB_IO_ASYNC) {
            ret = net_io_write_async(coro, connection, data, len, out_len);
        }
        else {
            ret = net_io_write(connection, data, len, out_len);
        }
    }
#ifdef FLB_HAVE_TLS
    else if (flags & FLB_IO_TLS) {
        if (flags & FLB_IO_ASYNC) {
            ret = flb_tls_net_write_async(coro, connection->tls_session, data, len, out_len);
        }
        else {
            ret = flb_tls_net_write(connection->tls_session, data, len, out_len);
        }
    }
#endif

    if (ret > 0) {
        flb_connection_reset_io_timeout(connection);
    }

    flb_trace("[io coro=%p] [net_write] ret=%i total=%lu/%lu",
              coro, ret, *out_len, len);

    return ret;
}

ssize_t flb_io_fd_read(int fd, void *buf, size_t len)
{
    /* TODO: support async mode */
    return fd_io_read(fd, NULL, buf, len);
}

ssize_t flb_io_net_read(struct flb_connection *connection, void *buf, size_t len)
{
    int ret;
    int flags;
    struct flb_coro *coro;

    ret = -1;
    coro = flb_coro_get();

    flb_trace("[io coro=%p] [net_read] try up to %zd bytes", coro, len);

    flags = flb_connection_get_flags(connection);

    if (!connection->tls_session) {
        if (flags & FLB_IO_ASYNC) {
            ret = net_io_read_async(coro, connection, buf, len);
        }
        else {
            ret = net_io_read(connection, buf, len);
        }
    }
#ifdef FLB_HAVE_TLS
    else if (flags & FLB_IO_TLS) {
        if (flags & FLB_IO_ASYNC) {
            ret = flb_tls_net_read_async(coro, connection->tls_session, buf, len);
        }
        else {
            ret = flb_tls_net_read(connection->tls_session, buf, len);
        }
    }
#endif

    if (ret > 0) {
        flb_connection_reset_io_timeout(connection);
    }

    flb_trace("[io coro=%p] [net_read] ret=%i", coro, ret);

    return ret;
}
