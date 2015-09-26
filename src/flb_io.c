/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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
 * Output plugins that flag their selfs with FLB_OUTPUT_TCP or FLB_OUTPUT_TLS
 * can take advante of this interface.
 *
 * The workflow to use this is the following:
 *
 * - A connection and data flow requires an flb_io_upstream context.
 * - We write data through the flb_io_write() interface.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_io_tls.h>
#include <fluent-bit/flb_tls.h>

#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_thread.h>

/* Creates a new upstream context */
struct flb_io_upstream *flb_io_upstream_new(struct flb_config *config,
                                            char *host, int port, int flags)
{
    int fd;
    struct flb_io_upstream *u;

    u = malloc(sizeof(struct flb_io_upstream));
    if (!u) {
        perror("malloc");
        return NULL;
    }

    /* Upon upstream creation, we always try to perform a connection */
    flb_debug("[upstream] connecting to %s:%i", host, port);
    fd = flb_net_tcp_connect(host, port);
    if (fd == -1) {
        flb_warn("[upstream] could not connect to %s:%i", host, port);
    }
    else {
        /* Make it non-blocking */
        flb_net_socket_nonblocking(fd);
        flb_debug("[upstream] connected!");
    }

    u->fd       = -1;//fd;
    u->tcp_host = strdup(host);
    u->tcp_port = port;
    u->flags    = flags;
    u->evl      = config->evl;

    return u;
}

/* This routine is called from a co-routine thread */
FLB_INLINE int io_write(struct flb_thread *th, struct flb_output_plugin *out,
                        void *data, size_t len, size_t *out_len)
{
    int ret;
    ssize_t bytes;
    size_t total = 0;
    struct flb_io_upstream *u;

    u = out->upstream;

 retry:
    bytes = write(u->fd, data + total, len - total);
    flb_debug("[io] write(2)=%d", bytes);

    if (bytes == -1) {
        if (errno == EAGAIN) {
            return 0;
        }
        else {
            /* The connection routine may yield */
            flb_debug("[io] trying to reconnect");
            ret = flb_io_connect(out, th, u);
            if (ret == -1) {
                return -1;
            }

            /*
             * Reach here means the connection was successful, let's retry
             * to write(2).
             *
             * note: the flb_io_connect() uses asyncronous sockets, register
             * the file descriptor with the main event loop and yields until
             * the main event loop returns the control back (resume), doing a
             * 'retry' it's pretty safe.
             */
            goto retry;
        }
    }

    /* Update statistics */
    flb_stats_update(bytes, 0, &out->stats);

    /* Update counters */
    total += bytes;
    if (total < len) {
        if (u->event.status == MK_EVENT_NONE) {
            u->event.mask = MK_EVENT_EMPTY;
            u->thread = th;
            ret = mk_event_add(u->evl,
                               u->fd,
                               FLB_ENGINE_EV_THREAD,
                               MK_EVENT_WRITE, &u->event);
            if (ret == -1) {
                /*
                 * If we failed here there no much that we can do, just
                 * let the caller we failed
                 */
                close(u->fd);
                return -1;
            }
        }
        flb_thread_yield(th, MK_FALSE);
        goto retry;
    }

    if (u->event.status == MK_EVENT_REGISTERED) {
        /* We got a notification, remove the event registered */
        ret = mk_event_del(u->evl, &u->event);
        assert(ret == 0);
    }

    *out_len = total;
    return bytes;
}

FLB_INLINE ssize_t io_read(struct flb_thread *th, struct flb_output_plugin *out,
                           void *buf, size_t len)
{
    struct flb_io_upstream *u;

    u = out->upstream;
    return read(u->fd, buf, len);
}

/* Write data to an upstream connection/server */
int flb_io_write(struct flb_output_plugin *out, void *data,
                 size_t len, size_t *out_len)
{
    int ret = -1;
    struct flb_thread *th;

    flb_debug("[io] trying to write %zd bytes", len);

    th = pthread_getspecific(flb_thread_key);

    if (out->flags & FLB_OUTPUT_TCP) {
        ret = io_write(th, out, data, len, out_len);
    }
#ifdef HAVE_TLS
    else if (out->flags & FLB_OUTPUT_TLS) {
        ret = io_tls_write(th, out, data, len, out_len);
    }
#endif

    flb_debug("[io] thread has finished");
    return ret;
}

ssize_t flb_io_read(struct flb_output_plugin *out, void *buf, size_t len)
{
    int ret = -1;
    struct flb_thread *th;

    flb_debug("[io] trying to read up to %zd bytes", len);

    th = pthread_getspecific(flb_thread_key);
    if (out->flags & FLB_OUTPUT_TCP) {
        ret = io_read(th, out, buf, len);
    }
#ifdef HAVE_TLS
    else if (out->flags & FLB_OUTPUT_TLS) {
        ret = io_tls_read(th, out, buf, len);
    }
#endif

    flb_debug("[io] thread has finished");
    return ret;
}


FLB_INLINE int flb_io_connect(struct flb_output_plugin *out,
                              struct flb_thread *th, struct flb_io_upstream *u)
{
    int fd;
    int ret;
    int error = 0;
    socklen_t len = sizeof(error);

    if (u->fd > 0) {
        close(u->fd);
    }

    /* Create the socket */
    fd = flb_net_socket_create(AF_INET, FLB_TRUE);
    if (fd == -1) {
        flb_error("[io] could not create socket");
        return -1;
    }
    u->fd = fd;

    /* Make the socket non-blocking */
    flb_net_socket_nonblocking(u->fd);

    /* Start the connection */
    ret = flb_net_tcp_fd_connect(fd, u->tcp_host, u->tcp_port);
    if (ret == -1) {
        if (errno == EINPROGRESS) {
            flb_debug("[upstream] connection in process");
        }
        else {
        }

        u->event.mask = MK_EVENT_EMPTY;
        u->event.status = MK_EVENT_NONE;
        u->thread = th;

        ret = mk_event_add(u->evl,
                           fd,
                           FLB_ENGINE_EV_THREAD,
                           MK_EVENT_WRITE, &u->event);
        if (ret == -1) {
            /*
             * If we failed here there no much that we can do, just
             * let the caller we failed
             */
            close(fd);
            return -1;
        }

        /*
         * Return the control to the parent caller, we need to wait for
         * the event loop to get back to us.
         */
        flb_thread_yield(th, FLB_FALSE);

        /* We got a notification, remove the event registered */
        ret = mk_event_del(u->evl, &u->event);
        assert(ret == 0);

        /* Check the connection status */
        if (u->event.mask & MK_EVENT_WRITE) {
            ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
            if (error != 0) {
                /* Connection is broken, not much to do here */
                flb_debug("[io] connection failed");
                return -1;
            }
            u->event.mask   = MK_EVENT_EMPTY;
            u->event.status = MK_EVENT_NONE;

        }
        else {
            return -1;
        }
    }

    flb_debug("[io] connection OK");
    return 0;
}
