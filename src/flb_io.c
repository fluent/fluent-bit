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

#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>

#include <ucontext.h>

struct flb_thread {
    ucontext_t parent;
    ucontext_t context;
    int (*function) (struct flb_output_plugin *, void *data, size_t, size_t *);
    void *data;
};

#define FLB_THREAD_STACK_SIZE  ((3 * PTHREAD_STACK_MIN) / 2)
#define FLB_THREAD_STACK(t)    (t + sizeof(struct flb_thread))

int flb_io_thread_run(struct flb_thread *th)
{
    ucontext_t main;

    swapcontext(&th->parent, &th->context);
    printf("after swap\n");
}

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
static int io_write(struct flb_output_plugin *out, void *data,
                    size_t len, size_t *out_len)
{
    int ret;
    ssize_t bytes;
    struct flb_io_upstream *u;

    u = out->upstream;

    bytes = write(u->fd, data, len);
    if (bytes == -1) {
        if (errno == EAGAIN) {
            return 0;
        }
        else {
            flb_debug("[io] try to reconnect");
            ret = flb_io_connect(u);
            if (ret == -1) {
                return -1;
            }

            /* A connection is in progress, we must yield here and try to
             * write again when the socket is available for that.
             *
             * Note: the connect() routine registered a notification request
             * the event loop.
             */
            printf("we should YIELD!\n");
        }
    }

    *out_len = bytes;
    return bytes;
}

static struct flb_thread *flb_io_thread_write(struct flb_output_plugin *out,
                                              char *buf, int size,
                                              struct flb_config *config)
{
    int ret;
    void *p;
    struct flb_thread *th;

    /* Create a thread context and initialize */
    p = malloc(sizeof(struct flb_thread) + FLB_THREAD_STACK_SIZE);
    if (!p) {
        perror("malloc");
        return NULL;
    }

    th = p;
    ret = getcontext(&th->context);
    if (ret == -1) {
        perror("getcontext");
        free(th);
        return NULL;
    }

    th->context.uc_stack.ss_sp    = FLB_THREAD_STACK(p);
    th->context.uc_stack.ss_size  = FLB_THREAD_STACK_SIZE;
    th->context.uc_stack.ss_flags = 0;
    th->context.uc_link           = NULL;
    th->function                  = io_write;

    makecontext(&th->context, (void (*)()) th->function, 4,
                buf, size, out->out_context, config);
    return th;
}

/* Write data to an upstream connection/server */
int flb_io_write(struct flb_output_plugin *out, void *data,
                 size_t len, size_t *out_len)
{
    int ret;
    ssize_t bytes;
    struct flb_thread *th;

    flb_debug("[io] trying...");

    th = flb_io_thread_write(out, data, len, out->out_context);
    memcpy(&th->parent, &out->th_context, sizeof(ucontext_t));

    /* Switch to the co-routine */
    flb_io_thread_run(th);
    printf("post coro\n");

}

int flb_io_connect(struct flb_io_upstream *u)
{
    int id;
    int fd;
    int ret;

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
            flb_debug("[upstream] connection in progress");
        }
        else {
        }

        u->event.mask = MK_EVENT_EMPTY;
        u->event.status = MK_EVENT_NONE;
        printf("REG FD=%i\n", fd);
        ret = mk_event_add(u->evl,
                           fd,
                           FLB_ENGINE_EV_UPSTREAM,
                           MK_EVENT_WRITE, &u->event);
        if (ret == -1) {
            /*
             * If we failed here there no much that we can do, just
             * let the caller we failed
             */
            close(fd);
            return -1;
        }
        printf("event registered\n");
        /*
         * We are OK, we are going to yield here and wait for the
         * event loop to notify when we can continue.
         */
        //printf("going to yield\n");
        //id = mk_thread_create(NULL, NULL);
        //printf("status = %i\n", mk_thread_status(id));
        //mk_thread_yield();
        //printf("thread id=%i\n", id);
    }
    else {
    }

    printf("returning 0\n");
    return 0;
}
