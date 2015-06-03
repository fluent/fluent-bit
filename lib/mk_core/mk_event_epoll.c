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

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>

#include "mk_event.h"
#include "mk_memory.h"
#include "mk_utils.h"

static inline void *_mk_event_loop_create(int size)
{
    struct mk_event_ctx *ctx;

    /* Main event context */
    ctx = mk_mem_malloc_z(sizeof(struct mk_event_ctx));
    if (!ctx) {
        return NULL;
    }

    /* Create the epoll instance */
    ctx->efd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->efd == -1) {
        mk_libc_error("epoll_create");
        mk_mem_free(ctx);
        return NULL;
    }

    /* Allocate space for events queue */
    ctx->events = mk_mem_malloc_z(sizeof(struct epoll_event) * size);
    if (!ctx->events) {
        close(ctx->efd);
        mk_mem_free(ctx);
        return NULL;
    }
    ctx->queue_size = size;
    return ctx;
}

/* Close handlers and memory */
static inline void _mk_event_loop_destroy(struct mk_event_ctx *ctx)
{
    close(ctx->efd);
    mk_mem_free(ctx->events);
    mk_mem_free(ctx);
}

/*
 * It register certain events for the file descriptor in question, if
 * the file descriptor have not been registered, create a new entry.
 */
static inline int _mk_event_add(struct mk_event_ctx *ctx, int fd,
                                int type, uint32_t events, void *data)
{
    int op;
    int ret;
    struct mk_event *event;
    struct epoll_event ep_event;

    /* Verify the FD status and desired operation */
    event = (struct mk_event *) data;
    if (event->mask == MK_EVENT_EMPTY) {
        op = EPOLL_CTL_ADD;
        event->fd   = fd;
        event->type = type;
    }
    else {
        op = EPOLL_CTL_MOD;
    }

    ep_event.events = EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    ep_event.data.ptr = data;

    if (events & MK_EVENT_READ) {
        ep_event.events |= EPOLLIN;
    }
    if (events & MK_EVENT_WRITE) {
        ep_event.events |= EPOLLOUT;
    }

    ret = epoll_ctl(ctx->efd, op, fd, &ep_event);
    if (ret < 0) {
        mk_libc_error("epoll_ctl");
        return -1;
    }

    event->mask = events;
    return ret;
}

/* Delete an event */
static inline int _mk_event_del(struct mk_event_ctx *ctx, int fd)
{
    int ret;

    ret = epoll_ctl(ctx->efd, EPOLL_CTL_DEL, fd, NULL);
    MK_TRACE("[FD %i] Epoll, remove from QUEUE_FD=%i, ret=%i",
             fd, ctx->efd, ret);
    if (ret < 0) {
        mk_libc_error("epoll_ctl");
    }

    return ret;
}

/* Register a timeout file descriptor */
static inline int _mk_event_timeout_create(struct mk_event_ctx *ctx,
                                           int expire, void *data)
{
    int ret;
    int timer_fd;
    struct itimerspec its;
    struct mk_event *event;

    mk_bug(!data);

    /* expiration interval */
    its.it_interval.tv_sec  = expire;
    its.it_interval.tv_nsec = 0;

    /* initial expiration */
    its.it_value.tv_sec  = time(NULL) + expire;
    its.it_value.tv_nsec = 0;

    timer_fd = timerfd_create(CLOCK_REALTIME, 0);
    if (timer_fd == -1) {
        mk_libc_error("timerfd");
        return -1;
    }

    ret = timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &its, NULL);
    if (ret < 0) {
        mk_libc_error("timerfd_settime");
        return -1;
    }

    event = data;
    event->fd   = timer_fd;
    event->type = MK_EVENT_NOTIFICATION;
    event->mask = MK_EVENT_EMPTY;

    /* register the timer into the epoll queue */
    ret = _mk_event_add(ctx, timer_fd,
                        MK_EVENT_NOTIFICATION, MK_EVENT_READ, data);
    if (ret != 0) {
        close(timer_fd);
        return ret;
    }

    return timer_fd;
}

static inline int _mk_event_channel_create(struct mk_event_ctx *ctx,
                                           int *r_fd, int *w_fd,
                                           void *data)
{
    int fd;
    int ret;
    struct mk_event *event;

    fd = eventfd(0, EFD_CLOEXEC);
    if (fd == -1) {
        mk_libc_error("eventfd");
        return -1;
    }

    event = data;
    event->fd   = fd;
    event->type = MK_EVENT_NOTIFICATION;
    event->mask = MK_EVENT_EMPTY;

    ret = _mk_event_add(ctx, fd,
                        MK_EVENT_NOTIFICATION, MK_EVENT_READ, data);
    if (ret != 0) {
        close(fd);
        return ret;
    }

    *w_fd = *r_fd = fd;
    return 0;
}

static inline int _mk_event_wait(struct mk_event_loop *loop)
{
    struct mk_event_ctx *ctx = loop->data;

    loop->n_events = epoll_wait(ctx->efd, ctx->events, ctx->queue_size, -1);
    return loop->n_events;
}

static inline char *_mk_event_backend()
{
    return "epoll";
}
