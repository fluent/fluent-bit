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

#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>

#ifdef MK_HAVE_EVENTFD
#include <sys/eventfd.h>
#endif

#ifdef MK_HAVE_TIMERFD_CREATE
#include <sys/timerfd.h>
#endif

#include <time.h>

#include <mk_core/mk_event.h>
#include <mk_core/mk_memory.h>
#include <mk_core/mk_utils.h>

/* For old systems */
#ifndef EPOLLRDHUP
#define EPOLLRDHUP  0x2000
#endif

static inline int _mk_event_init()
{
    return 0;
}

static inline void *_mk_event_loop_create(int size)
{
    int efd;
    struct mk_event_ctx *ctx;

    /* Main event context */
    ctx = mk_mem_alloc_z(sizeof(struct mk_event_ctx));
    if (!ctx) {
        return NULL;
    }

    /* Create the epoll instance */
 #ifdef EPOLL_CLOEXEC
    efd = epoll_create1(EPOLL_CLOEXEC);
 #else
    efd = epoll_create(1);
    if (efd > 0) {
        if (fcntl(efd, F_SETFD, FD_CLOEXEC) == -1) {
            perror("fcntl");
        }
    }
 #endif

    if (efd == -1) {
        mk_libc_error("epoll_create");
        mk_mem_free(ctx);
        return NULL;
    }
    ctx->efd = efd;

    /* Allocate space for events queue */
    ctx->events = mk_mem_alloc_z(sizeof(struct epoll_event) * size);
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
        event->status = MK_EVENT_REGISTERED;
        event->type = type;

    }
    else {
        op = EPOLL_CTL_MOD;
        if (type != MK_EVENT_UNMODIFIED) {
            event->type = type;
        }
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
static inline int _mk_event_del(struct mk_event_ctx *ctx, struct mk_event *event)
{
    int ret;

    ret = epoll_ctl(ctx->efd, EPOLL_CTL_DEL, event->fd, NULL);
    MK_TRACE("[FD %i] Epoll, remove from QUEUE_FD=%i, ret=%i",
             event->fd, ctx->efd, ret);
    if (ret < 0) {
#ifdef TRACE
        mk_libc_warn("epoll_ctl");
#endif
    }

    return ret;
}

#ifdef MK_HAVE_TIMERFD_CREATE
/* Register a timeout file descriptor */
static inline int _mk_event_timeout_create(struct mk_event_ctx *ctx,
                                           time_t sec, long nsec, void *data)
{
    int ret;
    int timer_fd;
    struct itimerspec its;
    struct mk_event *event;

    mk_bug(!data);
    memset(&its, '\0', sizeof(struct itimerspec));

    /* expiration interval */
    its.it_interval.tv_sec  = sec;
    its.it_interval.tv_nsec = nsec;

    /* initial expiration */
    its.it_value.tv_sec  = time(NULL) + sec;
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
#else /* MK_HAVE_TIMERFD_CREATE */

struct fd_timer {
    int fd;
    time_t sec;
    long   nsec;
};

/*
 * Timeout worker, it writes a byte every certain amount of seconds, it finish
 * once the other end of the pipe closes the fd[0].
 */
void _timeout_worker(void *arg)
{
    int ret;
    uint64_t val = 1;
    struct fd_timer *timer;
    struct timespec t_spec;

    timer = (struct fd_timer *) arg;
    t_spec.tv_sec  = timer->sec;
    t_spec.tv_nsec = timer->nsec;

    while (1) {
        /* sleep for a while */
        nanosleep(&t_spec, NULL);

        /* send notification */
        ret = write(timer->fd, &val, sizeof(uint64_t));
        if (ret == -1) {
            perror("write");
            break;
        }
    }

    close(timer->fd);
    free(timer);
}

/*
 * This routine creates a timer, since timerfd_create(2) is not available (as
 * Monkey could be be compiled in a very old Linux system), we implement a similar
 * function through a thread and a pipe(2).
 */
static inline int _mk_event_timeout_create(struct mk_event_ctx *ctx,
                                           time_t sec, long nsec, void *data)
{
    int ret;
    int fd[2];
    struct mk_event *event;
    struct fd_timer *timer;
    pthread_t tid;

    timer = mk_mem_alloc(sizeof(struct fd_timer));
    if (!timer) {
        return -1;
    }

    ret = pipe(fd);
    if (ret < 0) {
        mk_mem_free(timer);
        mk_libc_error("pipe");
        return ret;
    }

    event = (struct mk_event *) data;
    event->fd = fd[0];
    event->type = MK_EVENT_NOTIFICATION;
    event->mask = MK_EVENT_EMPTY;

    _mk_event_add(ctx, fd[0], MK_EVENT_NOTIFICATION, MK_EVENT_READ, data);
    event->mask = MK_EVENT_READ;

    /* Compose the timer context, this is released inside the worker thread */
    timer->fd   = fd[1];
    timer->sec  = sec;
    timer->nsec = nsec;

    /* Now the dirty workaround, create a thread */
    ret = mk_utils_worker_spawn(_timeout_worker, timer, &tid);
    if (ret < 0) {
        close(fd[0]);
        close(fd[1]);
        mk_mem_free(timer);
        return -1;
    }

    return fd[0];
}
#endif /* MK_HAVE_TIMERFD_CREATE */

static inline int _mk_event_timeout_destroy(struct mk_event_ctx *ctx, void *data)
{
    (void) ctx;
    (void) data;

    return 0;
}

static inline int _mk_event_channel_create(struct mk_event_ctx *ctx,
                                           int *r_fd, int *w_fd, void *data)
{
    int ret;
    int fd[2];
    struct mk_event *event;

    ret = pipe(fd);
    if (ret < 0) {
        mk_libc_error("pipe");
        return ret;
    }

    event = data;
    event->fd = fd[0];
    event->type = MK_EVENT_NOTIFICATION;
    event->mask = MK_EVENT_EMPTY;

    ret = _mk_event_add(ctx, fd[0],
                        MK_EVENT_NOTIFICATION, MK_EVENT_READ, event);
    if (ret != 0) {
        close(fd[0]);
        close(fd[1]);
        return ret;
    }

    *r_fd = fd[0];
    *w_fd = fd[1];

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
