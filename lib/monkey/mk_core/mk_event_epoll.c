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
    memset(&ep_event, 0, sizeof(ep_event));

    mk_bug(ctx == NULL);
    mk_bug(data == NULL);

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
    event->priority = MK_EVENT_PRIORITY_DEFAULT;

    /* Remove from priority queue */
    if (!mk_list_entry_is_orphan(&event->_priority_head)) {
        mk_list_del(&event->_priority_head);
    }

    return ret;
}

/* Delete an event */
static inline int _mk_event_del(struct mk_event_ctx *ctx, struct mk_event *event)
{
    int ret;

    mk_bug(ctx == NULL);
    mk_bug(event == NULL);

    if (!MK_EVENT_IS_REGISTERED(event)) {
        return 0;
    }

    ret = epoll_ctl(ctx->efd, EPOLL_CTL_DEL, event->fd, NULL);

    MK_TRACE("[FD %i] Epoll, remove from QUEUE_FD=%i, ret=%i",
             event->fd, ctx->efd, ret);

    if (ret < 0) {
#ifdef MK_HAVE_TRACE
        mk_libc_warn("epoll_ctl");
#endif
    }

    /* Remove from priority queue */
    if (!mk_list_entry_is_orphan(&event->_priority_head)) {
        mk_list_del(&event->_priority_head);
    }

    MK_EVENT_NEW(event);

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
    struct timespec now;
    struct mk_event *event;

    mk_bug(data == NULL);

    memset(&its, '\0', sizeof(struct itimerspec));

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        mk_libc_error("clock_gettime");
        return -1;
	}

    /* expiration interval */
    its.it_interval.tv_sec  = sec;
    its.it_interval.tv_nsec = nsec;

    /*
     * initial expiration: note that we don't use nanoseconds in the timer,
     * feel free to send a Pull Request if you need it.
     */
    its.it_value.tv_sec  = now.tv_sec + sec;
    its.it_value.tv_nsec = 0;

    timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (timer_fd == -1) {
        mk_libc_error("timerfd");
        return -1;
    }

    ret = timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &its, NULL);
    if (ret < 0) {
        mk_libc_error("timerfd_settime");
        close(timer_fd);
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

    mk_bug(data == NULL);

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
    struct mk_event *event;

    if (data == NULL) {
        return 0;
    }

    event = (struct mk_event *) data;
    _mk_event_del(ctx, event);
    close(event->fd);
    return 0;
}

static inline int _mk_event_channel_create(struct mk_event_ctx *ctx,
                                           int *r_fd, int *w_fd, void *data)
{
    int ret;
    int fd[2];
    struct mk_event *event;

    mk_bug(data == NULL);

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

static inline int _mk_event_channel_destroy(struct mk_event_ctx *ctx,
                                            int r_fd, int w_fd, void *data)
{
    struct mk_event *event;
    int ret;


    event = (struct mk_event *)data;
    if (event->fd != r_fd) {
        return -1;
    }

    ret = _mk_event_del(ctx, event);

    close(r_fd);
    close(w_fd);

    return ret;
}

static inline int _mk_event_inject(struct mk_event_loop *loop,
                                   struct mk_event *event,
                                   int mask,
                                   int prevent_duplication)
{
    int                  index;
    struct mk_event_ctx *ctx;

    ctx = loop->data;

    if (prevent_duplication) {
        for (index = 0 ; index < loop->n_events ; index++) {
            if (ctx->events[index].data.ptr == event) {
                return 0;
            }
        }
    }

    event->mask = mask;

    ctx->events[loop->n_events].data.ptr = event;

    loop->n_events++;

    return 0;
}

static inline int _mk_event_wait_2(struct mk_event_loop *loop, int timeout)
{
    struct mk_event_ctx *ctx = loop->data;
    int ret = 0;

    while(1) {
        ret = epoll_wait(ctx->efd, ctx->events, ctx->queue_size, timeout);
        if (ret >= 0) {
            break;
        }
        else if(ret < 0 && errno != EINTR) {
            mk_libc_error("epoll_wait");
            break;
        }
        /* retry when errno is EINTR */
    }
    loop->n_events = ret;
    return ret;
}

static inline char *_mk_event_backend()
{
    return "epoll";
}
