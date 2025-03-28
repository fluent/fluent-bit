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

#include <poll.h>
#include <mk_core/mk_event.h>
#include <time.h>

struct fd_timer {
    int    fd;
    time_t sec;
    long   nsec;
};

static inline int _mk_event_init()
{
    return 0;
}

static inline void *_mk_event_loop_create(int size)
{
    struct mk_event_ctx *ctx;

    /* Main event context */
    ctx = mk_mem_alloc_z(sizeof(struct mk_event_ctx));
    if (!ctx) {
        return NULL;
    }

    /* Allocate space for events queue */
    ctx->events = mk_mem_alloc_z(sizeof(struct mk_event *) * size);
    if (!ctx->events) {
        mk_mem_free(ctx);
        return NULL;
    }

    /* Fired events (upon poll(2) return) */
    ctx->fired = mk_mem_alloc_z(sizeof(struct mk_event) * size);
    if (!ctx->fired) {
        mk_mem_free(ctx->events);
        mk_mem_free(ctx);
        return NULL;
    }

    ctx->pfds = mk_mem_alloc_z(sizeof(struct pollfd) * size);
    if (!ctx->pfds) {
        mk_mem_free(ctx->events);
        mk_mem_free(ctx->fired);
        mk_mem_free(ctx);
        return NULL;
    }

    ctx->queue_size = size;

    return ctx;
}

/* Close handlers and memory */
static inline void _mk_event_loop_destroy(struct mk_event_ctx *ctx)
{
    mk_mem_free(ctx->fired);
    mk_mem_free(ctx->events);
    mk_mem_free(ctx->pfds);
    mk_mem_free(ctx);
}

/* Add the file descriptor to the arrays */
static inline int _mk_event_add(struct mk_event_ctx *ctx, int fd,
                                int type, uint32_t events, void *data)
{
    int i;
    int found = MK_FALSE;
    struct mk_event *event;

    mk_bug(ctx == NULL);
    mk_bug(data == NULL);

    /* check if the event file descriptor is already being monitored */
    for (i = 0; i < ctx->queue_size; i++) {
        if (ctx->events[i] == NULL) {
            continue;
        }

        if (ctx->events[i]->fd == fd) {
            found = MK_TRUE;
            break;
        }
    }

    if (found == MK_FALSE) {
        /* Find an empty slot */
        for (i = 0; i < ctx->queue_size; i++) {
            if (ctx->events[i] == NULL) {
                break;
            }
        }

        if (i == ctx->queue_size) {
            return -1;
        }
    }

    event = (struct mk_event *) data;
    ctx->events[i] = event;
    if (event->mask == MK_EVENT_EMPTY) {
        event->fd = fd;
        event->type = type;
        event->status = MK_EVENT_REGISTERED;
    }
    else {
        if (type != MK_EVENT_REGISTERED) {
            event->type = type;
        }
    }

    event->mask = events;
    event->priority = MK_EVENT_PRIORITY_DEFAULT;

    /* Remove from priority queue */
    if (!mk_list_entry_is_orphan(&event->_priority_head)) {
        mk_list_del(&event->_priority_head);
    }

    if (type != MK_EVENT_UNMODIFIED) {
        event->type = type;
    }

    return 0;
}

/* Delete an event */
static inline int _mk_event_del(struct mk_event_ctx *ctx, struct mk_event *event)
{
    int i;

    mk_bug(ctx == NULL);
    mk_bug(event == NULL);

    if (!MK_EVENT_IS_REGISTERED(event)) {
        return 0;
    }

    for (i = 0; i < ctx->queue_size; i++) {
        if (ctx->events[i] == event) {
            ctx->events[i] = NULL;
            break;
        }
    }

    /* check that event was found */
    if (i == ctx->queue_size) {
        return -1;
    }

    /* Remove from priority queue */
    if (!mk_list_entry_is_orphan(&event->_priority_head)) {
        mk_list_del(&event->_priority_head);
    }

    MK_EVENT_NEW(event);
    return 0;
}

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
            if (errno == EPIPE) {
                break;
            }
            else {
                mk_libc_error("write");
                break;
            }
            break;
        }
    }

    close(timer->fd);
    mk_mem_free(timer);

    pthread_exit(0);
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
        mk_libc_error("pipe");
        mk_mem_free(timer);
        return ret;
    }

    event = (struct mk_event *) data;
    event->fd = fd[0];
    event->type = MK_EVENT_NOTIFICATION;
    event->mask = MK_EVENT_EMPTY;
    mk_list_entry_init(&event->_priority_head);

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


static inline int _mk_event_timeout_destroy(struct mk_event_ctx *ctx, void *data)
{
    struct mk_event *event;

    if (data == NULL) {
        return 0;
    }

    event = (struct mk_event *) data;
    _mk_event_del(ctx, event);

    /* trigger an EPIPE */
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

    event = (struct mk_event *) data;
    if (event->fd != r_fd) {
        return -1;
    }

    ret = _mk_event_del(ctx, event);
    if (ret != 0) {
        return ret;
    }

    close(r_fd);
    close(w_fd);

    return 0;
}

static inline int _mk_event_inject(struct mk_event_loop *loop,
                                   struct mk_event *event,
                                   int mask,
                                   int prevent_duplication)
{
    int i;
    struct mk_event_ctx *ctx;

    ctx = loop->data;

    if (prevent_duplication) {
        for (i = 0; i < loop->n_events; i++) {
            if (ctx->fired[i].data == event) {
                return 0;
            }
        }
    }

    event->mask = mask;

    /* fired events are stored in order, so the last entry must be available */
    if (loop->n_events < ctx->queue_size) {
        ctx->fired[loop->n_events].data = event;
        loop->n_events++;
    }

    return 0;
}

static inline int _mk_event_wait_2(struct mk_event_loop *loop, int timeout)
{
    int i;
    int j;
    int n = 0;
    int ret;
    struct pollfd *pfds;
    struct mk_event_ctx *ctx = loop->data;

    pfds = ctx->pfds;

    /* Copy registered events into pollfd array */
    for (i = 0; i < ctx->queue_size; i++) {
        if (ctx->events[i] == NULL) {
            continue;
        }

        pfds[n].fd = ctx->events[i]->fd;
        pfds[n].events = 0;

        if (ctx->events[i]->mask & MK_EVENT_READ) {
            pfds[n].events |= POLLIN;
        }
        if (ctx->events[i]->mask & MK_EVENT_WRITE) {
            pfds[n].events |= POLLOUT;
        }
        n++;
    }

    /* wait for events */
    ret = poll(pfds, n, timeout);
    if (ret <= 0) {
        loop->n_events = 0;
        return ret;  // Timeout or error
    }

    loop->n_events = 0;

    /* for each event found, map the fired list data with the proper event */
    for (i = 0; i < n; i++) {
        if (pfds[i].revents == 0) {
            continue;
        }

        /* lookup the corresponding event */
        for (j = 0; j < ctx->queue_size; j++) {
            if (ctx->events[j] == NULL) {
                continue;
            }

            /* match, reference the .data */
            if (ctx->events[j]->fd == pfds[i].fd) {
                ctx->fired[loop->n_events].data = ctx->events[j];
                loop->n_events++;
                break;
            }
        }
    }

    return loop->n_events;
}

static inline char *_mk_event_backend()
{
    return "poll";
}
