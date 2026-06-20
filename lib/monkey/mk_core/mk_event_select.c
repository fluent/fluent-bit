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

#ifdef _WIN32
#include <Winsock2.h>
#else
#include <sys/select.h>
#endif

#include <mk_core/mk_event.h>
#include <time.h>

/* I could be wrong but i think the whole way in which
 * this module handles the event array seems to be flawed
 * because it's addressed by the file descriptor, which in
 * some cases could cause an out of bounds write of a non
 * controllable QWORD (ie. line 117)
 *
 * I'll leave it for the moment but I think we might want
 * to come back to it and refactor it to just use the event
 * array as a list (at most implementing a hash table like
 * addressing mechanism to make it faster)
 */

struct fd_timer {
    int    fd;
    int    run;
    time_t sec;
    long   nsec;
    pthread_t tid;
};

static inline int _mk_event_init()
{
    return 0;
}

static inline void *_mk_event_loop_create(int size)
{
    struct mk_event_ctx *ctx;

    /* Override caller 'size', we always use FD_SETSIZE */
    size = FD_SETSIZE;

    /* Main event context */
    ctx = mk_mem_alloc_z(sizeof(struct mk_event_ctx));
    if (!ctx) {
        return NULL;
    }

    FD_ZERO(&ctx->rfds);
    FD_ZERO(&ctx->wfds);

    /* Allocate space for events queue, re-use the struct mk_event */
    ctx->events = mk_mem_alloc_z(sizeof(struct mk_event *) * size);
    if (!ctx->events) {
        mk_mem_free(ctx);
        return NULL;
    }

    /* Fired events (upon select(2) return) */
    ctx->fired = mk_mem_alloc_z(sizeof(struct mk_event) * size);
    if (!ctx->fired) {
        mk_mem_free(ctx->events);
        mk_mem_free(ctx);
        return NULL;
    }
    ctx->queue_size = size;

    return ctx;
}

/* Close handlers and memory */
static inline void _mk_event_loop_destroy(struct mk_event_ctx *ctx)
{
    mk_mem_free(ctx->events);
    mk_mem_free(ctx->fired);
    mk_mem_free(ctx);
}

/* Add the file descriptor to the arrays */
static inline int _mk_event_add(struct mk_event_ctx *ctx, int fd,
                                int type, uint32_t events, void *data)
{
    struct mk_event *event;

    mk_bug(ctx == NULL);
    mk_bug(data == NULL);

    if (fd > FD_SETSIZE) {
        return -1;
    }

    if (events & MK_EVENT_READ) {
        FD_SET(fd, &ctx->rfds);
    }
    if (events & MK_EVENT_WRITE) {
        FD_SET(fd, &ctx->wfds);
    }

    event = (struct mk_event *) data;
    event->fd   = fd;
    event->mask = events;
    event->status = MK_EVENT_REGISTERED;

    event->priority = MK_EVENT_PRIORITY_DEFAULT;

    /* Remove from priority queue */
    if (!mk_list_entry_is_orphan(&event->_priority_head)) {
        mk_list_del(&event->_priority_head);
    }

    if (type != MK_EVENT_UNMODIFIED) {
        event->type = type;
    }

    ctx->events[fd] = event;
    if (fd > ctx->max_fd) {
        ctx->max_fd = fd;
    }

    return 0;
}

/* Delete an event */
static inline int _mk_event_del(struct mk_event_ctx *ctx, struct mk_event *event)
{
    int i;
    int fd;
    struct mk_event *s_event;

    mk_bug(ctx == NULL);
    mk_bug(event == NULL);

    if (!MK_EVENT_IS_REGISTERED(event)) {
        return 0;
    }

    fd = event->fd;

    if (event->mask & MK_EVENT_READ) {
        FD_CLR(event->fd, &ctx->rfds);
    }

    if (event->mask & MK_EVENT_WRITE) {
        FD_CLR(event->fd, &ctx->wfds);
    }

    /* Update max_fd, lookup */
    if (event->fd == ctx->max_fd) {
        for (i = (ctx->max_fd - 1); i > 0; i--) {
            if (!ctx->events[i]) {
                continue;
            }

            s_event = ctx->events[i];
            if (s_event->mask != MK_EVENT_EMPTY) {
                break;
            }
        }
        ctx->max_fd = i;
    }

    ctx->events[fd] = NULL;

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

    while (timer->run == MK_TRUE) {
        /* sleep for a while */
        nanosleep(&t_spec, NULL);

        /* send notification */
        ret = write(timer->fd, &val, sizeof(uint64_t));
        if (ret == -1) {
            perror("write");
            break;
        }
    }

    pthread_exit(NULL);
}

/*
 * This routine creates a timer, since this select(2) backend aims to be used
 * in very old systems to be compatible, we cannot trust timerfd_create(2)
 * will be available (e.g: Cygwin), so our workaround is to create a pipe(2)
 * and a thread, this thread writes a byte upon the expiration time is reached.
 */
static inline int _mk_event_timeout_create(struct mk_event_ctx *ctx,
                                           time_t sec, long nsec, void *data)
{
    int ret;
    int fd[2];
    struct mk_event *event;
    struct fd_timer *timer;

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
    timer->run  = MK_TRUE;

    event->data = timer;

    /* Now the dirty workaround, create a thread */
    ret = mk_utils_worker_spawn(_timeout_worker, timer, &timer->tid);
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
    int fd;
    struct mk_event *event;
    struct fd_timer *timer;

    event = (struct mk_event *) data;

    fd = event->fd;
    _mk_event_del(ctx, event);

    timer = event->data;
    timer->run = MK_FALSE;

    /* Wait for the background worker to finish */
    pthread_join(timer->tid, NULL);

    /* Cleanup */
    close(timer->fd);
    close(fd);
    mk_mem_free(timer);
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
    event->mask = MK_EVENT_READ;

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
    size_t               index;
    struct mk_event_ctx *ctx;

    ctx = loop->data;

    if (prevent_duplication) {
        for (index = 0 ; index < loop->n_events ; index++) {
            if (ctx->fired[index].data == event) {
                return 0;
            }
        }
    }

    event->mask = mask;

    ctx->fired[loop->n_events].data = event;

    loop->n_events++;

    return 0;
}

static inline int _mk_event_wait_2(struct mk_event_loop *loop, int timeout)
{
    int i;
    int f = 0;
    uint32_t mask;
    struct mk_event *fired;
    struct mk_event_ctx *ctx = loop->data;
    struct timeval timev = {timeout / 1000, (timeout % 1000) * 1000};

    memcpy(&ctx->_rfds, &ctx->rfds, sizeof(fd_set));
    memcpy(&ctx->_wfds, &ctx->wfds, sizeof(fd_set));

    loop->n_events = select(ctx->max_fd + 1, &ctx->_rfds, &ctx->_wfds, NULL,
                            (timeout != -1) ? &timev : NULL);
    if (loop->n_events <= 0) {
        return loop->n_events;
    }

    /*
     * Populate our events array with the data reported. In other backends such
     * as mk_event_epoll and mk_event_kqueue this is done when iterating the
     * results as their native implementation already provided an array ready
     * for processing.
     */
    for (i = 0; i <= ctx->max_fd; i++) {
        /* skip empty references */
        if (!ctx->events[i]) {
            continue;
        }

        mask = 0;
        if (FD_ISSET(i, &ctx->_rfds)) {
            mask |= MK_EVENT_READ;
        }
        if (FD_ISSET(i, &ctx->_wfds)) {
            mask |= MK_EVENT_WRITE;
        }

        if (mask) {
            fired = &ctx->fired[f];
            fired->fd   = i;
            fired->mask = mask;
            fired->data = ctx->events[i];
            f++;
        }
    }

    loop->n_events = f;
    return loop->n_events;
}

static inline char *_mk_event_backend()
{
    return "select";
}
