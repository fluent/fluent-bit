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

/* Structure for the fd_timer */
struct fd_timer {
    int fd;
    int run;
    time_t sec;
    long nsec;
    pthread_t tid;
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
    int i;

    mk_bug(ctx == NULL);
    mk_bug(data == NULL);

    /* Find an empty slot */
    for (i = 0; i < ctx->queue_size; i++) {
        if (ctx->events[i] == NULL) {
            break;
        }
    }

    if (i == ctx->queue_size) {
        return -1;
    }

    event = (struct mk_event *) data;
    ctx->events[i] = event;
    event->fd = fd;
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

    /* Remove from priority queue */
    if (!mk_list_entry_is_orphan(&event->_priority_head)) {
        mk_list_del(&event->_priority_head);
    }

    MK_EVENT_NEW(event);

    return 0;
}

/*
 * Timeout worker, it writes a byte every certain amount of seconds, it finishes
 * once the other end of the pipe closes the fd[0].
 */
void _timeout_worker(void *arg)
{
    int ret;
    uint64_t val = 1;
    struct fd_timer *timer;
    struct timespec t_spec;

    printf("timeout worker\n");

    timer = (struct fd_timer *) arg;
    t_spec.tv_sec = timer->sec;
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
 * This routine creates a timer, since timerfd_create(2) is not available on all
 * systems, we implement a similar function through a thread and a pipe(2).
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
    timer->fd = fd[1];
    timer->sec = sec;
    timer->nsec = nsec;
    timer->run = MK_TRUE;

    event->data = timer;

    /* Now the dirty workaround, create a thread */
    ret = mk_utils_worker_spawn(_timeout_worker, timer, &timer->tid);
    if (ret < 0) {
        close(fd[0]);
        close(fd[1]);
        mk_mem_free(timer);
        event->data = NULL;
        return -1;
    }

    return fd[0];
}

static inline int _mk_event_timeout_destroy(struct mk_event_ctx *ctx, void *data)
{
    int fd;
    struct mk_event *event;
    struct fd_timer *timer;

    printf("timeout destroy\n");

    event = (struct mk_event *) data;
    if (event->data == NULL) {
        return 0;
    }

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

    event->data = NULL;

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

    printf("inject event on fd=%i\n", event->fd);
    ctx = loop->data;

    if (prevent_duplication) {
        for (i = 0; i < loop->n_events; i++) {
            if (ctx->fired[i].fd == event->fd) {
                return 0;
            }
        }
    }

    event->mask = mask;

    for (i = 0; i < loop->n_events; i++) {
        if (ctx->fired[i].fd == -1) {
            ctx->fired[i] = *event;
            return 0;
        }
    }

    ctx->fired[loop->n_events] = *event;
    loop->n_events++;

    return 0;
}

//     int i;
//     struct mk_event_ctx *ctx;

//     ctx = loop->data;
//
//     if (prevent_duplication) {
//         for (i = 0; i < loop->n_events; i++) {
//             if (ctx->fired[i].fd == event->fd) {
//                 return 0;
//             }
//         }
//     }

//     event->mask = mask;

//     for (i = 0; i < ctx->queue_size; i++) {
//         if (ctx->fired[i].fd == -1) {
//             ctx->fired[i] = *event;
//             break;
//         }
//     }

//     loop->n_events++;

//     return 0;
// }

static inline int _mk_event_wait_2(struct mk_event_loop *loop, int timeout)
{

    int i;
    int n;
    int ret;
    struct pollfd *pfds;
    struct mk_event *fired;
    struct mk_event_ctx *ctx = loop->data;

    pfds = mk_mem_alloc_z(sizeof(struct pollfd) * ctx->queue_size);
    if (!pfds) {
        return -1;
    }

    for (i = 0, n = 0; i < ctx->queue_size; i++) {
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

    ret = poll(pfds, n, timeout);
    if (ret <= 0) {
        mk_mem_free(pfds);
        loop->n_events = 0;
        return ret;
    }

    loop->n_events = 0;
    for (i = 0; i < n; i++) {
        if (pfds[i].revents == 0) {
            continue;
        }

        fired = &ctx->fired[loop->n_events];
        fired->fd = pfds[i].fd;
        fired->mask = 0;

        if (pfds[i].revents & POLLIN) {
            fired->mask |= MK_EVENT_READ;
            printf("POLLIN event on fd=%i\n", pfds[i].fd);
        }
        if (pfds[i].revents & POLLOUT) {
            fired->mask |= MK_EVENT_WRITE;
            printf("POLLOUT event on fd=%i\n", pfds[i].fd);
        }

        if (pfds[i].revents & POLLERR) {
            fired->mask |= MK_EVENT_CLOSE;
            printf("POLLERR event on fd=%i\n", pfds[i].fd);
        }

        if (pfds[i].revents & POLLHUP) {
            fired->mask |= MK_EVENT_CLOSE;
            printf("POLLHUP event on fd=%i\n", pfds[i].fd);
        }

        if (pfds[i].revents & POLLNVAL) {
            fired->mask |= MK_EVENT_CLOSE;
            printf("POLLNVAL event on fd=%i\n", pfds[i].fd);
        }

        fired->data = ctx->events[i];
        loop->n_events++;
    }

    mk_mem_free(pfds);
    return loop->n_events;
}

static inline char *_mk_event_backend()
{
    return "poll";
}
