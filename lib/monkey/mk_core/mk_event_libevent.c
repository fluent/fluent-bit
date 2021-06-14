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


#include <mk_core/mk_event.h>

/* Libevent */
#include <event.h>

#ifdef _WIN32
#define ERR(e) (WSA##e)
#else
#define ERR(e) (e)
#endif

struct ev_map {
    /* for pipes */
    evutil_socket_t pipe[2];

    struct event *event;
    struct mk_event_ctx *ctx;
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

    /* Libevent context */
    ctx->base = event_base_new();

    /* Fired events (upon select(2) return) */
    ctx->fired = mk_mem_alloc_z(sizeof(struct mk_event) * size);
    if (!ctx->fired) {
        mk_mem_free(ctx);
        return NULL;
    }
    ctx->queue_size = size;

    return ctx;
}

/* Close handlers and memory */
static inline void _mk_event_loop_destroy(struct mk_event_ctx *ctx)
{
    event_base_free(ctx->base);
    mk_mem_free(ctx->fired);
    mk_mem_free(ctx);
}

static void cb_event(evutil_socket_t fd, short flags, void *data)
{
    int i;
    int mask = 0;
    struct mk_event *event = data;
    struct mk_event *fired;
    struct mk_event_ctx *ctx;
    struct ev_map *map = event->data;

    ctx = map->ctx;

    /* Compose mask */
    if (flags & EV_READ) {
        mask |= MK_EVENT_READ;
    }
    if (flags & EV_WRITE) {
        mask |= MK_EVENT_WRITE;
    }

    /* Register the event in the fired array */
    i = ctx->fired_count;
    fired = &ctx->fired[i];
    fired->fd   = event->fd;
    fired->mask = mask;
    fired->data = event;

    ctx->fired_count++;
}

/*
 * Update an event that is already associated with an event loop.
 *
 * We use this method in _mk_event_add so that it can handle a dirty
 * event transparently. In particular, this allows users to reuse an
 * event object without reconstructing it.
 *
 * Return 0 on success and -1 otherwise.
 */
static inline int _mk_event_update(struct mk_event_ctx *ctx, evutil_socket_t fd,
                                   int type, uint32_t events, void *data)
{
    int ret;
    int flags = 0;
    struct ev_map *ev_map;
    struct mk_event *event;
    struct event *libev;

    event = (struct mk_event *) data;
    ev_map = (struct ev_map *) event->data;

    /* Remove an existing timer first */
    event_del(ev_map->event);
    event_free(ev_map->event);

    /* Compose context */
    if (type != MK_EVENT_UNMODIFIED) {
        event->type = type;
    }
    if (events & MK_EVENT_READ) {
        flags |= EV_READ;
    }
    if (events & MK_EVENT_WRITE) {
        flags |= EV_WRITE;
    }
    flags |= EV_PERSIST;

    /* Register into libevent */
    libev = event_new(ctx->base, fd, flags, cb_event, event);
    if (libev == NULL) {
        return -1;
    }

    ret = event_add(libev, NULL);
    if (ret < 0) {
        return -1;
    }

    ev_map->event = libev;
    ev_map->ctx   = ctx;
    return 0;
}

/* Add the file descriptor to the arrays */
static inline int _mk_event_add(struct mk_event_ctx *ctx, evutil_socket_t fd,
                                int type, uint32_t events, void *data)
{
    int ret;
    int flags = 0;
    struct event *libev;
    struct mk_event *event;
    struct ev_map *ev_map;

    event = (struct mk_event *) data;
    if (event->mask != MK_EVENT_EMPTY) {
        return _mk_event_update(ctx, fd, type, events, data);
    }

    ev_map = mk_mem_alloc_z(sizeof(struct ev_map));
    if (!ev_map) {
        perror("malloc");
        return -1;
    }

    if (events & MK_EVENT_READ) {
        flags |= EV_READ;
    }
    if (events & MK_EVENT_WRITE) {
        flags |= EV_WRITE;
    }

    /* Compose context */
    event->fd   = fd;
    event->type = type;
    event->mask = events;
    event->status = MK_EVENT_REGISTERED;
    event->data   = ev_map;

    /* Register into libevent */
    flags |= EV_PERSIST;
    libev = event_new(ctx->base, fd, flags, cb_event, event);

    ev_map->event = libev;
    ev_map->ctx   = ctx;

    ret = event_add(libev, NULL);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

/* Delete an event */
static inline int _mk_event_del(struct mk_event_ctx *ctx, struct mk_event *event)
{
    int ret;
    struct ev_map *ev_map;

    ev_map = event->data;
    if (ev_map->pipe[0] > 0) {
        evutil_closesocket(ev_map->pipe[0]);
    }
    if (ev_map->pipe[1] > 0) {
        evutil_closesocket(ev_map->pipe[1]);
    }

    ret = event_del(ev_map->event);
    event_free(ev_map->event);
    mk_mem_free(ev_map);

    return ret;
}

/*
 * Timeout worker, it writes a byte every certain amount of seconds, it finish
 * once the other end of the pipe closes the fd[0].
 */
static void cb_timeout(evutil_socket_t fd, short flags, void *data)
{
    int ret;
    uint64_t val = 1;
    struct ev_map *ev_map = data;

    ret = send(ev_map->pipe[1], &val, sizeof(uint64_t), 0);
    if (ret == -1) {
        if (evutil_socket_geterror(fd) != ERR(ECONNABORTED)) {
            perror("write");
        }
        evutil_closesocket(ev_map->pipe[1]);
        event_del(ev_map->event);
        event_free(ev_map->event);
        mk_mem_free(ev_map);
    }
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
    evutil_socket_t fd[2];
    struct event *libev;
    struct mk_event *event;
    struct timeval timev = {sec, nsec / 1000}; /* (tv_sec, tv_usec} */
    struct ev_map *ev_map;

    if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == -1) {
        perror("socketpair");
        return -1;
    }

    event = (struct mk_event *) data;

    ev_map = mk_mem_alloc_z(sizeof(struct ev_map));
    if (!ev_map) {
        perror("malloc");
        return -1;
    }

    ev_map->pipe[0] = fd[0];
    ev_map->pipe[1] = fd[1];
    ev_map->ctx = ctx;

    libev = event_new(ctx->base, -1,
                      EV_TIMEOUT | EV_PERSIST,
                      cb_timeout, ev_map);
    ev_map->event = libev;

    event_add(libev, &timev);

    event->fd = fd[0];
    event->type = MK_EVENT_NOTIFICATION;
    event->mask = MK_EVENT_EMPTY;

    _mk_event_add(ctx, fd[0], MK_EVENT_NOTIFICATION, MK_EVENT_READ, data);
    event->mask = MK_EVENT_READ;

    return fd[0];
}

static inline int _mk_event_timeout_destroy(struct mk_event_ctx *ctx, void *data)
{
    struct mk_event *event;
    event = (struct mk_event *) data;
    evutil_closesocket(event->fd);
    return _mk_event_del(ctx, data);
}

static inline int _mk_event_channel_create(struct mk_event_ctx *ctx,
                                           int *r_fd, int *w_fd, void *data)
{
    int ret;
    evutil_socket_t fd[2];
    struct mk_event *event;

    if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == -1) {
        perror("socketpair");
        return -1;
    }

    event = data;
    event->fd = fd[0];
    event->type = MK_EVENT_NOTIFICATION;
    event->mask = MK_EVENT_EMPTY;

    ret = _mk_event_add(ctx, fd[0],
                        MK_EVENT_NOTIFICATION, MK_EVENT_READ, event);
    if (ret != 0) {
        evutil_closesocket(fd[0]);
        evutil_closesocket(fd[1]);
        return ret;
    }
    event->mask = MK_EVENT_READ;

    *r_fd = fd[0];
    *w_fd = fd[1];

    return 0;
}

static inline int _mk_event_wait(struct mk_event_loop *loop)
{
    struct mk_event_ctx *ctx = loop->data;

    /*
     * Libevent use callbacks, so on every callback the 'fired' array
     * is populated, so we reset the counter every time this function
     * is called.
     */
    ctx->fired_count = 0;
    event_base_loop(ctx->base, EVLOOP_ONCE);
    loop->n_events = ctx->fired_count;

    return loop->n_events;
}

static inline char *_mk_event_backend()
{
    return "libevent";
}
