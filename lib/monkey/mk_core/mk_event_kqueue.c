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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <mk_core/mk_event.h>
#include <mk_core/mk_memory.h>
#include <mk_core/mk_utils.h>

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

    /* Create the epoll instance */
    ctx->kfd = kqueue();
    if (ctx->kfd == -1) {
        mk_libc_error("kqueue");
        mk_mem_free(ctx);
        return NULL;
    }

    /* Allocate space for events queue */
    ctx->events = mk_mem_alloc_z(sizeof(struct kevent) * size);
    if (!ctx->events) {
        close(ctx->kfd);
        mk_mem_free(ctx);
        return NULL;
    }
    ctx->queue_size = size;
    return ctx;
}

/* Close handlers and memory */
static inline void _mk_event_loop_destroy(struct mk_event_ctx *ctx)
{
    close(ctx->kfd);
    mk_mem_free(ctx->events);
    mk_mem_free(ctx);
}

static inline int _mk_event_add(struct mk_event_ctx *ctx, int fd,
                                int type, uint32_t events, void *data)
{
    int ret;
    int set = MK_FALSE;
    struct mk_event *event;
    struct kevent ke;

    EV_SET(&ke, 0, 0, 0, 0, 0, 0);
    mk_bug(ctx == NULL);
    mk_bug(data == NULL);

    event = (struct mk_event *) data;
    if (event->mask == MK_EVENT_EMPTY) {
        event->fd   = fd;
        event->type = type;
        event->status = MK_EVENT_REGISTERED;
    }
    else {
        if (type != MK_EVENT_UNMODIFIED) {
            event->type = type;
        }
    }

    /* Read flag */
    if ((event->mask ^ MK_EVENT_READ) && (events & MK_EVENT_READ)) {
        EV_SET(&ke, fd, EVFILT_READ, EV_ADD, 0, 0, event);
        set = MK_TRUE;
    }
    else if ((event->mask & MK_EVENT_READ) && (events ^ MK_EVENT_READ)) {
        EV_SET(&ke, fd, EVFILT_READ, EV_DELETE, 0, 0, event);
        set = MK_TRUE;
    }

    if (set == MK_TRUE) {
        ret = kevent(ctx->kfd, &ke, 1, NULL, 0, NULL);
        if (ret < 0) {
            mk_libc_error("kevent");
            return ret;
        }
    }

    /* Write flag */
    set = MK_FALSE;
    if ((event->mask ^ MK_EVENT_WRITE) && (events & MK_EVENT_WRITE)) {
        EV_SET(&ke, fd, EVFILT_WRITE, EV_ADD, 0, 0, event);
        set = MK_TRUE;
    }
    else if ((event->mask & MK_EVENT_WRITE) && (events ^ MK_EVENT_WRITE)) {
        EV_SET(&ke, fd, EVFILT_WRITE, EV_DELETE, 0, 0, event);
        set = MK_TRUE;
    }

    if (set == MK_TRUE) {
        ret = kevent(ctx->kfd, &ke, 1, NULL, 0, NULL);
        if (ret < 0) {
            mk_libc_error("kevent");
            return ret;
        }
    }

    event->mask = events;
    event->priority = MK_EVENT_PRIORITY_DEFAULT;

    /* Remove from priority queue */
    if (!mk_list_entry_is_orphan(&event->_priority_head)) {
        mk_list_del(&event->_priority_head);
    }

    return 0;
}

static inline int _mk_event_del(struct mk_event_ctx *ctx, struct mk_event *event)
{
    int ret;
    struct kevent ke;

    EV_SET(&ke, 0, 0, 0, 0, 0, 0);
    mk_bug(ctx == NULL);
    mk_bug(event == NULL);

    if (!MK_EVENT_IS_REGISTERED(event)) {
        return 0;
    }

    if (event->mask & MK_EVENT_READ) {
        EV_SET(&ke, event->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        ret = kevent(ctx->kfd, &ke, 1, NULL, 0, NULL);
        if (ret < 0) {
            mk_libc_error("kevent");
            return ret;
        }
    }

    if (event->mask & MK_EVENT_WRITE) {
        EV_SET(&ke, event->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        ret = kevent(ctx->kfd, &ke, 1, NULL, 0, NULL);
        if (ret < 0) {
            mk_libc_error("kevent");
            return ret;
        }
    }

    /* Remove from priority queue */
    if (!mk_list_entry_is_orphan(&event->_priority_head)) {
        mk_list_del(&event->_priority_head);
    }

    MK_EVENT_NEW(event);

    return 0;
}

static inline int _mk_event_timeout_create(struct mk_event_ctx *ctx,
                                           time_t sec, long nsec, void *data)
{
    int fd;
    int ret;
    struct mk_event *event;
    struct kevent ke;

    mk_bug(data == NULL);

    /*
     * We just need a file descriptor number, we don't care from where it
     * comes from.
     */
    fd = open("/dev/null", 0);
    if (fd == -1) {
        mk_libc_error("open");
        return -1;
    }

    event = data;
    event->fd = fd;
    event->status = MK_EVENT_REGISTERED;
    event->type = MK_EVENT_NOTIFICATION;
    event->mask = MK_EVENT_EMPTY;

    event->priority = MK_EVENT_PRIORITY_DEFAULT;
    mk_list_entry_init(&event->_priority_head);

#if defined(NOTE_NSECONDS)
    /* The modern FreeBSD & NetBSD & OpenBSD & macOS have a high-resolution
       event timer. */
    EV_SET(&ke, fd, EVFILT_TIMER, EV_ADD, NOTE_NSECONDS,
           (sec * 1000000000) + nsec, event);
#elif defined(NOTE_SECONDS) && !defined(__APPLE__)
    /* LINUX_KQUEUE defined */
    EV_SET(&ke, fd, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, sec, event);
#else
    /* Keep backward compatibility; use the millisecond-resolution event timer. */
    /* Also, on macOS, NOTE_SECONDS has severe side effect that cause
     * performance degradation. */
    EV_SET(&ke, fd, EVFILT_TIMER, EV_ADD, 0, (sec * 1000) + (nsec / 1000000) , event);
#endif

    ret = kevent(ctx->kfd, &ke, 1, NULL, 0, NULL);
    if (ret < 0) {
        close(fd);
        mk_libc_error("kevent");
        return -1;
    }

    /*
     * FIXME: the timeout event is not triggered when using libkqueue, need
     * to confirm how it behave on native OSX.
     */
    event->mask = MK_EVENT_READ;

    return fd;
}

static inline int _mk_event_timeout_destroy(struct mk_event_ctx *ctx, void *data)
{
    int ret;
    struct mk_event *event;
    struct kevent ke;

    EV_SET(&ke, 0, 0, 0, 0, 0, 0);
    if (data == NULL) {
        return 0;
    }

    event = (struct mk_event *) data;
    if (!MK_EVENT_IS_REGISTERED(event)) {
        return 0;
    }
    EV_SET(&ke, event->fd, EVFILT_TIMER, EV_DELETE, 0,0, NULL);

    ret = kevent(ctx->kfd, &ke, 1, NULL, 0, NULL);
    if (ret < 0) {
        mk_libc_error("kevent");
        return ret;
    }

    /* Remove from priority queue */
    if (!mk_list_entry_is_orphan(&event->_priority_head)) {
        mk_list_del(&event->_priority_head);
    }

    close(event->fd);

    MK_EVENT_NEW(event);

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
    size_t               index;
    struct mk_event_ctx *ctx;

    ctx = loop->data;

    if (prevent_duplication) {
        for (index = 0 ; index < loop->n_events ; index++) {
            if (ctx->events[index].udata == event) {
                return 0;
            }
        }
    }

    event->mask = mask;

    ctx->events[loop->n_events].udata = event;

    loop->n_events++;

    return 0;
}

static inline int _mk_event_wait_2(struct mk_event_loop *loop, int timeout)
{
    struct mk_event_ctx *ctx = loop->data;

    struct timespec timev = {timeout / 1000, (timeout % 1000) * 1000000};
    loop->n_events = kevent(ctx->kfd, NULL, 0, ctx->events, ctx->queue_size,
                            (timeout != -1) ? &timev : NULL);
    return loop->n_events;
}

static inline char *_mk_event_backend()
{
#ifdef LINUX_KQUEUE
    return "libkqueue";
#else
    return "kqueue";
#endif
}
