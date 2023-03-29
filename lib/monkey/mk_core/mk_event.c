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

#include <stdlib.h>
#include <stdio.h>

#include <mk_core/mk_core_info.h>
#include <mk_core/mk_pipe.h>
#include <mk_core/mk_sleep.h>
#include <mk_core/mk_unistd.h>
#include <mk_core/mk_memory.h>
#include <mk_core/mk_utils.h>
#include <mk_core/mk_event.h>

#if defined(_WIN32)
    #include "mk_event_libevent.c"
#elif defined(MK_HAVE_EVENT_SELECT)
    #include "mk_event_select.c"
#elif defined(__linux__) && !defined(LINUX_KQUEUE)
    #include "mk_event_epoll.c"
#else
    #include "mk_event_kqueue.c"
#endif

/* Initialize backend */
int mk_event_init()
{
    return _mk_event_init();
}

/* Create a new loop */
struct mk_event_loop *mk_event_loop_create(int size)
{
    void *backend;
    struct mk_event_loop *loop;

    backend = _mk_event_loop_create(size);
    if (!backend) {
        return NULL;
    }

    loop = mk_mem_alloc_z(sizeof(struct mk_event_loop));
    if (!loop) {
        _mk_event_loop_destroy(backend);
        return NULL;
    }

    loop->events = mk_mem_alloc_z(sizeof(struct mk_event) * size);
    if (!loop->events) {
        _mk_event_loop_destroy(backend);
        mk_mem_free(loop);
        return NULL;
    }

    loop->size   = size;
    loop->data   = backend;

    return loop;
}

/* Destroy a loop context */
void mk_event_loop_destroy(struct mk_event_loop *loop)
{
    _mk_event_loop_destroy(loop->data);
    mk_mem_free(loop->events);
    mk_mem_free(loop);
}

/* Register or modify an event */
int mk_event_add(struct mk_event_loop *loop, int fd,
                 int type, uint32_t mask, void *data)
{
    int ret;
    struct mk_event_ctx *ctx;

#ifdef MK_HAVE_TRACE
    mk_bug(!data);
#endif

    ctx = loop->data;
    ret = _mk_event_add(ctx, fd, type, mask, data);
    if (ret == -1) {
        return -1;
    }

    return 0;
}

/* Inject an event */
int mk_event_inject(struct mk_event_loop *loop, struct mk_event *event,
                    int flags, int prevent_duplication)
{
    if (loop->n_events + 1 >= loop->size) {
        return -1;
    }

    _mk_event_inject(loop, event, flags, prevent_duplication);

    return 0;
}

/* Remove an event */
int mk_event_del(struct mk_event_loop *loop, struct mk_event *event)
{
    int ret;
    struct mk_event_ctx *ctx;

    ctx = loop->data;

    /* just remove a registered event */
    if ((event->status & MK_EVENT_REGISTERED) == 0) {
        return -1;
    }

    ret = _mk_event_del(ctx, event);
    if (ret == -1) {
        return -1;
    }

    /* Reset the status and mask */
    MK_EVENT_NEW(event);

    return 0;
}

/* Create a new timer in the loop */
int mk_event_timeout_create(struct mk_event_loop *loop,
                            time_t sec, long nsec, void *data)
{
    struct mk_event_ctx *ctx;

    ctx = loop->data;
    return _mk_event_timeout_create(ctx, sec, nsec, data);
}

/* Disable timer */
int mk_event_timeout_disable(struct mk_event_loop *loop, void *data)
{
    return mk_event_del(loop, (struct mk_event *) data);
}

/* Destroy timer */
int mk_event_timeout_destroy(struct mk_event_loop *loop, void *data)
{
    struct mk_event_ctx *ctx;

    ctx = loop->data;
    return _mk_event_timeout_destroy(ctx, data);
}

/* Create a new channel to distribute signals */
int mk_event_channel_create(struct mk_event_loop *loop,
                            int *r_fd, int *w_fd,
                            void *data)
{
    struct mk_event_ctx *ctx;

    mk_bug(!data);
    ctx = loop->data;
    return _mk_event_channel_create(ctx, r_fd, w_fd, data);
}

/* Destroy channel created to distribute signals */
int mk_event_channel_destroy(struct mk_event_loop *loop,
                            int r_fd, int w_fd,
                            void *data)
{
    struct mk_event_ctx *ctx;

    mk_bug(!data);
    ctx = loop->data;
    return _mk_event_channel_destroy(ctx, r_fd, w_fd, data);
}

/* Poll events */
int mk_event_wait(struct mk_event_loop *loop)
{
    return _mk_event_wait_2(loop, -1);
}

/*
 * Poll events with timeout in milliseconds
 * zero timeout for non blocking wait
 * -1 timeout for infinite wait
 */
int mk_event_wait_2(struct mk_event_loop *loop, int timeout)
{
    return _mk_event_wait_2(loop, timeout);
}

/* Return the backend name */
char *mk_event_backend()
{
    return _mk_event_backend();
}
