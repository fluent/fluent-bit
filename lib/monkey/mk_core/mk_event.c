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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <mk_core/mk_memory.h>
#include <mk_core/mk_utils.h>
#include <mk_core/mk_event.h>

#if defined(__linux__) && !defined(LINUX_KQUEUE)
    #include "mk_event_epoll.c"
#else
    #include "mk_event_kqueue.c"
#endif

/* Create a new loop */
struct mk_event_loop *mk_event_loop_create(int size)
{
    void *backend;
    struct mk_event_loop *loop;

    backend = _mk_event_loop_create(size);
    if (!backend) {
        return NULL;
    }

    loop = mk_mem_malloc_z(sizeof(struct mk_event_loop));
    if (!loop) {
        _mk_event_loop_destroy(backend);
        return NULL;
    }

    loop->events = mk_mem_malloc_z(sizeof(struct mk_event) * size);
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
    struct mk_event *event;
    struct mk_event_ctx *ctx;

#ifdef TRACE
    mk_bug(!data);
#endif

    event = (struct mk_event *) data;

    if ((event->status & MK_EVENT_NONE) == 0) {
        return -1;
    }

    ctx = loop->data;
    ret = _mk_event_add(ctx, fd, type, mask, data);
    if (ret == -1) {
        return -1;
    }

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

    event->status = MK_EVENT_NONE;
    return 0;
}

/* Create a new timer in the loop */
int mk_event_timeout_create(struct mk_event_loop *loop, int expire, void *data)
{
    struct mk_event_ctx *ctx;

    ctx = loop->data;
    return _mk_event_timeout_create(ctx, expire, data);
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

/* Poll events */
int mk_event_wait(struct mk_event_loop *loop)
{
    return _mk_event_wait(loop);
}

/* Return the backend name */
char *mk_event_backend()
{
    return _mk_event_backend();
}
