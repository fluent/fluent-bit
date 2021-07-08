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

#include <stdint.h>
#include "mk_macros.h"
#include "mk_list.h"

#ifndef MK_EVENT_H
#define MK_EVENT_H

/* Events type family */
#define MK_EVENT_UNMODIFIED     -1    /* keep old event type              */
#define MK_EVENT_NOTIFICATION    0    /* notification channel (pipe)      */
#define MK_EVENT_LISTENER        1    /* listener socket                  */
#define MK_EVENT_FIFO            2    /* FIFO - Messaging                 */
#define MK_EVENT_CONNECTION      3    /* data on active connection        */
#define MK_EVENT_CUSTOM          4    /* custom fd registered             */
#define MK_EVENT_THREAD          5    /* thread-coroutine                 */

/* Event triggered for file descriptors  */
#define MK_EVENT_EMPTY           0
#define MK_EVENT_READ            1
#define MK_EVENT_WRITE           4
#define MK_EVENT_SLEEP           8
#define MK_EVENT_CLOSE          (16 | 8 | 8192)
#define MK_EVENT_IDLE           (16 | 8)

/* The event queue size */
#define MK_EVENT_QUEUE_SIZE    256

/* Events behaviors */
#define MK_EVENT_LEVEL         256
#define MK_EVENT_EDGE          512

/* Event status */
#define MK_EVENT_NONE            1    /* nothing */
#define MK_EVENT_REGISTERED      2    /* event is registered into the ev loop */

/* Legacy definitions: temporal
 *  ----------------------------
 *
 * Once a connection is dropped, define
 * a reason.
 */
#define MK_EP_SOCKET_CLOSED   0
#define MK_EP_SOCKET_ERROR    1
#define MK_EP_SOCKET_TIMEOUT  2
#define MK_EP_SOCKET_DONE     3
/* ---- end ---- */

#if defined(_WIN32)
    #include "mk_event_libevent.h"
#elif defined(MK_HAVE_EVENT_SELECT)
    #include "mk_event_select.h"
#elif defined(__linux__) && !defined(LINUX_KQUEUE)
    #include "mk_event_epoll.h"
#else
    #include "mk_event_kqueue.h"
#endif

#if defined(_WIN32)
    #define mk_event_closesocket(s) evutil_closesocket(s)
#else
    #define mk_event_closesocket(s) close(s)
#endif

/* Event reported by the event loop */
struct mk_event {
    int      fd;       /* monitored file descriptor */
    int      type;     /* event type  */
    uint32_t mask;     /* events mask */
    uint8_t  status;   /* internal status */
    void    *data;     /* custom data reference */

    /* function handler for custom type */
    int     (*handler)(void *data);
    struct mk_list _head;
};

struct mk_event_loop {
    int size;                  /* size of events array */
    int n_events;              /* number of events reported */
    struct mk_event *events;   /* copy or reference of events triggered */
    void *data;                /* mk_event_ctx_t from backend */
};

static inline void MK_EVENT_INIT(struct mk_event *ev, int fd, void *data,
                                 int (*callback)(void *))
{
    ev->fd      = fd;
    ev->type    = MK_EVENT_CUSTOM;
    ev->mask    = MK_EVENT_EMPTY;
    ev->status  = MK_EVENT_NONE;
    ev->data    = data;
    ev->handler = callback;
}

static inline void MK_EVENT_ZERO(struct mk_event *e)
{
    MK_EVENT_INIT(e, -1, NULL, NULL);
}

static inline void MK_EVENT_NEW(struct mk_event *e)
{
    e->mask   = MK_EVENT_EMPTY;
    e->status = MK_EVENT_NONE;
}

int mk_event_init();
int mk_event_initialize();
struct mk_event_loop *mk_event_loop_create(int size);
void mk_event_loop_destroy(struct mk_event_loop *loop);
int mk_event_add(struct mk_event_loop *loop, int fd,
                 int type, uint32_t mask, void *data);
int mk_event_del(struct mk_event_loop *loop, struct mk_event *event);
int mk_event_timeout_create(struct mk_event_loop *loop,
                            time_t sec, long nsec,void *data);
int mk_event_timeout_destroy(struct mk_event_loop *loop, void *data);
int mk_event_channel_create(struct mk_event_loop *loop,
                            int *r_fd, int *w_fd, void *data);
int mk_event_wait(struct mk_event_loop *loop);
int mk_event_translate(struct mk_event_loop *loop);
char *mk_event_backend();
struct mk_event_fdt *mk_event_get_fdt();

#endif
