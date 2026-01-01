/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_engine_dispatch.h>
#include <fluent-bit/flb_random.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

FLB_TLS_DEFINE(struct flb_sched, flb_sched_ctx);
FLB_TLS_DEFINE(struct flb_sched_timer_coro_cb_params, sched_timer_coro_cb_params);

void flb_sched_ctx_init()
{
    FLB_TLS_INIT(flb_sched_ctx);
    FLB_TLS_INIT(sched_timer_coro_cb_params);
}

struct flb_sched *flb_sched_ctx_get()
{
    struct flb_sched *sched;

    sched = FLB_TLS_GET(flb_sched_ctx);
    return sched;
}

void flb_sched_ctx_set(struct flb_sched *sched)
{
    FLB_TLS_SET(flb_sched_ctx, sched);
}

static inline double xmin(double a, double b)
{
    return a < b ? a : b;
}

/* Consume an unsigned 64 bit number from fd */
static inline int consume_byte(flb_pipefd_t fd)
{
    int ret;
    uint64_t val;

    /* We need to consume the byte */
    ret = flb_pipe_r(fd, &val, sizeof(val));

    /* ref: https://github.com/fluent/fluent-bit/pull/2463 */
#if defined(__APPLE__) || __FreeBSD__ >= 12
    if (ret < 0) {
#else
    if (ret <= 0) {
#endif
        flb_errno();
        return -1;
    }

    return 0;
}

/*
 * Generate an uniform random value between min and max. Original version
 * taken from internet and modified to use /dev/urandom to set a seed on
 * each call. Despites using the urandom device may add some overhead,
 * this function is not called too often so it should not be an issue.
 */
static int random_uniform(int min, int max)
{
    int val;
    int range;
    int copies;
    int limit;
    int ra;

    if (flb_random_bytes((unsigned char *) &val, sizeof(int))) {
        val = time(NULL);
    }
    srand(val);

    range  = max - min + 1;
    copies = (RAND_MAX / range);
    limit  = range * copies;
    ra     = -1;

    while (ra < 0 || ra >= limit) {
        ra = rand();
    }

    return ra / copies + min;
}


/*
 * Schedule a request that will be processed within the next
 * FLB_SCHED_REQUEST_FRAME seconds.
 */
static int schedule_request_now(int seconds,
                                struct flb_sched_timer *timer,
                                struct flb_sched_request *request,
                                struct flb_config *config)
{
    flb_pipefd_t fd;
    struct mk_event *event;
    struct flb_sched *sched = config->sched;

    /* Initialize event */
    event = &timer->event;
    event->mask   = MK_EVENT_EMPTY;
    event->status = MK_EVENT_NONE;

    /* Create a timeout into the main event loop */
    fd = mk_event_timeout_create(config->evl, seconds, 0, event);
    event->priority = FLB_ENGINE_PRIORITY_CB_SCHED;
    if (fd == -1) {
        return -1;
    }
    request->fd = fd;
    timer->timer_fd = fd;

    /*
     * Note: mk_event_timeout_create() sets a type = MK_EVENT_NOTIFICATION by
     * default, we need to overwrite this value so we can do a clean check
     * into the Engine when the event is triggered.
     */
    event->type = FLB_ENGINE_EV_SCHED;
    mk_list_add(&request->_head, &sched->requests);

    return 0;
}

/*
 * Enqueue a request that will wait until it expected timeout reach the
 * FLB_SCHED_REQUEST_FRAME interval.
 */
static int schedule_request_wait(struct flb_sched_request *request,
                                 struct flb_config *config)
{
    struct flb_sched *sched = config->sched;

    mk_list_add(&request->_head, &sched->requests_wait);
    return 0;
}

/*
 * Iterate requests_wait list looking for candidates to be promoted
 * to the 'requests' list.
 */
static int schedule_request_promote(struct flb_sched *sched)
{
    int ret;
    int next;
    int passed;
    time_t now;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list failed_requests;
    struct flb_sched_request *request;

    now = time(NULL);
    mk_list_init(&failed_requests);

    mk_list_foreach_safe(head, tmp, &sched->requests_wait) {
        request = mk_list_entry(head, struct flb_sched_request, _head);

        /* First check how many seconds have passed since the request creation */
        passed = (now - request->created);
        ret = 0;

        /* If we passed the original time, schedule now for the next second */
        if (passed > request->timeout) {
            mk_list_del(&request->_head);
            ret = schedule_request_now(1, request->timer, request, sched->config);
            if (ret != 0) {
                mk_list_add(&request->_head, &failed_requests);
            }
        }
        else if (passed + FLB_SCHED_REQUEST_FRAME >= request->timeout) {
            /* Check if we should schedule within this frame */
            mk_list_del(&request->_head);
            next = labs(passed - request->timeout);
            ret = schedule_request_now(next, request->timer, request, sched->config);
            if (ret != 0) {
                mk_list_add(&request->_head, &failed_requests);
            }
        }
        else {
            continue;
        }

        /*
         * If the 'request' could not be scheduled, this could only happen due to memory
         * exhaustion or running out of file descriptors. There is no much we can do
         * at this time.
         */
        if (ret == -1) {
            flb_error("[sched] a 'retry request' could not be scheduled. the "
                      "system might be running out of memory or file "
                      "descriptors. The scheduler will do a retry later.");
        }
    }

    /* For each failed request, re-add them to the wait list */
    mk_list_foreach_safe(head, tmp, &failed_requests) {
        request = mk_list_entry(head, struct flb_sched_request, _head);
        mk_list_del(&request->_head);
        mk_list_add(&request->_head, &sched->requests_wait);
    }

    return 0;
}

static double ipow(double base, int exp)
{
    double result = 1;

    for (;;) {
        if (exp & 1) {
            result *= base;
        }

        exp >>= 1;
        if (!exp) {
            break;
        }
        base *= base;
    }

    return result;
}

/*
 * The 'backoff full jitter' algorithm implements a capped backoff with a jitter
 * to generate numbers to be used as 'wait times', this implementation is fully
 * based on the following article:
 *
 *   https://www.awsarchitectureblog.com/2015/03/backoff.html
 */
static int backoff_full_jitter(int base, int cap, int n)
{
    int temp;

    temp = xmin(cap, base * ipow(2, n));
    return random_uniform(base, temp);
}

/* Schedule the 'retry' for a thread buffer flush */
int flb_sched_request_create(struct flb_config *config, void *data, int tries)
{
    int ret;
    int seconds;
    struct flb_sched_timer *timer;
    struct flb_sched_request *request;

    /* Allocate timer context */
    timer = flb_sched_timer_create(config->sched);
    if (!timer) {
        return -1;
    }

    /* Allocate request node */
    request = flb_malloc(sizeof(struct flb_sched_request));
    if (!request) {
        flb_errno();
        return -1;
    }

    /* Link timer references */
    timer->type = FLB_SCHED_TIMER_REQUEST;
    timer->data = request;
    timer->event.mask = MK_EVENT_EMPTY;

    /* Get suggested wait_time for this request. If shutting down, set to 0. */
    if (config->is_shutting_down) {
        seconds = 0;
    } else {
        seconds = backoff_full_jitter((int)config->sched_base, (int)config->sched_cap,
                                      tries);
    }
    seconds += 1;

    /* Populare request */
    request->fd      = -1;
    request->created = time(NULL);
    request->timeout = seconds;
    request->data    = data;
    request->timer   = timer;

    /* Request to be placed into the sched_requests_wait list */
    if (seconds > FLB_SCHED_REQUEST_FRAME) {
        schedule_request_wait(request, config);
    }
    else {
        ret = schedule_request_now(seconds, timer, request, config);
        if (ret == -1) {
            flb_error("[sched]  'retry request' could not be created. the "
                      "system might be running out of memory or file "
                      "descriptors.");
            flb_sched_timer_destroy(timer);
            flb_free(request);
            return -1;
        }
    }

    return seconds;
}

int flb_sched_request_destroy(struct flb_sched_request *req)
{
    struct flb_sched_timer *timer;

    if (!req) {
        return 0;
    }

    mk_list_del(&req->_head);

    timer = req->timer;

    /*
     * We invalidate the timer since in the same event loop round
     * an event associated to this timer can be present. Invalidation
     * means the timer will do nothing and will be removed after
     * the event loop round finish.
     */
    flb_sched_timer_invalidate(timer);

    /* Remove request */
    flb_free(req);

    return 0;
}

int flb_sched_request_invalidate(struct flb_config *config, void *data)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_sched_request *request;
    struct flb_sched *sched;

    sched = config->sched;
    mk_list_foreach_safe(head, tmp, &sched->requests) {
        request = mk_list_entry(head, struct flb_sched_request, _head);
        if (request->data == data) {
            flb_sched_request_destroy(request);
            return 0;
        }
    }

    /*
     *  Clean up retry tasks that are scheduled more than 60s.
     *  Task might be destroyed when there are still retry
     *  scheduled but no thread is running for the task.
     *
     *  We need to drop buffered chunks when the filesystem buffer
     *  limit is reached. We need to make sure that all requests
     *  should be destroyed to avoid invoke an invlidated request.
     */
    mk_list_foreach_safe(head, tmp, &sched->requests_wait) {
        request = mk_list_entry(head, struct flb_sched_request, _head);
        if (request->data == data) {
            flb_sched_request_destroy(request);
            return 0;
        }
    }

    return -1;
}

/*
 * Depending on the backend that provides the timer, most of the time except
 * on event loops based on 'kqueue', we need to read the notification byte, which
 * usually comes from a file descriptor registered through the backend based on
 * epoll(), select() or poll().
 *
 * If we are NOT using kequeue, just read(2) the byte.
 */
static inline int event_fd_consume_byte(int fd)
{
#ifndef FLB_EVENT_LOOP_KQUEUE
    return consume_byte(fd);
#endif

    return 0;
}

/*
 * Lookup for the next available 'id' for a struct flb_sched_timer_coro. This is a slow search,
 * however is expected we don't have more than a couple dozen active timer_coro contexts under
 * the same scheduler context.
 *
 * We cap this as an uint32_t so we can use the sched->ch_events channels to send the id and
 * link it to some notification.
 */
static inline uint32_t sched_timer_coro_get_id(struct flb_sched *sched)
{
    uint32_t id = 0;
    int found = FLB_FALSE;
    struct cfl_list *head;
    struct flb_sched_timer_coro *stc;

    while (id < UINT32_MAX) {
        /* check if the proposed id is in use already */
        cfl_list_foreach(head, &sched->timer_coro_list) {
            stc = cfl_list_entry(head, struct flb_sched_timer_coro, _head);
            if (stc->id == id) {
                found = FLB_TRUE;
                break;
            }
        }

        if (!found) {
            break;
        }
        else {
            id++;
            found = FLB_FALSE;
        }
    }

    return id;
}

static inline struct flb_sched_timer_coro *sched_timer_coro_get_by_id(
                                            struct flb_sched *sched,
                                            uint32_t id)
{
    struct cfl_list *head;
    struct flb_sched_timer_coro *stc;

    /* check if the proposed id is in use already */
    cfl_list_foreach(head, &sched->timer_coro_list) {
        stc = cfl_list_entry(head, struct flb_sched_timer_coro, _head);
        if (stc->id == id) {
            return stc;
        }
    }

    return NULL;
}


/* context of a scheduled timer that holds a coroutine context */
struct flb_sched_timer_coro *flb_sched_timer_coro_create(struct flb_sched_timer *timer,
                                                         struct flb_config *config,
                                                         void *data)
{
    size_t stack_size;
    struct flb_coro *coro;
    struct flb_sched *sched;
    struct flb_sched_timer_coro *stc;

    /* get scheduler context */
    sched = flb_sched_ctx_get();
    if (!sched) {
        flb_error("[sched] no scheduler context available");
        return NULL;
    }

    stc = flb_calloc(1, sizeof(struct flb_sched_timer_coro));
    if (!stc) {
        flb_errno();
        return NULL;
    }

    stc->id = sched_timer_coro_get_id(sched);
    stc->timer = timer;
    stc->config = config;
    stc->data = data;

    coro = flb_coro_create(stc);
    if (!coro) {
        flb_free(stc);
        return NULL;
    }
    stc->coro = coro;

    coro->caller = co_active();
    coro->callee = co_create(config->coro_stack_size,
                             sched_timer_coro_cb_run, &stack_size);

#ifdef FLB_HAVE_VALGRIND
    coro->valgrind_stack_id = VALGRIND_STACK_REGISTER(coro->callee, ((char *) coro->callee) + stack_size);
#endif
    cfl_list_add(&stc->_head, &sched->timer_coro_list);

    sched_timer_cb_params_set(stc, coro, config, data);
    return stc;
}

void flb_sched_timer_coro_destroy(struct flb_sched_timer_coro *instance)
{
    if (instance == NULL) {
        return;
    }

    if (instance->coro != NULL) {
        flb_coro_destroy(instance->coro);
    }

    cfl_list_del(&instance->_head);

    flb_free(instance);
}

/*
 * Create a timer that triggers the defined callback every N milliseconds.
 */
static void timer_cb_coro_trampoline(struct flb_config *config,
                                     struct flb_sched_timer *timer, void *data)
{
    struct flb_sched_timer_coro *stc;

    stc = flb_sched_timer_coro_create(timer, config, data);
    if (!stc) {
        return;
    }

    flb_coro_resume(stc->coro);
}

/* Handle a timeout event set by a previous flb_sched_request_create(...) */
int flb_sched_event_handler(struct flb_config *config, struct mk_event *event)
{
    int ret;
    uint64_t val;
    uint32_t op;
    uint32_t id;

    struct flb_sched *sched;
    struct flb_sched_timer *timer;
    struct flb_sched_request *req;
    struct flb_sched_timer_coro *stc;

    if (event->type == FLB_ENGINE_EV_SCHED_CORO) {
        sched = flb_sched_ctx_get();

        /* consume the notification */
        ret = flb_pipe_r(event->fd, &val, sizeof(val));
        if (ret == -1) {
            flb_errno();
            return -1;
        }

        op = FLB_BITS_U64_HIGH(val);
        id = FLB_BITS_U64_LOW(val);

        stc = sched_timer_coro_get_by_id(sched, id);

        if (stc == NULL) {
            flb_error("[sched] invalid timer coroutine id %u", id);
            return -1;
        }

        if (op == FLB_SCHED_TIMER_CORO_RETURN) {
            /* move stc to the drop list */
            cfl_list_del(&stc->_head);
            cfl_list_add(&stc->_head, &sched->timer_coro_list_drop);
        }
        else {
            flb_error("[sched] unknown coro event operation %u", op);
        }

        return 0;
    }

    /* Everything else is just a normal timer handling */
    timer = (struct flb_sched_timer *) event;
    if (timer->active == FLB_FALSE) {
        return 0;
    }

    if (timer->type == FLB_SCHED_TIMER_REQUEST) {
        /* Map request struct */
        req = timer->data;
        consume_byte(req->fd);

        /* Dispatch 'retry' */
        ret = flb_engine_dispatch_retry(req->data, config);

        /* Destroy this scheduled request, it's not longer required */
        if (ret == 0) {
            flb_sched_request_destroy(req);
        }
    }
    else if (timer->type == FLB_SCHED_TIMER_FRAME) {
        sched = timer->data;
        event_fd_consume_byte(sched->frame_fd);
        schedule_request_promote(sched);
    }
    else if (timer->type == FLB_SCHED_TIMER_CB_ONESHOT) {
        event_fd_consume_byte(timer->timer_fd);
        flb_sched_timer_cb_disable(timer);
        timer->cb(config, timer->data);
        flb_sched_timer_cb_destroy(timer);
    }
    else if (timer->type == FLB_SCHED_TIMER_CB_PERM) {
        event_fd_consume_byte(timer->timer_fd);

        if (timer->coro == FLB_TRUE) {
            timer_cb_coro_trampoline(config, timer, timer->data);
        }
        else {
            timer->cb(config, timer->data);
        }
    }

    return 0;
}

/*
 * Create a timer that once it expire, it triggers the defined callback
 * upon creation. This interface is for generic purposes and not specific
 * for re-tries.
 *
 * use-case: invoke function A() after M milliseconds.
 */
int flb_sched_timer_cb_create(struct flb_sched *sched, int type, int ms,
                              void (*cb)(struct flb_config *, void *),
                              void *data, struct flb_sched_timer **out_timer)
{
    int fd;
    time_t sec;
    long nsec;
    struct mk_event *event;
    struct flb_sched_timer *timer;

    if (type != FLB_SCHED_TIMER_CB_ONESHOT && type != FLB_SCHED_TIMER_CB_PERM) {
        flb_error("[sched] invalid callback timer type %i", type);
        return -1;
    }

    timer = flb_sched_timer_create(sched);
    if (!timer) {
        return -1;
    }

    timer->type = type;
    timer->data = data;
    timer->cb   = cb;

    /* Initialize event */
    event = &timer->event;
    event->mask   = MK_EVENT_EMPTY;
    event->status = MK_EVENT_NONE;

    /* Convert from milliseconds to seconds and nanoseconds */
    sec = (ms / 1000);
    nsec = ((ms % 1000) * 1000000);

    /* Create the frame timer */
    fd = mk_event_timeout_create(sched->evl, sec, nsec, event);
    event->priority = FLB_ENGINE_PRIORITY_CB_TIMER;
    if (fd == -1) {
        flb_error("[sched] cannot do timeout_create()");
        flb_sched_timer_destroy(timer);
        return -1;
    }

    /*
     * Note: mk_event_timeout_create() sets a type = MK_EVENT_NOTIFICATION by
     * default, we need to overwrite this value so we can do a clean check
     * into the Engine when the event is triggered.
     */
    event->type = FLB_ENGINE_EV_SCHED;
    timer->timer_fd = fd;

    if (out_timer != NULL) {
        *out_timer = timer;
    }

    return 0;
}

/*
 * Creates a timer that triggers the defined callback every N milliseconds. The target
 * function runs in a coroutine context.
 */
int flb_sched_timer_coro_cb_create(struct flb_sched *sched, int type, int64_t ms,
                                   void (*cb)(struct flb_config *, void *),
                                   void *data, struct flb_sched_timer **out_timer)

{
    int ret;
    struct flb_sched_timer *timer = NULL;

    ret = flb_sched_timer_cb_create(sched, type, ms, cb, data, &timer);
    if (ret == -1) {
        flb_error("[sched] cannot create timer for coroutine callback");
        return -1;
    }

    /* mark that the callback will run inside a coroutine */
    timer->coro = FLB_TRUE;

    return 0;
}

/* Disable notifications, used before to destroy the context */
int flb_sched_timer_cb_disable(struct flb_sched_timer *timer)
{
    if (timer->timer_fd != -1) {
        mk_event_timeout_destroy(timer->sched->evl, &timer->event);
        timer->timer_fd = -1;
    }

    return 0;
}

int flb_sched_timer_cb_destroy(struct flb_sched_timer *timer)
{
    flb_sched_timer_destroy(timer);
    return 0;
}

/* Initialize the Scheduler */
struct flb_sched *flb_sched_create(struct flb_config *config,
                                   struct mk_event_loop *evl)
{
    int ret;
    flb_pipefd_t fd;
    struct mk_event *event;
    struct flb_sched *sched;
    struct flb_sched_timer *timer;

    sched = flb_calloc(1, sizeof(struct flb_sched));
    if (!sched) {
        flb_errno();
        return NULL;
    }

    sched->config = config;
    sched->evl = evl;

    /* Initialize lists */
    mk_list_init(&sched->requests);
    mk_list_init(&sched->requests_wait);
    mk_list_init(&sched->timers);
    mk_list_init(&sched->timers_drop);

    cfl_list_init(&sched->timer_coro_list);
    cfl_list_init(&sched->timer_coro_list_drop);

    /* Create the frame timer who enqueue 'requests' for future time */
    timer = flb_sched_timer_create(sched);
    if (!timer) {
        flb_free(sched);
        return NULL;
    }

    timer->type = FLB_SCHED_TIMER_FRAME;
    timer->data = sched;

    /* Initialize event */
    event = &timer->event;
    event->mask   = MK_EVENT_EMPTY;
    event->status = MK_EVENT_NONE;

    /* Create the frame timer */
    fd = mk_event_timeout_create(evl, FLB_SCHED_REQUEST_FRAME, 0,
                                 event);
    event->priority = FLB_ENGINE_PRIORITY_CB_SCHED;
    if (fd == -1) {
        flb_sched_timer_destroy(timer);
        flb_free(sched);
        return NULL;
    }
    sched->frame_fd = fd;

    /* Creates a channel to handle notifications */
    ret = mk_event_channel_create(sched->evl,
                                  &sched->ch_events[0],
                                  &sched->ch_events[1],
                                  sched);
    if (ret == -1) {
        flb_sched_destroy(sched);
        return NULL;
    }
    sched->event.type = FLB_ENGINE_EV_SCHED_CORO;

    /*
     * Note: mk_event_timeout_create() sets a type = MK_EVENT_NOTIFICATION by
     * default, we need to overwrite this value so we can do a clean check
     * into the Engine when the event is triggered.
     */
    event->type = FLB_ENGINE_EV_SCHED_FRAME;

    return sched;
}

/* Release all resources used by the Scheduler */
int flb_sched_destroy(struct flb_sched *sched)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_sched_timer *timer;
    struct flb_sched_request *request;

    if (!sched) {
        return 0;
    }

    mk_list_foreach_safe(head, tmp, &sched->requests) {
        request = mk_list_entry(head, struct flb_sched_request, _head);
        flb_sched_request_destroy(request);
        c++; /* evil counter */
    }

    /* Delete requests on wait list */
    mk_list_foreach_safe(head, tmp, &sched->requests_wait) {
        request = mk_list_entry(head, struct flb_sched_request, _head);
        flb_sched_request_destroy(request);
        c++; /* evil counter */
    }

    /* Delete timers */
    mk_list_foreach_safe(head, tmp, &sched->timers) {
        timer = mk_list_entry(head, struct flb_sched_timer, _head);
        mk_event_timeout_destroy(sched->evl, &timer->event);
        flb_sched_timer_destroy(timer);
        c++;
    }

    /* Delete timers drop list */
    mk_list_foreach_safe(head, tmp, &sched->timers_drop) {
        timer = mk_list_entry(head, struct flb_sched_timer, _head);
        flb_sched_timer_destroy(timer);
        c++;
    }

    flb_free(sched);
    return c;
}

/* Create a timer context */
struct flb_sched_timer *flb_sched_timer_create(struct flb_sched *sched)
{
    struct flb_sched_timer *timer;

    /* Create timer context */
    timer = flb_calloc(1, sizeof(struct flb_sched_timer));
    if (!timer) {
        flb_errno();
        return NULL;
    }
    MK_EVENT_ZERO(&timer->event);

    timer->timer_fd = -1;
    timer->config = sched->config;
    timer->sched = sched;
    timer->data = NULL;
    timer->coro = FLB_FALSE;

    /* Active timer (not invalidated) */
    timer->active = FLB_TRUE;
    mk_list_add(&timer->_head, &sched->timers);

    return timer;
}

void flb_sched_timer_invalidate(struct flb_sched_timer *timer)
{
    flb_sched_timer_cb_disable(timer);

    timer->active = FLB_FALSE;

    mk_list_del(&timer->_head);
    mk_list_add(&timer->_head, &timer->sched->timers_drop);
}

/* Destroy a timer context */
int flb_sched_timer_destroy(struct flb_sched_timer *timer)
{
    flb_sched_timer_cb_disable(timer);

    mk_list_del(&timer->_head);
    flb_free(timer);

    return 0;
}

/* Used by the engine to cleanup pending timers waiting to be destroyed */
int flb_sched_timer_cleanup(struct flb_sched *sched)
{
    int timer_count = 0;
    int timer_coro_count = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_sched_timer *timer;

    mk_list_foreach_safe(head, tmp, &sched->timers_drop) {
        timer = mk_list_entry(head, struct flb_sched_timer, _head);
        flb_sched_timer_destroy(timer);
        timer_count++;
    }

    timer_coro_count = flb_sched_timer_coro_cleanup(sched);
    flb_trace("[sched] %i timer coroutines destroyed", timer_coro_count);

    return timer_count + timer_coro_count;
}

int flb_sched_timer_coro_cleanup(struct flb_sched *sched)
{
    int c = 0;
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct flb_sched_timer_coro *stc;

    cfl_list_foreach_safe(head, tmp, &sched->timer_coro_list_drop) {
        stc = cfl_list_entry(head, struct flb_sched_timer_coro, _head);
        flb_sched_timer_coro_destroy(stc);
        c++;
    }

    return c;
}

int flb_sched_retry_now(struct flb_config *config,
                        struct flb_task_retry *retry)
{
    int ret;
    struct flb_sched_timer *timer;
    struct flb_sched_request *request;

    /* Allocate timer context */
    timer = flb_sched_timer_create(config->sched);
    if (!timer) {
        return -1;
    }

    /* Allocate request node */
    request = flb_malloc(sizeof(struct flb_sched_request));
    if (!request) {
        flb_errno();
        flb_sched_timer_destroy(timer);
        return -1;
    }

    /* Link timer references */
    timer->type = FLB_SCHED_TIMER_REQUEST;
    timer->data = request;
    timer->event.mask = MK_EVENT_EMPTY;

    /* Populate request */
    request->fd      = -1;
    request->created = time(NULL);
    request->timeout = 0;
    request->data    = retry;
    request->timer   = timer;

    ret = schedule_request_now(0 /* seconds */, timer, request, config);
    if (ret == -1) {
        flb_error("[sched] 'retry-now request' could not be created. the "
                  "system might be running out of memory or file "
                  "descirptors.");
        flb_sched_timer_destroy(timer);
        flb_free(request);
        return -1;
    }
    return 0;
}

struct flb_sched_timer_coro *flb_sched_timer_coro_get(struct flb_sched *sched, uint32_t id)
{
    struct cfl_list *head;
    struct flb_sched_timer_coro *stc;

    cfl_list_foreach(head, &sched->timer_coro_list) {
        stc = cfl_list_entry(head, struct flb_sched_timer_coro, _head);
        if (stc->id == id) {
            return stc;
        }
    }

    return NULL;
}
