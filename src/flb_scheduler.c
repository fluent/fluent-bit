/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_engine_dispatch.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
    if (ret <= 0) {
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
    int fd;
    int range;
    int copies;
    int limit;
    int ra;
    int ret;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        srand(time(NULL));
    }
    else {
        ret = read(fd, &val, sizeof(val));
        if (ret > 0) {
            srand(val);
        }
        else {
            srand(time(NULL));
        }
        close(fd);
    }

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
    if (fd == -1) {
        return -1;
    }
    request->fd = fd;

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
    int passed;
    int next;
    time_t now;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_sched_request *request;

    now = time(NULL);
    mk_list_foreach_safe(head, tmp, &sched->requests_wait) {
        request = mk_list_entry(head, struct flb_sched_request, _head);

        /* First check how many seconds have passed since the request creation */
        passed = (now - request->created);

        /* If we passed the original time, schedule now for the next second */
        if (passed > request->timeout) {
            mk_list_del(&request->_head);
            schedule_request_now(1, request->timer, request, sched->config);
        }
        else {
            /* Check if we should schedule within this frame */
            if (passed + FLB_SCHED_REQUEST_FRAME >= request->timeout) {
                next = labs(passed - request->timeout);
                mk_list_del(&request->_head);
                schedule_request_now(next, request->timer, request, sched->config);
            }
        }
    }

    return 0;
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
    int exp;

    exp = xmin(cap, (1 << n /*pow(2, n)*/) * base);
    return random_uniform(0, exp);
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

    /* Get suggested wait_time for this request */
    seconds = backoff_full_jitter(FLB_SCHED_BASE, FLB_SCHED_CAP, tries);
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
            flb_free(request);
            return -1;
        }
    }

    return seconds;
}

int flb_sched_request_destroy(struct flb_config *config,
                              struct flb_sched_request *req)
{
    struct flb_sched_timer *timer;

    mk_list_del(&req->_head);

    timer = req->timer;
    if (config->evl && timer->event.mask != MK_EVENT_EMPTY) {
        mk_event_del(config->evl, &timer->event);
    }
    flb_pipe_close(req->fd);

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
            flb_sched_request_destroy(config, request);
            return 0;
        }
    }

    return -1;
}

/* Handle a timeout event set by a previous flb_sched_request_create(...) */
int flb_sched_event_handler(struct flb_config *config, struct mk_event *event)
{
    struct flb_sched *sched;
    struct flb_sched_timer *timer;
    struct flb_sched_request *req;

    timer = (struct flb_sched_timer *) event;
    if (timer->active == FLB_FALSE) {
        return 0;
    }

    if (timer->type == FLB_SCHED_TIMER_REQUEST) {
        /* Map request struct */
        req = timer->data;
        consume_byte(req->fd);

        /* Dispatch 'retry' */
        flb_engine_dispatch_retry(req->data, config);

        /* Destroy this scheduled request, it's not longer required */
        flb_sched_request_destroy(config, req);
    }
    else if (timer->type == FLB_SCHED_TIMER_FRAME) {
        sched = timer->data;
#ifndef __APPLE__
        consume_byte(sched->frame_fd);
#endif
        schedule_request_promote(sched);
    }
    else if (timer->type == FLB_SCHED_TIMER_CUSTOM) {
        consume_byte(timer->timer_fd);
        flb_sched_timer_cb_disable(timer);
        timer->cb(config, timer->data);
        flb_sched_timer_cb_destroy(timer);
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
int flb_sched_timer_cb_create(struct flb_config *config, int ms,
                              void (*cb)(struct flb_config *, void *),
                              void *data)
{
    int fd;
    time_t sec;
    long nsec;
    struct mk_event *event;
    struct flb_sched_timer *timer;

    timer = flb_sched_timer_create(config->sched);
    if (!timer) {
        return -1;
    }

    timer->type = FLB_SCHED_TIMER_CUSTOM;
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
    fd = mk_event_timeout_create(config->evl, sec, nsec, event);
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

    return 0;
}

/* Disable notifications, used before to destroy the context */
int flb_sched_timer_cb_disable(struct flb_sched_timer *timer)
{
    int ret;

    ret = close(timer->timer_fd);
    timer->timer_fd = -1;
    return ret;
}

int flb_sched_timer_cb_destroy(struct flb_sched_timer *timer)
{
    if (timer->timer_fd > 0) {
        flb_sched_timer_cb_disable(timer);
    }
    flb_sched_timer_destroy(timer);
    return 0;
}

/* Initialize the Scheduler */
int flb_sched_init(struct flb_config *config)
{
    flb_pipefd_t fd;
    struct mk_event *event;
    struct flb_sched_timer *timer;
    struct flb_sched *sched;

    sched = flb_malloc(sizeof(struct flb_sched));
    if (!sched) {
        flb_errno();
        return -1;
    }
    config->sched = sched;
    sched->config = config;

    /* Initialize lists */
    mk_list_init(&sched->requests);
    mk_list_init(&sched->requests_wait);
    mk_list_init(&sched->timers);
    mk_list_init(&sched->timers_drop);

    /* Create the frame timer who enqueue 'requests' for future time */
    timer = flb_sched_timer_create(sched);
    if (!timer) {
        flb_free(sched);
        return -1;
    }

    timer->type = FLB_SCHED_TIMER_FRAME;
    timer->data = sched;

    /* Initialize event */
    event = &timer->event;
    event->mask   = MK_EVENT_EMPTY;
    event->status = MK_EVENT_NONE;

    /* Create the frame timer */
    fd = mk_event_timeout_create(config->evl, FLB_SCHED_REQUEST_FRAME, 0,
                                 event);
    if (fd == -1) {
        flb_sched_timer_destroy(timer);
        flb_free(sched);
        return -1;
    }
    sched->frame_fd = fd;

    /*
     * Note: mk_event_timeout_create() sets a type = MK_EVENT_NOTIFICATION by
     * default, we need to overwrite this value so we can do a clean check
     * into the Engine when the event is triggered.
     */
    event->type = FLB_ENGINE_EV_SCHED_FRAME;

    return 0;
}

/* Release all resources used by the Scheduler */
int flb_sched_exit(struct flb_config *config)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_sched *sched;
    struct flb_sched_timer *timer;
    struct flb_sched_request *request;

    /* Delete requests */
    sched = config->sched;
    if (!sched) {
        return 0;
    }

    mk_list_foreach_safe(head, tmp, &sched->requests) {
        request = mk_list_entry(head, struct flb_sched_request, _head);
        flb_sched_request_destroy(config, request);
        c++; /* evil counter */
    }

    /* Delete requests on wait list */
    mk_list_foreach_safe(head, tmp, &sched->requests_wait) {
        request = mk_list_entry(head, struct flb_sched_request, _head);
        flb_sched_request_destroy(config, request);
        c++; /* evil counter */
    }

    /* Delete timers */
    mk_list_foreach_safe(head, tmp, &sched->timers) {
        timer = mk_list_entry(head, struct flb_sched_timer, _head);
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
    timer->data = NULL;

    /* Active timer (not invalidated) */
    timer->active = FLB_TRUE;
    mk_list_add(&timer->_head, &sched->timers);

    return timer;
}

void flb_sched_timer_invalidate(struct flb_sched_timer *timer)
{
    struct flb_sched *sched;

    sched  = timer->config->sched;

    timer->active = FLB_FALSE;
    mk_list_del(&timer->_head);
    mk_list_add(&timer->_head, &sched->timers_drop);
}

/* Destroy a timer context */
int flb_sched_timer_destroy(struct flb_sched_timer *timer)
{
    mk_event_timeout_destroy(timer->config->evl, &timer->event);
    if (timer->timer_fd > 0) {
        flb_sched_timer_cb_disable(timer);
    }

    mk_list_del(&timer->_head);
    flb_free(timer);
    return 0;
}

/* Used by the engine to cleanup pending timers waiting to be destroyed */
int flb_sched_timer_cleanup(struct flb_sched *sched)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_sched_timer *timer;

    mk_list_foreach_safe(head, tmp, &sched->timers_drop) {
        timer = mk_list_entry(head, struct flb_sched_timer, _head);
        flb_sched_timer_destroy(timer);
        c++;
    }

    return c;
}
