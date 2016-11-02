/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_engine_dispatch.h>

#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>

/* Consume an unsigned 64 bit number from fd */
static inline int consume_byte(int fd)
{
    int ret;
    uint64_t val;

    /* We need to consume the byte */
    ret = read(fd, &val, sizeof(val));
    if (ret <= 0) {
        perror("read");
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
 * The 'backoff full jitter' algorithm implements a capped backoff with a jitter
 * to generate numbers to be used as 'wait times', this implementation is fully
 * based on the following article:
 *
 *   https://www.awsarchitectureblog.com/2015/03/backoff.html
 */
static int backoff_full_jitter(int base, int cap, int n)
{
    int exp;

    exp = MIN(cap, pow(2, n) * base);
    return random_uniform(0, exp);
}

/* Schedule the 'retry' for a thread buffer flush */
int flb_sched_request_create(struct flb_config *config,
                             void *data, int tries)
{
    int fd;
    int seconds;
    struct mk_event *event;
    struct flb_sched_request *request;

    /* Allocate request node */
    request = flb_malloc(sizeof(struct flb_sched_request));
    if (!request) {
        perror("malloc");
        return -1;
    }

    /* Initialize event */
    event = &request->event;
    event->mask   = MK_EVENT_EMPTY;
    event->status = MK_EVENT_NONE;

    /* Get suggested wait_time for this request */
    seconds = backoff_full_jitter(FLB_SCHED_BASE, FLB_SCHED_CAP, tries);

    /* Create a timeout into the main event loop */
    fd = mk_event_timeout_create(config->evl, seconds, 0, event);
    if (fd == -1) {
        flb_free(request);
        return -1;
    }

    /*
     * Note: mk_event_timeout_create() sets a type = MK_EVENT_NOTIFICATION by
     * default, we need to overwrite this value so we can do a clean check
     * into the Engine when the event is triggered.
     */
    event->type      = FLB_ENGINE_EV_SCHED;
    request->fd      = fd;
    request->created = time(NULL);
    request->timeout = seconds;
    request->data    = data;

    mk_list_add(&request->_head, &config->sched_requests);
    return seconds;
}

int flb_sched_request_destroy(struct flb_config *config,
                              struct flb_sched_request *req)
{
    mk_event_del(config->evl, &req->event);
    close(req->fd);
    mk_list_del(&req->_head);
    flb_free(req);

    return 0;
}

/* Handle a timeout event set by a previous flb_sched_request_create(...) */
int flb_sched_event_handler(struct flb_config *config, struct mk_event *event)
{
    struct flb_sched_request *req;

    req = (struct flb_sched_request *) event;
    consume_byte(req->fd);

    /* Dispatch 'retry' */
    flb_engine_dispatch_retry(req->data, config);

    /* Destroy this scheduled request, it's not longer required */
    flb_sched_request_destroy(config, req);

    return 0;
}

/* Release all resources used by the Scheduler */
int flb_sched_exit(struct flb_config *config)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_sched_request *request;

    mk_list_foreach_safe(head, tmp, &config->sched_requests) {
        request = mk_list_entry(head, struct flb_sched_request, _head);
        flb_sched_request_destroy(config, request);
        c++;
    }

    return c;
}
