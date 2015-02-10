/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_engine.h>

static int collector_fd(time_t sec, long nsec)
{
    int ret;
    int timer_fd;
    struct timeval tv;
    struct timezone tz;
    struct itimerspec its;

    gettimeofday(&tv, &tz);

    /* expiration interval */
    its.it_interval.tv_sec  = sec;
    its.it_interval.tv_nsec = nsec;

    /* initial expiration */
    its.it_value.tv_sec  = tv.tv_sec + sec;
    its.it_value.tv_nsec = (tv.tv_usec * 1000) + nsec;

    timer_fd = timerfd_create(CLOCK_REALTIME, 0);
    if (timer_fd == -1) {
        perror("timerfd");
        return -1;
    }

    ret = timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &its, NULL);
    if (ret < 0) {
        perror("timerfd_settime");
        return -1;
    }

    return timer_fd;
}

static int flb_engine_loop_create()
{
    int efd;

    efd = epoll_create(1000);
    if (efd == -1) {
        perror("epoll_create");
        return -1;
    }
}

static int flb_engine_loop_add(int efd, int fd, int mode)
{
    int ret;
    struct epoll_event event = {0, {0}};

    event.data.fd = fd;
    event.events = EPOLLERR | EPOLLHUP | EPOLLRDHUP | mode;

    ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    if (ret == -1) {
        perror("epoll_ctl");
        return -1;
    }
}

static int flb_engine_handle_event(int fd, int mask, struct flb_config *config)
{
    int ret;
    uint64_t val;
    struct mk_list *head;
    struct flb_input_collector *collector;

    if (mask & FLB_ENGINE_READ) {
        ret = read(fd, &val, sizeof(val));
        if (ret <= 0) {
            perror("read");
            return -1;
        }

        /* As of now, it should be a collector */
        mk_list_foreach(head, &config->collectors) {
            collector = mk_list_entry(head, struct flb_input_collector, _head);
            if (collector->timer == fd) {
                collector->cb_collect(collector->plugin->in_context);
                return 0;
            }
        }
    }
}

int flb_engine_start(struct flb_config *config)
{
    int i;
    int fd;
    int ret;
    int mask;
    int loop;
    int nfds;
    int size = 64;
    struct mk_list *head;
    struct epoll_event *events;
    struct flb_input_collector *collector;

    flb_info("starting engine");

    loop = flb_engine_loop_create();
    if (loop == -1) {
        return -1;
    }

    events = malloc(sizeof(struct epoll_event) * size);
    if (!events) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    /* For each Collector, register the event into the main loop */
    mk_list_foreach(head, &config->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);
        fd = collector_fd(collector->seconds, collector->nanoseconds);
        if (fd == -1) {
            continue;
        }

        ret = flb_engine_loop_add(loop, fd, FLB_ENGINE_READ);
        if (ret == -1) {
            close(fd);
            continue;
        }
        collector->timer = fd;
    }

    while (1) {
        nfds = epoll_wait(loop, events, size, -1);

        for (i = 0; i < nfds; i++) {
            fd = events[i].data.fd;
            mask = events[i].events;

            flb_engine_handle_event(fd, mask, config);
        }
    }
}
