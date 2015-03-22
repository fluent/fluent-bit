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

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>

static int timer_fd(time_t sec, long nsec)
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

    return efd;
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

    return ret;
}

int flb_engine_flush(struct flb_config *config, struct flb_input_plugin *in_force)
{
    int fd;
    int size;
    int len;
    int bytes;
    char *buf;
    struct iovec *iov;
    struct mk_list *head;
    struct flb_input_plugin *in;

    /*
     * Lazy flush: it does a connect in blocking mode, this needs
     * to be changed later and be integrated with the main loop.
     */
    fd = flb_net_tcp_connect(config->out_host, config->out_port);
    if (fd == -1) {
        flb_error("Error connecting to output service");
        return -1;
    }

    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_plugin, _head);

        if (in_force != NULL && in != in_force) {
            continue;
        }

        if (in->active == FLB_TRUE) {
            if (in->cb_flush_buf) {
                buf = in->cb_flush_buf(in->in_context, &size);
                if (!buf) {
                    goto flush_done;
                }

                bytes = write(fd, buf, size);
                if (bytes <= 0) {
                    perror("write");
                }
                else {
                    flb_info("Flush buf %i bytes", bytes);
                }
                free(buf);
            }

            if (in->cb_flush_iov) {
                iov = in->cb_flush_iov(in->in_context, &len);
                if (len <= 0) {
                    goto flush_done;
                }

                bytes = writev(fd, iov, len);
                if (bytes <= 0) {
                    perror("writev");
                }
                else {
                    flb_info("Flush iov %i bytes (%i entries)", bytes, len);
                }
            }

        flush_done:
            if (in->cb_flush_end) {
                in->cb_flush_end(in->in_context);
            }
        }
    }
    close(fd);
    return 0;
}

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

static int flb_engine_handle_event(int fd, int mask, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_collector *collector;

    if (mask & FLB_ENGINE_READ) {
        /* Check if we need to flush */
        if (config->flush_fd == fd) {
            consume_byte(fd);
            flb_engine_flush(config, NULL);
            return 0;
        }

        /* Determinate what is this file descriptor */
        mk_list_foreach(head, &config->collectors) {
            collector = mk_list_entry(head, struct flb_input_collector, _head);
            if (collector->fd_event == fd) {
                return collector->cb_collect(config,
                                             collector->plugin->in_context);
            }
            else if (collector->fd_timer == fd) {
                consume_byte(fd);
                return collector->cb_collect(config,
                                             collector->plugin->in_context);
            }
        }
    }

    return -1;
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

    /* Inputs pre-run */
    flb_input_pre_run_all(config);

    /* main loop */
    loop = flb_engine_loop_create();
    if (loop == -1) {
        return -1;
    }

    /* Allocate space for the events */
    events = malloc(sizeof(struct epoll_event) * size);
    if (!events) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    /* Create and register the timer fd for flush procedure */
    config->flush_fd = timer_fd(config->flush, 0);
    if (config->flush_fd == -1) {
        flb_utils_error(FLB_ERR_CFG_FLUSH_CREATE);
    }
    ret = flb_engine_loop_add(loop, config->flush_fd, FLB_ENGINE_READ);
    if (ret == -1) {
        flb_utils_error(FLB_ERR_CFG_FLUSH_REGISTER);
    }

    /* For each Collector, register the event into the main loop */
    mk_list_foreach(head, &config->collectors) {
        collector = mk_list_entry(head, struct flb_input_collector, _head);

        if (collector->type == FLB_COLLECT_TIME) {
            fd = timer_fd(collector->seconds, collector->nanoseconds);
            if (fd == -1) {
                continue;
            }
            ret = flb_engine_loop_add(loop, fd, FLB_ENGINE_READ);
            if (ret == -1) {
                close(fd);
                continue;
            }
            collector->fd_timer = fd;
        }
        else if (collector->type == FLB_COLLECT_FD_EVENT) {
            ret = flb_engine_loop_add(loop, collector->fd_event,
                                      FLB_ENGINE_READ);
            if (ret == -1) {
                close(fd);
                continue;
            }
        }
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
