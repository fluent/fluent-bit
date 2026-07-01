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

#ifndef _WIN32
#include <unistd.h>
#include <sys/timerfd.h>
#endif

#include <monkey/mk_lib.h>
#include <monkey/monkey.h>

#include "mk_tests.h"

static void consume_timer_tick(int fd) 
{
    int ret;
    uint64_t val;
#ifdef _WIN32
    ret = recv(fd, &val, sizeof(val), 0);
#else
    ret = read(fd, &val, sizeof(val));
#endif
    TEST_ASSERT(ret >= 0);
}

#ifdef _WIN32
static void check_timer_invalidated(int fd) 
{
}
#else
static void check_timer_invalidated(int fd) 
{
    struct itimerspec timer_spec;
    TEST_ASSERT(timerfd_gettime(fd, &timer_spec) == -1);
}
#endif

void test_timeout_tick_destroy(void)
{
    struct mk_event_loop *evl;
    struct mk_event *ev;
    int fd;
    int timeout_interval = 1;

    evl = mk_event_loop_create(1);
    ev = mk_mem_alloc_z(sizeof(struct mk_event*));
    fd = mk_event_timeout_create(evl, timeout_interval, 0, ev);
    TEST_ASSERT(ev->fd == fd);

    consume_timer_tick(ev->fd);
    mk_event_timeout_destroy(evl, ev);

    check_timer_invalidated(fd);
}

TEST_LIST = {
    {
        "timeout_create_tick_destroy",
        test_timeout_tick_destroy,
    },
    {NULL, NULL}
};
