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

#include <monkey/mk_core.h>

#include "mk_tests.h"

#ifdef _WIN32
struct test_event_map {
    evutil_socket_t pipe[2];
};
#endif

static int consume_timer_tick(int fd, uint64_t *val)
{
#ifdef _WIN32
    return recv(fd, (char *) val, sizeof(*val), MSG_WAITALL);
#else
    return read(fd, val, sizeof(*val));
#endif
}

void test_timeout_tick_destroy(void)
{
    int ret;
    int tries;
    struct mk_event_loop *evl;
    struct mk_event *fired;
    struct mk_event ev = {0};
    uint64_t tick = 0;
    int fd;
    int timeout_interval = 1;

    TEST_CHECK(mk_event_init() == 0);

    evl = mk_event_loop_create(4);
    TEST_ASSERT(evl != NULL);

    fd = mk_event_timeout_create(evl, timeout_interval, 0, &ev);
    TEST_ASSERT(fd >= 0);
    TEST_ASSERT(ev.fd == fd);

    ret = 0;
    for (tries = 0; tries < 2 && ret == 0; tries++) {
        ret = mk_event_wait_2(evl, 1500);
    }
    TEST_ASSERT(ret == 1);

    fired = NULL;
    mk_event_foreach(fired, evl) {
        TEST_ASSERT(fired == &ev);
        TEST_ASSERT((fired->mask & MK_EVENT_READ) != 0);
        break;
    }

    ret = consume_timer_tick(ev.fd, &tick);
    TEST_ASSERT(ret == sizeof(tick));
    TEST_ASSERT(tick == 1);

    ret = mk_event_timeout_destroy(evl, &ev);
    TEST_ASSERT(ret == 0);

    mk_event_loop_destroy(evl);
}

#ifdef _WIN32
void test_timeout_notification_backpressure(void)
{
    int fd;
    int ret;
    int error;
    DWORD send_timeout;
    uint64_t tick;
    struct test_event_map *event_map;
    struct mk_event_loop *evl;
    struct mk_event ev = {0};

    TEST_CHECK(mk_event_init() == 0);

    evl = mk_event_loop_create(4);
    TEST_ASSERT(evl != NULL);

    fd = mk_event_timeout_create(evl, 0, 1000, &ev);
    TEST_ASSERT(fd >= 0);

    event_map = ev.data;
    TEST_ASSERT(event_map != NULL);

    send_timeout = 100;
    ret = setsockopt(event_map->pipe[1], SOL_SOCKET, SO_SNDTIMEO,
                     (const char *) &send_timeout, sizeof(send_timeout));
    TEST_ASSERT(ret == 0);

    tick = 1;
    do {
        ret = send(event_map->pipe[1], (char *) &tick, sizeof(tick), 0);
    } while (ret > 0);

    error = WSAGetLastError();
    TEST_ASSERT(ret == SOCKET_ERROR);
    TEST_ASSERT(error == WSAEWOULDBLOCK);

    ret = mk_event_wait_2(evl, 100);
    TEST_ASSERT(ret == 1);
    TEST_ASSERT(ev.data == event_map);

    ret = mk_event_timeout_destroy(evl, &ev);
    TEST_ASSERT(ret == 0);

    mk_event_loop_destroy(evl);
}
#endif

TEST_LIST = {
    {
        "timeout_create_tick_destroy",
        test_timeout_tick_destroy,
    },
#ifdef _WIN32
    {
        "timeout_notification_backpressure",
        test_timeout_notification_backpressure,
    },
#endif
    {NULL, NULL}
};
