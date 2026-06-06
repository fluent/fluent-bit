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

TEST_LIST = {
    {
        "timeout_create_tick_destroy",
        test_timeout_tick_destroy,
    },
    {NULL, NULL}
};
