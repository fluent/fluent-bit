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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_scheduler.h>

#include "flb_tests_internal.h"

static void test_scheduler_event_channel_cleanup(void)
{
    int ret;
    char data = '\0';
    flb_pipefd_t read_fd[2];
    flb_pipefd_t write_fd[2];
    struct flb_sched *sched[2];
    struct flb_config *config;
    struct mk_event_loop *evl;
#ifdef FLB_SYSTEM_WINDOWS
    WSADATA wsa_data;

    ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (!TEST_CHECK(ret == 0)) {
        return;
    }
#endif

    config = flb_config_init();
    if (!TEST_CHECK(config != NULL)) {
        goto socket_cleanup;
    }

    config->evl = mk_event_loop_create(8);
    if (!TEST_CHECK(config->evl != NULL)) {
        flb_config_exit(config);
        goto socket_cleanup;
    }

    sched[0] = flb_sched_create(config, config->evl);
    if (!TEST_CHECK(sched[0] != NULL)) {
        flb_config_exit(config);
        goto socket_cleanup;
    }
    config->sched = sched[0];

    evl = mk_event_loop_create(8);
    if (!TEST_CHECK(evl != NULL)) {
        flb_config_exit(config);
        goto socket_cleanup;
    }

    sched[1] = flb_sched_create(config, evl);
    if (!TEST_CHECK(sched[1] != NULL)) {
        mk_event_loop_destroy(evl);
        flb_config_exit(config);
        goto socket_cleanup;
    }

    read_fd[0] = sched[0]->ch_events[0];
    write_fd[0] = sched[0]->ch_events[1];
    read_fd[1] = sched[1]->ch_events[0];
    write_fd[1] = sched[1]->ch_events[1];

    flb_sched_destroy(sched[1]);
    mk_event_loop_destroy(evl);

    flb_sched_destroy(sched[0]);
    config->sched = NULL;

    ret = flb_pipe_w(write_fd[0], &data, sizeof(data));
    TEST_CHECK(ret == -1);

    ret = flb_pipe_r(read_fd[0], &data, sizeof(data));
    TEST_CHECK(ret == -1);

    ret = flb_pipe_w(write_fd[1], &data, sizeof(data));
    TEST_CHECK(ret == -1);

    ret = flb_pipe_r(read_fd[1], &data, sizeof(data));
    TEST_CHECK(ret == -1);

    flb_config_exit(config);

socket_cleanup:
    (void) ret;
#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

TEST_LIST = {
    {"event_channel_cleanup", test_scheduler_event_channel_cleanup},
    {NULL, NULL}
};
