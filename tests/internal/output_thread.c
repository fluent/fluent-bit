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

#include <stdint.h>
#include <string.h>

#include <cfl/cfl_atomic.h>

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_lib.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_output_thread.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_thread_pool.h>

#include "flb_tests_internal.h"

static int test_worker_exit(void *context, struct flb_config *config)
{
    uint64_t *exit_count;

    (void) config;

    exit_count = context;
    cfl_atomic_store(exit_count, cfl_atomic_load(exit_count) + 1);

    return 0;
}

static void test_stop_write_failure_joins_worker(void)
{
    int ret;
    char fragment;
    uint64_t exit_count;
    flb_pipefd_t writer;
    struct flb_config *config;
    struct flb_log log;
    struct flb_output_instance output;
    struct flb_output_plugin plugin;
    struct flb_tp_thread *thread;
    struct flb_out_thread_instance *thread_instance;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    exit_count = 0;
    fragment = 0;
    memset(&output, 0, sizeof(output));
    memset(&plugin, 0, sizeof(plugin));
    memset(&log, 0, sizeof(log));

#ifdef _WIN32
    ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        return;
    }
#endif

    flb_init_env();
    flb_sched_ctx_init();

    config = flb_config_init();
    TEST_CHECK(config != NULL);
    if (config == NULL) {
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }
    log.level = FLB_LOG_OFF;
    config->log = &log;

    plugin.name = "output_thread_test";
    plugin.cb_worker_exit = test_worker_exit;
    output.config = config;
    output.p = &plugin;
    output.context = &exit_count;
    output.tp_workers = 1;
    output.log_level = FLB_LOG_OFF;
    memcpy(output.name, plugin.name, strlen(plugin.name) + 1);
    mk_list_init(&output.upstreams);

    ret = flb_output_thread_pool_create(config, &output);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        config->log = NULL;
        flb_config_exit(config);
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }
    TEST_CHECK(mk_list_size(&output.tp->list_threads) == 1);
    if (mk_list_is_empty(&output.tp->list_threads) == 0) {
        flb_output_thread_pool_destroy(&output);
        config->log = NULL;
        flb_config_exit(config);
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    thread = mk_list_entry_first(&output.tp->list_threads,
                                 struct flb_tp_thread, _head);
    thread_instance = thread->params.data;
    writer = thread_instance->ch_parent_events[1];

    /* Leave an incomplete dispatch frame queued, then force the stop write to fail. */
    ret = flb_pipe_w(writer, &fragment, sizeof(fragment));
    TEST_CHECK(ret == sizeof(fragment));
    thread_instance->ch_parent_events[1] = FLB_INVALID_SOCKET;

    flb_output_thread_pool_start(&output);
    TEST_CHECK(thread->status == FLB_THREAD_POOL_RUNNING);
    flb_output_thread_pool_destroy(&output);

    TEST_CHECK(output.tp == NULL);
    TEST_CHECK(cfl_atomic_load(&exit_count) == 1);

    flb_pipe_close(writer);
    config->log = NULL;
    flb_config_exit(config);
#ifdef _WIN32
    WSACleanup();
#endif
}

TEST_LIST = {
    {"stop_write_failure_joins_worker", test_stop_write_failure_joins_worker},
    {0}
};
