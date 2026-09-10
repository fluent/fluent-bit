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

struct test_worker_context {
    uint64_t exit_count;
    flb_pipefd_t result_writer;
};

static int test_worker_init(void *context, struct flb_config *config)
{
    struct test_worker_context *test_context;
    struct flb_out_thread_instance *thread_instance;

    (void) config;

    test_context = context;
    thread_instance = flb_output_thread_instance_get();
    test_context->result_writer = thread_instance->ch_thread_events[1];
    thread_instance->ch_thread_events[1] = FLB_INVALID_SOCKET;

    return 0;
}

static int test_worker_exit(void *context, struct flb_config *config)
{
    struct test_worker_context *test_context;

    (void) config;

    test_context = context;
    cfl_atomic_store(&test_context->exit_count,
                     cfl_atomic_load(&test_context->exit_count) + 1);

    return 0;
}

static void init_dropped_route(struct flb_task *task,
                               struct flb_task_route *route,
                               struct flb_output_instance *output,
                               int task_id)
{
    memset(task, 0, sizeof(*task));
    memset(route, 0, sizeof(*route));
    pthread_mutex_init(&task->lock, NULL);
    mk_list_init(&task->routes);
    mk_list_init(&task->retries);
    task->id = task_id;
    route->task = task;
    route->out = output;
    route->status = FLB_TASK_ROUTE_ACTIVE;
    route->dispatch_state = FLB_TASK_ROUTE_DISPATCH_UNQUEUED;
    mk_list_init(&route->_deferred_head);
    mk_list_add(&route->_head, &task->routes);
}

static void test_failed_wakeup_preserves_dispatch_ownership(void)
{
    int ret;
    char wakeups[3];
    flb_pipefd_t writer;
    struct flb_config *config;
    struct flb_log log;
    struct flb_output_instance output;
    struct flb_output_plugin plugin;
    struct flb_output_dispatch *dispatch_a;
    struct flb_output_dispatch *dispatch_b;
    struct flb_task task_a;
    struct flb_task task_b;
    struct flb_task_route route_a;
    struct flb_task_route route_b;
    struct flb_tp_thread *thread;
    struct flb_out_thread_instance *thread_instance;
    struct test_worker_context test_context;
#ifdef _WIN32
    WSADATA wsa_data;
#endif

    memset(wakeups, 0xa5, sizeof(wakeups));
    memset(&output, 0, sizeof(output));
    memset(&plugin, 0, sizeof(plugin));
    memset(&log, 0, sizeof(log));
    memset(&test_context, 0, sizeof(test_context));
    test_context.result_writer = FLB_INVALID_SOCKET;

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
    plugin.cb_worker_init = test_worker_init;
    plugin.cb_worker_exit = test_worker_exit;
    output.config = config;
    output.p = &plugin;
    output.context = &test_context;
    output.tp_workers = 1;
    output.log_level = FLB_LOG_OFF;
    output.ch_events[1] = FLB_INVALID_SOCKET;
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

    /* A closed queue leaves ownership with the caller. */
    init_dropped_route(&task_a, &route_a, &output, 1);
    dispatch_a = flb_output_dispatch_create(&task_a, &output, config);
    TEST_CHECK(dispatch_a != NULL);
    if (dispatch_a == NULL) {
        flb_output_thread_pool_start(&output);
        flb_output_thread_pool_destroy(&output);
        flb_pipe_close(test_context.result_writer);
        pthread_mutex_destroy(&task_a.lock);
        config->log = NULL;
        flb_config_exit(config);
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }
    thread_instance->dispatch_shutdown = FLB_TRUE;
    TEST_CHECK(flb_output_thread_pool_flush(dispatch_a) == -1);
    TEST_CHECK(dispatch_a->_head.next == &dispatch_a->_head);
    TEST_CHECK(dispatch_a->_head.prev == &dispatch_a->_head);
    thread_instance->dispatch_shutdown = FLB_FALSE;
    flb_output_dispatch_destroy(dispatch_a);

    /* Wake bytes carry no pointer data and a failed wake leaves queued ownership intact. */
    ret = flb_pipe_w(writer, wakeups, sizeof(wakeups));
    TEST_CHECK(ret == sizeof(wakeups));
    thread_instance->ch_parent_events[1] = FLB_INVALID_SOCKET;

    init_dropped_route(&task_b, &route_b, &output, 2);
    TEST_CHECK(flb_task_route_queue(&task_a, &output) == 0);
    TEST_CHECK(flb_task_route_queue(&task_b, &output) == 0);
    route_a.status = FLB_TASK_ROUTE_DROPPED;
    route_b.status = FLB_TASK_ROUTE_DROPPED;
    dispatch_a = flb_output_dispatch_create(&task_a, &output, config);
    dispatch_b = flb_output_dispatch_create(&task_b, &output, config);
    TEST_CHECK(dispatch_a != NULL);
    TEST_CHECK(dispatch_b != NULL);
    if (dispatch_a == NULL || dispatch_b == NULL) {
        if (dispatch_a != NULL) {
            flb_output_dispatch_destroy(dispatch_a);
        }
        if (dispatch_b != NULL) {
            flb_output_dispatch_destroy(dispatch_b);
        }
        flb_task_route_unqueue(&task_a, &output);
        flb_task_users_dec(&task_a, FLB_FALSE);
        flb_task_route_unqueue(&task_b, &output);
        flb_task_users_dec(&task_b, FLB_FALSE);
        flb_output_thread_pool_start(&output);
        flb_output_thread_pool_destroy(&output);
        flb_pipe_close(writer);
        flb_pipe_close(test_context.result_writer);
        pthread_mutex_destroy(&task_a.lock);
        pthread_mutex_destroy(&task_b.lock);
        config->log = NULL;
        flb_config_exit(config);
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }
    TEST_CHECK(flb_output_thread_pool_flush(dispatch_a) == 0);
    TEST_CHECK(flb_output_thread_pool_flush(dispatch_b) == 0);
    TEST_CHECK(mk_list_size(&thread_instance->dispatch_queue) == 2);

    flb_output_thread_pool_start(&output);
    TEST_CHECK(thread->status == FLB_THREAD_POOL_RUNNING);
    flb_output_thread_pool_destroy(&output);

    TEST_CHECK(output.tp == NULL);
    TEST_CHECK(cfl_atomic_load(&test_context.exit_count) == 1);
    TEST_CHECK(task_a.users == 0);
    TEST_CHECK(task_b.users == 0);
    TEST_CHECK(output.dispatches_inflight == 0);
    TEST_CHECK(route_a.dispatch_state == FLB_TASK_ROUTE_DISPATCH_UNQUEUED);
    TEST_CHECK(route_b.dispatch_state == FLB_TASK_ROUTE_DISPATCH_UNQUEUED);

    flb_pipe_close(writer);
    flb_pipe_close(test_context.result_writer);
    pthread_mutex_destroy(&task_a.lock);
    pthread_mutex_destroy(&task_b.lock);
    config->log = NULL;
    flb_config_exit(config);
#ifdef _WIN32
    WSACleanup();
#endif
}

TEST_LIST = {
    {"failed_wakeup_preserves_dispatch_ownership",
     test_failed_wakeup_preserves_dispatch_ownership},
    {0}
};
