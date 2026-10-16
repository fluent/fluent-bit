/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_downstream_worker.h>
#include <fluent-bit/flb_pthread.h>
#include <fluent-bit/flb_time.h>
#ifdef FLB_SYSTEM_WINDOWS
#include <fluent-bit/flb_compat.h>
#endif

#include <string.h>

#include "flb_tests_internal.h"

struct downstream_worker_test_context {
    pthread_mutex_t mutex;
    struct flb_downstream_worker_runtime *runtime;
    int init_calls;
    int exit_calls;
    int foreach_calls;
    int worker_ids;
    int accessor_failures;
    int nested_foreach_failures;
    int nested_stop_failures;
    int fail_worker_id;
};

struct downstream_worker_foreach_call {
    struct flb_downstream_worker_runtime *runtime;
    int callback_calls;
    int result;
};

struct downstream_worker_stop_context {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    struct flb_downstream_worker_runtime *runtime;
    int callback_entered;
    int callback_released;
    int foreach_result;
    int stop_result;
};

static int downstream_worker_test_network_init(void)
{
#ifdef FLB_SYSTEM_WINDOWS
    int ret;
    WSADATA wsa_data;

    ret = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    TEST_CHECK(ret == 0);
    return ret;
#else
    return 0;
#endif
}

static void downstream_worker_test_network_cleanup(void)
{
#ifdef FLB_SYSTEM_WINDOWS
    WSACleanup();
#endif
}

static void downstream_worker_test_context_init(
    struct downstream_worker_test_context *context)
{
    memset(context, 0, sizeof(struct downstream_worker_test_context));
    pthread_mutex_init(&context->mutex, NULL);
    context->fail_worker_id = -1;
}

static void downstream_worker_test_context_destroy(
    struct downstream_worker_test_context *context)
{
    pthread_mutex_destroy(&context->mutex);
}

static int downstream_worker_test_init(struct flb_downstream_worker *worker,
                                       void *parent,
                                       void **worker_context)
{
    int worker_id;
    struct downstream_worker_test_context *context;

    context = parent;
    worker_id = flb_downstream_worker_id_get(worker);
    *worker_context = context;

    pthread_mutex_lock(&context->mutex);
    context->init_calls++;
    pthread_mutex_unlock(&context->mutex);

    if (worker_id == context->fail_worker_id) {
        return -1;
    }

    return 0;
}

static void downstream_worker_test_exit(struct flb_downstream_worker *worker,
                                        void *worker_context)
{
    struct downstream_worker_test_context *context;

    (void) worker;
    context = worker_context;

    pthread_mutex_lock(&context->mutex);
    context->exit_calls++;
    pthread_mutex_unlock(&context->mutex);
}

static void downstream_worker_test_noop(struct flb_downstream_worker *worker,
                                        void *worker_context,
                                        void *data)
{
    (void) worker;
    (void) worker_context;
    (void) data;
}

static void downstream_worker_test_count(struct flb_downstream_worker *worker,
                                         void *worker_context,
                                         void *data)
{
    struct downstream_worker_foreach_call *call;

    (void) worker;
    (void) worker_context;

    call = data;
    call->callback_calls++;
}

static void *downstream_worker_test_foreach_thread(void *data)
{
    struct downstream_worker_foreach_call *call;

    call = data;
    call->result = flb_downstream_worker_runtime_foreach(
        call->runtime, downstream_worker_test_count, call);

    return NULL;
}

static void downstream_worker_test_block(struct flb_downstream_worker *worker,
                                         void *worker_context,
                                         void *data)
{
    struct downstream_worker_stop_context *stop_context;

    (void) worker;
    (void) worker_context;

    stop_context = data;
    pthread_mutex_lock(&stop_context->mutex);
    stop_context->callback_entered = FLB_TRUE;
    pthread_cond_broadcast(&stop_context->condition);
    while (stop_context->callback_released == FLB_FALSE) {
        pthread_cond_wait(&stop_context->condition, &stop_context->mutex);
    }
    pthread_mutex_unlock(&stop_context->mutex);
}

static void *downstream_worker_test_stop_thread(void *data)
{
    struct downstream_worker_stop_context *stop_context;

    stop_context = data;
    stop_context->stop_result = flb_downstream_worker_runtime_stop(
        stop_context->runtime);

    return NULL;
}

static void *downstream_worker_test_blocking_foreach_thread(void *data)
{
    struct downstream_worker_stop_context *stop_context;

    stop_context = data;
    stop_context->foreach_result = flb_downstream_worker_runtime_foreach(
        stop_context->runtime, downstream_worker_test_block, stop_context);

    return NULL;
}

static void downstream_worker_test_foreach(struct flb_downstream_worker *worker,
                                           void *worker_context,
                                           void *data)
{
    int worker_count;
    int worker_id;
    int nested_foreach_result;
    int nested_stop_result;
    struct downstream_worker_test_context *context;

    (void) data;
    context = worker_context;
    worker_id = flb_downstream_worker_id_get(worker);
    worker_count = flb_downstream_worker_count_get(worker);

    nested_foreach_result = flb_downstream_worker_runtime_foreach(
        context->runtime, downstream_worker_test_noop, NULL);
    nested_stop_result = flb_downstream_worker_runtime_stop(context->runtime);

    pthread_mutex_lock(&context->mutex);
    context->foreach_calls++;

    if (worker_id < 0 || worker_id >= worker_count || worker_count != 2 ||
        flb_downstream_worker_event_loop_get(worker) == NULL) {
        context->accessor_failures++;
    }
    else {
        context->worker_ids |= (1 << worker_id);
    }

    if (nested_foreach_result != -1) {
        context->nested_foreach_failures++;
    }

    if (nested_stop_result != -1) {
        context->nested_stop_failures++;
    }
    pthread_mutex_unlock(&context->mutex);
}

void test_downstream_worker_validation()
{
    int ret;
    struct flb_downstream_worker_options options;
    struct flb_downstream_worker_runtime *runtime;

    memset(&options, 0, sizeof(struct flb_downstream_worker_options));
    runtime = (struct flb_downstream_worker_runtime *) 0x1;

    ret = flb_downstream_worker_runtime_start(&runtime, &options);
    TEST_CHECK(ret == -1);
    TEST_CHECK(runtime == NULL);
    TEST_CHECK(flb_downstream_worker_runtime_start(NULL, &options) == -1);
    TEST_CHECK(flb_downstream_worker_runtime_foreach(NULL,
                                                     downstream_worker_test_noop,
                                                     NULL) == -1);
    TEST_CHECK(flb_downstream_worker_runtime_stop(NULL) == 0);
    TEST_CHECK(flb_downstream_worker_event_loop_get(NULL) == NULL);
    TEST_CHECK(flb_downstream_worker_id_get(NULL) == -1);
    TEST_CHECK(flb_downstream_worker_count_get(NULL) == -1);
    TEST_CHECK(flb_downstream_worker_listener_fd_set(NULL,
                                                     FLB_INVALID_SOCKET) == -1);
}

void test_downstream_worker_lifecycle()
{
    int ret;
    struct downstream_worker_test_context context;
    struct flb_downstream_worker_options options;
    struct flb_downstream_worker_runtime *runtime;

    ret = downstream_worker_test_network_init();
    if (ret != 0) {
        return;
    }

    downstream_worker_test_context_init(&context);
    memset(&options, 0, sizeof(struct flb_downstream_worker_options));
    options.workers = 2;
    options.parent = &context;
    options.cb_init = downstream_worker_test_init;
    options.cb_exit = downstream_worker_test_exit;

    runtime = NULL;
    ret = flb_downstream_worker_runtime_start(&runtime, &options);
    TEST_CHECK(ret == 0);
    TEST_CHECK(runtime != NULL);
    if (ret != 0) {
        downstream_worker_test_context_destroy(&context);
        downstream_worker_test_network_cleanup();
        return;
    }

    context.runtime = runtime;
    ret = flb_downstream_worker_runtime_foreach(runtime,
                                                downstream_worker_test_foreach,
                                                NULL);
    TEST_CHECK(ret == 0);
    TEST_CHECK(context.init_calls == 2);
    TEST_CHECK(context.foreach_calls == 2);
    TEST_CHECK(context.worker_ids == 3);
    TEST_CHECK(context.accessor_failures == 0);
    TEST_CHECK(context.nested_foreach_failures == 0);
    TEST_CHECK(context.nested_stop_failures == 0);

    ret = flb_downstream_worker_runtime_stop(runtime);
    TEST_CHECK(ret == 0);
    TEST_CHECK(context.exit_calls == 2);

    downstream_worker_test_context_destroy(&context);
    downstream_worker_test_network_cleanup();
}

void test_downstream_worker_startup_rollback()
{
    int ret;
    struct downstream_worker_test_context context;
    struct flb_downstream_worker_options options;
    struct flb_downstream_worker_runtime *runtime;

    ret = downstream_worker_test_network_init();
    if (ret != 0) {
        return;
    }

    downstream_worker_test_context_init(&context);
    context.fail_worker_id = 1;

    memset(&options, 0, sizeof(struct flb_downstream_worker_options));
    options.workers = 3;
    options.parent = &context;
    options.cb_init = downstream_worker_test_init;
    options.cb_exit = downstream_worker_test_exit;

    runtime = (struct flb_downstream_worker_runtime *) 0x1;
    ret = flb_downstream_worker_runtime_start(&runtime, &options);
    TEST_CHECK(ret == -1);
    TEST_CHECK(runtime == NULL);
    TEST_CHECK(context.init_calls == 2);
    TEST_CHECK(context.exit_calls == 2);

    downstream_worker_test_context_destroy(&context);
    downstream_worker_test_network_cleanup();
}

void test_downstream_worker_concurrent_foreach()
{
    int i;
    int ret;
    int threads_created;
    pthread_t threads[4];
    struct downstream_worker_foreach_call calls[4];
    struct downstream_worker_test_context context;
    struct flb_downstream_worker_options options;
    struct flb_downstream_worker_runtime *runtime;

    ret = downstream_worker_test_network_init();
    if (ret != 0) {
        return;
    }

    downstream_worker_test_context_init(&context);
    memset(&options, 0, sizeof(struct flb_downstream_worker_options));
    options.workers = 2;
    options.parent = &context;
    options.cb_init = downstream_worker_test_init;
    options.cb_exit = downstream_worker_test_exit;

    runtime = NULL;
    ret = flb_downstream_worker_runtime_start(&runtime, &options);
    if (!TEST_CHECK(ret == 0)) {
        downstream_worker_test_context_destroy(&context);
        downstream_worker_test_network_cleanup();
        return;
    }

    memset(calls, 0, sizeof(calls));
    threads_created = 0;
    for (i = 0; i < 4; i++) {
        calls[i].runtime = runtime;
        ret = pthread_create(&threads[i], NULL,
                             downstream_worker_test_foreach_thread,
                             &calls[i]);
        if (!TEST_CHECK(ret == 0)) {
            break;
        }
        threads_created++;
    }

    for (i = 0; i < threads_created; i++) {
        ret = pthread_join(threads[i], NULL);
        TEST_CHECK(ret == 0);
        TEST_CHECK(calls[i].result == 0);
        TEST_CHECK(calls[i].callback_calls == 2);
    }

    ret = flb_downstream_worker_runtime_stop(runtime);
    TEST_CHECK(ret == 0);
    TEST_CHECK(context.exit_calls == 2);
    downstream_worker_test_context_destroy(&context);
    downstream_worker_test_network_cleanup();
}

void test_downstream_worker_stop_waits_for_foreach()
{
    int ret;
    pthread_t foreach_thread;
    pthread_t queued_foreach_thread;
    pthread_t stop_thread;
    struct downstream_worker_foreach_call queued_call;
    struct downstream_worker_stop_context stop_context;
    struct downstream_worker_test_context context;
    struct flb_downstream_worker_options options;
    struct flb_downstream_worker_runtime *runtime;

    ret = downstream_worker_test_network_init();
    if (ret != 0) {
        return;
    }

    downstream_worker_test_context_init(&context);
    memset(&options, 0, sizeof(struct flb_downstream_worker_options));
    options.workers = 1;
    options.parent = &context;
    options.cb_init = downstream_worker_test_init;
    options.cb_exit = downstream_worker_test_exit;

    runtime = NULL;
    ret = flb_downstream_worker_runtime_start(&runtime, &options);
    if (!TEST_CHECK(ret == 0)) {
        downstream_worker_test_context_destroy(&context);
        downstream_worker_test_network_cleanup();
        return;
    }

    memset(&stop_context, 0, sizeof(stop_context));
    pthread_mutex_init(&stop_context.mutex, NULL);
    pthread_cond_init(&stop_context.condition, NULL);
    stop_context.runtime = runtime;

    ret = pthread_create(&foreach_thread, NULL,
                         downstream_worker_test_blocking_foreach_thread,
                         &stop_context);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_downstream_worker_runtime_stop(runtime);
        goto cleanup;
    }

    pthread_mutex_lock(&stop_context.mutex);
    while (stop_context.callback_entered == FLB_FALSE) {
        pthread_cond_wait(&stop_context.condition, &stop_context.mutex);
    }
    pthread_mutex_unlock(&stop_context.mutex);

    memset(&queued_call, 0, sizeof(queued_call));
    queued_call.runtime = runtime;
    ret = pthread_create(&queued_foreach_thread, NULL,
                         downstream_worker_test_foreach_thread,
                         &queued_call);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        pthread_mutex_lock(&stop_context.mutex);
        stop_context.callback_released = FLB_TRUE;
        pthread_cond_broadcast(&stop_context.condition);
        pthread_mutex_unlock(&stop_context.mutex);
        pthread_join(foreach_thread, NULL);
        flb_downstream_worker_runtime_stop(runtime);
        goto cleanup;
    }

    /* Give the second operation time to enter admission and queue behind the
     * blocking foreach call before shutdown begins.
     */
    flb_time_msleep(50);

    ret = pthread_create(&stop_thread, NULL,
                         downstream_worker_test_stop_thread, &stop_context);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        pthread_mutex_lock(&stop_context.mutex);
        stop_context.callback_released = FLB_TRUE;
        pthread_cond_broadcast(&stop_context.condition);
        pthread_mutex_unlock(&stop_context.mutex);
        pthread_join(foreach_thread, NULL);
        pthread_join(queued_foreach_thread, NULL);
        flb_downstream_worker_runtime_stop(runtime);
        goto cleanup;
    }

    pthread_mutex_lock(&stop_context.mutex);
    stop_context.callback_released = FLB_TRUE;
    pthread_cond_broadcast(&stop_context.condition);
    pthread_mutex_unlock(&stop_context.mutex);

    ret = pthread_join(foreach_thread, NULL);
    TEST_CHECK(ret == 0);
    TEST_CHECK(stop_context.foreach_result == 0);

    ret = pthread_join(queued_foreach_thread, NULL);
    TEST_CHECK(ret == 0);
    TEST_CHECK(queued_call.result == 0);
    TEST_CHECK(queued_call.callback_calls == 1);

    ret = pthread_join(stop_thread, NULL);
    TEST_CHECK(ret == 0);
    TEST_CHECK(stop_context.stop_result == 0);
    TEST_CHECK(context.exit_calls == 1);

cleanup:
    pthread_cond_destroy(&stop_context.condition);
    pthread_mutex_destroy(&stop_context.mutex);
    downstream_worker_test_context_destroy(&context);
    downstream_worker_test_network_cleanup();
}

TEST_LIST = {
    { "downstream_worker_validation", test_downstream_worker_validation },
    { "downstream_worker_lifecycle", test_downstream_worker_lifecycle },
    { "downstream_worker_startup_rollback", test_downstream_worker_startup_rollback },
    { "downstream_worker_concurrent_foreach", test_downstream_worker_concurrent_foreach },
    { "downstream_worker_stop_waits_for_foreach", test_downstream_worker_stop_waits_for_foreach },
    { 0 }
};
