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

#include <fluent-bit.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_notification.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_time.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "flb_tests_runtime.h"

#define SHUTDOWN_TIME_LIMIT_SEC 5   /* grace=2 + safety margin */
#define SHUTDOWN_WATCHDOG_SEC   10

struct shutdown_observer {
    int worker_exit_called;
    int exit_called;
    int worker_exit_on_pipeline_thread;
    int exit_after_worker_exit;
    int exit_on_worker_thread;
    int notification_enqueued;
    int notification_destroyed;
    pthread_t caller_thread;
    pthread_t worker_thread;
};

struct shutdown_notification {
    struct flb_notification base;
    struct shutdown_observer *observer;
};

static void shutdown_notification_destroy(void *data)
{
    struct shutdown_notification *notification = data;

    notification->observer->notification_destroyed++;
}

static int shutdown_observer_init(struct flb_output_instance *ins,
                                  struct flb_config *config, void *data)
{
    (void) config;

    flb_output_set_context(ins, data);
    return 0;
}

static void shutdown_observer_flush(struct flb_event_chunk *event_chunk,
                                    struct flb_output_flush *out_flush,
                                    struct flb_input_instance *i_ins,
                                    void *out_context,
                                    struct flb_config *config)
{
    (void) event_chunk;
    (void) i_ins;
    (void) out_context;
    (void) config;

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int shutdown_observer_worker_exit(void *data, struct flb_config *config)
{
    struct shutdown_observer *observer = data;
    struct shutdown_notification *notification;

    /* The main event loop has stopped before output workers exit. */
    notification = flb_calloc(1, sizeof(struct shutdown_notification));
    if (notification != NULL) {
        notification->base.dynamically_allocated = FLB_TRUE;
        notification->base.destructor = shutdown_notification_destroy;
        notification->observer = observer;
        if (flb_notification_enqueue(FLB_PLUGIN_INPUT, "lib.0",
                                     &notification->base, config) == 0) {
            observer->notification_enqueued++;
        }
        else {
            flb_notification_cleanup(&notification->base);
        }
    }

    observer->worker_exit_called++;
    observer->worker_thread = pthread_self();
    observer->worker_exit_on_pipeline_thread =
        pthread_equal(observer->worker_thread, observer->caller_thread) == 0;
    return 0;
}

static int shutdown_observer_exit(void *data, struct flb_config *config)
{
    struct shutdown_observer *observer = data;

    (void) config;

    observer->exit_called++;
    observer->exit_after_worker_exit = observer->worker_exit_called == 1;
    if (observer->exit_after_worker_exit) {
        observer->exit_on_worker_thread =
            pthread_equal(pthread_self(), observer->worker_thread) != 0;
    }
    return 0;
}

static struct flb_output_plugin shutdown_observer_plugin = {
    .name = "shutdown_observer",
    .description = "Observe library-mode engine shutdown",
    .cb_init = shutdown_observer_init,
    .cb_flush = shutdown_observer_flush,
    .cb_exit = shutdown_observer_exit,
    .cb_worker_exit = shutdown_observer_worker_exit,
    .flags = 0
};

static int register_shutdown_observer(flb_ctx_t *ctx)
{
    struct flb_output_plugin *plugin;

    plugin = flb_malloc(sizeof(struct flb_output_plugin));
    if (plugin == NULL) {
        return -1;
    }

    memcpy(plugin, &shutdown_observer_plugin,
           sizeof(struct flb_output_plugin));
    mk_list_add(&plugin->_head, &ctx->config->out_plugins);
    return 0;
}

/* Async-signal-safe abort used when flb_stop() hangs on a regression. */
static void timeout_abort(int sig)
{
    static const char msg[] =
        "\nFAIL: core shutdown test timed out; "
        "shutdown regression likely present.\n";
    (void) sig;
    (void) write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(1);
}

/* Regression: two back-to-back STOPs must not cause a shutdown busy-loop. */
void flb_test_duplicate_stop_no_spin(void)
{
    flb_ctx_t        *ctx;
    int               in_ffd;
    int               out_ffd;
    int64_t           ret;
    time_t            start;
    time_t            elapsed;
    struct sigaction  sa;

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);

    TEST_CHECK(flb_service_set(ctx,
                               "Flush",     "1",
                               "Grace",     "2",
                               "Log_Level", "info",
                               NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    out_ffd = flb_output(ctx, (char *) "null", NULL);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd, "match", "*", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");

    /* Let the engine enter its main event loop. */
    sleep(1);

    TEST_CHECK(flb_engine_exit(ctx->config) >= 0);

    /* Let the first STOP be processed before the second arrives. */
    usleep(100 * 1000);

    TEST_CHECK(flb_engine_exit(ctx->config) >= 0);

    /* Bound flb_stop() so a regression fails fast. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timeout_abort;
    sigaction(SIGALRM, &sa, NULL);
    alarm(SHUTDOWN_WATCHDOG_SEC);

    start = time(NULL);
    ret = flb_stop(ctx);
    elapsed = time(NULL) - start;

    alarm(0);

    TEST_CHECK_(ret == 0, "flb_stop returned %lld", (long long) ret);
    TEST_CHECK_(elapsed <= SHUTDOWN_TIME_LIMIT_SEC,
                "shutdown took %lds; expected <= %ds (shutdown spin?)",
                (long) elapsed, SHUTDOWN_TIME_LIMIT_SEC);

    if (ctx) {
        flb_destroy(ctx);
    }
}

static pthread_mutex_t worker_exit_mutex = PTHREAD_MUTEX_INITIALIZER;
static int worker_exit_started;
static int worker_exit_finished;

static int slow_worker_exit(void *context, struct flb_config *config)
{
    pthread_mutex_lock(&worker_exit_mutex);
    worker_exit_started++;
    pthread_mutex_unlock(&worker_exit_mutex);

    /* Keep the engine in pthread_join() when the caller invokes flb_stop(). */
    flb_time_msleep(300);

    pthread_mutex_lock(&worker_exit_mutex);
    worker_exit_finished++;
    pthread_mutex_unlock(&worker_exit_mutex);
    return 0;
}

static void flb_test_stop_waits_for_output_workers(void)
{
    flb_ctx_t *ctx;
    struct flb_output_instance *output;
    struct flb_output_plugin plugin;
    int out_ffd;
    int started;
    int finished;
    int i;

    worker_exit_started = 0;
    worker_exit_finished = 0;
    ctx = flb_create();
    TEST_ASSERT(ctx != NULL);
    TEST_ASSERT(flb_service_set(ctx, "Grace", "1", "Log_Level", "error", NULL) == 0);
    TEST_ASSERT(flb_input(ctx, "lib", NULL) >= 0);
    out_ffd = flb_output(ctx, "null", NULL);
    TEST_ASSERT(out_ffd >= 0);
    TEST_ASSERT(flb_output_set(ctx, out_ffd, "match", "*", "workers", "2", NULL) == 0);

    output = mk_list_entry_first(&ctx->config->outputs, struct flb_output_instance, _head);
    plugin = *output->p;
    plugin.cb_worker_exit = slow_worker_exit;
    output->p = &plugin;
    TEST_ASSERT(flb_start(ctx) == 0);
    TEST_ASSERT(flb_engine_exit(ctx->config) >= 0);

    started = 0;
    for (i = 0; i < 500 && started == 0; i++) {
        flb_time_msleep(10);
        pthread_mutex_lock(&worker_exit_mutex);
        started = worker_exit_started;
        pthread_mutex_unlock(&worker_exit_mutex);
    }
    TEST_ASSERT(started > 0);
    TEST_CHECK(flb_stop(ctx) == 0);

    pthread_mutex_lock(&worker_exit_mutex);
    finished = worker_exit_finished;
    pthread_mutex_unlock(&worker_exit_mutex);
    TEST_CHECK_(finished == 2, "only %d of 2 workers exited before flb_stop returned", finished);
    if (finished != 2) {
        /* A cancelled engine may leave workers using the context until process exit. */
        return;
    }
    flb_destroy(ctx);
}

/* Regression: flb_stop() must wait for pipeline-owned cleanup to finish. */
void flb_test_stop_waits_for_cleanup(void)
{
    int in_ffd;
    int out_ffd;
    int ret;
    flb_ctx_t *ctx;
    struct sigaction sa;
    struct shutdown_observer observer;

    memset(&observer, 0, sizeof(observer));
    observer.caller_thread = pthread_self();

    ctx = flb_create();
    TEST_CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }

    TEST_CHECK(register_shutdown_observer(ctx) == 0);
    TEST_CHECK(flb_service_set(ctx,
                               "Flush",     "1",
                               "Grace",     "1",
                               "Log_Level", "error",
                               NULL) == 0);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    TEST_CHECK(flb_input_set(ctx, in_ffd, "tag", "test", NULL) == 0);

    out_ffd = flb_output(ctx, (char *) "shutdown_observer",
                         (struct flb_lib_out_cb *) &observer);
    TEST_CHECK(out_ffd >= 0);
    TEST_CHECK(flb_output_set(ctx, out_ffd, "match", "*", NULL) == 0);

    ret = flb_start(ctx);
    TEST_CHECK_(ret == 0, "starting engine");
    if (ret != 0) {
        flb_destroy(ctx);
        return;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timeout_abort;
    sigaction(SIGALRM, &sa, NULL);
    alarm(SHUTDOWN_WATCHDOG_SEC);

    ret = flb_stop(ctx);

    alarm(0);
    TEST_CHECK_(ret == 0, "flb_stop returned %d", ret);
    TEST_CHECK(observer.worker_exit_called == 1);
    TEST_CHECK(observer.notification_enqueued == 1);
    TEST_CHECK(observer.notification_destroyed == 1);
    TEST_CHECK(observer.exit_called == 1);
    TEST_CHECK(observer.worker_exit_on_pipeline_thread != 0);
    TEST_CHECK(observer.exit_after_worker_exit != 0);
    TEST_CHECK(observer.exit_on_worker_thread != 0);
    TEST_CHECK(ctx->config->is_running == FLB_FALSE);

    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"duplicate_stop_no_spin", flb_test_duplicate_stop_no_spin},
    {"stop_waits_for_output_workers", flb_test_stop_waits_for_output_workers},
    {"stop_waits_for_cleanup", flb_test_stop_waits_for_cleanup},
    {NULL, NULL}
};
