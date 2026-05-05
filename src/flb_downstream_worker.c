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

#include <fluent-bit/flb_downstream_worker.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_network.h>

#include <string.h>

struct flb_downstream_worker_runtime {
    struct flb_downstream_worker *workers;
    int worker_count;
    int active_workers;
    struct flb_config *config;
    void *parent;
    flb_downstream_worker_init_cb cb_init;
    flb_downstream_worker_exit_cb cb_exit;
    flb_downstream_worker_maintenance_cb cb_maintenance;
};

static void downstream_worker_context_reset(struct flb_downstream_worker *worker)
{
    memset(worker, 0, sizeof(struct flb_downstream_worker));
    pthread_mutex_init(&worker->mutex, NULL);
    pthread_cond_init(&worker->condition, NULL);
}

static void downstream_worker_context_cleanup(struct flb_downstream_worker *worker)
{
    pthread_mutex_destroy(&worker->mutex);
    pthread_cond_destroy(&worker->condition);
}

static void *downstream_worker_thread(void *data)
{
    int ret;
    struct mk_event *event;
    struct flb_net_dns dns_ctx = {0};
    struct flb_downstream_worker *worker;
    struct flb_downstream_worker_runtime *runtime;

    worker = data;
    runtime = worker->runtime;

    worker->event_loop = mk_event_loop_create(256);
    if (worker->event_loop == NULL) {
        ret = -1;
        goto signal_and_exit;
    }

    flb_engine_evl_set(worker->event_loop);
    flb_net_ctx_init(&dns_ctx);
    flb_net_dns_ctx_set(&dns_ctx);

    ret = runtime->cb_init(worker, runtime->parent, &worker->context);

signal_and_exit:
    pthread_mutex_lock(&worker->mutex);
    worker->startup_result = ret;
    worker->initialized = FLB_TRUE;
    pthread_cond_signal(&worker->condition);
    pthread_mutex_unlock(&worker->mutex);

    if (ret != 0) {
        goto cleanup;
    }

    while (atomic_load(&worker->should_exit) == FLB_FALSE) {
        mk_event_wait_2(worker->event_loop, 250);

        mk_event_foreach(event, worker->event_loop) {
            if (event->type == FLB_ENGINE_EV_CUSTOM) {
                event->handler(event);
            }
        }

        if (runtime->cb_maintenance != NULL) {
            runtime->cb_maintenance(worker, worker->context);
        }
    }

cleanup:
    if (runtime->cb_exit != NULL && worker->context != NULL) {
        runtime->cb_exit(worker, worker->context);
        worker->context = NULL;
    }

    if (worker->event_loop != NULL) {
        mk_event_loop_destroy(worker->event_loop);
        worker->event_loop = NULL;
    }

    return NULL;
}

int flb_downstream_worker_runtime_start(struct flb_downstream_worker_runtime **out_runtime,
                                        struct flb_downstream_worker_options *options)
{
    int i;
    int ret;
    struct flb_downstream_worker_runtime *runtime;

    if (out_runtime == NULL || options == NULL || options->workers <= 0 ||
        options->cb_init == NULL) {
        return -1;
    }

    runtime = flb_calloc(1, sizeof(struct flb_downstream_worker_runtime));
    if (runtime == NULL) {
        flb_errno();
        return -1;
    }

    runtime->workers = flb_calloc(options->workers,
                                  sizeof(struct flb_downstream_worker));
    if (runtime->workers == NULL) {
        flb_errno();
        flb_free(runtime);
        return -1;
    }

    runtime->worker_count = options->workers;
    runtime->config = options->config;
    runtime->parent = options->parent;
    runtime->cb_init = options->cb_init;
    runtime->cb_exit = options->cb_exit;
    runtime->cb_maintenance = options->cb_maintenance;

    *out_runtime = runtime;

    for (i = 0; i < runtime->worker_count; i++) {
        downstream_worker_context_reset(&runtime->workers[i]);
        runtime->active_workers++;
        runtime->workers[i].runtime = runtime;
        runtime->workers[i].parent = runtime->parent;
        runtime->workers[i].worker_id = i;
        runtime->workers[i].worker_count = runtime->worker_count;

        ret = pthread_create(&runtime->workers[i].thread,
                             NULL,
                             downstream_worker_thread,
                             &runtime->workers[i]);
        if (ret != 0) {
            runtime->workers[i].startup_result = -1;
            break;
        }

        runtime->workers[i].thread_created = FLB_TRUE;
        pthread_mutex_lock(&runtime->workers[i].mutex);
        while (runtime->workers[i].initialized == FLB_FALSE) {
            pthread_cond_wait(&runtime->workers[i].condition,
                              &runtime->workers[i].mutex);
        }
        ret = runtime->workers[i].startup_result;
        pthread_mutex_unlock(&runtime->workers[i].mutex);

        if (ret != 0) {
            break;
        }
    }

    if (i != runtime->worker_count) {
        flb_downstream_worker_runtime_stop(runtime);
        *out_runtime = NULL;
        return -1;
    }

    return 0;
}

void flb_downstream_worker_runtime_stop(struct flb_downstream_worker_runtime *runtime)
{
    int i;

    if (runtime == NULL) {
        return;
    }

    for (i = 0; i < runtime->active_workers; i++) {
        atomic_store(&runtime->workers[i].should_exit, FLB_TRUE);
        if (runtime->workers[i].thread_created == FLB_TRUE) {
            pthread_join(runtime->workers[i].thread, NULL);
        }
        downstream_worker_context_cleanup(&runtime->workers[i]);
    }

    flb_free(runtime->workers);
    flb_free(runtime);
}

void flb_downstream_worker_runtime_foreach(struct flb_downstream_worker_runtime *runtime,
                                           flb_downstream_worker_foreach_cb callback,
                                           void *data)
{
    int i;

    if (runtime == NULL || callback == NULL) {
        return;
    }

    for (i = 0; i < runtime->worker_count; i++) {
        if (runtime->workers[i].context != NULL) {
            callback(&runtime->workers[i],
                     runtime->workers[i].context,
                     data);
        }
    }
}
