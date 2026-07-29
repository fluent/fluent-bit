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

#include <cfl/cfl_atomic.h>

#include <fluent-bit/flb_downstream_worker.h>
#include <fluent-bit/flb_connection.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_pthread.h>

#include <monkey/mk_core.h>

#include <string.h>

struct flb_downstream_worker {
    struct flb_downstream_worker_runtime *runtime;
    struct mk_event_loop *event_loop;
    struct mk_event control_event;
    flb_pipefd_t control_channel[2];
    flb_sockfd_t listener_fd;
    void *context;
    int worker_id;
    int worker_count;
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    uint64_t should_exit;
    flb_downstream_worker_foreach_cb control_callback;
    void *control_data;
    int initialized;
    int thread_created;
    int control_channel_created;
    int control_done;
    int control_result;
    int startup_result;
};

struct flb_downstream_worker_runtime {
    struct flb_downstream_worker *workers;
    int worker_count;
    int active_workers;
    void *parent;
    flb_downstream_worker_init_cb cb_init;
    flb_downstream_worker_exit_cb cb_exit;
    flb_downstream_worker_maintenance_cb cb_maintenance;
    pthread_mutex_t lifecycle_mutex;
    pthread_cond_t lifecycle_condition;
    pthread_mutex_t foreach_mutex;
    int active_operations;
    int stopping;
    int listener_address_set;
    struct sockaddr_storage listener_address;
};

static int downstream_worker_context_reset(struct flb_downstream_worker *worker)
{
    int ret;

    memset(worker, 0, sizeof(struct flb_downstream_worker));
    worker->listener_fd = FLB_INVALID_SOCKET;

    ret = pthread_mutex_init(&worker->mutex, NULL);
    if (ret != 0) {
        return -1;
    }

    ret = pthread_cond_init(&worker->condition, NULL);
    if (ret != 0) {
        pthread_mutex_destroy(&worker->mutex);
        return -1;
    }

    return 0;
}

static int downstream_worker_listener_validate(
    struct flb_downstream_worker_runtime *runtime,
    struct flb_downstream_worker *worker)
{
    int result;
    socklen_t address_length;
    int addresses_match;
    struct sockaddr_in *address_ipv4;
    struct sockaddr_in *runtime_address_ipv4;
    struct sockaddr_in6 *address_ipv6;
    struct sockaddr_in6 *runtime_address_ipv6;
    struct sockaddr_storage address;

    if (worker->listener_fd == FLB_INVALID_SOCKET) {
        return 0;
    }

    memset(&address, 0, sizeof(struct sockaddr_storage));
    address_length = sizeof(struct sockaddr_storage);
    result = getsockname(worker->listener_fd,
                         (struct sockaddr *) &address,
                         &address_length);
    if (result != 0) {
        return -1;
    }

    if (runtime->listener_address_set == FLB_FALSE) {
        memcpy(&runtime->listener_address, &address,
               sizeof(struct sockaddr_storage));
        runtime->listener_address_set = FLB_TRUE;
        return 0;
    }

    addresses_match = FLB_FALSE;
    if (runtime->listener_address.ss_family == AF_INET &&
        address.ss_family == AF_INET) {
        runtime_address_ipv4 = (struct sockaddr_in *) &runtime->listener_address;
        address_ipv4 = (struct sockaddr_in *) &address;
        if (runtime_address_ipv4->sin_port == address_ipv4->sin_port &&
            memcmp(&runtime_address_ipv4->sin_addr,
                   &address_ipv4->sin_addr,
                   sizeof(struct in_addr)) == 0) {
            addresses_match = FLB_TRUE;
        }
    }
    else if (runtime->listener_address.ss_family == AF_INET6 &&
             address.ss_family == AF_INET6) {
        runtime_address_ipv6 = (struct sockaddr_in6 *) &runtime->listener_address;
        address_ipv6 = (struct sockaddr_in6 *) &address;
        if (runtime_address_ipv6->sin6_port == address_ipv6->sin6_port &&
            runtime_address_ipv6->sin6_scope_id == address_ipv6->sin6_scope_id &&
            memcmp(&runtime_address_ipv6->sin6_addr,
                   &address_ipv6->sin6_addr,
                   sizeof(struct in6_addr)) == 0) {
            addresses_match = FLB_TRUE;
        }
    }

    if (addresses_match == FLB_FALSE) {
        flb_error("[downstream worker] listeners did not bind the same endpoint");
        return -1;
    }

    return 0;
}

static void downstream_worker_context_cleanup(struct flb_downstream_worker *worker)
{
    pthread_mutex_destroy(&worker->mutex);
    pthread_cond_destroy(&worker->condition);
}

static int downstream_worker_control_event(struct flb_downstream_worker *worker)
{
    ssize_t bytes;
    char signal;
    flb_downstream_worker_foreach_cb callback;
    void *data;

    bytes = flb_pipe_r(worker->control_channel[0], &signal, sizeof(signal));
    if (bytes != sizeof(signal)) {
        pthread_mutex_lock(&worker->mutex);
        worker->control_callback = NULL;
        worker->control_data = NULL;
        worker->control_result = -1;
        worker->control_done = FLB_TRUE;
        pthread_cond_broadcast(&worker->condition);
        pthread_mutex_unlock(&worker->mutex);
        return -1;
    }

    pthread_mutex_lock(&worker->mutex);
    callback = worker->control_callback;
    data = worker->control_data;
    pthread_mutex_unlock(&worker->mutex);

    if (callback != NULL && worker->context != NULL) {
        callback(worker, worker->context, data);
    }

    pthread_mutex_lock(&worker->mutex);
    worker->control_callback = NULL;
    worker->control_data = NULL;
    worker->control_result = 0;
    worker->control_done = FLB_TRUE;
    pthread_cond_signal(&worker->condition);
    pthread_mutex_unlock(&worker->mutex);

    return 0;
}

static void downstream_worker_dispatch_event(struct mk_event *event)
{
    struct flb_connection *connection;

    if (event->type == FLB_ENGINE_EV_CUSTOM) {
        event->handler(event);
    }
    else if (event->type == FLB_ENGINE_EV_THREAD) {
        connection = (struct flb_connection *) event;
        if (connection->coroutine != NULL) {
            if (connection->event_coroutine != NULL) {
                flb_downstream_conn_event_resume(connection);
            }
            else {
                flb_coro_resume(connection->coroutine);
            }
        }
    }
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
    flb_net_ctx_init(&dns_ctx);

    worker->event_loop = mk_event_loop_create(256);
    if (worker->event_loop == NULL) {
        ret = -1;
        goto signal_and_exit;
    }

    MK_EVENT_NEW(&worker->control_event);
    ret = mk_event_channel_create(worker->event_loop,
                                  &worker->control_channel[0],
                                  &worker->control_channel[1],
                                  &worker->control_event);
    if (ret != 0) {
        ret = -1;
        goto signal_and_exit;
    }
    worker->control_channel_created = FLB_TRUE;

    flb_engine_evl_init();
    flb_engine_evl_set(worker->event_loop);
    flb_coro_thread_init();
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

    while (cfl_atomic_load(&worker->should_exit) == FLB_FALSE) {
        ret = mk_event_wait_2(worker->event_loop, 250);
        if (ret < 0) {
            flb_error("[downstream worker %i] event loop wait failed",
                      worker->worker_id);
            pthread_mutex_lock(&worker->mutex);
            worker->startup_result = -1;
            pthread_mutex_unlock(&worker->mutex);
            break;
        }

        if (cfl_atomic_load(&worker->should_exit) == FLB_TRUE) {
            break;
        }

        {
            mk_event_foreach(event, worker->event_loop) {
                downstream_worker_dispatch_event(event);
            }
        }

        {
            mk_event_foreach(event, worker->event_loop) {
                if (event == &worker->control_event) {
                    downstream_worker_control_event(worker);
                }
            }
        }

        if (runtime->cb_maintenance != NULL) {
            runtime->cb_maintenance(worker, worker->context);
        }

        flb_net_dns_lookup_context_cleanup(&dns_ctx);
    }

cleanup:
    flb_net_dns_lookup_context_cleanup(&dns_ctx);

    if (runtime->cb_exit != NULL && worker->context != NULL) {
        runtime->cb_exit(worker, worker->context);
    }

    pthread_mutex_lock(&worker->mutex);
    if (worker->context != NULL) {
        worker->context = NULL;
    }

    if (worker->control_done == FLB_FALSE &&
        worker->control_callback != NULL) {
        worker->control_callback = NULL;
        worker->control_data = NULL;
        worker->control_result = -1;
        worker->control_done = FLB_TRUE;
        pthread_cond_broadcast(&worker->condition);
    }

    if (worker->control_channel_created == FLB_TRUE) {
        mk_event_channel_destroy(worker->event_loop,
                                 worker->control_channel[0],
                                 worker->control_channel[1],
                                 &worker->control_event);
        worker->control_channel_created = FLB_FALSE;
    }
    pthread_mutex_unlock(&worker->mutex);

    if (worker->event_loop != NULL) {
        flb_engine_evl_set(NULL);
        flb_net_dns_ctx_set(NULL);
        mk_event_loop_destroy(worker->event_loop);
        worker->event_loop = NULL;
    }

    return NULL;
}

int flb_downstream_worker_runtime_start(struct flb_downstream_worker_runtime **out_runtime,
                                        const struct flb_downstream_worker_options *options)
{
    int i;
    int ret;
    struct flb_downstream_worker_runtime *runtime;

    if (out_runtime == NULL) {
        return -1;
    }

    *out_runtime = NULL;

    if (options == NULL || options->workers <= 0 || options->cb_init == NULL) {
        return -1;
    }

    runtime = flb_calloc(1, sizeof(struct flb_downstream_worker_runtime));
    if (runtime == NULL) {
        flb_errno();
        return -1;
    }

    ret = pthread_mutex_init(&runtime->lifecycle_mutex, NULL);
    if (ret != 0) {
        flb_free(runtime);
        return -1;
    }

    ret = pthread_cond_init(&runtime->lifecycle_condition, NULL);
    if (ret != 0) {
        pthread_mutex_destroy(&runtime->lifecycle_mutex);
        flb_free(runtime);
        return -1;
    }

    ret = pthread_mutex_init(&runtime->foreach_mutex, NULL);
    if (ret != 0) {
        pthread_cond_destroy(&runtime->lifecycle_condition);
        pthread_mutex_destroy(&runtime->lifecycle_mutex);
        flb_free(runtime);
        return -1;
    }
    runtime->workers = flb_calloc(options->workers,
                                  sizeof(struct flb_downstream_worker));
    if (runtime->workers == NULL) {
        flb_errno();
        pthread_mutex_destroy(&runtime->foreach_mutex);
        pthread_cond_destroy(&runtime->lifecycle_condition);
        pthread_mutex_destroy(&runtime->lifecycle_mutex);
        flb_free(runtime);
        return -1;
    }

    runtime->worker_count = options->workers;
    runtime->parent = options->parent;
    runtime->cb_init = options->cb_init;
    runtime->cb_exit = options->cb_exit;
    runtime->cb_maintenance = options->cb_maintenance;

    *out_runtime = runtime;

    for (i = 0; i < runtime->worker_count; i++) {
        ret = downstream_worker_context_reset(&runtime->workers[i]);
        if (ret != 0) {
            break;
        }

        runtime->active_workers++;
        runtime->workers[i].runtime = runtime;
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
            ret = pthread_cond_wait(&runtime->workers[i].condition,
                                    &runtime->workers[i].mutex);
            if (ret != 0) {
                break;
            }
        }
        if (ret == 0) {
            ret = runtime->workers[i].startup_result;
        }
        pthread_mutex_unlock(&runtime->workers[i].mutex);

        if (ret == 0) {
            ret = downstream_worker_listener_validate(runtime,
                                                      &runtime->workers[i]);
        }

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

static int downstream_worker_runtime_is_worker_thread(
    struct flb_downstream_worker_runtime *runtime)
{
    int i;

    for (i = 0; i < runtime->active_workers; i++) {
        if (runtime->workers[i].thread_created == FLB_TRUE &&
            pthread_equal(runtime->workers[i].thread, pthread_self())) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

int flb_downstream_worker_runtime_stop(struct flb_downstream_worker_runtime *runtime)
{
    int i;
    char signal;

    if (runtime == NULL) {
        return 0;
    }

    if (downstream_worker_runtime_is_worker_thread(runtime) == FLB_TRUE) {
        return -1;
    }

    signal = 1;

    pthread_mutex_lock(&runtime->lifecycle_mutex);
    runtime->stopping = FLB_TRUE;
    while (runtime->active_operations > 0) {
        pthread_cond_wait(&runtime->lifecycle_condition,
                          &runtime->lifecycle_mutex);
    }
    pthread_mutex_unlock(&runtime->lifecycle_mutex);

    /* Wake every worker before joining so shutdown latency is not cumulative. */
    for (i = 0; i < runtime->active_workers; i++) {
        cfl_atomic_store(&runtime->workers[i].should_exit, FLB_TRUE);

        pthread_mutex_lock(&runtime->workers[i].mutex);
        if (runtime->workers[i].startup_result == 0 &&
            runtime->workers[i].control_channel_created == FLB_TRUE) {
            flb_pipe_w(runtime->workers[i].control_channel[1],
                       &signal, sizeof(signal));
        }
        pthread_mutex_unlock(&runtime->workers[i].mutex);
    }

    for (i = 0; i < runtime->active_workers; i++) {
        if (runtime->workers[i].thread_created == FLB_TRUE) {
            pthread_join(runtime->workers[i].thread, NULL);
        }
        downstream_worker_context_cleanup(&runtime->workers[i]);
    }

    pthread_mutex_destroy(&runtime->foreach_mutex);
    pthread_cond_destroy(&runtime->lifecycle_condition);
    pthread_mutex_destroy(&runtime->lifecycle_mutex);
    flb_free(runtime->workers);
    flb_free(runtime);

    return 0;
}

int flb_downstream_worker_runtime_foreach(struct flb_downstream_worker_runtime *runtime,
                                          flb_downstream_worker_foreach_cb callback,
                                          void *data)
{
    int i;
    int result;
    int wait_result;
    ssize_t bytes;
    char signal;
    struct flb_downstream_worker *worker;

    if (runtime == NULL || callback == NULL) {
        return -1;
    }

    if (downstream_worker_runtime_is_worker_thread(runtime) == FLB_TRUE) {
        return -1;
    }

    pthread_mutex_lock(&runtime->lifecycle_mutex);
    if (runtime->stopping == FLB_TRUE) {
        pthread_mutex_unlock(&runtime->lifecycle_mutex);
        return -1;
    }
    runtime->active_operations++;
    pthread_mutex_unlock(&runtime->lifecycle_mutex);

    pthread_mutex_lock(&runtime->foreach_mutex);

    result = 0;
    signal = 1;

    for (i = 0; i < runtime->worker_count; i++) {
        worker = &runtime->workers[i];

        pthread_mutex_lock(&worker->mutex);
        if (worker->context == NULL || worker->thread_created != FLB_TRUE ||
            worker->control_channel_created != FLB_TRUE) {
            pthread_mutex_unlock(&worker->mutex);
            result = -1;
            continue;
        }

        worker->control_callback = callback;
        worker->control_data = data;
        worker->control_done = FLB_FALSE;
        worker->control_result = 0;

        bytes = flb_pipe_w(worker->control_channel[1], &signal, sizeof(signal));
        if (bytes != sizeof(signal)) {
            worker->control_callback = NULL;
            worker->control_data = NULL;
            worker->control_done = FLB_TRUE;
            pthread_mutex_unlock(&worker->mutex);
            result = -1;
            continue;
        }

        while (worker->control_done == FLB_FALSE) {
            wait_result = pthread_cond_wait(&worker->condition, &worker->mutex);
            if (wait_result != 0) {
                worker->control_callback = NULL;
                worker->control_data = NULL;
                worker->control_result = -1;
                worker->control_done = FLB_TRUE;
                break;
            }
        }
        if (worker->control_result != 0) {
            result = -1;
        }
        pthread_mutex_unlock(&worker->mutex);
    }
    pthread_mutex_unlock(&runtime->foreach_mutex);

    pthread_mutex_lock(&runtime->lifecycle_mutex);
    runtime->active_operations--;
    if (runtime->active_operations == 0) {
        pthread_cond_signal(&runtime->lifecycle_condition);
    }
    pthread_mutex_unlock(&runtime->lifecycle_mutex);

    return result;
}

struct mk_event_loop *flb_downstream_worker_event_loop_get(
    struct flb_downstream_worker *worker)
{
    if (worker == NULL) {
        return NULL;
    }

    return worker->event_loop;
}

int flb_downstream_worker_id_get(struct flb_downstream_worker *worker)
{
    if (worker == NULL) {
        return -1;
    }

    return worker->worker_id;
}

int flb_downstream_worker_count_get(struct flb_downstream_worker *worker)
{
    if (worker == NULL) {
        return -1;
    }

    return worker->worker_count;
}

int flb_downstream_worker_listener_fd_set(struct flb_downstream_worker *worker,
                                          flb_sockfd_t listener_fd)
{
    if (worker == NULL || listener_fd == FLB_INVALID_SOCKET) {
        return -1;
    }

    worker->listener_fd = listener_fd;

    return 0;
}
