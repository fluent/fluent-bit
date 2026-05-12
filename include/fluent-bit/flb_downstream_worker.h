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

#ifndef FLB_DOWNSTREAM_WORKER_H
#define FLB_DOWNSTREAM_WORKER_H

#include <cfl/cfl_atomic.h>

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_pthread.h>

#include <monkey/mk_core.h>

struct flb_downstream_worker;
struct flb_downstream_worker_runtime;

typedef int (*flb_downstream_worker_init_cb)(struct flb_downstream_worker *worker,
                                             void *parent,
                                             void **worker_context);

typedef void (*flb_downstream_worker_exit_cb)(struct flb_downstream_worker *worker,
                                              void *worker_context);

typedef void (*flb_downstream_worker_maintenance_cb)(
    struct flb_downstream_worker *worker,
    void *worker_context);

typedef void (*flb_downstream_worker_foreach_cb)(struct flb_downstream_worker *worker,
                                                 void *worker_context,
                                                 void *data);

struct flb_downstream_worker {
    struct flb_downstream_worker_runtime *runtime;
    struct mk_event_loop *event_loop;
    struct mk_event control_event;
    flb_pipefd_t control_channel[2];
    void *context;
    void *parent;
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
    int startup_result;
};

struct flb_downstream_worker_options {
    int workers;
    struct flb_config *config;
    void *parent;
    flb_downstream_worker_init_cb cb_init;
    flb_downstream_worker_exit_cb cb_exit;
    flb_downstream_worker_maintenance_cb cb_maintenance;
};

int flb_downstream_worker_runtime_start(struct flb_downstream_worker_runtime **out_runtime,
                                        struct flb_downstream_worker_options *options);

void flb_downstream_worker_runtime_stop(struct flb_downstream_worker_runtime *runtime);

void flb_downstream_worker_runtime_foreach(struct flb_downstream_worker_runtime *runtime,
                                           flb_downstream_worker_foreach_cb callback,
                                           void *data);

#endif
