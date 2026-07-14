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

#include <fluent-bit/flb_socket.h>

struct mk_event_loop;
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

struct flb_downstream_worker_options {
    int workers;
    void *parent;
    flb_downstream_worker_init_cb cb_init;
    flb_downstream_worker_exit_cb cb_exit;
    flb_downstream_worker_maintenance_cb cb_maintenance;
};

int flb_downstream_worker_runtime_start(struct flb_downstream_worker_runtime **out_runtime,
                                        const struct flb_downstream_worker_options *options);

/* Runtime operations must not be invoked from a worker callback. */
int flb_downstream_worker_runtime_stop(struct flb_downstream_worker_runtime *runtime);

/* The callback is run synchronously once on every worker thread. */
int flb_downstream_worker_runtime_foreach(struct flb_downstream_worker_runtime *runtime,
                                          flb_downstream_worker_foreach_cb callback,
                                          void *data);

struct mk_event_loop *flb_downstream_worker_event_loop_get(
    struct flb_downstream_worker *worker);

int flb_downstream_worker_id_get(struct flb_downstream_worker *worker);

int flb_downstream_worker_count_get(struct flb_downstream_worker *worker);

/* Register the listener created by cb_init for shared-endpoint validation. */
int flb_downstream_worker_listener_fd_set(struct flb_downstream_worker *worker,
                                          flb_sockfd_t listener_fd);

#endif
