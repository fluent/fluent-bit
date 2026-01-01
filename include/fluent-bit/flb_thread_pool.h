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

#ifndef FLB_THREAD_POOL_H
#define FLB_THREAD_POOL_H

/* Thread status */
#define FLB_THREAD_POOL_ERROR    -1
#define FLB_THREAD_POOL_NONE      0
#define FLB_THREAD_POOL_RUNNING   1
#define FLB_THREAD_POOL_STOPPED   2

#include <fluent-bit/flb_info.h>
#ifdef FLB_SYSTEM_WINDOWS
#include <monkey/mk_core/external/winpthreads.h>
#else
#include <pthread.h>
#endif

struct worker_params {
    void (*func) (void *);
    void *data;
};

struct flb_tp_thread {
    int id;                        /* thread id inside the pool */
    int status;
    pthread_t tid;                 /* OS task id */
    struct worker_params params;   /* worker params before initialization */
    struct flb_worker *worker;     /* worker context */
    struct mk_list _head;          /* link to flb_tp->list_threads */
    struct flb_config *config;
};

struct flb_tp {
    struct mk_list list_threads;
    struct mk_list *thread_cur;
    struct flb_config *config;
};

struct flb_tp *flb_tp_create(struct flb_config *config);
void flb_tp_destroy(struct flb_tp *tp);

struct flb_tp_thread *flb_tp_thread_create(struct flb_tp *tp,
                                           void (*func)(void *), void *arg,
                                           struct flb_config *config);
struct flb_tp_thread *flb_tp_thread_get_rr(struct flb_tp *tp);
int flb_tp_thread_start(struct flb_tp *tp, struct flb_tp_thread *th);
int flb_tp_thread_start_id(struct flb_tp *tp, int id);
int flb_tp_thread_start_all(struct flb_tp *tp);
int flb_tp_thread_stop(struct flb_tp *tp, struct flb_tp_thread *th);
int flb_tp_thread_stop_all(struct flb_tp *tp);
int flb_tp_thread_destroy();

#endif
