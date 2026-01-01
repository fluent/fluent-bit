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

#ifndef FLB_OUTPUT_THREAD_H
#define FLB_OUTPUT_THREAD_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_queue.h>

/*
 * For every 'upstream' registered in the output plugin initialization, we create
 * a local entry so we can manage the connections queues locally, on this way we
 * avoid sharing a single list with the other threads.
 */
struct flb_out_thread_upstream {
    /* output instance upstream connection context */
    struct flb_upstream *u;

    /*
     * Local implementation of upstream queues: same as in the co-routines case, we
     * implement our own lists of upstream connections so they can be only reused inside
     * the same thread.
     *
     * The flb_upstream_queue structure have the following queues:
     *
     * - av_queue: connections in a persistent state (keepalive) ready to be
     *             used.
     *
     * - busy_queue: connections doing I/O, being used by a co-routine.
     *
     * - destroy_queue: connections that cannot be longer used, the connections linked
     *                  to this list will be destroyed in the event loop once there is
     *                  no pending events associated.
     *
     * note: in single-thread mode, the same fields are in 'struct flb_upstream'
     */
    struct flb_upstream_queue queue;

    /* Link to struct flb_out_thread_instance->upstreams */
    struct mk_list _head;
};

struct flb_out_thread_instance {
    struct mk_event event;               /* event context to associate events */
    struct mk_event_loop *evl;           /* thread event loop context */
    struct flb_bucket_queue *evl_bktq;    /* bucket queue for evl track event priority */
    flb_pipefd_t ch_parent_events[2];    /* channel to receive parent notifications */
    flb_pipefd_t ch_thread_events[2];    /* channel to send messages local event loop */
    int notification_channels_initialized;
    flb_pipefd_t notification_channels[2];
    struct mk_event notification_event;
    struct flb_output_instance *ins;     /* output plugin instance */
    struct flb_config *config;
    struct flb_tp_thread *th;
    struct mk_list _head;

    /*
     * In multithread mode, we move some contexts to independent references per thread
     * so we can avoid to have shared resources and mutexes.
     *
     * The following 'coro' fields maintains a state of co-routines inside the thread
     * event loop.
     *
     * note: in single-thread mode, the same fields are in 'struct flb_output_instance'.
     */
    int flush_id;                             /* coroutine id counter */
    struct mk_list flush_list;                /* flush context list */
    struct mk_list flush_list_destroy;        /* flust context destroy list */

    /*
     * If the main engine (parent thread) needs to query the number of active
     * 'flushes' running by a threaded instance, then the access to the 'flush_list'
     * must be protected: we use 'flush_mutex for that purpose.
     */
     pthread_mutex_t flush_mutex;         /* mutex for 'flush_list' */

    /* List of mapped 'upstream' contexts */
    struct mk_list upstreams;
};

int flb_output_thread_pool_create(struct flb_config *config,
                                  struct flb_output_instance *ins);
int flb_output_thread_pool_coros_size(struct flb_output_instance *ins);
void flb_output_thread_pool_destroy(struct flb_output_instance *ins);
int flb_output_thread_pool_start(struct flb_output_instance *ins);
int flb_output_thread_pool_flush(struct flb_task *task,
                                 struct flb_output_instance *out_ins,
                                 struct flb_config *config);


void flb_output_thread_instance_init();
struct flb_out_thread_instance *flb_output_thread_instance_get();
void flb_output_thread_instance_set(struct flb_out_thread_instance *th_ins);

#endif
