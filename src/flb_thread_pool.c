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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_worker.h>
#include <fluent-bit/flb_thread_pool.h>

/* Return the next thread id. We use the list size to set an id */
static int flb_tp_thread_get_id(struct flb_tp *tp)
{
    return mk_list_size(&tp->list_threads);
}

/* Create a thread manager context */
struct flb_tp *flb_tp_create(struct flb_config *config)
{
    struct flb_tp *tp;

    tp = flb_calloc(1, sizeof(struct flb_tp));
    if (!tp) {
        flb_errno();
        return NULL;
    }
    tp->config = config;
    mk_list_init(&tp->list_threads);

    return tp;
}

void flb_tp_destroy(struct flb_tp *tp)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tp_thread *th;

    mk_list_foreach_safe(head, tmp, &tp->list_threads) {
        th = mk_list_entry(head, struct flb_tp_thread, _head);
        mk_list_del(&th->_head);
        flb_free(th);
    }

    flb_free(tp);
}

struct flb_tp_thread *flb_tp_thread_create(struct flb_tp *tp,
                                           void (*func)(void *), void *arg,
                                           struct flb_config *config)

{
    struct flb_tp_thread *th;

    /* Create thread context */
    th = flb_calloc(1, sizeof(struct flb_tp_thread));
    if (!th) {
        flb_errno();
        return NULL;
    }
    th->config = config;

    /*
     * To spawn a thread, we use the 'worker' interface. Since the worker will
     * start the thread as soon as is invoked, we keep a reference to the worker
     * parameters in our context and we only use them when the thread is really
     * started through the call flb_tp_thread_start().
     */
    th->params.func = func;
    th->params.data = arg;

    /* Status */
    th->status = FLB_THREAD_POOL_NONE;

    /* Set the thread id */
    th->id = flb_tp_thread_get_id(tp);

    /* Link this thread context to the parent context list */
    mk_list_add(&th->_head, &tp->list_threads);

    return th;
}


/* Get a candidate thread using round-robin */
struct flb_tp_thread *flb_tp_thread_get_rr(struct flb_tp *tp)
{
    struct flb_tp_thread *th;

    if (!tp->thread_cur) {
        th = mk_list_entry_first(&tp->list_threads,
                                 struct flb_tp_thread, _head);
    }
    else {
        th = mk_list_entry_next(tp->thread_cur,
                                struct flb_tp_thread, _head,
                                &tp->list_threads);
    }
    tp->thread_cur = &th->_head;

    return th;
}

int flb_tp_thread_start(struct flb_tp *tp, struct flb_tp_thread *th)
{
    int ret;

    ret = flb_worker_create(th->params.func, th->params.data, &th->tid,
                            th->config);
    if (ret == -1) {
        th->status = FLB_THREAD_POOL_ERROR;
        return -1;
    }

    /*
     * Retrieve the Worker context. The worker API don't return the
     * id or the context, so we use the created pthread_t (task id)
     * to obtain the reference.
     */
    th->worker = flb_worker_lookup(th->tid, tp->config);
    th->status = FLB_THREAD_POOL_RUNNING;

    return 0;
}

int flb_tp_thread_start_id(struct flb_tp *tp, int id)
{
    int i = 0;
    struct mk_list *head;
    struct flb_tp_thread *th = NULL;

    mk_list_foreach(head, &tp->list_threads) {
        if (i == id) {
            th = mk_list_entry(head, struct flb_tp_thread, _head);
            break;
        }
        th = NULL;
        i++;
    }

    if (!th) {
        return -1;
    }

    return flb_tp_thread_start(tp, th);
}

int flb_tp_thread_start_all(struct flb_tp *tp)
{
    struct mk_list *head;
    struct flb_tp_thread *th;

    mk_list_foreach(head, &tp->list_threads) {
        th = mk_list_entry(head, struct flb_tp_thread, _head);
        flb_tp_thread_start(tp, th);
    }

    return 0;
}

int flb_tp_thread_stop(struct flb_tp *tp, struct flb_tp_thread *th)
{
    return 0;
}

int flb_tp_thread_stop_all(struct flb_tp *tp)
{
    int ret;
    struct mk_list *head;
    struct flb_tp_thread *th;

    /*
     * Iterate each worker thread, signal them to stop working
     * and wait a proper exit.
     */
    mk_list_foreach(head, &tp->list_threads) {
        th = mk_list_entry(head, struct flb_tp_thread, _head);
        if (th->status != FLB_THREAD_POOL_RUNNING) {
            continue;
        }

        ret = flb_tp_thread_stop(tp, th);
        if (ret == -1) {

        }
    }

    return 0;
}

int flb_tp_thread_destroy()
{
    return 0;
}
