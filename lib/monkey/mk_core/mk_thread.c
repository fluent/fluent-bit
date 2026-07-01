/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server (Duda I/O)
 *  -----------------------------
 *  Copyright 2017 Eduardo Silva <eduardo@monkey.io>
 *  Copyright 2014, Zeying Xie <swpdtz at gmail dot com>
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

#include <assert.h>
#include <string.h>

#if defined (__APPLE__)
#include <sys/ucontext.h>
#else
#include <ucontext.h>
#endif

#include <limits.h>

#include <mk_core/mk_pthread.h>
#include <mk_core/mk_memory.h>
#include <mk_core/mk_thread.h>

/*
 * @OBJ_NAME: dthread
 * @OBJ_MENU: Dthread
 * @OBJ_DESC: The dthread object provides a set of methods to handle user space cooperative thread, namely dthread(duda thread).
 * A dthread can be suspended when it encounters something that will block(in other
 * words, something will be available in the future), while another dthread that
 * is ready to run is awakened. Back and forth, all dthreads within the same pthread
 * work collaboratively. This means dthread is non-preemptive and requires the user
 * to explicitly give up control when necessary.
 * Dthreads communicate with each other by using channel, a channel is like a pipe,
 * one dthread feeds data to the channel while another cosumes from it.
 *
 */

#ifdef USE_VALGRIND
#include <valgrind/valgrind.h>
#endif

#define MK_THREAD_STACK_SIZE (3 * (PTHREAD_STACK_MIN) / 2)
#define DEFAULT_MK_THREAD_NUM    16

struct mk_thread {
    mk_thread_func func;
    void *data;
    ucontext_t context;
    struct mk_thread_scheduler *sch;
    int status;
    int parent_id;
#ifdef USE_VALGRIND
    unsigned int valgrind_stack_id;
#endif
    struct mk_list chan_list;
    char stack[MK_THREAD_STACK_SIZE];
} mk_thread_t;

struct mk_thread_scheduler {
    ucontext_t main;
    int n_dthread;
    int cap;
    int running_id;
    struct mk_thread **dt;
};

static void _mk_thread_release(struct mk_thread *dt);

static void _mk_thread_entry_point(struct mk_thread_scheduler *sch)
{
    int id;
    struct mk_thread *dt;
    struct mk_list *head;
    struct mk_thread_channel *chan;

    assert(sch);
    id = sch->running_id;
    dt = sch->dt[id];
    dt->func(dt->data);
    dt->status = MK_THREAD_DEAD;

    mk_list_foreach(head, &dt->chan_list) {
        chan = mk_list_entry(head, struct mk_thread_channel, _head);
        chan->receiver = -1;
    }
    sch->n_dthread--;
    sch->running_id = dt->parent_id;
}

struct mk_thread_scheduler *mk_thread_open()
{
    struct mk_thread_scheduler *sch;

    sch = mk_mem_alloc(sizeof(*sch));
    if (!sch) {
        return NULL;
    }

    sch->n_dthread = 0;
    sch->cap = DEFAULT_MK_THREAD_NUM;
    sch->running_id = -1;
    sch->dt = mk_mem_alloc_z(sizeof(struct mk_thread *) * sch->cap);
    if (!sch->dt) {
        mk_mem_free(sch);
        return NULL;
    }

    return sch;
}

void mk_thread_close(struct mk_thread_scheduler *sch)
{
    struct mk_thread *dt;

    int i;
    for (i = 0; i < sch->cap; ++i) {
        dt = sch->dt[i];
        if (dt) {
            _mk_thread_release(dt);
        }
    }
    mk_mem_free(sch->dt);
    sch->dt = NULL;
    mk_mem_free(sch);
}

/*
 * @METHOD_NAME: create
 * @METHOD_DESC: create a new dthread.
 * @METHOD_PROTO: int create(mk_thread_func func, void *data)
 * @METHOD_PARAM: func the function to be executed when the newly created dthread
 * is started.
 * @METHOD_PARAM: data user specific data that will be passed to func.
 * @METHOD_RETURN: the dthread id associated with the new dthread.
 */
int mk_thread_create(mk_thread_func func, void *data)
{
    int i;
    int id;
    void *p;
    struct mk_thread_scheduler *sch;
    struct mk_thread *dt;

    sch = pthread_getspecific(mk_thread_scheduler);
    if (!sch) {
        sch = mk_thread_open();
        assert(sch);
        pthread_setspecific(mk_thread_scheduler, (void *) sch);
    }

    if (sch->n_dthread >= sch->cap) {
        id = sch->cap;

        p = mk_mem_realloc(sch->dt, sch->cap * 2 * sizeof(struct mk_thread *));
        if (!p) {
            return -1;
        }
        sch->dt = p;
        memset(sch->dt + sch->cap, 0, sizeof(struct mk_thread *) * sch->cap);
        sch->cap *= 2;
    }
    else {
        for (i = 0; i < sch->cap; ++i) {
            id = (i + sch->cap) % sch->cap;
            if (sch->dt[id] == NULL || sch->dt[id]->status == MK_THREAD_DEAD) {
                break;
            }
        }
    }

    /* may use dthread pooling instead of release and realloc */
    if (sch->dt[id] && sch->dt[id]->status == MK_THREAD_DEAD) {
        _mk_thread_release(sch->dt[id]);
        sch->dt[id] = NULL;
    }

    dt = mk_mem_alloc(sizeof(*dt));
    if (!dt) {
        return -1;
    }

    dt->func = func;
    dt->data = data;
    dt->sch = sch;
    dt->status = MK_THREAD_READY;
    dt->parent_id = -1;
#ifdef USE_VALGRIND
    dt->valgrind_stack_id = VALGRIND_STACK_REGISTER(dt->stack, dt->stack + MK_THREAD_STACK_SIZE);
#endif
    mk_list_init(&dt->chan_list);
    sch->dt[id] = dt;
    sch->n_dthread++;
    return id;
}

static void _mk_thread_release(struct mk_thread *dt)
{
    assert(dt);
#ifdef USE_VALGRIND
    VALGRIND_STACK_DEREGISTER(dt->valgrind_stack_id);
#endif
    mk_mem_free(dt);
}

/*
 * @METHOD_NAME: status
 * @METHOD_DESC: get the status of a given dthread.
 * @METHOD_PROTO: int status(int id)
 * @METHOD_PARAM: id the dthread id of the target dthread.
 * @METHOD_RETURN: it returns one of the following status: MK_THREAD_DEAD, MK_THREAD_READY,
 * MK_THREAD_RUNNING, MK_THREAD_SUSPEND.
 */
int mk_thread_status(int id)
{
    struct mk_thread_scheduler *sch;

    sch = pthread_getspecific(mk_thread_scheduler);
    assert(sch);
    assert(id >= 0 && id < sch->cap);
    if (!sch->dt[id]) return MK_THREAD_DEAD;
    return sch->dt[id]->status;
}

/*
 * @METHOD_NAME: yield
 * @METHOD_DESC: require the currently running dthread explicitly to give up control
 * back to the dthread scheduler.
 * @METHOD_PROTO: void yield()
 * @METHOD_RETURN: this method do not return any value.
 */
void mk_thread_yield()
{
    int id;
    struct mk_thread *dt;
    struct mk_thread_scheduler *sch;

    sch = pthread_getspecific(mk_thread_scheduler);
    assert(sch);

    id = sch->running_id;
    assert(id >= 0);

    dt = sch->dt[id];
    dt->status = MK_THREAD_SUSPEND;
    sch->running_id = -1;
    swapcontext(&dt->context, &sch->main);
}

/*
 * @METHOD_NAME: resume
 * @METHOD_DESC: resume a given dthread and suspend the currently running dthread.
 * @METHOD_PROTO: void resume(int id)
 * @METHOD_PARAM: id the dthread id of the target dthread.
 * @METHOD_RETURN: this method do not return any value.
 */
void mk_thread_resume(int id)
{
    struct mk_thread *dt;
    struct mk_thread *running_dt;
    struct mk_thread_scheduler *sch;

    sch = pthread_getspecific(mk_thread_scheduler);
    assert(sch);
    assert(id >= 0 && id < sch->cap);

    running_dt = NULL;
    if (sch->running_id != -1) {
        running_dt = sch->dt[sch->running_id];
    }

    dt = sch->dt[id];
    if (!dt) return;
    switch (dt->status) {
    case MK_THREAD_READY:
        getcontext(&dt->context);
        dt->context.uc_stack.ss_sp = dt->stack;
        dt->context.uc_stack.ss_size = MK_THREAD_STACK_SIZE;
        if (running_dt) {
            dt->context.uc_link = &running_dt->context;
            dt->parent_id = sch->running_id;
            running_dt->status = MK_THREAD_SUSPEND;
        } else {
            dt->context.uc_link = &sch->main;
        }
        sch->running_id = id;
        dt->status = MK_THREAD_RUNNING;
        makecontext(&dt->context, (void (*)(void))_mk_thread_entry_point, 1, sch);
        if (running_dt) {
            swapcontext(&running_dt->context, &dt->context);
        } else {
            swapcontext(&sch->main, &dt->context);
        }
        break;
    case MK_THREAD_SUSPEND:
        sch->running_id = id;
        dt->status = MK_THREAD_RUNNING;
        if (running_dt) {
            running_dt->status = MK_THREAD_SUSPEND;
            swapcontext(&running_dt->context, &dt->context);
        } else {
            swapcontext(&sch->main, &dt->context);
        }
        break;
    default:
        assert(0);
    }
}

/*
 * @METHOD_NAME: running
 * @METHOD_DESC: get the id of the currently running dthread.
 * @METHOD_PROTO: int running()
 * @METHOD_RETURN: the dthread id associated with the currently running dthread.
 */
int mk_thread_running()
{
    struct mk_thread_scheduler *sch;

    sch = pthread_getspecific(mk_thread_scheduler);
    assert(sch);
    return sch->running_id;
}

void mk_thread_add_channel(int id, struct mk_thread_channel *chan)
{
    struct mk_thread_scheduler *sch;
    struct mk_thread *dt;

    assert(chan);
    sch = pthread_getspecific(mk_thread_scheduler);
    assert(sch);
    assert(id >= 0 && id < sch->cap);
    dt = sch->dt[id];
    mk_list_add(&chan->_head, &dt->chan_list);
}
