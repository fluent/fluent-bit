/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_INPUT_THREAD_H
#define FLB_INPUT_THREAD_H

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_thread_pool.h>
#include <mpack/mpack.h>
#include <signal.h>

#define BUFFER_SIZE 65535

/* Message from parent to child thread */
#define FLB_INPUT_THREAD_TO_PARENT  (uint32_t) 1
#define FLB_INPUT_THREAD_TO_THREAD  (uint32_t) 2

/* Event types from parent to child thread */
#define FLB_INPUT_THREAD_PAUSE             (uint32_t) 1
#define FLB_INPUT_THREAD_RESUME            (uint32_t) 2
#define FLB_INPUT_THREAD_EXIT              (uint32_t) 3
#define FLB_INPUT_THREAD_START_COLLECTORS  (uint32_t) 4
#define FLB_INPUT_THREAD_OK                (uint32_t) 5
#define FLB_INPUT_THREAD_ERROR             (uint32_t) 6
#define FLB_INPUT_THREAD_NOT_READY         (uint32_t) 7

typedef void (*flb_input_thread_cb) (int write_fd, void *data);

struct flb_input_thread {
    pthread_mutex_t mutex;        /* mutex used to synchronize the "exit" flag */
    bool exit;                    /* flag set by the main thread to tell worker to exit */
    FILE *write_file;             /* std FILE wrapper around write fd */
    mpack_writer_t writer;        /* mpack writer to serialize events */
    pthread_t thread;             /* thread producing input */
    flb_pipefd_t read, write;     /* pipe read/write fds */
    int coll_fd;                  /* collector fd */
    flb_input_thread_cb callback; /* user callback to run in the thread */
    void *data;                   /* user data passed to the callback */
    char buf[BUFFER_SIZE];        /* temporary buffer for incomplete msgpack data */
    size_t bufpos;                /* current offset in the msgpack buffer */
};

struct flb_input_thread_instance {
    struct mk_event event;               /* event context to associate events */
    struct mk_event event_local;         /* local events inside the thread/event loop */
    struct mk_event_loop *evl;           /* thread event loop context */
    flb_pipefd_t ch_parent_events[2];    /* communication between parent and thread */
    flb_pipefd_t ch_thread_events[2];    /* local messages in the thread event loop */
    int notification_channels_initialized;
    flb_pipefd_t notification_channels[2];
    struct mk_event notification_event;
    struct flb_input_instance *ins;      /* output plugin instance */
    struct flb_tp *tp;
    struct flb_tp_thread *th;
    struct flb_config *config;

    /* pthread initialization helpers for synchronization */
    int init_status;
    pthread_mutex_t init_mutex;
    pthread_cond_t init_condition;

    /*
     * In multithread mode, we move some contexts to independent references per thread
     * so we can avoid to have shared resources and mutexes.
     *
     * The following 'coro' fields maintains a state of co-routines inside the thread
     * event loop.
     *
     * note: in single-thread mode, the same fields are in 'struct flb_inpu_instance'.
     */
    int input_coro_id;
    struct mk_list input_coro_list;
    struct mk_list input_coro_list_destroy;

    /*
     * Pause state flag for shutdown synchronization.
     * Set to 1 when thread completes pause processing.
     * Checked by main thread to ensure safe shutdown.
     */
    volatile sig_atomic_t is_paused;
};

int flb_input_thread_instance_init(struct flb_config *config,
                                   struct flb_input_instance *ins);
int flb_input_thread_instance_pre_run(struct flb_config *config, struct flb_input_instance *ins);

int flb_input_thread_instance_pause(struct flb_input_instance *ins);
int flb_input_thread_instance_resume(struct flb_input_instance *ins);
int flb_input_thread_instance_exit(struct flb_input_instance *ins);

int flb_input_thread_collectors_signal_start(struct flb_input_instance *ins);
int flb_input_thread_collectors_signal_wait(struct flb_input_instance *ins);
int flb_input_thread_collectors_start(struct flb_input_instance *ins);

int flb_input_thread_init_fail(struct flb_input_instance *ins);
int flb_input_thread_is_ready(struct flb_input_instance *ins);
int flb_input_thread_wait_until_is_ready(struct flb_input_instance *ins);

#endif
