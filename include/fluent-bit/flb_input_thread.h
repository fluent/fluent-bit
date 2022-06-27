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
#include <fluent-bit/flb_pthread.h>
#include <mpack/mpack.h>

#define BUFFER_SIZE 65535

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

int flb_input_thread_init(struct flb_input_thread *it,
                          flb_input_thread_cb callback,
                          void *data);
int flb_input_thread_destroy(struct flb_input_thread *it,
                             struct flb_input_instance *ins);
int flb_input_thread_collect(struct flb_input_instance *ins,
                             struct flb_config *config,
                             void *in_context);
void flb_input_thread_exit(void *in_context, struct flb_input_instance *ins);
bool flb_input_thread_exited(struct flb_input_thread *it);

#endif
