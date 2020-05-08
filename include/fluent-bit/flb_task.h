/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#ifndef FLB_TASK_H
#define FLB_TASK_H

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>

/* Task status */
#define FLB_TASK_NEW      0
#define FLB_TASK_RUNNING  1

/*
 * Macro helpers to determinate return value, task_id and thread_id. When an
 * output plugin returns, it must call FLB_OUTPUT_RETURN(val) where val is
 * the return value, as of now defined as FLB_OK or FLB_ERROR.
 *
 * The FLB_OUTPUT_RETURN macro lookup the current active 'engine thread' and
 * it 'engine task' associated, so it emits an event to the main event loop
 * indicating an output thread has done. In order to specify return values
 * and the proper IDs an unsigned 32 bits number is used:
 *
 *     AAAA     BBBBBBBBBBBBBB CCCCCCCCCCCCCC   > 32 bit number
 *       ^            ^              ^
 *    4 bits       14 bits        14 bits
 *  return val     task_id       thread_id
 */

#define FLB_TASK_RET(val)  (val >> 28)
#define FLB_TASK_ID(val)   (uint32_t) (val & 0xfffc000) >> 14
#define FLB_TASK_TH(val)   (val & 0x3fff)
#define FLB_TASK_SET(ret, task_id, th_id)               \
    (uint32_t) ((ret << 28) | (task_id << 14) | th_id)

struct flb_task_route {
    struct flb_output_instance *out;
    struct mk_list _head;
};

/*
 * When a Task failed in an output instance plugin and this last one
 * requested a FLB_RETRY, a flb_engine_task_retry entry is created and
 * linked into the parent flb_engine_task->retries lists.
 *
 * This reference is used later by the scheduler to re-dispatch the
 * task data to the desired output path.
 */
struct flb_task_retry {
    int attemps;                        /* number of attemps, default 1 */
    struct flb_output_instance *o_ins;  /* route that we are retrying   */
    struct flb_task *parent;            /* parent task reference        */
    struct mk_list _head;               /* link to parent task list     */
};

/* A task takes a buffer and sync input and output instances to handle it */
struct flb_task {
    int id;                             /* task id                   */
    uint64_t ref_id;                    /* external reference id     */
    uint8_t status;                     /* new task or running ?     */
    int n_threads;                      /* number number of threads  */
    int users;                          /* number of users (threads) */
    char *tag;                          /* record tag                */
    int tag_len;                        /* tag length                */
    const char *buf;                    /* buffer                    */
    size_t size;                        /* buffer data size          */
    void *ic;                           /* input chunk */
#ifdef FLB_HAVE_METRICS
    int records;                        /* numbers of records in 'buf'   */
#endif
    struct mk_list threads;             /* ref flb_input_instance->tasks */
    struct mk_list routes;              /* routes to dispatch data       */
    struct mk_list retries;             /* queued in-memory retries      */
    struct mk_list _head;               /* link to input_instance        */
    struct flb_input_instance *i_ins;   /* input instance                */
    struct flb_config *config;          /* parent flb config             */
};

int flb_task_running_count(struct flb_config *config);
int flb_task_running_print(struct flb_config *config);

struct flb_task *flb_task_create(uint64_t ref_id,
                                 const char *buf,
                                 size_t size,
                                 struct flb_input_instance *i_ins,
                                 void *ic,
                                 const char *tag_buf, int tag_len,
                                 struct flb_config *config,
                                 int *err);

void flb_task_add_thread(struct flb_thread *thread,
                         struct flb_task *task);

void flb_task_destroy(struct flb_task *task, int del);

struct flb_task_retry *flb_task_retry_create(struct flb_task *task,
                                             void *data);
void flb_task_retry_destroy(struct flb_task_retry *retry);
int flb_task_retry_reschedule(struct flb_task_retry *retry, struct flb_config *config);
int flb_task_from_fs_storage(struct flb_task *task);
int flb_task_retry_count(struct flb_task *task, void *data);
int flb_task_retry_clean(struct flb_task *task, void *data);


struct flb_task *flb_task_chunk_create(uint64_t ref_id,
                                       const char *buf,
                                       size_t size,
                                       struct flb_input_instance *i_ins,
                                       void *ic,
                                       const char *tag_buf, int tag_len,
                                       struct flb_config *config);
#endif
