/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#ifndef FLB_ENGINE_TASK_H
#define FLB_ENGINE_TASK_H

#include <pthread.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_buffer.h>
#include <fluent-bit/flb_thread.h>
#include <fluent-bit/flb_input.h>

/* Task status */
#define FLB_ENGINE_TASK_NEW      0
#define FLB_ENGINE_TASK_RUNNING  1

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

#define FLB_ENGINE_TASK_RET(val)  (val >> 28)
#define FLB_ENGINE_TASK_ID(val)   (uint16_t) (val & 0xfffc000) >> 14
#define FLB_ENGINE_TASK_TH(val)   (val & 0x3fff)
#define FLB_ENGINE_TASK_SET(ret, task_id, th_id)    \
    (uint32_t) ((ret << 28) | (task_id << 14) | th_id)

struct flb_engine_task_route {
    struct flb_output_instance *out;
    struct mk_list _head;
};

/* A task takes a buffer and sync input and output instances to handle it */
struct flb_engine_task {
    int id;                                /* task id                   */
    int status;                            /* new task or running ?     */
    int deleted;                           /* should be deleted ?       */
    int n_threads;                         /* number number of threads  */
    int users;                             /* number of users (threads) */
    char *tag;                             /* original tag              */
    char *buf;                             /* buffer                    */
    size_t size;                           /* buffer data size          */
    struct flb_input_dyntag *dt;           /* dyntag node (if applies)  */
    struct flb_input_instance *i_ins;      /* input instance            */
    struct mk_list threads;                /* ref flb_input_instance->tasks */
    struct mk_list routes;                 /* routes to dispatch data   */
    struct mk_list _head;                  /* link to input_instance    */
    struct flb_config *config;             /* parent flb config         */

#ifdef FLB_HAVE_FLUSH_PTHREADS
    pthread_mutex_t mutex_threads;
#endif
};

struct flb_engine_task *flb_engine_task_create(char *buf,
                                               size_t size,
                                               struct flb_input_instance *i_ins,
                                               struct flb_input_dyntag *dt,
                                               char *tag,
                                               struct flb_config *config);
void flb_engine_task_destroy(struct flb_engine_task *task);

#endif
