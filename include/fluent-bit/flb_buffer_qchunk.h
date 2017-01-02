/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#ifdef FLB_HAVE_BUFFERING

#ifndef FLB_BUFFER_QCHUNK_H
#define FLB_BUFFER_QCHUNK_H

#include <monkey/mk_core.h>
#include <fluent-bit/flb_output.h>

#define FLB_BUFFER_EVENT MK_EVENT_NOTIFICATION

/* qchunk buffer signaling */
#define FLB_BUFFER_QC_STOP           1  /* stop worker event loop            */
#define FLB_BUFFER_QC_PUSH_REQUEST   2  /* external request to push a qchunk */
#define FLB_BUFFER_QC_POP_REQUEST    3  /* external request to pop a qchunk  */
#define FLB_BUFFER_QC_PUSH           4  /* qchunk ready, push done           */

/*
 * A queue chunk (qchunk) represents a buffer chunk that resides in the
 * filesystem and at some point needs to be enqueued into the engine.
 * Entries of this type are linked into 'struct flb_buffer->queue' at
 * startup when discovering not processed buffer chunks.
 */
struct flb_buffer_qchunk {
    uint16_t id;               /* qchunk id (max = (1<<14) - 1         */
    char *file_path;           /* Absolute path to source buffer chunk */
    char *tag;                 /* Tag (offset of file_path position)   */
    uint64_t routes;           /* All pending destinations             */
    char *data;                /* chunk data, after mmap(2)            */
    size_t size;               /* data size                            */
    char hash_str[41];         /* buffer hash (taken from filename     */
    struct mk_list _head;      /* Link to buffer head at ctx->queue    */
};

struct flb_buffer_qworker {
    struct mk_event ch_event;  /* root event               */
    pthread_t tid;             /* pthread ID               */
    pid_t task_id;             /* OS PID for this thread   */
    int ch_manager[2];         /* channel to signal worker */
    struct mk_event_loop *evl; /* event loop               */
    struct mk_list queue;      /* chunks queue             */
};

int flb_buffer_qchunk_signal(uint64_t type, uint64_t val,
                             struct flb_buffer_qworker *qw);

struct flb_buffer_qchunk *flb_buffer_qchunk_add(struct flb_buffer_qworker *qw,
                                                char *path, uint64_t routes,
                                                char *tag, char *hash_str);
int flb_buffer_qchunk_delete(struct flb_buffer_qchunk *qchunk);

int flb_buffer_qchunk_create(struct flb_buffer *ctx);
void flb_buffer_qchunk_destroy(struct flb_buffer *ctx);

int flb_buffer_qchunk_start(struct flb_buffer *ctx);
int flb_buffer_qchunk_stop(struct flb_buffer *ctx);

int flb_buffer_qchunk_push(struct flb_buffer *ctx, int id);

#endif
#endif
