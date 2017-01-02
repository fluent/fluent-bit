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

#include <fluent-bit/flb_info.h>

#ifdef FLB_HAVE_BUFFERING

#include <monkey/mk_core.h>
#include <fluent-bit/flb_buffer.h>
#include <fluent-bit/flb_task.h>

#ifndef FLB_BUFFER_CHUNK_H
#define FLB_BUFFER_CHUNK_H

#define FLB_BUFFER_CHUNK_INCOMING 0
#define FLB_BUFFER_CHUNK_OUTGOING 1
#define FLB_BUFFER_CHUNK_DEFERRED 3

/* Return values */
#define FLB_BUFFER_OK            0
#define FLB_BUFFER_ERROR        -1
#define FLB_BUFFER_NOTFOUND   -404

struct flb_buffer_chunk {
    void *data;
    size_t size;
    uint64_t routes;        /* bitmask routes */
    uint8_t tmp_len;
    int buf_worker;
    char tmp[128];          /* temporal ref: Tag/output_instance */
    char hash_hex[42];
};

int flb_buffer_chunk_add(struct flb_buffer_worker *worker,
                         struct mk_event *event, char **filename);
int flb_buffer_chunk_delete(struct flb_buffer_worker *worker,
                            struct mk_event *event);
int flb_buffer_chunk_delete_ref(struct flb_buffer_worker *worker,
                                struct mk_event *event);

int flb_buffer_chunk_push(struct flb_buffer *ctx, void *data,
                          size_t size, char *tag, uint64_t routes,
                          char *hash_hex);

int flb_buffer_chunk_pop(struct flb_buffer *ctx, int thread_id,
                         struct flb_task *task);

int flb_buffer_chunk_mov(int type, char *name, uint64_t routes,
                         struct flb_buffer_worker *worker);

int flb_buffer_chunk_real_move(struct flb_buffer_worker *worker,
                               struct mk_event *event);
int flb_buffer_chunk_scan(struct flb_buffer *ctx);

#endif

#endif /* !FLB_HAVE_BUFFERING */
