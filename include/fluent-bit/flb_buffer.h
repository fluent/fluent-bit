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

#ifdef FLB_HAVE_BUFFERING

#ifndef FLB_BUFFER_H
#define FLB_BUFFER_H

#include <mk_core.h>

struct flb_buffer_chunk {
    void *data;
    size_t size;
    int tag_len;
    char tag[128];
};

struct flb_buffer_worker {
    /* worker info */
    int id;                /* local id */
    pthread_t tid;         /* pthread ID  */
    pid_t task_id;         /* OS PID for this thread */

    /* channels */
    int ch_mng[2];         /* management channel    */
    int ch_add[2];         /* add buffer channel    */
    int ch_del[2];         /* remove buffer channel */

    /* event loop */
    struct mk_event_loop *evl;

    struct mk_list _head;

    struct flb_buffer *parent;
};

struct flb_buffer {

    /* List of flb_buffer_worker nodes */
    int workers_n;
    struct mk_list workers;
};


struct flb_buffer *flb_buffer_create(char *path, int workers);
int flb_buffer_start(struct flb_buffer *ctx);

#endif /* !FLB_BUFFER_H*/
#endif /* !FLB_HAVE_BUFFERING */
