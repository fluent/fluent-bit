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

#include <fluent-bit/flb_info.h>

#ifdef FLB_HAVE_BUFFERING

#ifndef FLB_BUFFER_H
#define FLB_BUFFER_H

#include <mk_core.h>
#include <fluent-bit/flb_config.h>

/* Worker event loop event type */
#define FLB_BUFFER_EV_MNG  1024
#define FLB_BUFFER_EV_ADD  1025
#define FLB_BUFFER_EV_DEL  1026
#define FLB_BUFFER_EV_MOV  1027

struct flb_buffer_worker {
    /* worker info */
    int id;                /* local id */
    pthread_t tid;         /* pthread ID  */
    pid_t task_id;         /* OS PID for this thread */

    /*
     * event mapping: the event loop handle 'struct mk_event' types, we
     * set a new one per channel.
     */
    struct mk_event e_mng;
    struct mk_event e_add;
    struct mk_event e_del;
    struct mk_event e_mov;

    /* channels */
    int ch_mng[2];         /* management channel    */
    int ch_add[2];         /* add buffer channel    */
    int ch_del[2];         /* remove buffer channel */
    int ch_mov[2];         /* move/promote a buffer */

    /* event loop */
    struct mk_event_loop *evl;

    struct mk_list _head;
    struct mk_list requests;
    struct flb_buffer *parent;
};

struct flb_buffer {
    char *path;
    int workers_n;             /* total number of workers */
    int worker_lru;            /* Last-Recent-Used worker */
    struct flb_config *config;
    struct mk_list workers;    /* List of flb_buffer_worker nodes */
};

/* */
struct flb_buffer_request {
    int type;
    char *name;
    struct mk_list _head;   /* Link to buffer_worker->requests */
};

#define FLB_BUFFER_PATH(b)   b->parent->path

struct flb_buffer *flb_buffer_create(char *path, int workers,
                                     struct flb_config *config);

void flb_buffer_destroy(struct flb_buffer *ctx);

int flb_buffer_start(struct flb_buffer *ctx);

#endif /* !FLB_BUFFER_H*/
#endif /* !FLB_HAVE_BUFFERING */
