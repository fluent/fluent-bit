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

#ifndef FLB_BUFFER_H
#define FLB_BUFFER_H

#include <monkey/mk_core.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pipe.h>

/* Worker event loop event type */
#define FLB_BUFFER_EV_MNG     1024
#define FLB_BUFFER_EV_ADD     1025
#define FLB_BUFFER_EV_DEL     1026
#define FLB_BUFFER_EV_DEL_REF 1027
#define FLB_BUFFER_EV_MOV     1028

/* Macros to handle events into Buffering event loops */
#define FLB_BUFFER_EV_QCHUNK_PUSH  1
#define FLB_BUFFER_EV_QCHUNK_POP   2

/*
 * Each event is an unsigned 32 bit number where it have 3 sections:
 *
 * - type : identify event type (4 bits)
 * - key  : key identification for the event (14 bits)
 * - value: some value associated to the key (14 bits)
 *
 * the format is as follows:
 *
 *     AAAA     BBBBBBBBBBBBBB CCCCCCCCCCCCCC   > 32 bit number
 *       ^            ^              ^
 *    4 bits       14 bits        14 bits
 *  event type       key           value
 */

#define FLB_BUFFER_EV_TYPE(val)  (val >> 28)
#define FLB_BUFFER_EV_KEY(val)   (uint16_t) (val & 0xfffc000) >> 14
#define FLB_BUFFER_EV_VAL(val)   (val & 0x3fff)
#define FLB_BUFFER_EV_SET(type, key, val)           \
    (uint32_t) ((type << 28) | (key << 14) | val)

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
    struct mk_event e_del_ref;
    struct mk_event e_mov;

    /* channels */
    flb_pipefd_t ch_mng[2];     /* management channel                    */
    flb_pipefd_t ch_add[2];     /* add buffer channe                     */
    flb_pipefd_t ch_del[2];     /* remove buffer chunk channel           */
    flb_pipefd_t ch_del_ref[2]; /* remove buffer chunk reference channel */
    flb_pipefd_t ch_mov[2];     /* move/promote a buffer chunk           */

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
    void *qworker;             /* queue chunk nodes  */
    struct flb_config *config; /* Fluent Bit context */
    struct mk_list workers;    /* List of flb_buffer_worker nodes  */

    /*
     * When the buffering interface through the queue-worker system load
     * some 'buffers' for processing, it needs to instruct the Engine about
     * it. So the buffer context behaves as an input instance so further
     * tasks and threads can be created.
     */
    struct flb_input_instance *i_ins;
};

/* */
struct flb_buffer_request {
    int type;
    char name[1024];
    struct mk_list _head;   /* Link to buffer_worker->requests */
};

#define FLB_BUFFER_PATH(b)   b->parent->path

struct flb_buffer *flb_buffer_create(char *path, int workers,
                                     struct flb_config *config);

void flb_buffer_destroy(struct flb_buffer *ctx);

int flb_buffer_start(struct flb_buffer *ctx);
int flb_buffer_stop(struct flb_buffer *ctx);
int flb_buffer_engine_event(struct flb_buffer *ctx, uint32_t event);

#endif /* !FLB_BUFFER_H*/
#endif /* !FLB_HAVE_BUFFERING */
