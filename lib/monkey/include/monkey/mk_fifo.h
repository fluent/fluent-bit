/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#ifndef MK_FIFO_H
#define MK_FIFO_H

#include <monkey/mk_info.h>
#include <monkey/mk_config.h>
#include <monkey/mk_core.h>

#define MK_FIFO_BUF_SIZE   32768

#ifdef _WIN32
#ifdef _WIN64
typedef long long mk_fifo_channel_fd;
#else
typedef long long mk_fifo_channel_fd;
#endif
#else
typedef int mk_fifo_channel_fd;
#endif

struct mk_fifo_worker {
    struct mk_event event; /* event loop 'event' */
    int worker_id;         /* worker ID */
    mk_fifo_channel_fd channel[2];        /* pipe(2) communication channel */
    void *data;            /* opaque data for thread */

    /* Read buffer */
    char *buf_data;
    size_t buf_len;
    size_t buf_size;

    void *fifo;            /* original FIFO context associated with */
    struct mk_list _head;  /* link to paremt mk_msg.workers list */
};

struct mk_fifo_msg {
    uint32_t length;
    uint16_t flags;
    uint16_t queue_id;
    char data[];
};

struct mk_fifo_queue {
    uint16_t id;            /* queue id */
    char name[16];          /* queue name */
    struct mk_list _head;   /* link to parent mk_msg.queues list */

    /*
     * Callback function to be used by message reader once a complete
     * message is ready to be processed. This callback is invoked
     * from a thread context (pipe read end).
     */
    void (*cb_message)(struct mk_fifo_queue *, void *, size_t, void *);
    void *data;
};

struct mk_fifo {
    pthread_key_t *key;          /* pthread key */
    pthread_mutex_t mutex_init;  /* pthread mutex used for initialization */
    void *data;                  /* opate data context */
    struct mk_list queues;       /* list of registered queues */
    struct mk_list workers;      /* context for Monkey workers */
};

void mk_fifo_worker_setup(void *data);
int mk_fifo_worker_read(void *event);

struct mk_fifo *mk_fifo_create(pthread_key_t *key, void *data);
int mk_fifo_queue_create(struct mk_fifo *ctx, char *name,
                         void (*cb)(struct mk_fifo_queue *, void *,
                                    size_t, void *),
                         void *data);
struct mk_fifo_queue *mk_fifo_queue_get(struct mk_fifo *ctx, int id);
int mk_fifo_queue_destroy(struct mk_fifo *ctx, struct mk_fifo_queue *q);
int mk_fifo_queue_id_destroy(struct mk_fifo *ctx, int id);
int mk_fifo_destroy(struct mk_fifo *ctx);
int mk_fifo_send(struct mk_fifo *ctx, int id, void *data, size_t size);

#endif
