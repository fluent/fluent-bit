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

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_buffer.h>
#include <fluent-bit/flb_buffer_qchunk.h>
#include <fluent-bit/flb_engine_dispatch.h>
#include <fluent-bit/flb_worker.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

/* qworker thread initializator */
static int pth_init;
static pthread_cond_t  pth_cond;
static pthread_mutex_t pth_mutex;

/*
 * The 'qchunk' interface provides read-only operations to load Fluent Bit
 * buffer chunks into the engine for further processing.
 *
 * qchunk_add(): upon detection of a buffer chunk, this interface is used
 *               to create a reference to it.
 *
 * qchunk_del(): remove a qchunk reference from the main list.
 *
 * qchunk_worker(): this function runs in a POSIX thread context and it indicate
 *                  the engine when a buffer chunk (data) have been loaded in
 *                  the heap and is ready to be associated to an outgoing task.
 */
struct flb_buffer_qchunk *flb_buffer_qchunk_add(struct flb_buffer_qworker *qw,
                                                char *path, uint64_t routes,
                                                char *tag, char *hash_str)
{
    int len;
    struct flb_buffer_qchunk *qchunk;

    qchunk = flb_malloc(sizeof(struct flb_buffer_qchunk));
    if (!qchunk) {
        perror("malloc");
        return NULL;
    }
    qchunk->id        = 0;
    qchunk->file_path = flb_strdup(path);
    qchunk->routes    = routes;
    memcpy(&qchunk->hash_str, hash_str, 41);

    /* Create the Tag using an offset of the path */
    len = strlen(path);
    qchunk->tag       = (char *) qchunk->file_path + (len - strlen(tag));


    /* Link to the queue */
    mk_list_add(&qchunk->_head, &qw->queue);

    return qchunk;
}


int flb_buffer_qchunk_delete(struct flb_buffer_qchunk *qchunk)
{
    if (qchunk->id > 0) {
        munmap(qchunk->data, qchunk->size);
    }
    flb_free(qchunk->file_path);
    mk_list_del(&qchunk->_head);
    flb_free(qchunk);

    return 0;
}

/* Load a buffer chunk into memory */
static char *qchunk_get_data(struct flb_buffer_qchunk *qchunk, size_t *size)
{
    int fd;
    int ret;
    char *buf;
    struct stat st;

    fd = open(qchunk->file_path, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return NULL;
    }

    ret = fstat(fd, &st);
    if (ret == -1) {
        perror("fstat");
        close(fd);
        return NULL;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return NULL;
    }

    buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (buf == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return NULL;
    }

    close(fd);
    *size = st.st_size;
    return buf;
}

static int qchunk_get_id(struct flb_buffer_qworker *qw)
{
    uint8_t available;
    uint16_t id;
    uint16_t max = (1 << 14) - 1;
    struct mk_list *head;
    struct flb_buffer_qchunk *qchunk;

    for (id = 1; id < max; id++) {
        available = FLB_TRUE;

        mk_list_foreach(head, &qw->queue) {
            qchunk = mk_list_entry(head, struct flb_buffer_qchunk, _head);
            if (qchunk->id == id) {
                available = FLB_FALSE;
                break;
            }
        }

        if (available == FLB_TRUE) {
            return id;
        }
    }

    return -1;
}

/*
 * Upon a PUSH_REQUEST, iterate the qworker queue and look for the first
 * available buffer chunk, load it in memory and notify the engine about
 * this new 'entry' available.
 */
static inline int qchunk_event_push_request(struct flb_buffer *ctx)
{
    int id;
    int ret = 0;
    uint64_t val;
    uint32_t set = 0;
    size_t buf_size;
    char *buf;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_buffer_qchunk *qchunk;
    struct flb_buffer_qworker *qw;

    qw = ctx->qworker;

    flb_trace("[buffer qchunk] event: PUSH_REQUEST received");

    /* Always send the first qchunk entry from the lsit */
    mk_list_foreach_safe(head, tmp, &qw->queue) {
        qchunk = mk_list_entry(head, struct flb_buffer_qchunk, _head);
        if (qchunk->id > 0) {
            continue;
        }

        /* Load into memory */
        buf = qchunk_get_data(qchunk, &buf_size);
        if (!buf) {
            flb_error("[buffer qchunk] could not load %s", qchunk->file_path);
        }

        /* Obtain an ID for this qchunk */
        id = qchunk_get_id(qw);
        if (id == -1) {
            flb_free(buf);
            flb_error("[buffer qchunk] unvailable IDs / max=(1<<14)-1");
            continue;
        }
        qchunk->id   = id;
        qchunk->data = buf;
        qchunk->size = buf_size;

        /*
         * Compose the event message: since we are running in a separate
         * thread and we need to let the Engine that a buffer chunk needs
         * to be loaded with the Scheduler, we issue a 64bits message with
         * the required info.
         *
         * Then the Engine manager will decode the message and invoke back
         * the function flb_buffer_engine_event() where this message will
         * be decoded and processed. The goal is to make this process happen
         * from the parent thread. With this mechanism we avoid the usage
         * locks and we avoid to copy a bunch of data between threads.
         */
        set = FLB_BUFFER_EV_SET(FLB_BUFFER_EV_QCHUNK_PUSH, qchunk->id, 0);
        val = FLB_BITS_U64_SET(FLB_ENGINE_BUFFER, set);
        ret = flb_pipe_w(ctx->config->ch_manager[1], &val, sizeof(val));
        if (ret == -1) {
            perror("write");
            flb_error("[buffer qchunk] could not notify engine");
            flb_free(buf);
            continue;
        }
        return ret;
    }

    return -1;
}

/*
 * Upon a POP_REQUEST, lookup the loaded qchunk buffer, delete it resources
 * and remove it from the list (this routine will NOT touch the original buffer
 * chunk file, that's done by the engine.
 */
static inline int qchunk_event_pop_request(struct flb_buffer *ctx,
                                           uint64_t key)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_buffer_qchunk *qchunk;
    struct flb_buffer_qworker *qw;

    qw = ctx->qworker;

    flb_debug("[buffer qchunk] event: POP_REQUEST received");

    /* Lookup target qchunk for removal */
    mk_list_foreach_safe(head, tmp, &qw->queue) {
        qchunk = mk_list_entry(head, struct flb_buffer_qchunk, _head);
        if (qchunk->id == key) {
            flb_buffer_qchunk_delete(qchunk);
            return 0;
        }
    }

    return -1;
}

/* Handle events from the event loop */
static int qchunk_handle_event(int fd, int mask, struct flb_buffer *ctx)
{
    int ret;
    uint64_t type;
    uint64_t key;
    uint64_t val;

    /* Read the signal value */
    ret = flb_pipe_r(fd, &val, sizeof(val));
    if (ret <= 0) {
        perror("read");
        return -1;
    }

    /* Get type and key */
    type = (val >> 56);
    key  = (val & FLB_BIT_MASK(uint64_t, 56));

    if (type == FLB_BUFFER_QC_STOP) {
        return FLB_BUFFER_QC_STOP;
    }
    else if (type == FLB_BUFFER_QC_PUSH_REQUEST) {
        ret = qchunk_event_push_request(ctx);
    }
    else if (type == FLB_BUFFER_QC_POP_REQUEST) {
        ret = qchunk_event_pop_request(ctx, key);
    }

    return ret;
}

/*
 * This worker function (under a POSIX thread) iterate the qchunk list and
 * upon demand load the physical files into memory and signal the Engine.
 */
static void flb_buffer_qchunk_worker(void *data)
{
    int ret;
    int run = FLB_TRUE;
    struct mk_event *event;
    struct flb_buffer *ctx;
    struct flb_buffer_qworker *qw;

    ctx = data;
    qw = ctx->qworker;

    /* Unlock the conditional */
    pthread_mutex_lock(&pth_mutex);
    pth_init = FLB_TRUE;
    pthread_cond_signal(&pth_cond);
    pthread_mutex_unlock(&pth_mutex);

    /* event loop, listen for events */
    while (run) {
        mk_event_wait(qw->evl);
        mk_event_foreach(event, qw->evl) {
            if (event->type == FLB_BUFFER_EVENT) {
                /* stop the event loop, thread will be destroyed */
                ret = qchunk_handle_event(event->fd, event->mask, ctx);
                if (ret == FLB_BUFFER_QC_STOP) {
                    run = FLB_FALSE;
                }
            }
        }
    }

    pthread_exit(NULL);
}

/* It send a signal to the buffer qchunk worker */
int flb_buffer_qchunk_signal(uint64_t type, uint64_t val,
                             struct flb_buffer_qworker *qw)
{
    uint64_t set;

    set = (type << 56) | (val & FLB_BIT_MASK(uint64_t, 56));
    return flb_pipe_w(qw->ch_manager[1], &set, sizeof(set));
}

int flb_buffer_qchunk_create(struct flb_buffer *ctx)
{
    int ret;
    struct flb_buffer_qworker *qw;

    /* Allocate context */
    qw = flb_malloc(sizeof(struct flb_buffer_qworker));
    if (!qw) {
        perror("malloc");
        return -1;
    }
    qw->tid = 0;
    mk_list_init(&qw->queue);

    /* Create an event loop */
    qw->evl = mk_event_loop_create(16);
    if (!qw->evl) {
        flb_free(qw);
        return -1;
    }

    /* Create a channel for admin purposes */
    ret = mk_event_channel_create(qw->evl,
                                  &qw->ch_manager[0],
                                  &qw->ch_manager[1],
                                  qw);
    if (ret != 0) {
        flb_error("[buffer qchunk] could not create manager channels");
        mk_event_loop_destroy(qw->evl);
        flb_free(qw);
        return -1;
    }

    ctx->qworker = qw;
    return 0;
}

void flb_buffer_qchunk_destroy(struct flb_buffer *ctx)
{
    struct flb_buffer_qworker *qw;
    struct flb_buffer_qchunk *qchunk;
    struct mk_list *tmp;
    struct mk_list *head;

    qw = ctx->qworker;

    /* Delete the list of qchunk entries */
    mk_list_foreach_safe(head, tmp, &qw->queue) {
        qchunk = mk_list_entry(head, struct flb_buffer_qchunk, _head);
        flb_buffer_qchunk_delete(qchunk);
    }

    mk_event_loop_destroy(qw->evl);
    flb_free(qw);
    ctx->qworker = NULL;

    return;
}

int flb_buffer_qchunk_start(struct flb_buffer *ctx)
{
    int ret;
    struct flb_buffer_qworker *qw;

    qw = ctx->qworker;

    pthread_mutex_init(&pth_mutex, NULL);
    pthread_cond_init(&pth_cond, NULL);
    pth_init = FLB_FALSE;

    /*
     * This lock is used for the 'pth_cond' conditional. Once the worker
     * thread is ready will signal the condition.
     */
    pthread_mutex_lock(&pth_mutex);

    /*  Spawn the worker */
    ret = flb_worker_create(flb_buffer_qchunk_worker,
                            ctx, &qw->tid, ctx->config);
    if (ret == -1) {
        flb_warn("[buffer qchunk] could not spawn worker");
        pthread_mutex_unlock(&pth_mutex);
        mk_event_loop_destroy(qw->evl);
        flb_free(qw);
        return -1;
    }

    /* Block until the child thread is ready */
    while (!pth_init) {
        pthread_cond_wait(&pth_cond, &pth_mutex);
    }
    pthread_mutex_unlock(&pth_mutex);

    return 0;
}

int flb_buffer_qchunk_stop(struct flb_buffer *ctx)
{
    struct flb_buffer_qworker *qw;

    qw = ctx->qworker;
    if (qw->tid == 0) {
        flb_buffer_qchunk_destroy(ctx);
        return 0;
    }

    /* Signal (stop) the thread worker */
    flb_buffer_qchunk_signal(FLB_BUFFER_QC_STOP, 0, qw);

    pthread_join(qw->tid, NULL);
    flb_buffer_qchunk_destroy(ctx);

    return 0;
}

/*
 * It push a qchunk data into the Engine. This function is called from
 * the main Engine thread through a previous signal handled on the
 * flb_buffer_engine_event(...) function.
 */
int flb_buffer_qchunk_push(struct flb_buffer *ctx, int id)
{
    int ret;
    struct mk_list *head;
    struct flb_buffer_qworker *qw;
    struct flb_buffer_qchunk *qchunk = NULL;

    qw = ctx->qworker;
    mk_list_foreach(head, &qw->queue) {
        qchunk = mk_list_entry(head, struct flb_buffer_qchunk, _head);
        if (qchunk->id == id) {
            break;
        }
        qchunk = NULL;
    }

    if (!qchunk) {
        return -1;
    }

    ret = flb_engine_dispatch_direct(qchunk->id,
                                     ctx->i_ins,
                                     qchunk->data,
                                     qchunk->size,
                                     qchunk->tag,
                                     qchunk->routes,
                                     qchunk->hash_str,
                                     ctx->config);
    return ret;
}
