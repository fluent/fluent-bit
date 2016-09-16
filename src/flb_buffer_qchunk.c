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
#include <fluent-bit/flb_buffer.h>
#include <fluent-bit/flb_buffer_qchunk.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

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
                                                char *path,
                                                uint64_t routes)
{
    struct flb_buffer_qchunk *qchunk;

    qchunk = malloc(sizeof(struct flb_buffer_qchunk));
    if (!qchunk) {
        perror("malloc");
        return NULL;
    }
    qchunk->id        = 0;
    qchunk->file_path = strdup(path);
    qchunk->routes    = routes;
    mk_list_add(&qchunk->_head, &qw->queue);

    return qchunk;
}


int flb_buffer_qchunk_delete(struct flb_buffer_qchunk *qchunk)
{
    free(qchunk->file_path);
    mk_list_del(&qchunk->_head);
    free(qchunk);

    return 0;
}

/* Load a buffer chunk into memory */
static char *qchunk_get_data(struct flb_buffer_qchunk *qchunk, size_t *size)
{
    int fd;
    int ret;
    char *buf;
    struct stat st;

    ret = stat(qchunk->file_path, &st);
    if (ret == -1) {
        perror("stat");
        return NULL;
    }

    fd = open(qchunk->file_path, O_RDONLY);
    if (fd == -1) {
        perror("open");
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
            printf("offering qchunk ID=%i\n", id);
            return id;
        }
    }

    printf("no ID\n");
    return -1;
}

/*
 * This worker function (under a POSIX thread) iterate the qchunk list and
 * upon demand load the physical files into memory and signal the Engine.
 */
static void flb_buffer_qchunk_worker(void *data)
{
    int id;
    int ret;
    char *buf;
    uint32_t set = 0;
    uint64_t val = 0;
    size_t buf_size;
    struct mk_event *event;
    struct flb_buffer *ctx;
    struct flb_buffer_qworker *qw;
    struct flb_buffer_qchunk *qchunk;
    struct mk_list *tmp;
    struct mk_list *head;

    ctx = data;
    qw = ctx->qworker;

    /*
     * Here we do a lazy request into the engine, chunk by chunk:
     *
     * - Iterate qchunk list
     * - For each file entry, load it into memory
     * - Issue the request into the engine
     */
    mk_list_foreach_safe(head, tmp, &qw->queue) {
        qchunk = mk_list_entry(head, struct flb_buffer_qchunk, _head);

        /* Load into memory */
        buf = qchunk_get_data(qchunk, &buf_size);
        if (!buf) {
            flb_error("[buffer qchunk] could not load %s", qchunk->file_path);
        }

        /* Obtain an ID for this qchunk */
        id = qchunk_get_id(qw);
        if (id == -1) {
            free(buf);
            flb_error("[buffer qchunk] unvailable IDs / max=(1<<14)-1");
            continue;
        }
        qchunk->id = id;

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
        ret = write(ctx->config->ch_manager[1], &val, sizeof(val));
        if (ret == -1) {
            perror("write");
            flb_error("[buffer qchunk] could not notify engine");
            free(buf);
            continue;
        }

        mk_event_wait(qw->evl);
        mk_event_foreach(event, qw->evl) {
            /* FIXME: do signal handling */
            (void) event;
        }
    }
}

int flb_buffer_qchunk_create(struct flb_buffer *ctx)
{
    struct flb_buffer_qworker *qw;

    /* Allocate context */
    qw = malloc(sizeof(struct flb_buffer_qworker));
    if (!qw) {
        perror("malloc");
        return -1;
    }
    mk_list_init(&qw->queue);

    /* Create an event loop */
    qw->evl = mk_event_loop_create(16);
    if (!qw->evl) {
        free(qw);
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
    ctx->qworker = NULL;

    /* FIXME: stop thread */
    return;
}

int flb_buffer_qchunk_start(struct flb_buffer *ctx)
{
    int ret;
    struct flb_buffer_qworker *qw;

    qw = ctx->qworker;

    /*  Spawn the worker */
    ret = mk_utils_worker_spawn(flb_buffer_qchunk_worker,
                                ctx, &qw->tid);
    if (ret == -1) {
        flb_warn("[buffer qchunk] could not spawn worker");
        mk_event_loop_destroy(qw->evl);
        free(qw);
        return -1;
    }

    return 0;
}

int flb_buffer_qchunk_stop(struct flb_buffer *ctx)
{
    (void) ctx;
    return 0;
}

/*
 * It push a qchunk data into the Engine. This function is called from
 * the main Engine thread through a previous signal handled on the
 * flb_buffer_engine_event(...) function.
 */
int flb_buffer_qchunk_push(struct flb_buffer *ctx, int id)
{
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

    printf("found qchunk=%p id=%i\n", qchunk, qchunk->id);
    return 0;
}
