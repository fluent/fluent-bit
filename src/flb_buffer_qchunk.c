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
struct flb_buffer_qchunk *flb_buffer_qchunk_add(struct flb_buffer *ctx,
                                                char *path,
                                                uint64_t routes)
{
    struct flb_buffer_qchunk *qchunk;

    qchunk = malloc(sizeof(struct flb_buffer_qchunk));
    if (!qchunk) {
        perror("malloc");
        return NULL;
    }

    qchunk->file_path = strdup(path);
    qchunk->routes    = routes;
    mk_list_add(&qchunk->_head, &ctx->queue);

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

/*
 * The worker iterate the qchunk list and upon demand load the physical files
 * into memory.man
 */
static void *flb_buffer_qchunk_worker(struct flb_buffer_qworker *qw)
{
    struct mk_event *event;

    while (1) {
        mk_event_wait(qw->evl);
        mk_event_foreach(event, qw->evl) {
            /* FIXME: do signal handling */
        }
    }
}

int flb_buffer_qchunk_init(struct flb_buffer *ctx)
{
    int ret;
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

    /*  Spawn the worker */
    ret = mk_utils_worker_spawn(flb_buffer_qchunk_worker,
                                qw, &qw->tid);
    if (ret == -1) {
        flb_warn("[buffer qchunk] could not spawn worker");
        mk_event_loop_destroy(qw->evl);
        free(qw);
        return -1;
    }

    ctx->qworker = qw;

    return 0;
}
