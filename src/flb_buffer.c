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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <inttypes.h>

#include <fluent-bit/flb_info.h>

#ifdef FLB_HAVE_BUFFERING

#include <mk_core.h>
#include <fluent-bit/flb_buffer.h>
#include <fluent-bit/flb_utils.h>

/*
 * This routine runs in a POSIX thread and it aims to listen for requests
 * to store and remove 'record buffers'.
 *
 * An input instance plugin generate a set of records in MessagePack format,
 * and here we write to a storage point in the file system.
 *
 * Each buffer is stored in a file with the following name/format:
 *
 *    flb.unixtimestamp.TAG
 */
static void flb_buffer_worker_init(void *arg)
{
    struct flb_buffer_worker *ctx;

    /* Get context */
    ctx = (struct flb_buffer_worker *) arg;
    ctx->task_id = syscall(__NR_gettid);

}

void flb_buffer_destroy(struct flb_buffer *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_buffer_worker *worker;

    /* Destroy workers if any */
    mk_list_foreach_safe(head, tmp, &ctx->workers) {
        worker = mk_list_entry(head, struct flb_buffer_worker, _head);

        /* Management channel */
        if (worker->ch_mng[0] > 0) {
            close(worker->ch_mng[0]);
            close(worker->ch_mng[1]);
        }

        /* Add buffer channel */
        if (worker->ch_add[0] > 0) {
            close(worker->ch_add[0]);
            close(worker->ch_add[1]);
        }

        /* Delete buffer channel */
        if (worker->ch_del[0] > 0) {
            close(worker->ch_del[0]);
            close(worker->ch_del[1]);
        }

        /* Event loop */
        if (worker->evl) {
            mk_event_loop_destroy(worker->evl);
        }
        mk_list_del(&worker->_head);
        free(worker);

        /* FIXME: channel to notify a shutdown */
    }
}

/*
 * This function creates a buffer handler instance and it creates
 * a fixed number of POSIX threads which will take care of I/O
 * operations to the file system.
 */
struct flb_buffer *flb_buffer_create(char *path, int workers)
{
    int i;
    int ret;
    struct flb_buffer *ctx;
    struct flb_buffer_worker *worker;
    struct stat st;

    /* Validate the incoming path/directory */
    ret = stat(path, &st);
    if (ret == -1) {
        perror("stat");
        return NULL;
    }

    if (!S_ISDIR(st.st_mode)) {
        flb_error("[buffer] path '%s' is not a directory", path);
        return NULL;
    }

    ret = access(path, W_OK);
    if (ret != 0) {
        flb_error("[buffer] not enough permissions on path '%s'", path);
        return NULL;
    }

    /* Main buffer context */
    ctx = malloc(sizeof(struct flb_buffer));
    if (!ctx) {
        return NULL;
    }
    mk_list_init(&ctx->workers);

    if (workers <= 0) {
        ctx->workers_n = 1;
    }

    printf("workers to init=%i\n", ctx->workers_n);
    for (i = 0; i < ctx->workers_n; i++) {
        /* Allocate worker context */
        worker = calloc(1, sizeof(struct flb_buffer_worker));
        if (!worker) {
            flb_buffer_destroy(ctx);
            return NULL;
        }
        worker->id = i;
        worker->parent = ctx;
        mk_list_add(&worker->_head, &ctx->workers);

        /* Management channel */
        ret = pipe(worker->ch_mng);
        if (ret == -1) {
            perror("pipe");
            flb_buffer_destroy(ctx);
            return NULL;
        }

        /* Add buffer channel */
        ret = pipe(worker->ch_add);
        if (ret == -1) {
            perror("pipe");
            flb_buffer_destroy(ctx);
            return NULL;
        }

        /* Delete buffer channel */
        ret = pipe(worker->ch_del);
        if (ret == -1) {
            perror("pipe");
            flb_buffer_destroy(ctx);
            return NULL;
        }

        worker->evl = mk_event_loop_create(4);
        if (!worker->evl) {
            flb_buffer_destroy(ctx);
            return NULL;
        }
    }

    ctx->workers_n = i;

    flb_debug("[buffer] new instance created; workers=%i", ctx->workers_n);
    return ctx;
}

/* Start buffer workers and event loops */
int flb_buffer_start(struct flb_buffer *ctx)
{
    int n = 0;
    int ret;
    struct mk_list *head;
    struct flb_buffer_worker *worker;

    mk_list_foreach(head, &ctx->workers) {
        worker = mk_list_entry(head, struct flb_buffer_worker, _head);

        /* spawn a POSIX thread */
        ret = mk_utils_worker_spawn(flb_buffer_worker_init,
                                    worker, &worker->tid);
        flb_debug("[buffer] start worker #%i status=%i task_id=%d",
                  worker->id, ret, worker->task_id);
        if (ret == 0) {
            n++;
        }
    }

    return n;
}

#endif /* !FLB_HAVE_BUFFERING */
