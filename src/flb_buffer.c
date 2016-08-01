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
#include <fluent-bit/flb_buffer_chunk.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_output.h>

/*
 * This routine runs in a POSIX thread and it aims to listen for requests
 * to store and remove 'record buffers'.
 *
 * An input instance plugin generate a set of records in MessagePack format,
 * and here we write to a storage point in the file system.
 *
 * Each buffer is stored in a file with the following name/format:
 *
 *    SHA1(chunk_content).routes_id.wID.TAG
 */
static void flb_buffer_worker_init(void *arg)
{
    int ret;
    uint64_t routes;
    char *filename;
    struct flb_buffer_worker *ctx;
    struct mk_event *event;
    struct flb_buffer_request *req;

    /* Get context */
    ctx = (struct flb_buffer_worker *) arg;
#ifdef __linux__
    ctx->task_id = syscall(__NR_gettid);
#endif

    MK_EVENT_NEW(&ctx->e_mng);
    MK_EVENT_NEW(&ctx->e_add);
    MK_EVENT_NEW(&ctx->e_del);

    /* Register channel manager into the event loop */
    ret = mk_event_add(ctx->evl, ctx->ch_mng[0],
                       FLB_BUFFER_EV_MNG, MK_EVENT_READ, &ctx->e_mng);
    if (ret == -1) {
        flb_error("[buffer:worker %i] aborting", ctx->id);
        return;
    }

    /* Register channel 'add' into the event loop */
    ret = mk_event_add(ctx->evl, ctx->ch_add[0],
                       FLB_BUFFER_EV_ADD, MK_EVENT_READ, &ctx->e_add);
    if (ret == -1) {
        flb_error("[buffer:worker %i] aborting", ctx->id);
        return;
    }

    /* Register channel 'del' into the event loop */
    ret = mk_event_add(ctx->evl, ctx->ch_del[0],
                       FLB_BUFFER_EV_DEL, MK_EVENT_READ, &ctx->e_del);
    if (ret == -1) {
        flb_error("[buffer:worker %i] aborting", ctx->id);
        return;
    }

    /* Register channel 'mov' into the event loop */
    ret = mk_event_add(ctx->evl, ctx->ch_mov[0],
                       FLB_BUFFER_EV_MOV, MK_EVENT_READ, &ctx->e_mov);
    if (ret == -1) {
        flb_error("[buffer:worker %i] aborting", ctx->id);
        return;
    }

    /* Join into the event loop (start listening for events) */
    while (1) {
        mk_event_wait(ctx->evl);
        mk_event_foreach(event, ctx->evl) {
            if (event->type == FLB_BUFFER_EV_MNG) {
                printf("[buffer] [ev_mng]\n");
            }
            else if (event->type == FLB_BUFFER_EV_ADD) {
                printf("[buffer] [ev_add]\n");
                filename = NULL;
                ret = flb_buffer_chunk_add(ctx, event, &filename);
                if (ret >= 0) {
                    /*
                     * If a buffer chunk have been stored properly, now it
                     * must be promoted to the next 'outgoing' stage. We do this
                     * sending a request through the event loop.
                     *
                     * Create and enqueue a new request type.
                     */
                    routes = ret;
                    req = flb_buffer_chunk_mov(FLB_BUFFER_CHUNK_OUTGOING,
                                               filename, routes, ctx);
                    if (!req) {
                        printf("[buffer] could not create request %s\n", filename);
                        free(filename);
                        continue;
                    }
                }
            }
            else if (event->type == FLB_BUFFER_EV_DEL) {
                printf("[buffer] [ev_del]\n");
            }
            else if (event->type == FLB_BUFFER_EV_MOV) {
                printf("[buffer] [ev_mov]\n");
                flb_buffer_chunk_real_move(ctx, event);
            }
        }
    }
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
            mk_event_del(worker->evl, &worker->e_mng);
            close(worker->ch_mng[0]);
            close(worker->ch_mng[1]);
        }

        /* Add buffer channel */
        if (worker->ch_add[0] > 0) {
            mk_event_del(worker->evl, &worker->e_add);
            close(worker->ch_add[0]);
            close(worker->ch_add[1]);
        }

        /* Delete buffer channel */
        if (worker->ch_del[0] > 0) {
            mk_event_del(worker->evl, &worker->e_del);
            close(worker->ch_del[0]);
            close(worker->ch_del[1]);
        }

        /* Move buffer channel */
        if (worker->ch_mov[0] > 0) {
            mk_event_del(worker->evl, &worker->e_mov);
            close(worker->ch_mov[0]);
            close(worker->ch_mov[1]);
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

/* Check that a directory exists and have write access, if not, create it */
static int buffer_dir(char *path)
{
    int ret;
    struct stat st;

    ret = stat(path, &st);
    if (ret == -1) {
        /* The directory don't exists, try to create it */
        ret = mkdir(path, 0700);
        if (ret == -1) {
            perror("mkdir");
            flb_error("[buffer] path '%s' cannot be created", path);
            return -1;
        }
        /* re-stat the new path */
        ret = stat(path, &st);
        if (ret == -1) {
            perror("stat");
            flb_error("[buffer] unexpected error on path '%s'", path);
            return -1;
        }
    }

    /* Validate entry is a directory */
    if (!S_ISDIR(st.st_mode)) {
        flb_error("[buffer] path '%s' is not a directory", path);
        return -1;
    }

    return 0;
}

/* Check and prepare the buffer queue tree */
static int buffer_queue_path(char *path, struct flb_config *config)
{
    int ret;
    char tmp[PATH_MAX];
    struct mk_list *head;
    struct flb_output_instance *ins;

    /* /incoming/ */
    snprintf(tmp, sizeof(tmp) - 1, "%s/incoming", path);
    ret = buffer_dir(tmp);
    if (ret == -1) {
        return -1;
    }

    /* /outgoing/ */
    snprintf(tmp, sizeof(tmp) - 1, "%s/outgoing", path);
    ret = buffer_dir(tmp);
    if (ret == -1) {
        return -1;
    }

    /* /tasks/ */
    snprintf(tmp, sizeof(tmp) - 1, "%s/tasks", path);
    ret = buffer_dir(tmp);
    if (ret == -1) {
        return -1;
    }

    /* /deferred/ */
    snprintf(tmp, sizeof(tmp) - 1, "%s/deferred", path);
    ret = buffer_dir(tmp);
    if (ret == -1) {
        return -1;
    }

    /* For each output plugin instance, create an entry on tasks and deferred */
    mk_list_foreach(head, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);

        /* tasks/PLUGIN_NAME */
        snprintf(tmp, sizeof(tmp) - 1, "%s/tasks/%s",
                 path, ins->name);
        ret = buffer_dir(tmp);
        if (ret == -1) {
            return -1;
        }

        /* deferred/PLUGIN_NAME */
        snprintf(tmp, sizeof(tmp) - 1, "%s/deferred/%s",
                 path, ins->p->name);
        ret = buffer_dir(tmp);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

/*
 * This function creates a buffer handler instance and it creates
 * a fixed number of POSIX threads which will take care of I/O
 * operations to the file system.
 */
struct flb_buffer *flb_buffer_create(char *path, int workers,
                                     struct flb_config *config)
{
    int i;
    int ret;
    struct flb_buffer *ctx;
    struct flb_buffer_worker *worker;
    struct stat st;

    /* Validate the incoming ROOT path/directory */
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

    /* Prepare the directories to manage the buffer queues */
    ret = buffer_queue_path(path, config);
    if (ret != 0) {
        return NULL;
    }

    /* Main buffer context */
    ctx = malloc(sizeof(struct flb_buffer));
    if (!ctx) {
        return NULL;
    }
    ctx->path       = strdup(path);
    ctx->worker_lru = -1;
    ctx->config     = config;
    mk_list_init(&ctx->workers);

    ctx->workers_n = workers;
    if (workers <= 0) {
        ctx->workers_n = 1;
    }

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
        mk_list_init(&worker->requests);

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

        /* Move buffer channel */
        ret = pipe(worker->ch_mov);
        if (ret == -1) {
            perror("pipe");
            flb_buffer_destroy(ctx);
            return NULL;
        }

        worker->evl = mk_event_loop_create(16);
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

/* Stop buffer workers */
int flb_buffer_stop(struct flb_buffer *ctx)
{
    (void) ctx;
    return 0;
}

#endif /* !FLB_HAVE_BUFFERING */
