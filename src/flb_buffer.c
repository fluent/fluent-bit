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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <inttypes.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>

#ifdef FLB_HAVE_BUFFERING

#include <monkey/mk_core.h>
#include <fluent-bit/flb_buffer.h>
#include <fluent-bit/flb_buffer_chunk.h>
#include <fluent-bit/flb_buffer_qchunk.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_worker.h>

/* qworker thread initializator */
static int pth_buffer_init;
static pthread_cond_t  pth_buffer_cond;
static pthread_mutex_t pth_buffer_mutex;

/*
 * This routine runs in a POSIX thread and it aims to listen for requests
 * to store and remove 'buffer chunks'.
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
    int run = FLB_TRUE;
    uint64_t routes;
    char *filename;
    struct flb_buffer_worker *ctx;
    struct mk_event *event;

    /* Get context */
    ctx = (struct flb_buffer_worker *) arg;
#ifdef __linux__
    ctx->task_id = syscall(__NR_gettid);
#endif

    MK_EVENT_NEW(&ctx->e_mng);
    MK_EVENT_NEW(&ctx->e_add);
    MK_EVENT_NEW(&ctx->e_del);
    MK_EVENT_NEW(&ctx->e_del_ref);

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

    /* Register channel 'del_reference' into the event loop */
    ret = mk_event_add(ctx->evl, ctx->ch_del_ref[0],
                       FLB_BUFFER_EV_DEL_REF, MK_EVENT_READ, &ctx->e_del_ref);
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

    /* Unlock the conditional */
    pthread_mutex_lock(&pth_buffer_mutex);
    pth_buffer_init = FLB_TRUE;
    pthread_cond_signal(&pth_buffer_cond);
    pthread_mutex_unlock(&pth_buffer_mutex);

    flb_debug("[buffer: worker %i] ready", ctx->id);

    /* Join into the event loop (start listening for events) */
    while (run) {
        mk_event_wait(ctx->evl);
        mk_event_foreach(event, ctx->evl) {
            if (event->type == FLB_BUFFER_EV_MNG) {
                run = FLB_FALSE;
            }
            else if (event->type == FLB_BUFFER_EV_ADD) {
                /* Read event triggered from flb_buffer_chunk_push(...) */
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
                    ret = flb_buffer_chunk_mov(FLB_BUFFER_CHUNK_OUTGOING,
                                               filename, routes, ctx);
                    if (ret == -1) {
                        printf("[buffer] could not create request %s\n", filename);
                        flb_free(filename);
                        continue;
                    }
                }
                flb_free(filename);
            }
            else if (event->type == FLB_BUFFER_EV_DEL) {
                flb_buffer_chunk_delete(ctx, event);
            }
            else if (event->type == FLB_BUFFER_EV_DEL_REF) {
                ret = flb_buffer_chunk_delete_ref(ctx, event);
                if (ret == FLB_BUFFER_NOTFOUND) {
                    /*
                     * The Buffer Chunk Reference was not found, likely it
                     * tried to find:
                     *
                     *    task/abc/000000000000000000000000000000.A.B.C
                     *
                     * if it was not found could be because the Task have not
                     * been stored yet into the file system. The buffer worker
                     * it's a separate POSIX thread, so in some cases output
                     * plugins may finish before the buffer chunk is promoted
                     * to the 'outgoing queue'.
                     *
                     * Anyways this is not problem, the chunk_delete_ref() already
                     * issued a chunk_miss() call to cleanup this situation.
                     */
                }
            }
            else if (event->type == FLB_BUFFER_EV_MOV) {
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
        pthread_join(worker->tid, NULL);

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

        /* Delete reference buffer channel */
        if (worker->ch_del_ref[0] > 0) {
            mk_event_del(worker->evl, &worker->e_del_ref);
            close(worker->ch_del_ref[0]);
            close(worker->ch_del_ref[1]);
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
        flb_free(worker);
    }

    mk_list_del(&ctx->i_ins->_head);
    flb_free(ctx->i_ins);
    flb_free(ctx->path);
    flb_free(ctx);
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
            flb_errno();
            flb_error("[buffer] path '%s' cannot be created", path);
            return -1;
        }
        /* re-stat the new path */
        ret = stat(path, &st);
        if (ret == -1) {
            flb_errno();
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

    /* For each output plugin instance, create an entry on tasks */
    mk_list_foreach(head, &config->outputs) {
        ins = mk_list_entry(head, struct flb_output_instance, _head);

        /* tasks/PLUGIN_NAME */
        snprintf(tmp, sizeof(tmp) - 1, "%s/tasks/%s",
                 path, ins->name);
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
    int path_len;
    struct flb_buffer *ctx;
    struct flb_buffer_worker *worker;
    struct stat st;

    /* Validate the incoming ROOT path/directory */
    ret = stat(path, &st);
    if (ret == -1) {
        flb_errno();
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
    ctx = flb_malloc(sizeof(struct flb_buffer));
    if (!ctx) {
        return NULL;
    }
    ctx->qworker = NULL;
    ctx->i_ins = NULL;

    path_len = strlen(path);
    if (path[path_len - 1] != '/') {
        ctx->path = flb_malloc(path_len + 2);
        memcpy(ctx->path, path, path_len);
        ctx->path[path_len++] = '/';
        ctx->path[path_len++] = '\0';
    }
    else {
        ctx->path = flb_strdup(path);
    }

    ctx->worker_lru = -1;
    ctx->config     = config;
    mk_list_init(&ctx->workers);

    ctx->workers_n = workers;
    if (workers <= 0) {
        ctx->workers_n = 1;
    }

    for (i = 0; i < ctx->workers_n; i++) {
        /* Allocate worker context */
        worker = flb_calloc(1, sizeof(struct flb_buffer_worker));
        if (!worker) {
            flb_buffer_destroy(ctx);
            return NULL;
        }
        worker->id = i;
        worker->parent = ctx;
        mk_list_add(&worker->_head, &ctx->workers);
        mk_list_init(&worker->requests);

        /* Management channel */
        ret = flb_pipe_create(worker->ch_mng);
        if (ret == -1) {
            flb_errno();
            flb_buffer_destroy(ctx);
            return NULL;
        }

        /* Add buffer channel */
        ret = flb_pipe_create(worker->ch_add);
        if (ret == -1) {
            flb_errno();
            flb_buffer_destroy(ctx);
            return NULL;
        }

        /* Delete buffer channel */
        ret = flb_pipe_create(worker->ch_del);
        if (ret == -1) {
            flb_errno();
            flb_buffer_destroy(ctx);
            return NULL;
        }

        /* Delete reference buffer channel */
        ret = flb_pipe_create(worker->ch_del_ref);
        if (ret == -1) {
            flb_errno();
            flb_buffer_destroy(ctx);
            return NULL;
        }

        /* Move buffer channel */
        ret = flb_pipe_create(worker->ch_mov);
        if (ret == -1) {
            flb_errno();
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

    /* Generate pseudo input plugin and instance */
    ctx->i_ins = flb_calloc(1, sizeof(struct flb_input_instance));
    if (!ctx->i_ins) {
        flb_errno();
        flb_buffer_destroy(ctx);
        return NULL;
    }
    snprintf(ctx->i_ins->name, sizeof(ctx->i_ins->name) - 1,
             "buffering.0");
    mk_list_init(&ctx->i_ins->routes);
    mk_list_init(&ctx->i_ins->tasks);
    mk_list_init(&ctx->i_ins->dyntags);

    ctx->i_ins->mp_total_buf_size = 0;
    ctx->i_ins->mp_buf_limit = 0;
    ctx->i_ins->mp_buf_status = FLB_INPUT_RUNNING;

    mk_list_add(&ctx->i_ins->_head, &config->inputs);

    /* We are done */
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

    pthread_mutex_init(&pth_buffer_mutex, NULL);
    pthread_cond_init(&pth_buffer_cond, NULL);

    /* Start workers in charge to store/delete buffer chunks */
    mk_list_foreach(head, &ctx->workers) {
        worker = mk_list_entry(head, struct flb_buffer_worker, _head);

        pth_buffer_init = FLB_FALSE;
        pthread_mutex_lock(&pth_buffer_mutex);

        /* Spawn workers */
        ret = flb_worker_create(flb_buffer_worker_init,
                                worker, &worker->tid, ctx->config);

        /* Block until the child worker is ready */
        while (!pth_buffer_init) {
            pthread_cond_wait(&pth_buffer_cond, &pth_buffer_mutex);
        }
        pthread_mutex_unlock(&pth_buffer_mutex);

        flb_debug("[buffer] started worker #%i status=%i task_id=%d (PID)",
                  worker->id, ret, worker->task_id);

        if (ret == 0) {
            n++;
        }
    }

    /*
     * Start workers in charge to read existent buffer chunks, they aim
     * to put them back into the engine for processing.
     */
    ret = flb_buffer_qchunk_create(ctx);
    if (ret == -1) {
        flb_buffer_destroy(ctx);
        return -1;
    }

    /*
     * Once the path is ready, check if we have some previous buffer chunk
     * files.
     */
    ret = flb_buffer_chunk_scan(ctx);
    if (ret == -1) {
        flb_buffer_destroy(ctx);
        return -1;
    }

    /* Start the qchunk worker thread */
    ret = flb_buffer_qchunk_start(ctx);
    if (ret == -1) {
        flb_buffer_destroy(ctx);
        return -1;
    }

    return n;
}

/* Stop buffer workers */
int flb_buffer_stop(struct flb_buffer *ctx)
{
    int n;
    uint64_t val = 0;
    struct mk_list *head;
    struct flb_buffer_worker *worker;

    /* Remove any pending task loaded from qchunk */
    flb_engine_destroy_tasks(&ctx->i_ins->tasks);

    /*
     * Signal the manager of each buffer worker (chunk writers), the signal
     * will let them stop working and exit.
     */
    mk_list_foreach(head, &ctx->workers) {
        worker = mk_list_entry(head, struct flb_buffer_worker, _head);
        n = flb_pipe_w(worker->ch_mng[1], &val, sizeof(val));
        if (n == -1) {
            flb_errno();
        }
    }

    /* Stop and destroy the qchunk worker */
    flb_buffer_qchunk_stop(ctx);

    /*
     * Destroy the context: iterate each worker, do a pthread_join, release
     * context, event loops and pipes.
     */
    flb_buffer_destroy(ctx);

    return 0;
}

int flb_buffer_engine_event(struct flb_buffer *ctx, uint32_t event)
{
    int type;
    int key;
    int ret;

    /* Decode the event set */
    type = FLB_BUFFER_EV_TYPE(event);
    key  = FLB_BUFFER_EV_KEY(event);

    if (type == FLB_BUFFER_EV_QCHUNK_PUSH) {
        ret = flb_buffer_qchunk_push(ctx, key);
        if (ret == -1) {
            flb_error("[buffer] could not schedule qchunk");
            return -1;
        }
    }

    return 0;
}

#endif /* !FLB_HAVE_BUFFERING */
