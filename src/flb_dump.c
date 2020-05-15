/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_task.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_utils.h>

#ifdef FLB_DUMP_STACKTRACE
#include <fluent-bit/flb_stacktrace.h>
#endif

#include <stdio.h>
#include <time.h>

/*
 * Input Chunks
 * ============
 * Every input plugin instance has it own Chunk I/O stream. The stream is used to
 * associate data from the specific origin.
 *
 * This dump prints out information about current status of chunks registered by
 * the input plugin interface and resources usage.
 */
static void dump_input_chunks(struct flb_config *ctx)
{
    /* general */
    int ret;
    ssize_t size;

    /* tasks */
    int task_new;
    int task_running;

    /* chunks */
    int up;
    int down;
    int busy;
    int busy_size_err;
    ssize_t busy_size;
    char tmp[32];

    struct mk_list *head;
    struct mk_list *h_chunks;
    struct mk_list *h_task;
    struct flb_input_instance *i;
    struct flb_input_chunk *ic;
    struct flb_task *task;

    fprintf(stdout, "\n===== Input =====\n");

    mk_list_foreach(head, &ctx->inputs) {
        i = mk_list_entry(head, struct flb_input_instance, _head);
        fprintf(stdout, "%s (%s)\n", flb_input_name(i), i->p->name);

        fprintf(stdout, "│\n");
        fprintf(stdout, "├─ status\n");

        /* Overlimit checks */
        ret = FLB_FALSE;
        if (i->mem_buf_limit > 0) {
            if (i->mem_chunks_size >= i->mem_buf_limit) {
                ret = FLB_TRUE;
            }
        }
        fprintf(stdout, "│  └─ overlimit     : %s\n",
                ret ? "yes" : "no");

        /* Current memory size used based on last ingestion */
        flb_utils_bytes_to_human_readable_size(i->mem_chunks_size,
                                               tmp, sizeof(tmp) - 1);
        fprintf(stdout, "│     ├─ mem size   : %s (%lu bytes)\n",
                tmp, i->mem_chunks_size);

        /* Mem buf limit set */
        flb_utils_bytes_to_human_readable_size(i->mem_buf_limit,
                                               tmp, sizeof(tmp) - 1);
        fprintf(stdout, "│     └─ mem limit  : %s (%lu bytes)\n",
                tmp, i->mem_buf_limit);

        /*
         * Tasks
         * =====
         * Upon flush time, the engine look for 'chunks' ready to be flushed.
         * For each one, it creates a Task, this task can be routed and
         * referenced by different output destinations.
         *
         * For short: every task is a chunk. But it's a different structure
         * handled by the engine to coordinate the flush process.
         */
        fprintf(stdout, "│\n");
        fprintf(stdout, "├─ tasks\n");
        fprintf(stdout, "│  ├─ total tasks   : %i\n", mk_list_size(&i->tasks));

        size = 0;
        task_new = 0;
        task_running = 0;
        /* Iterate tasks and print a summary */
        mk_list_foreach(h_task, &i->tasks) {
            task = mk_list_entry(h_task, struct flb_task, _head);
            size += task->size;
            if (task->status == FLB_TASK_NEW) {
                task_new++;
            }
            else if (task->status == FLB_TASK_RUNNING) {
                task_running++;
            }
        }

        flb_utils_bytes_to_human_readable_size(size, tmp, sizeof(tmp) - 1);

        fprintf(stdout, "│  ├─ new           : %i\n", task_new);
        fprintf(stdout, "│  ├─ running       : %i\n", task_running);
        fprintf(stdout, "│  └─ size          : %s (%lu bytes)\n", tmp, size);

        /*
         * Chunks
         * ======
         * Input plugins ingest record into a 'chunk'. If the storage layer type
         * for the instance is memory, all chunks are considered 'up' (meaning:
         * up in memory), for filesystem based chunks they can be 'up' or 'down'.
         *
         * We avoid to have all of them 'up' at the same time since this can
         * lead to a high memory consumption. When filesystem mode is used, some
         * of them are 'down' and only get 'up' when they are going to be
         * processed.
         */
        fprintf(stdout, "│\n");
        fprintf(stdout, "└─ chunks\n");

        /* Number of chunks registered */
        fprintf(stdout, "   └─ total chunks  : %i\n", mk_list_size(&i->chunks));

        /* Busy chunks
         * -----------
         * Chunks marked as 'busy' are 'locked' since they are in a 'flush' state.
         * No more data can be appended to a busy chunk.
         */
        busy = 0;
        busy_size = 0;
        busy_size_err = 0;

        /* up/down */
        up = 0;
        down = 0;

        /* Iterate chunks for the input instance in question */
        mk_list_foreach(h_chunks, &i->chunks) {
            ic = mk_list_entry(h_chunks, struct flb_input_chunk, _head);
            if (ic->busy == FLB_TRUE) {
                busy++;
                size = cio_chunk_get_content_size(ic->chunk);
                if (size >= 0) {
                    busy_size += size;
                }
                else {
                    busy_size_err++;
                }
            }

            if (cio_chunk_is_up(ic->chunk) == CIO_TRUE) {
                up++;
            }
            else {
                down++;
            }
        }

        fprintf(stdout, "      ├─ up chunks  : %i\n", up);
        fprintf(stdout, "      ├─ down chunks: %i\n", down);
        flb_utils_bytes_to_human_readable_size(busy_size, tmp, sizeof(tmp) - 1);

        fprintf(stdout, "      └─ busy chunks: %i\n", busy);
        fprintf(stdout, "         ├─ size    : %s (%lu bytes)\n", tmp, busy_size);
        fprintf(stdout, "         └─ size err: %i\n", busy_size_err);
        fprintf(stdout, "\n");
    }
}

/*
 * Storage
 * =======
 * Dump Chunk I/O statistics, basic counters
 */
static void dump_storage(struct flb_config *ctx)
{
    struct cio_stats storage_st;

    fprintf(stdout, "\n===== Storage Layer =====\n");
    cio_stats_get(ctx->cio, &storage_st);

    fprintf(stdout, "total chunks     : %i\n", storage_st.chunks_total);
    fprintf(stdout, "├─ mem chunks    : %i\n", storage_st.chunks_mem);
    fprintf(stdout, "└─ fs chunks     : %i\n", storage_st.chunks_fs);
    fprintf(stdout, "   ├─ up         : %i\n", storage_st.chunks_fs_up);
    fprintf(stdout, "   └─ down       : %i\n", storage_st.chunks_fs_down);
}

void flb_dump(struct flb_config *ctx)
{
    time_t now;
    struct tm *current;

    now = time(NULL);
    current = localtime(&now);

    fprintf(stdout,
            "[%i/%02i/%02i %02i:%02i:%02i] Fluent Bit Dump\n",
            current->tm_year + 1900,
            current->tm_mon + 1,
            current->tm_mday,
            current->tm_hour,
            current->tm_min,
            current->tm_sec);

    /* Stacktrace */
#ifdef FLB_DUMP_STACKTRACE
    /*
     * Sorry, I had to disable the stacktrace as part of the dump
     * since if backtrace_full() is called while Fluent Bit is
     * inside a co-routine (output flush), it might crash.
     *
     * If we are in a co-routine likely we need a different libbacktrace
     * context, but it's just a guess, not tested.
     */
    //fprintf(stdout, "\n===== Stacktrace =====\n");
    //flb_stacktrace_print();
#endif

    /* Input Plugins + Storage */
    dump_input_chunks(ctx);

    /* Storage Layer */
    dump_storage(ctx);

    /* Make sure to flush the stdout buffer in case output
     * has been redirected to a file
     */
    fflush(stdout);
}
