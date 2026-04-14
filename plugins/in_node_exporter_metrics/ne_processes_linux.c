/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2023-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>

static int processes_configure(struct flb_ne *ctx)
{
    struct cmt_gauge *g;

    /* node_processes_threads_max */
    g = cmt_gauge_create(ctx->cmt, "node", "processes", "threads",
                         "Allocated threads in the system",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->processes_thread_alloc = g;

    /* node_processes_threads_max */
    g = cmt_gauge_create(ctx->cmt, "node", "processes", "max_threads",
                         "Limit of threads in the system",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->processes_threads_limit = g;

    /* node_processes_threads_state */
    g = cmt_gauge_create(ctx->cmt, "node", "processes", "threads_state",
                         "The number of processes in each thread state",
                         1, (char *[]) {"thread_state"});
    if (!g) {
        return -1;
    }
    ctx->processes_threads_state = g;

    /* node_processes_state */
    g = cmt_gauge_create(ctx->cmt, "node", "processes", "state",
                         "The number of processes in each state",
                         1, (char *[]) {"state"});
    if (!g) {
        return -1;
    }
    ctx->processes_procs_state = g;

    /* node_processes_pids */
    g = cmt_gauge_create(ctx->cmt, "node", "processes", "pids",
                         "The number of PIDs in the system",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->processes_pid_used = g;

    /* node_processes_max_processeses */
    g = cmt_gauge_create(ctx->cmt, "node", "processes", "max_processeses",
                         "Limit of PID in the system",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->processes_pid_max = g;

    return 0;
}

struct proc_state {
    int64_t running;
    int64_t interruptible_sleeping;
    int64_t uninterruptible_sleeping;
    int64_t zombie;
    int64_t stopped;
    int64_t idle;
};

static int update_processes_proc_state(struct flb_ne *ctx, struct proc_state *state, char* state_str)
{
    if (strcmp(state_str, "R") == 0) {
        state->running++;
    }
    else if (strcmp(state_str, "S") == 0) {
        state->interruptible_sleeping++;
    }
    else if (strcmp(state_str, "D") == 0) {
        state->uninterruptible_sleeping++;
    }
    else if (strcmp(state_str, "Z") == 0) {
        state->zombie++;
    }
    else if (strcmp(state_str, "T") == 0) {
        state->stopped++;
    }
    else if (strcmp(state_str, "I") == 0) {
        state->idle++;
    }

    return 0;
}

static int check_path_for_proc(struct flb_ne *ctx, const char *prefix, const char *path)
{
    int len;
    flb_sds_t p;

    /* Compose the proc path */
    p = flb_sds_create(prefix);
    if (!p) {
        return -1;
    }

    if (path) {
        flb_sds_cat_safe(&p, "/", 1);
        len = strlen(path);
        flb_sds_cat_safe(&p, path, len);
    }

    if (access(p, F_OK) == -1 &&
        (errno == ENOENT || errno == ESRCH)) {
        flb_plg_debug(ctx->ins, "error reading stat for path %s. errno = %d", p, errno);
        flb_sds_destroy(p);

        return -1;
    }

    flb_sds_destroy(p);
    return 0;
}

static int processes_thread_update(struct flb_ne *ctx, flb_sds_t pid_str, flb_sds_t pstate_str,
                                   struct proc_state *tstate)
{
    int ret;
    flb_sds_t tmp;
    flb_sds_t tid_str;
    flb_sds_t state_str;
    const char *pattern = "/[0-9]*";
    struct mk_list *head;
    struct mk_list *ehead;
    struct mk_list thread_list;
    struct mk_list stat_list;
    struct mk_list split_list;
    struct flb_slist_entry *thread;
    struct flb_slist_entry *entry;
    char thread_procfs[PATH_MAX];

    snprintf(thread_procfs, sizeof(thread_procfs) - 1, "%s/%s/task", ctx->path_procfs, pid_str);

    /* scan thread entries */
    ret = ne_utils_path_scan(ctx, thread_procfs, pattern, NE_SCAN_DIR, &thread_list);
    if (ret != 0) {
        return -1;
    }

    if (mk_list_size(&thread_list) == 0) {
        return 0;
    }

    /* thread entries */
    mk_list_foreach(head, &thread_list) {
        thread = mk_list_entry(head, struct flb_slist_entry, _head);
        tid_str = thread->str + strlen(thread_procfs) + 1;

        /* When pid and tid are equal, the state of the thread should be the same
         * for pid's. */
        if (strcmp(tid_str, pid_str) == 0) {
            update_processes_proc_state(ctx, tstate, pstate_str);
            continue;
        }

        if (check_path_for_proc(ctx, thread->str, "stat") != 0) {
            continue;
        }

        mk_list_init(&stat_list);
        ret = ne_utils_file_read_lines(thread->str, "/stat", &stat_list);
        if (ret == -1) {
            continue;
        }

        mk_list_foreach(ehead, &stat_list) {
            entry = mk_list_entry(ehead, struct flb_slist_entry, _head);

            /* split with the close parenthesis.
             * The entry of processes stat will start after that. */
            tmp = strstr(entry->str, ")");
            if (tmp == NULL) {
                continue;
            }

            mk_list_init(&split_list);
            ret = flb_slist_split_string(&split_list, tmp+2, ' ', -1);
            if (ret == -1) {
                continue;
            }

            /* Thread State */
            entry = flb_slist_entry_get(&split_list, 0);
            state_str = entry->str;
            update_processes_proc_state(ctx, tstate, state_str);

            flb_slist_destroy(&split_list);
        }
        flb_slist_destroy(&stat_list);
    }

    flb_slist_destroy(&thread_list);

    return 0;
}

static int processes_update(struct flb_ne *ctx)
{
    int ret;
    flb_sds_t tmp;
    flb_sds_t pid_str;
    flb_sds_t state_str;
    flb_sds_t thread_str;
    struct mk_list *head;
    struct mk_list *ehead;
    struct mk_list procfs_list;
    struct mk_list stat_list;
    struct mk_list split_list;
    struct flb_slist_entry *process;
    struct flb_slist_entry *entry;
    uint64_t val;
    uint64_t ts;
    const char *pattern = "/[0-9]*";
    int64_t pids = 0;
    int64_t threads = 0;
    struct proc_state pstate = {
        .running = 0,
        .interruptible_sleeping = 0,
        .uninterruptible_sleeping = 0,
        .zombie = 0,
        .stopped = 0,
        .idle = 0
    };
    struct proc_state tstate = {
        .running = 0,
        .interruptible_sleeping = 0,
        .uninterruptible_sleeping = 0,
        .zombie = 0,
        .stopped = 0,
        .idle = 0
    };

    mk_list_init(&procfs_list);

    ts = cfl_time_now();

    ret = ne_utils_file_read_uint64(ctx->path_procfs, "/sys", "kernel", "threads-max", &val);
    if (ret == -1) {
        return -1;
    }

    /* node_processes_threads_max */
    if (ret == 0) {
        cmt_gauge_set(ctx->processes_threads_limit, ts,
                      (double)val, 0, NULL);
    }

    ret = ne_utils_file_read_uint64(ctx->path_procfs, "/sys", "kernel", "pid_max", &val);
    if (ret == -1) {
        return -1;
    }

    /* node_processes_max_processes */
    if (ret == 0) {
        cmt_gauge_set(ctx->processes_pid_max, ts,
                      (double)val, 0, NULL);
    }

    /* scan pid entries */
    ret = ne_utils_path_scan(ctx, ctx->path_procfs, pattern, NE_SCAN_DIR, &procfs_list);
    if (ret != 0) {
        return -1;
    }

    if (mk_list_size(&procfs_list) == 0) {
        return 0;
    }

    /* PID entries */
    mk_list_foreach(head, &procfs_list) {
        process = mk_list_entry(head, struct flb_slist_entry, _head);
        pid_str = process->str + strlen(ctx->path_procfs) + 1;

        if (check_path_for_proc(ctx, process->str, "stat") != 0) {
            continue;
        }

        mk_list_init(&stat_list);
        ret = ne_utils_file_read_lines(process->str, "/stat", &stat_list);
        if (ret == -1) {
            continue;
        }

        mk_list_foreach(ehead, &stat_list) {
            entry = mk_list_entry(ehead, struct flb_slist_entry, _head);

            /* split with the close parenthesis.
             * The entry of processes stat will start after that. */
            tmp = strstr(entry->str, ")");
            if (tmp == NULL) {
                continue;
            }

            mk_list_init(&split_list);
            ret = flb_slist_split_string(&split_list, tmp+2, ' ', -1);
            if (ret == -1) {
                continue;
            }

            /* State */
            entry = flb_slist_entry_get(&split_list, 0);
            state_str = entry->str;
            update_processes_proc_state(ctx, &pstate, state_str);

            /* Threads */
            entry = flb_slist_entry_get(&split_list, 17);
            thread_str = entry->str;

            /* Collect the number of threads */
            if (ne_utils_str_to_uint64(thread_str, &val) != -1) {
                threads += val;
            }

            /* Collect the states of threads */
            ret = processes_thread_update(ctx, pid_str, state_str, &tstate);
            if (ret != 0) {
                flb_slist_destroy(&split_list);
                continue;
            }

            flb_slist_destroy(&split_list);
        }
        flb_slist_destroy(&stat_list);

        pids++;
    }

    /* node_processes_state
     * Note: we don't use hash table for it. Because we need to update
     * every state of the processes due to architecture reasons of cmetrics.
     */
    cmt_gauge_set(ctx->processes_procs_state, ts, pstate.running,                  1, (char *[]){ "R" });
    cmt_gauge_set(ctx->processes_procs_state, ts, pstate.interruptible_sleeping,   1, (char *[]){ "S" });
    cmt_gauge_set(ctx->processes_procs_state, ts, pstate.uninterruptible_sleeping, 1, (char *[]){ "D" });
    cmt_gauge_set(ctx->processes_procs_state, ts, pstate.zombie,                   1, (char *[]){ "Z" });
    cmt_gauge_set(ctx->processes_procs_state, ts, pstate.stopped,                  1, (char *[]){ "T" });
    cmt_gauge_set(ctx->processes_procs_state, ts, pstate.idle,                     1, (char *[]){ "I" });

    /* node_processes_threads_state
     * Note: we don't use hash table for it. Because we need to update
     * every state of the processes due to architecture reasons of cmetrics.
     */
    cmt_gauge_set(ctx->processes_threads_state, ts, tstate.running,                  1, (char *[]){ "R" });
    cmt_gauge_set(ctx->processes_threads_state, ts, tstate.interruptible_sleeping,   1, (char *[]){ "S" });
    cmt_gauge_set(ctx->processes_threads_state, ts, tstate.uninterruptible_sleeping, 1, (char *[]){ "D" });
    cmt_gauge_set(ctx->processes_threads_state, ts, tstate.zombie,                   1, (char *[]){ "Z" });
    cmt_gauge_set(ctx->processes_threads_state, ts, tstate.stopped,                  1, (char *[]){ "T" });
    cmt_gauge_set(ctx->processes_threads_state, ts, tstate.idle,                     1, (char *[]){ "I" });

    /* node_processes_threads */
    cmt_gauge_set(ctx->processes_thread_alloc, ts,
                  (double)threads, 0, NULL);

    /* node_processes_pids */
    cmt_gauge_set(ctx->processes_pid_used, ts,
                  (double)pids, 0, NULL);


    flb_slist_destroy(&procfs_list);

    return 0;
}

static int ne_processes_init(struct flb_ne *ctx)
{
    processes_configure(ctx);
    return 0;
}

static int ne_processes_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    processes_update(ctx);
    return 0;
}

static int ne_processes_exit(struct flb_ne *ctx)
{
    return 0;
}

struct flb_ne_collector processes_collector = {
    .name = "processes",
    .cb_init = ne_processes_init,
    .cb_update = ne_processes_update,
    .cb_exit = ne_processes_exit
};
