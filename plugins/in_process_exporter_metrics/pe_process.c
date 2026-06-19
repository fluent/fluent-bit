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
#include <fluent-bit/flb_input_plugin.h>

#include "pe.h"
#include "pe_utils.h"

#include <unistd.h>
#include <dirent.h>

#define USER_HZ 100

static int process_configure(struct flb_pe *ctx)
{
    struct cmt_gauge *g;
    struct cmt_counter *c;

    /* Initialize regex for the list of including process */
    ctx->process_regex_include_list = flb_regex_create(ctx->process_regex_include_list_text);
    if (!ctx->process_regex_include_list) {
        flb_plg_error(ctx->ins,
                      "could not initialize regex pattern for the list of including "
                      "process: '%s'",
                      ctx->process_regex_include_list_text);
        return -1;
    }

    /* Initialize regex for the list of excluding process */
    if (ctx->process_regex_exclude_list_text != NULL) {
        ctx->process_regex_exclude_list = flb_regex_create(ctx->process_regex_exclude_list_text);
        if (!ctx->process_regex_exclude_list) {
            flb_plg_error(ctx->ins,
                          "could not initialize regex pattern for the list of excluding "
                          "process: '%s'",
                          ctx->process_regex_exclude_list_text);
            return -1;
        }
    }

    /* process_cpu_seconds_total */
    c = cmt_counter_create(ctx->cmt, "process", "", "cpu_seconds_total",
                           "CPU usage in seconds",
                           4, (char *[]){"name", "pid", "ppid", "mode"});
    if (!c) {
        return -1;
    }
    ctx->cpu_seconds = c;

    /* process_read_bytes_total */
    c = cmt_counter_create(ctx->cmt, "process", "", "read_bytes_total",
                           "number of bytes read",
                           3, (char *[]){"name", "pid", "ppid"});
    if (!c) {
        return -1;
    }
    ctx->read_bytes = c;

    /* process_write_bytes_total */
    c = cmt_counter_create(ctx->cmt, "process", "", "write_bytes_total",
                           "number of bytes write",
                           3, (char *[]){"name", "pid", "ppid"});
    if (!c) {
        return -1;
    }
    ctx->write_bytes = c;

    /* process_major_page_faults_total */
    c = cmt_counter_create(ctx->cmt, "process", "", "major_page_faults_total",
                           "Major page fault",
                           3, (char *[]){"name", "pid", "ppid"});
    if (!c) {
        return -1;
    }
    ctx->major_page_faults = c;

    /* process_minor_page_faults_total */
    c = cmt_counter_create(ctx->cmt, "process", "", "minor_page_faults_total",
                           "Minor page fault",
                           3, (char *[]){"name", "pid", "ppid"});
    if (!c) {
        return -1;
    }
    ctx->minor_page_faults = c;

    /* process_context_switches_total */
    c = cmt_counter_create(ctx->cmt, "process", "", "context_switches_total",
                           "Context switches",
                           3, (char *[]){"name", "pid", "context_switch_type"});
    if (!c) {
        return -1;
    }
    ctx->context_switches = c;

    /* process_memory_bytes */
    g = cmt_gauge_create(ctx->cmt, "process", "", "memory_bytes",
                         "number of bytes of memory in use per type (VirtualMemory, RSS)",
                         4, (char *[]){"name", "pid", "ppid", "type"});
    if (!g) {
        return -1;
    }
    ctx->memory_bytes = g;

    /* process_open_filedesc */
    g = cmt_gauge_create(ctx->cmt, "process", "", "open_filedesc",
                         "number of open file descriptors",
                         3, (char *[]){"name", "pid", "ppid"});
    if (!g) {
        return -1;
    }
    ctx->open_fds = g;

    /* process_fd_ratio */
    g = cmt_gauge_create(ctx->cmt, "process", "", "fd_ratio",
                         "the ratio between open fds and max fds",
                         3, (char *[]){"name", "pid", "ppid"});
    if (!g) {
        return -1;
    }
    ctx->fd_ratio = g;

    /* process_start_time_seconds */
    g = cmt_gauge_create(ctx->cmt, "process", "", "start_time_seconds",
                         "start time in seconds since 1970/01/01",
                         3, (char *[]){"name", "pid", "ppid"});
    if (!g) {
        return -1;
    }
    ctx->start_time = g;

    /* process_num_threads */
    g = cmt_gauge_create(ctx->cmt, "process", "", "num_threads",
                         "Number of threads",
                         3, (char *[]){"name", "pid", "ppid"});
    if (!g) {
        return -1;
    }
    ctx->num_threads = g;

    /* process_states */
    g = cmt_gauge_create(ctx->cmt, "process", "", "states",
                         "Process in states Running, Sleeping, Waiting, Zombie, or Other",
                         4, (char *[]){"name", "pid", "ppid", "state"});
    if (!g) {
        return -1;
    }
    ctx->states = g;

    /*
     * Thread metrics
     */

    /* process_thread_wchan */
    g = cmt_gauge_create(ctx->cmt, "process", "", "thread_wchan",
                         "Number of threads in this process waiting on each wchan",
                         3, (char *[]){"name", "pid", "wchan"});
    if (!g) {
        return -1;
    }
    ctx->thread_wchan = g;

    /* process_thread_cpu_seconds_total */
    c = cmt_counter_create(ctx->cmt, "process", "", "thread_cpu_seconds_total",
                           "CPU user/system usage in seconds with the same threadname",
                           4, (char *[]){"name", "threadname", "thread_id", "mode"});
    if (!c) {
        return -1;
    }
    ctx->thread_cpu_seconds = c;

    /* process_thread_io_bytes_total */
    c = cmt_counter_create(ctx->cmt, "process", "", "thread_io_bytes_total",
                           "number of bytes read/written by these threads",
                           4, (char *[]){"name", "threadname", "thread_id", "iomode"});
    if (!c) {
        return -1;
    }
    ctx->thread_io_bytes = c;

    /* process_thread_major_page_faults_total */
    c = cmt_counter_create(ctx->cmt, "process", "", "thread_major_page_faults_total",
                           "Major page fault for these threads",
                           3, (char *[]){"name", "threadname", "thread_id"});
    if (!c) {
        return -1;
    }
    ctx->thread_major_page_faults = c;

    /* process_thread_minor_page_faults_total */
    c = cmt_counter_create(ctx->cmt, "process", "", "thread_minor_page_faults_total",
                           "Minor page fault for these threads",
                           3, (char *[]){"name", "threadname", "thread_id"});
    if (!c) {
        return -1;
    }
    ctx->thread_minor_page_faults = c;

    /* process_thread_context_switches_total */
    c = cmt_counter_create(ctx->cmt, "process", "", "thread_context_switches_total",
                           "Context switches",
                           4, (char *[]){"name", "threadname", "thread_id", "context_switch_type"});
    if (!c) {
        return -1;
    }
    ctx->thread_context_switches = c;

    return 0;
}

int pe_process_init(struct flb_pe *ctx)
{
    process_configure(ctx);

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

static int update_process_proc_state(struct flb_pe *ctx, struct proc_state *state, char* state_str)
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

static void reset_proc_state(struct proc_state *state) {
    state->running = 0;
    state->interruptible_sleeping = 0;
    state->uninterruptible_sleeping = 0;
    state->zombie = 0;
    state->stopped = 0;
    state->idle = 0;
}

static int check_path_for_proc(struct flb_pe *ctx, const char *prefix, const char *path)
{
    int len;
    flb_sds_t p = NULL;

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
        flb_sds_destroy(p);

        return -1;
    }

    flb_sds_destroy(p);
    return 0;
}

static int get_name(const char *entry, char **out_name, char *id_entry)
{
    flb_sds_t tmp = NULL;
    flb_sds_t tmp_name = NULL;

    tmp = strdup(entry);
    tmp_name = strtok(tmp, ")");
    if (tmp_name == NULL) {
        flb_free(tmp);
        return -1;
    }

    *out_name = strdup(tmp_name + strlen(id_entry) + 2);
    flb_free(tmp);

    return 0;
}

static int process_proc_thread_io(struct flb_pe *ctx, uint64_t ts,
                                  flb_sds_t name, flb_sds_t thread_name, flb_sds_t thread_id,
                                  struct flb_slist_entry *thread)
{
    int ret;
    flb_sds_t tmp = NULL;
    flb_sds_t status = NULL;
    uint64_t val;
    struct mk_list io_list;
    struct mk_list *ihead;
    struct flb_slist_entry *entry;

    if (check_path_for_proc(ctx, thread->str, "io") != 0) {
        return -1;
    }

    mk_list_init(&io_list);
    ret = pe_utils_file_read_lines(thread->str, "/io", &io_list);
    if (ret == -1) {
        return -1;
    }

    mk_list_foreach(ihead, &io_list) {
        entry = mk_list_entry(ihead, struct flb_slist_entry, _head);

        if (strncmp("read_bytes", entry->str, 10) == 0) {
            tmp = strstr(entry->str, ":");
            if (tmp == NULL) {
                continue;
            }
            status = flb_sds_create_len(tmp+1, strlen(tmp+1));
            flb_sds_trim(status);
            /* Collect the number of minor page faults per process */
            if (pe_utils_str_to_uint64(status, &val) != -1) {
                cmt_counter_set(ctx->thread_io_bytes, ts, val, 4, (char *[]){ name, thread_name, thread_id, "read" });
            }
            flb_sds_destroy(status);
        }

        if (strncmp("write_bytes", entry->str, 11) == 0) {
            tmp = strstr(entry->str, ":");
            if (tmp == NULL) {
                continue;
            }
            status = flb_sds_create_len(tmp+1, strlen(tmp+1));
            flb_sds_trim(status);
            /* Collect the number of minor page faults per process */
            if (pe_utils_str_to_uint64(status, &val) != -1) {
                cmt_counter_set(ctx->thread_io_bytes, ts, val, 4, (char *[]){ name, thread_name, thread_id, "write" });
            }
            flb_sds_destroy(status);
        }
    }
    flb_slist_destroy(&io_list);

    return 0;
}

static int process_proc_thread_status(struct flb_pe *ctx, uint64_t ts,
                                      flb_sds_t thread_name, flb_sds_t thread_id,
                                      struct flb_slist_entry *thread)
{
    int ret;
    flb_sds_t tmp = NULL;
    flb_sds_t name = NULL;
    flb_sds_t status = NULL;
    uint64_t val;
    struct mk_list status_list;
    struct mk_list *shead;
    struct flb_slist_entry *entry;
    int include_flag = FLB_FALSE;

    if (check_path_for_proc(ctx, thread->str, "status") != 0) {
        return -1;
    }

    mk_list_init(&status_list);
    ret = pe_utils_file_read_lines(thread->str, "/status", &status_list);
    if (ret == -1) {
        return -1;
    }

    mk_list_foreach(shead, &status_list) {
        entry = mk_list_entry(shead, struct flb_slist_entry, _head);

        if (strncmp("Name", entry->str, 4) == 0) {
            tmp = strstr(entry->str, ":");
            if (tmp == NULL) {
                continue;
            }
            name = flb_sds_create_len(tmp+1, strlen(tmp+1));
            flb_sds_trim(name);

            /* Check for regexes */
            if (ctx->process_regex_include_list != NULL) {
                include_flag = flb_regex_match(ctx->process_regex_include_list,
                                                (unsigned char *) name,
                                                flb_sds_len(name));
            }
            else {
                include_flag = FLB_TRUE;
            }

            if (!include_flag) {
                goto cleanup;
            }

            if (ctx->process_regex_exclude_list != NULL) {
                include_flag = !flb_regex_match(ctx->process_regex_exclude_list,
                                                (unsigned char *) name,
                                                flb_sds_len(name));
            }
            else {
                include_flag = FLB_TRUE;
            }

            if (!include_flag) {
                goto cleanup;
            }
        }

        if (strncmp("voluntary_ctxt_switches", entry->str, 23) == 0) {
            tmp = strstr(entry->str, ":");
            if (tmp == NULL) {
                continue;
            }
            status = flb_sds_create_len(tmp+1, strlen(tmp+1));
            flb_sds_trim(status);
            /* Collect the number of minor page faults per process */
            if (pe_utils_str_to_uint64(status, &val) != -1) {
                cmt_counter_set(ctx->thread_context_switches, ts, val,
                                4, (char *[]){ name, thread_name, thread_id, "voluntary_ctxt_switches" });
            }
            flb_sds_destroy(status);
        }

        if (strncmp("nonvoluntary_ctxt_switches", entry->str, 26) == 0) {
            tmp = strstr(entry->str, ":");
            if (tmp == NULL) {
                continue;
            }
            status = flb_sds_create_len(tmp+1, strlen(tmp+1));
            flb_sds_trim(status);
            /* Collect the number of minor page faults per process */
            if (pe_utils_str_to_uint64(status, &val) != -1) {
                cmt_counter_set(ctx->thread_context_switches, ts, val,
                                4, (char *[]){ name, thread_name, thread_id, "nonvoluntary_ctxt_switches" });
            }
            flb_sds_destroy(status);
        }
    }

cleanup:
    flb_sds_destroy(name);
    flb_slist_destroy(&status_list);

    return 0;
}

static int process_thread_update(struct flb_pe *ctx, uint64_t ts, flb_sds_t pid, flb_sds_t name)
{
    int ret;
    flb_sds_t tmp = NULL;
    flb_sds_t thread_name = NULL;
    flb_sds_t tid_str = NULL;
    uint64_t val;
    const char *pattern = "/[0-9]*";
    struct mk_list *head;
    struct mk_list *ehead;
    struct mk_list thread_list;
    struct mk_list stat_list;
    struct mk_list split_list;
    struct flb_slist_entry *thread;
    struct flb_slist_entry *entry;
    char thread_procfs[PATH_MAX];

    snprintf(thread_procfs, sizeof(thread_procfs) - 1, "%s/%s/task", ctx->path_procfs, pid);

    /* scan thread entries */
    ret = pe_utils_path_scan(ctx, thread_procfs, pattern, NE_SCAN_DIR, &thread_list);
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
        if (strcmp(tid_str, pid) == 0) {
            continue;
        }

        if (check_path_for_proc(ctx, thread->str, "stat") != 0) {
            continue;
        }

        mk_list_init(&stat_list);
        ret = pe_utils_file_read_lines(thread->str, "/stat", &stat_list);
        if (ret == -1) {
            continue;
        }

        mk_list_foreach(ehead, &stat_list) {
            entry = mk_list_entry(ehead, struct flb_slist_entry, _head);

            if (get_name(entry->str, &thread_name, tid_str) != 0) {
                continue;
            }

            /* split with the close parenthesis.
             * The entry of processes stat will start after that. */
            tmp = strstr(entry->str, ")");
            if (tmp == NULL) {
                flb_free(thread_name);
                continue;
            }

            mk_list_init(&split_list);
            ret = flb_slist_split_string(&split_list, tmp+2, ' ', -1);
            if (ret == -1) {
                flb_free(thread_name);
                continue;
            }

            /* Thread CPU Seconds (user) */
            entry = flb_slist_entry_get(&split_list, 11);
            tmp = entry->str;
            /* Collect the number of cpu_seconds per process */
            if (pe_utils_str_to_uint64(tmp, &val) != -1) {
                cmt_counter_set(ctx->thread_cpu_seconds, ts, val/USER_HZ, 4, (char *[]){ name, thread_name, tid_str, "user" });
            }

            /* Thread CPU Seconds (system) */
            entry = flb_slist_entry_get(&split_list, 12);
            tmp = entry->str;
            /* Collect the number of cpu_seconds per process */
            if (pe_utils_str_to_uint64(tmp, &val) != -1) {
                cmt_counter_set(ctx->thread_cpu_seconds, ts, val/USER_HZ, 4, (char *[]){ name, thread_name, tid_str, "system" });
            }

            /* Thread Major Page Faults */
            entry = flb_slist_entry_get(&split_list, 9);
            tmp = entry->str;
            /* Collect the number of major page faults per process */
            if (pe_utils_str_to_uint64(tmp, &val) != -1) {
                cmt_counter_set(ctx->thread_major_page_faults, ts, val, 3, (char *[]){ name, thread_name, tid_str });
            }

            /* Thread Minor Page Faults */
            entry = flb_slist_entry_get(&split_list, 7);
            tmp = entry->str;
            /* Collect the number of minor page faults per process */
            if (pe_utils_str_to_uint64(tmp, &val) != -1) {
                cmt_counter_set(ctx->thread_minor_page_faults, ts, val, 3, (char *[]){ name, thread_name, tid_str });
            }

            ret = process_proc_thread_io(ctx, ts,
                                         name, thread_name, tid_str,
                                         thread);
            if (ret == -1) {
                goto cleanup;
            }

            ret = process_proc_thread_status(ctx, ts,
                                             thread_name, tid_str,
                                             thread);
            if (ret == -1) {
                goto cleanup;
            }

        cleanup:
            /* Teardown */
            flb_free(thread_name);
            flb_slist_destroy(&split_list);
        }
        flb_slist_destroy(&stat_list);
    }

    flb_slist_destroy(&thread_list);

    return 0;
}

static int process_proc_wchan(struct flb_pe *ctx, uint64_t ts,
                              flb_sds_t pid, flb_sds_t name, struct flb_slist_entry *process)
{
    int ret;
    struct mk_list wchan_list;
    struct mk_list *whead;
    struct flb_slist_entry *entry;

    if (check_path_for_proc(ctx, process->str, "wchan") != 0) {
        return -1;
    }

    /* Collect wchan status */
    mk_list_init(&wchan_list);
    ret = pe_utils_file_read_lines(process->str, "/wchan", &wchan_list);
    if (ret == -1) {
        return -1;
    }

    mk_list_foreach(whead, &wchan_list) {
        entry = mk_list_entry(whead, struct flb_slist_entry, _head);
        if (strcmp("0", entry->str) == 0 ||
            strcmp("", entry->str) == 0) {
            cmt_gauge_set(ctx->thread_wchan, ts, 1, 3, (char *[]) { name, pid, "" });
        }
        else {
            cmt_gauge_set(ctx->thread_wchan, ts, 1, 3, (char *[]) { name, pid, entry->str });
        }
    }
    flb_slist_destroy(&wchan_list);

    return 0;
}

static int process_proc_io(struct flb_pe *ctx, uint64_t ts,
                           flb_sds_t pid, flb_sds_t ppid, flb_sds_t name,
                           struct flb_slist_entry *process)
{
    int ret;
    flb_sds_t tmp = NULL;
    flb_sds_t status = NULL;
    uint64_t val;
    struct mk_list io_list;
    struct mk_list *ihead;
    struct flb_slist_entry *entry;

    if (check_path_for_proc(ctx, process->str, "io") != 0) {
        return -1;
    }

    mk_list_init(&io_list);
    ret = pe_utils_file_read_lines(process->str, "/io", &io_list);
    if (ret == -1) {
        return -1;
    }

    mk_list_foreach(ihead, &io_list) {
        entry = mk_list_entry(ihead, struct flb_slist_entry, _head);

        if (strncmp("read_bytes", entry->str, 10) == 0) {
            tmp = strstr(entry->str, ":");
            if (tmp == NULL) {
                continue;
            }
            status = flb_sds_create_len(tmp+1, strlen(tmp+1));
            flb_sds_trim(status);
            /* Collect the number of minor page faults per process */
            if (pe_utils_str_to_uint64(status, &val) != -1) {
                cmt_counter_set(ctx->read_bytes, ts, val, 3, (char *[]){ name, pid, ppid });
            }
            flb_sds_destroy(status);
        }

        if (strncmp("write_bytes", entry->str, 11) == 0) {
            tmp = strstr(entry->str, ":");
            if (tmp == NULL) {
                continue;
            }
            status = flb_sds_create_len(tmp+1, strlen(tmp+1));
            flb_sds_trim(status);
            /* Collect the number of minor page faults per process */
            if (pe_utils_str_to_uint64(status, &val) != -1) {
                cmt_counter_set(ctx->write_bytes, ts, val, 3, (char *[]){ name, pid, ppid });
            }
            flb_sds_destroy(status);
        }
    }
    flb_slist_destroy(&io_list);

    return 0;
}

static int process_proc_limit_fd(struct flb_pe *ctx, flb_sds_t pid,
                                 struct flb_slist_entry *process,
                                 uint64_t *out_val)
{
    int ret;
    uint64_t val;
    flb_sds_t status;
    struct mk_list limits_list;
    struct mk_list split_list;
    struct mk_list *lhead;
    struct flb_slist_entry *entry;
    struct flb_slist_entry *limit;

    mk_list_init(&limits_list);
    ret = pe_utils_file_read_lines(process->str, "/limits", &limits_list);
    if (ret == -1) {
        return -1;
    }

    mk_list_foreach(lhead, &limits_list) {
        entry = mk_list_entry(lhead, struct flb_slist_entry, _head);

        mk_list_init(&split_list);
        if (strncmp("Max open files", entry->str, 14) == 0) {
            ret = flb_slist_split_string(&split_list, entry->str, ' ', -1);
            if (ret == -1) {
                continue;
            }

            limit = flb_slist_entry_get(&split_list, 4);
            status = flb_sds_create_len(limit->str, strlen(limit->str));
            flb_sds_trim(status);
            /* Collect the limit of max open files */
            if (pe_utils_str_to_uint64(status, &val) != -1) {
                *out_val = val;
            }
            flb_sds_destroy(status);
            flb_slist_destroy(&split_list);
        }
    }
    flb_slist_destroy(&limits_list);

    return 0;
}

static int process_proc_fds(struct flb_pe *ctx, uint64_t ts,
                            flb_sds_t pid, flb_sds_t ppid, flb_sds_t name,
                            struct flb_slist_entry *process)
{
    int ret;
    size_t fds = 0;
    uint64_t max_fd = 0;
    DIR *dir;
    struct dirent *ent;
    char fd_procfs[PATH_MAX] = {0};

    snprintf(fd_procfs, sizeof(fd_procfs) - 1, "%s/%s", process->str, "fd");
    dir = opendir(fd_procfs);
    if (dir == NULL) {
        if (errno == EACCES) {
            flb_plg_debug(ctx->ins, "NO read access for path: %s", fd_procfs);
        }
        return -1;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_LNK) {
            fds++;
        }
    }
    closedir(dir);

    cmt_gauge_set(ctx->open_fds, ts, (double)fds, 3, (char *[]){ name, pid, ppid });

    ret = process_proc_limit_fd(ctx, pid, process, &max_fd);
    if (ret != -1) {
        cmt_gauge_set(ctx->fd_ratio, ts, (double)fds/max_fd, 3, (char *[]){ name, pid, ppid });
    }

    return 0;
}

static int process_proc_status(struct flb_pe *ctx, uint64_t ts, flb_sds_t pid, struct flb_slist_entry *process)
{
    int ret;
    flb_sds_t tmp = NULL;
    flb_sds_t name = NULL;
    flb_sds_t status = NULL;
    uint64_t val;
    struct mk_list status_list;
    struct mk_list *shead;
    struct flb_slist_entry *entry;
    int include_flag = FLB_FALSE;

    if (check_path_for_proc(ctx, process->str, "status") != 0) {
        return -1;
    }

    mk_list_init(&status_list);
    ret = pe_utils_file_read_lines(process->str, "/status", &status_list);
    if (ret == -1) {
        return -1;
    }

    mk_list_foreach(shead, &status_list) {
        entry = mk_list_entry(shead, struct flb_slist_entry, _head);

        if (strncmp("Name", entry->str, 4) == 0) {
            tmp = strstr(entry->str, ":");
            if (tmp == NULL) {
                continue;
            }
            name = flb_sds_create_len(tmp+1, strlen(tmp+1));
            flb_sds_trim(name);

            /* Check for regexes */
            if (ctx->process_regex_include_list != NULL) {
                include_flag = flb_regex_match(ctx->process_regex_include_list,
                                                (unsigned char *) name,
                                                flb_sds_len(name));
            }
            else {
                include_flag = FLB_TRUE;
            }

            if (!include_flag) {
                goto cleanup;
            }

            if (ctx->process_regex_exclude_list != NULL) {
                include_flag = !flb_regex_match(ctx->process_regex_exclude_list,
                                                (unsigned char *) name,
                                                flb_sds_len(name));
            }
            else {
                include_flag = FLB_TRUE;
            }

            if (!include_flag) {
                goto cleanup;
            }
        }

        if (strncmp("voluntary_ctxt_switches", entry->str, 23) == 0) {
            tmp = strstr(entry->str, ":");
            if (tmp == NULL) {
                continue;
            }
            status = flb_sds_create_len(tmp+1, strlen(tmp+1));
            flb_sds_trim(status);
            /* Collect the number of minor page faults per process */
            if (pe_utils_str_to_uint64(status, &val) != -1) {
                cmt_counter_set(ctx->context_switches, ts, val, 3, (char *[]){ name, pid, "voluntary_ctxt_switches" });
            }
            flb_sds_destroy(status);
        }

        if (strncmp("nonvoluntary_ctxt_switches", entry->str, 26) == 0) {
            tmp = strstr(entry->str, ":");
            if (tmp == NULL) {
                continue;
            }
            status = flb_sds_create_len(tmp+1, strlen(tmp+1));
            flb_sds_trim(status);
            /* Collect the number of minor page faults per process */
            if (pe_utils_str_to_uint64(status, &val) != -1) {
                cmt_counter_set(ctx->context_switches, ts, val, 3, (char *[]){ name, pid, "nonvoluntary_ctxt_switches" });
            }
            flb_sds_destroy(status);
        }
    }

cleanup:
    flb_sds_destroy(name);
    flb_slist_destroy(&status_list);

    return 0;
}

static int process_proc_boot_time(struct flb_pe *ctx, uint64_t *out_boot_time)
{
    int ret;
    flb_sds_t tmp = NULL;
    flb_sds_t status = NULL;
    uint64_t val;
    struct mk_list stat_list;
    struct mk_list *rshead;
    struct flb_slist_entry *entry;

    if (check_path_for_proc(ctx, ctx->path_procfs, "stat") != 0) {
        return -1;
    }

    mk_list_init(&stat_list);
    ret = pe_utils_file_read_lines(ctx->path_procfs, "/stat", &stat_list);
    if (ret == -1) {
        return -1;
    }

    mk_list_foreach(rshead, &stat_list) {
        entry = mk_list_entry(rshead, struct flb_slist_entry, _head);

        if (strncmp("btime", entry->str, 5) == 0) {
            tmp = strstr(entry->str, " ");
            if (tmp == NULL) {
                continue;
            }
            status = flb_sds_create_len(tmp+1, strlen(tmp+1));
            flb_sds_trim(status);
            /* Collect the number of btime */
            if (pe_utils_str_to_uint64(status, &val) != -1) {
                *out_boot_time = val;
            }
            flb_sds_destroy(status);
        }
    }
    flb_slist_destroy(&stat_list);

    return 0;
}

static int process_update(struct flb_pe *ctx)
{
    int ret;
    flb_sds_t tmp = NULL;
    flb_sds_t name = NULL;
    flb_sds_t pid_str = NULL;
    flb_sds_t state_str = NULL;
    flb_sds_t ppid_str = NULL;
    flb_sds_t thread_str = NULL;
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
    struct proc_state pstate;
    uint64_t boot_time = 0;
    int include_flag = FLB_FALSE;

    mk_list_init(&procfs_list);

    ts = cfl_time_now();

    /* scan pid entries */
    ret = pe_utils_path_scan(ctx, ctx->path_procfs, pattern, NE_SCAN_DIR, &procfs_list);
    if (ret != 0) {
        return -1;
    }

    if (mk_list_size(&procfs_list) == 0) {
        return 0;
    }

    /* Collect boot_time (btime) */
    ret = process_proc_boot_time(ctx, &boot_time);
    if (ret != 0) {
        boot_time = 0;
    }

    /* PID entries */
    mk_list_foreach(head, &procfs_list) {
        process = mk_list_entry(head, struct flb_slist_entry, _head);
        pid_str = process->str + strlen(ctx->path_procfs) + 1;

        if (check_path_for_proc(ctx, process->str, "stat") != 0) {
            continue;
        }

        mk_list_init(&stat_list);
        ret = pe_utils_file_read_lines(process->str, "/stat", &stat_list);
        if (ret == -1) {
            continue;
        }

        mk_list_foreach(ehead, &stat_list) {
            entry = mk_list_entry(ehead, struct flb_slist_entry, _head);

            if (get_name(entry->str, &name, pid_str) != 0) {
                continue;
            }

            /* Check for regexes */
            if (ctx->process_regex_include_list != NULL) {
                include_flag = flb_regex_match(ctx->process_regex_include_list,
                                                (unsigned char *) name,
                                                strlen(name));
            }
            else {
                include_flag = FLB_TRUE;
            }

            if (!include_flag) {
                flb_free(name);

                continue;
            }

            if (ctx->process_regex_exclude_list != NULL) {
                include_flag = !flb_regex_match(ctx->process_regex_exclude_list,
                                                (unsigned char *) name,
                                                strlen(name));
            }
            else {
                include_flag = FLB_TRUE;
            }

            if (!include_flag) {
                flb_free(name);

                continue;
            }

            mk_list_init(&split_list);

            /* split with the close parenthesis.
             * The entry of processes stat will start after that. */
            tmp = strstr(entry->str, ")");
            if (tmp == NULL) {
                goto cleanup;
            }

            ret = flb_slist_split_string(&split_list, tmp+2, ' ', -1);
            if (ret == -1) {
                goto cleanup;
            }

            /* State */
            reset_proc_state(&pstate);
            entry = flb_slist_entry_get(&split_list, 0);
            state_str = entry->str;
            update_process_proc_state(ctx, &pstate, state_str);

            entry = flb_slist_entry_get(&split_list, 1);
            ppid_str = entry->str;

            /* State */
            if (ctx->enabled_flag & METRIC_STATE) {
                /* node_processes_state
                 * Note: we don't use hash table for it. Because we need to update
                 * every state of the processes due to architecture reasons of cmetrics.
                 */
                cmt_gauge_set(ctx->states, ts, pstate.running,                  4, (char *[]){ name, pid_str, ppid_str, "R" });
                cmt_gauge_set(ctx->states, ts, pstate.interruptible_sleeping,   4, (char *[]){ name, pid_str, ppid_str, "S" });
                cmt_gauge_set(ctx->states, ts, pstate.uninterruptible_sleeping, 4, (char *[]){ name, pid_str, ppid_str, "D" });
                cmt_gauge_set(ctx->states, ts, pstate.zombie,                   4, (char *[]){ name, pid_str, ppid_str, "Z" });
                cmt_gauge_set(ctx->states, ts, pstate.stopped,                  4, (char *[]){ name, pid_str, ppid_str, "T" });
                cmt_gauge_set(ctx->states, ts, pstate.idle,                     4, (char *[]){ name, pid_str, ppid_str, "I" });
            }

            /* CPU */
            if (ctx->enabled_flag & METRIC_CPU) {
                /* CPU Seconds (user) */
                entry = flb_slist_entry_get(&split_list, 11);
                tmp = entry->str;
                /* Collect the number of cpu_seconds per process */
                if (pe_utils_str_to_uint64(tmp, &val) != -1) {
                    cmt_counter_set(ctx->cpu_seconds, ts, val/USER_HZ, 4, (char *[]){ name, pid_str, ppid_str, "user" });
                }

                /* CPU Seconds (system) */
                entry = flb_slist_entry_get(&split_list, 12);
                tmp = entry->str;
                /* Collect the number of cpu_seconds per process */
                if (pe_utils_str_to_uint64(tmp, &val) != -1) {
                    cmt_counter_set(ctx->cpu_seconds, ts, val/USER_HZ, 4, (char *[]){ name, pid_str, ppid_str, "system" });
                }
            }

            /* StartTime */
            if (ctx->enabled_flag & METRIC_START_TIME) {
                entry = flb_slist_entry_get(&split_list, 19);
                tmp = entry->str;
                /* Collect the number of cpu_seconds per process */
                if (pe_utils_str_to_uint64(tmp, &val) != -1) {
                    cmt_gauge_set(ctx->start_time, ts, (boot_time + val/USER_HZ), 3, (char *[]){ name, pid_str, ppid_str });
                }
            }

            /* Threads */
            if (ctx->enabled_flag & METRIC_THREAD) {
                entry = flb_slist_entry_get(&split_list, 17);
                thread_str = entry->str;
                /* Collect the number of threads per process */
                if (pe_utils_str_to_uint64(thread_str, &val) != -1) {
                    cmt_gauge_set(ctx->num_threads, ts, val, 3, (char *[]){ name, pid_str, ppid_str });
                }
            }

            /* Memory */
            if (ctx->enabled_flag & METRIC_MEMORY) {
                /* Memory Size */
                entry = flb_slist_entry_get(&split_list, 20);
                tmp = entry->str;
                /* Collect the number of Virtual Memory per process */
                if (pe_utils_str_to_uint64(tmp, &val) != -1) {
                    cmt_gauge_set(ctx->memory_bytes, ts, val, 4, (char *[]){ name, pid_str, ppid_str, "virtual_memory" });
                }

                entry = flb_slist_entry_get(&split_list, 21);
                tmp = entry->str;
                /* Collect the number of RSS per process */
                if (pe_utils_str_to_uint64(tmp, &val) != -1) {
                    /* convert RSS memory in number of pages to bytes */
                    val = val * ctx->page_size;
                    cmt_gauge_set(ctx->memory_bytes, ts, val, 4, (char *[]){ name, pid_str, ppid_str, "rss" });
                }

                /* Major Page Faults */
                entry = flb_slist_entry_get(&split_list, 9);
                tmp = entry->str;
                /* Collect the number of major page faults per process */
                if (pe_utils_str_to_uint64(tmp, &val) != -1) {
                    cmt_counter_set(ctx->major_page_faults, ts, val, 3, (char *[]){ name, pid_str, ppid_str });
                }

                /* Minor Page Faults */
                entry = flb_slist_entry_get(&split_list, 7);
                tmp = entry->str;
                /* Collect the number of minor page faults per process */
                if (pe_utils_str_to_uint64(tmp, &val) != -1) {
                    cmt_counter_set(ctx->minor_page_faults, ts, val, 3, (char *[]){ name, pid_str, ppid_str });
                }
            }

            /* Collect fds */
            if (ctx->enabled_flag & METRIC_FD) {
                ret = process_proc_fds(ctx, ts, pid_str, ppid_str, name, process);
                if (ret == -1) {
                    flb_plg_debug(ctx->ins, "collect fds is failed on the pid = %s", pid_str);
                }
            }

            /* Collect thread_wchan */
            if (ctx->enabled_flag & METRIC_THREAD_WCHAN) {
                ret = process_proc_wchan(ctx, ts, pid_str, name, process);
                if (ret == -1) {
                    flb_plg_debug(ctx->ins, "collect thread_wchan is failed on the pid = %s", pid_str);
                }
            }

            /* Collect IO status */
            if (ctx->enabled_flag & METRIC_IO) {
                ret = process_proc_io(ctx, ts, pid_str, ppid_str, name, process);
                if (ret == -1) {
                    flb_plg_debug(ctx->ins, "collect process io procfs is failed on the pid = %s", pid_str);
                }
            }

            /* Collect the states of threads */
            if (ctx->enabled_flag & METRIC_THREAD) {
                ret = process_thread_update(ctx, ts, pid_str, name);
                if (ret == -1) {
                    flb_plg_debug(ctx->ins, "collect thread procfs is failed on the pid = %s", pid_str);
                }
            }

        cleanup:
            /* Teardown */
            flb_slist_destroy(&split_list);
            flb_free(name);
        }
        flb_slist_destroy(&stat_list);

        /* Context Switches */
        if (ctx->enabled_flag & METRIC_CTXT) {
            process_proc_status(ctx, ts, pid_str, process);
        }
    }

    flb_slist_destroy(&procfs_list);

    return 0;
}

int pe_process_update(struct flb_pe *ctx)
{
    process_update(ctx);
    return 0;
}

int pe_process_exit(struct flb_pe *ctx)
{
    if (ctx->process_regex_include_list != NULL) {
        flb_regex_destroy(ctx->process_regex_include_list);
    }
    if (ctx->process_regex_exclude_list != NULL) {
        flb_regex_destroy(ctx->process_regex_exclude_list);
    }

    return 0;
}
