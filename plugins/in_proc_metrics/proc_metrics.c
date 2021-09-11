/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_compat.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <msgpack.h>
#include <glob.h>
#include <ctype.h>
#include <fcntl.h>

#include "proc_metrics.h"

#define FLB_CMD_LEN 256

/* rchar: 260189
 * wchar: 413454
 * syscr: 2036
 * syscw: 2564
 * read_bytes: 0
 * write_bytes: 0
 * cancelled_write_bytes: 0
 */
static int parse_proc_io(const char *buf, struct proc_metrics_io_status *status)
{
    struct mk_list *llines;
    struct mk_list *head;
    struct flb_split_entry *cur = NULL;
    int line = 0;

    llines = flb_utils_split(buf, '\n', 7);
    mk_list_foreach(head, llines) {
        cur = mk_list_entry(head, struct flb_split_entry, _head);
        switch(line) {
        case 0:
            sscanf(cur->value, "rchar: %lu", &status->rchar);
            break;
        case 1:
            sscanf(cur->value, "wchar: %lu", &status->wchar);
            break;
        case 2:
            sscanf(cur->value, "syscr: %lu", &status->syscr);
            break;
        case 3:
            sscanf(cur->value, "syscw: %lu", &status->syscw);
            break;
        case 4:
            sscanf(cur->value, "read_bytes: %lu", &status->read_bytes);
            break;
        case 5:
            sscanf(cur->value, "write_bytes: %lu", &status->write_bytes);
            break;
        case 6:
            sscanf(cur->value, "cancelled_write_bytes: %lu",
                   &status->cancelled_write_bytes);
            break;
        }
        line++;
    }
    flb_utils_split_free(llines);
    return 0;
}

/* size res trs lrs drs dt (implied)
 * 1793 516 482 4 0 180 0
 */
static int parse_proc_mem(const char *buf, struct proc_metrics_mem_status *status)
{
    struct mk_list *lfields;
    struct mk_list *head;
    struct flb_split_entry *cur = NULL;
    int line = 0;

    lfields = flb_utils_split(buf, ' ', 7);
    mk_list_foreach(head, lfields) {
        cur = mk_list_entry(head, struct flb_split_entry, _head);
        switch(line) {
        case 0:
            sscanf(cur->value, "%lu", &status->size);
            break;
        case 1:
            sscanf(cur->value, "%lu", &status->resident);
            break;
        case 2:
            sscanf(cur->value, "%lu", &status->shared);
            break;
        case 3:
            sscanf(cur->value, "%lu", &status->trs);
            break;
        case 4:
            sscanf(cur->value, "%lu", &status->lrs);
            break;
        case 5:
            sscanf(cur->value, "%lu", &status->drs);
            break;
        case 6:
            sscanf(cur->value, "%lu", &status->dt);
            break;
        }
        line++;
    }
    flb_utils_split_free(lfields);
    return 0;
}

/* We specifically *CANNOT* use flb_utils_read_file because
 * /proc special files tend to report their own size as 0.
 */
static int read_file_lines(const char *path, char *buf, size_t maxlen, int lines)
{
    int fd;
    int rc;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        flb_errno();
        return -1;
    }
    rc = read(fd, buf, maxlen-1);
    if (rc == -1) {
        close(fd);
        flb_errno();
        return -1;
    }
    buf[rc] = '\0';
    close(fd);
    return 0;
}

static int read_stat_file(pid_t pid, const char *file,
                          char *buf, size_t maxlen, int lines)
{
    char pathname[PATH_MAX];
    if (pid > 0) {
        snprintf(pathname, sizeof(pathname)-1, "/proc/%d/%s", pid, file);
    } else {
        snprintf(pathname, sizeof(pathname)-1, "/proc/%d/%s", getpid(), file);
    }
    if (read_file_lines(pathname, buf, maxlen, lines) == -1) {
        flb_errno();
        return -1;
    }
    return 0;
}

static pid_t get_pid_from_procname_linux(struct proc_metrics_ctx *ctx,
                                         const char* proc)
{
    pid_t ret = -1;
    glob_t glb;
    int i;
    int fd = -1;
    long ret_scan = -1;
    int ret_glb = -1;
    ssize_t count;

    char  cmdname[FLB_CMD_LEN];
    char* bname = NULL;

    ret_glb = glob("/proc/*/cmdline", 0 ,NULL, &glb);
    if (ret_glb != 0) {
        switch(ret_glb){
        case GLOB_NOSPACE:
            flb_plg_warn(ctx->ins, "glob: no space");
            break;
        case GLOB_NOMATCH:
            flb_plg_warn(ctx->ins, "glob: no match");
            break;
        case GLOB_ABORTED:
            flb_plg_warn(ctx->ins, "glob: aborted");
            break;
        default:
            flb_plg_warn(ctx->ins, "glob: other error");
        }
        return ret;
    }

    for (i = 0; i < glb.gl_pathc; i++) {
        fd = open(glb.gl_pathv[i], O_RDONLY);
        if (fd < 0) {
            continue;
        }
        count = read(fd, &cmdname, FLB_CMD_LEN);
        if (count <= 0){
            close(fd);
            continue;
        }
        cmdname[FLB_CMD_LEN-1] = '\0';
        bname = basename(cmdname);

        if (strncmp(proc, bname, FLB_CMD_LEN) == 0) {
            sscanf(glb.gl_pathv[i],"/proc/%ld/cmdline",&ret_scan);
            ret = (pid_t)ret_scan;
            close(fd);
            break;
        }
        close(fd);
    }
    globfree(&glb);
    return ret;
}

static struct proc_metrics_pid_cmt *create_pid_cmt(struct flb_input_instance *ins, pid_t pid)
{
    struct proc_metrics_pid_cmt *ctx;

    ctx = flb_calloc(1, sizeof(struct proc_metrics_pid_cmt));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->pid = pid;

    ctx->cmt = cmt_create();
    if (!ctx->cmt) {
        flb_plg_error(ins, "could not initialize CMetrics");
        goto cmt_error;
    }

    ctx->rchar = cmt_counter_create(ctx->cmt, "proc_metrics", "io", "rchar",
                                    "The number of bytes which this task has "
                                    "caused to be read from storage.", 1, (char *[]) {"pid"});
    if (ctx->rchar == NULL) {
        flb_plg_error(ins, "could not initialize rchar counter");
        goto cmt_counter_error;
    }

    ctx->wchar = cmt_counter_create(ctx->cmt, "proc_metrics", "io", "wchar",
                                    "The number of bytes which this task has "
                                    "caused, or shall cause to be written to "
                                    "disk.", 1, (char *[]) {"pid"});
    if (ctx->wchar == NULL) {
        flb_plg_error(ins, "could not initialize wchar counter");
        goto cmt_counter_error;
    }

    ctx->syscr = cmt_counter_create(ctx->cmt, "proc_metrics", "io", "syscr",
                                    "Attempt to count the number of read I/O "
                                    "operations, i.e. syscalls like read() and "
                                    "pread().", 1, (char *[]) {"pid"});
    if (ctx->syscr == NULL) {
        flb_plg_error(ins, "could not initialize syscr counter");
        goto cmt_counter_error;
    }

    ctx->syscw = cmt_counter_create(ctx->cmt, "proc_metrics", "io", "syscw",
                                    "Attempt to count the number of write I/O "
                                    "operations, i.e. syscalls like write() and "
                                    "pwrite().", 1, (char *[]) {"pid"});
    if (ctx->syscw == NULL) {
        flb_plg_error(ins, "could not initialize syscw counter");
        goto cmt_counter_error;
    }

    ctx->read_bytes = cmt_counter_create(ctx->cmt, "proc_metrics", "io", "read_bytes",
                                         "Attempt to count the number of bytes "
                                         "which this process really did cause to"
                                         " be fetched from the storage layer.",
                                         1, (char *[]) {"pid"});
    if (ctx->read_bytes == NULL) {
        flb_plg_error(ins, "could not initialize read_bytes counter");
        goto cmt_counter_error;
    }

    ctx->write_bytes = cmt_counter_create(ctx->cmt, "proc_metrics", "io", "write_bytes",
                                         "Attempt to count the number of bytes "
                                         "which this process caused to be sent "
                                         "to the storage layer.", 1, (char *[]) {"pid"});
    if (ctx->write_bytes == NULL) {
        flb_plg_error(ins, "could not initialize write_bytes counter");
        goto cmt_counter_error;
    }

    ctx->cancelled_write_bytes = cmt_counter_create(ctx->cmt, "proc_metrics", "io",
                                                    "cancelled_write_bytes",
                                                    "The number of bytes which "
                                                    "this process caused to not "
                                                    "happen, by truncating "
                                                    "pagecache.", 1, (char *[]) {"pid"});
    if (ctx->cancelled_write_bytes == NULL) {
        flb_plg_error(ins, "could not initialize cancelled_write_bytes counter");
        goto cmt_counter_error;
    }

    ctx->size = cmt_gauge_create(ctx->cmt, "proc_metrics", "mem", "size",
                                 "total program size (pages).", 1, (char *[]) {"pid"});
    if (ctx->size == NULL) {
        flb_plg_error(ins, "could not initialize size gauge");
        goto cmt_gauge_error;
    }

    ctx->resident = cmt_gauge_create(ctx->cmt, "proc_metrics", "mem", "resident",
                                     "size of memory portions (pages).", 1, (char *[]) {"pid"});
    if (ctx->resident == NULL) {
        flb_plg_error(ins, "could not initialize resident gauge");
        goto cmt_gauge_error;
    }

    ctx->shared = cmt_gauge_create(ctx->cmt, "proc_metrics", "mem", "shared",
                                   "number of pages that are shared.", 1, (char *[]) {"pid"});
    if (ctx->shared == NULL) {
        flb_plg_error(ins, "could not initialize shared gauge");
        goto cmt_gauge_error;
    }

    ctx->trs = cmt_gauge_create(ctx->cmt, "proc_metrics", "mem", "trs",
                                "number of pages that are ‘code’.", 1, (char *[]) {"pid"});
    if (ctx->trs == NULL) {
        flb_plg_error(ins, "could not initialize trs gauge");
        goto cmt_gauge_error;
    }

    ctx->lrs = cmt_gauge_create(ctx->cmt, "proc_metrics", "mem", "lrs",
                                 "number of pages of library.", 1, (char *[]) {"pid"});
    if (ctx->lrs == NULL) {
        flb_plg_error(ins, "could not initialize lrs gauge");
        goto cmt_gauge_error;
    }

    ctx->drs = cmt_gauge_create(ctx->cmt, "proc_metrics", "mem", "drs",
                                 "number of pages of data/stack.", 1, (char *[]) {"pid"});
    if (ctx->drs == NULL) {
        flb_plg_error(ins, "could not initialize drs gauge");
        goto cmt_gauge_error;
    }

    ctx->dt = cmt_gauge_create(ctx->cmt, "proc_metrics", "mem", "dt",
                                 "number of dirty pages.", 1, (char *[]) {"pid"});
    if (ctx->dt == NULL) {
        flb_plg_error(ins, "could not initialize dt gauge");
        goto cmt_gauge_error;
    }

    return ctx;
cmt_gauge_error:
    if (ctx->size != NULL) {
        cmt_gauge_destroy(ctx->size);
    }
cmt_counter_error:
    if (ctx->rchar != NULL) {
        cmt_counter_destroy(ctx->rchar);
    }
    if (ctx->wchar != NULL) {
        cmt_counter_destroy(ctx->wchar);
    }
    if (ctx->syscr != NULL) {
        cmt_counter_destroy(ctx->syscr);
    }
    if (ctx->syscw != NULL) {
        cmt_counter_destroy(ctx->syscw);
    }
    if (ctx->read_bytes != NULL) {
        cmt_counter_destroy(ctx->read_bytes);
    }
    if (ctx->write_bytes != NULL) {
        cmt_counter_destroy(ctx->write_bytes);
    }
    if (ctx->cancelled_write_bytes != NULL) {
        cmt_counter_destroy(ctx->cancelled_write_bytes);
    }
    cmt_destroy(ctx->cmt);
cmt_error:
    flb_free(ctx);
    return NULL;
}

struct proc_metrics_pid_cmt *get_proc_metrics(struct proc_metrics_ctx *ctx, pid_t pid)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct proc_metrics_pid_cmt *proc;

    if (mk_list_is_empty(&ctx->procs)) {
        proc = create_pid_cmt(ctx->ins, pid);
        mk_list_add(&proc->_head, &ctx->procs);
        return proc;
    }

    mk_list_foreach_safe(head, tmp, &ctx->procs) {
        proc = mk_list_entry(head, struct proc_metrics_pid_cmt, _head);
        if (proc->pid == pid) {
            return proc;
        }
    }

    proc = create_pid_cmt(ctx->ins, pid);
    mk_list_add(&proc->_head, &ctx->procs);
    return proc;
}

/**
 * Callback function to gather statistics from /proc/$PID.
 *
 *
 * @param ins           Pointer to flb_input_instance
 * @param config        Pointer to flb_config
 * @param in_context    void Pointer used to cast to
 *                      flb_in_de_config
 *
 * @return int 0 for success -1 for failure.
 */
static int proc_metrics_collect(struct flb_input_instance *ins,
                              struct flb_config *config, void *in_context)
{
    char buf[1024];
    struct proc_metrics_ctx *ctx = (struct proc_metrics_ctx *)in_context;
    uint64_t ts = cmt_time_now();
    struct proc_metrics_status status;
    char pid[64];
    int ret;
    struct proc_metrics_pid_cmt *metrics;

    if (ctx->proc_name != NULL) {
        ret = get_pid_from_procname_linux(ctx, ctx->proc_name);
        if (ret == -1) {
            return -1;
        }
        ctx->pid = ret;
    }

    if (ctx->pid > 0) {
        metrics = get_proc_metrics(ctx, ctx->pid);
    } else {
        metrics = get_proc_metrics(ctx, getpid());
    }

    if (read_stat_file(metrics->pid, "io", buf, sizeof(buf)-1, 7) == -1) {
        return -1;
    }

    if (parse_proc_io(buf, &status.io) != 0) {
        flb_free(buf);
        return -1;
    }

    if (read_stat_file(metrics->pid, "statm", buf, sizeof(buf)-1, 1) == -1) {
        return -1;
    }

    if (parse_proc_mem(buf, &status.mem) != 0) {
        return -1;
    }

    if (metrics->pid == 0) {
       snprintf(pid, sizeof(pid)-1, "%d", getpid());
    } else {
        snprintf(pid, sizeof(pid)-1, "%d", metrics->pid);
    }

    cmt_counter_set(metrics->rchar, ts, (double)status.io.rchar, 1, (char *[]) {(char *) pid});
    cmt_counter_set(metrics->wchar, ts, (double)status.io.wchar, 1, (char *[]) {(char *) pid});
    cmt_counter_set(metrics->syscr, ts, (double)status.io.syscr, 1, (char *[]) {(char *) pid});
    cmt_counter_set(metrics->syscw, ts, (double)status.io.syscw, 1, (char *[]) {(char *) pid});
    cmt_counter_set(metrics->read_bytes, ts, (double)status.io.read_bytes,
                    1, (char *[]) {(char *) pid});
    cmt_counter_set(metrics->write_bytes, ts, (double)status.io.write_bytes,
                    1, (char *[]) {(char *) pid});
    cmt_counter_set(metrics->cancelled_write_bytes, ts,
                    (double)status.io.cancelled_write_bytes, 1, (char *[]) {(char *) pid});

    cmt_gauge_set(metrics->size, ts, (double)status.mem.size, 1, (char *[]) {(char *) pid});
    cmt_gauge_set(metrics->resident, ts, (double)status.mem.resident,
                  1, (char *[]) {(char *) pid});
    cmt_gauge_set(metrics->shared, ts, (double)status.mem.shared, 1, (char *[]) {(char *) pid});
    cmt_gauge_set(metrics->trs, ts, (double)status.mem.trs, 1, (char *[]) {(char *) pid});
    cmt_gauge_set(metrics->lrs, ts, (double)status.mem.lrs, 1, (char *[]) {(char *) pid});
    cmt_gauge_set(metrics->drs, ts, (double)status.mem.drs, 1, (char *[]) {(char *) pid});
    cmt_gauge_set(metrics->dt, ts, (double)status.mem.dt, 1, (char *[]) {(char *) pid});

    ret = flb_input_metrics_append(ins, NULL, 0, metrics->cmt);
    if (ret != 0) {
        flb_plg_error(ins, "could not append metrics");
    }
    return ret;
}

int str_isnumeric(const char *str)
{
    int i;

    if (str == NULL) {
        return FLB_FALSE;
    }
    for (i = 0; i < strlen(str); i++) {
        if (isdigit(str[i]) == 0) {
            return FLB_FALSE;
        }
    }
    return FLB_TRUE;
}

/**
 * Function to initialize the proc stats plugin.
 *
 * @param ins     Pointer to flb_input_instance
 * @param config  Pointer to flb_config
 * @param data    Unused
 *
 * @return int 0 on success, -1 on failure
 */
static int proc_metrics_init(struct flb_input_instance *ins,
                           struct flb_config *config, void *data)
{
    struct proc_metrics_ctx *ctx;
    int ret;

    ctx = flb_calloc(1, sizeof(struct proc_metrics_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* save the PID just once if the process is numeric */
    if (str_isnumeric(ctx->process) == FLB_TRUE) {
        ret = strtol(ctx->process, (char **)NULL, 10);
        if (ret == -1) {
            goto cmt_error;
        }
        ctx->pid = ret;
    } else {
        ctx->proc_name = ctx->process;
    }

    mk_list_init(&ctx->procs);

    flb_input_set_context(ins, ctx);
    ctx->coll_id = flb_input_set_collector_time(ins,
                                                proc_metrics_collect,
                                                1, 0, config);
    return 0;
cmt_error:
    flb_free(ctx);
    return -1;
}

/**
 * Function to destroy proc_metrics_status plugin.
 *
 * @param ctx  Pointer to proc_metrics_ctx
 *
 * @return int 0
 */
static int proc_metrics_ctx_destroy(struct proc_metrics_ctx *ctx)
{
    flb_free(ctx);
    return 0;
}

/**
 * Callback exit function to cleanup plugin
 *
 * @param data    Pointer cast to flb_in_de_config
 * @param config  Unused
 *
 * @return int    Always returns 0
 */
static int proc_metrics_exit(void *data, struct flb_config *config)
{
    struct proc_metrics_ctx *ctx = (struct proc_metrics_ctx *)data;
    if (!ctx) {
        return 0;
    }
    proc_metrics_ctx_destroy(ctx);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "process", 0,
     0, FLB_TRUE, offsetof(struct proc_metrics_ctx, process),
     "The Process Name or ID to collect statistics for."
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_proc_metrics_plugin = {
    .name         = "proc_metrics",
    .description  = "Process ID stats metrics",
    .cb_init      = proc_metrics_init,
    .cb_pre_run   = NULL,
    .cb_collect   = proc_metrics_collect,
    .cb_flush_buf = NULL,
    .config_map   = config_map,
    .cb_exit      = proc_metrics_exit,
    .event_type   = FLB_INPUT_METRICS
};
