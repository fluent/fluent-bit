/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_gauge.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <glob.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>

#define DEFAULT_INTERVAL_SEC  "5"
#define DEFAULT_INTERVAL_NSEC "0"

struct mem_metrics {
    int coll_fd;
    struct flb_input_instance *ins;
    flb_sds_t procfs_path;
    struct mk_list *chosen_cmd;
    struct mk_list *chosen_exec;
    struct mk_list *chosen_pid;

    int interval_sec;
    int interval_nsec;

    struct cmt *cmt;
    struct cmt_gauge *rss;
    /* types=base,dirty,anon,file,shmem */
    struct cmt_gauge *pss;
    /* types=dirty,clean */
    struct cmt_gauge *shared;
    struct cmt_gauge *private;
    struct cmt_gauge *referenced;
    struct cmt_gauge *anonymous;
    struct cmt_gauge *lazy_free;
    struct cmt_gauge *anon_huge_pages;
    struct cmt_gauge *shmem_pmd_mapped;
    struct cmt_gauge *file_pmd_mapped;
    struct cmt_gauge *shared_hugetlb;
    struct cmt_gauge *private_hugetlb;
    struct cmt_gauge *swap;
    struct cmt_gauge *swap_pss;
    struct cmt_gauge *locked;
};

static inline int is_empty_choice(struct mk_list *choice)
{
    if (choice == NULL || mk_list_size(choice) == 0) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

static inline int is_chosen_exec(struct mem_metrics *ctx, const char *proc_path)
{
    char real_path[2048] = {0};
    char exe_path[2048] = {0};
    struct mk_list *head = NULL;
    struct flb_slist_entry *cur;
    ssize_t len;

    if (is_empty_choice(ctx->chosen_exec)) {
        return FLB_FALSE;
    }

    snprintf(real_path, sizeof(real_path) - 1, "%s/exe", proc_path);

    len = readlink(real_path, exe_path, sizeof(exe_path)-1);

    if (len < 0) {
        return FLB_FALSE;
    }

    exe_path[len] = '\0';

    mk_list_foreach(head, ctx->chosen_exec) {
        cur = mk_list_entry(head, struct flb_slist_entry, _head);
        if (strcmp(exe_path, cur->str) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static inline int is_chosen_cmd(struct mem_metrics *ctx, const char *proc_path)
{
    char real_path[2048] = {0};
    char cmdline[2048] = {0};
    int fd;
    int rc;
    struct mk_list *head = NULL;
    struct flb_slist_entry *cur;

    if (is_empty_choice(ctx->chosen_cmd)) {
        return FLB_FALSE;
    }

    snprintf(real_path, sizeof(real_path) - 1, "%s/cmdline", proc_path);
    fd = open(real_path, O_RDONLY);
    if (fd == -1) {
        return FLB_FALSE;
    }

    rc = read(fd, cmdline, sizeof(cmdline)-1);
    close(fd);
    if (rc == -1) {
        return FLB_FALSE;
    }

    cmdline[rc] = '\0';

    mk_list_foreach(head, ctx->chosen_cmd) {
        cur = mk_list_entry(head, struct flb_slist_entry, _head);
        if (strcmp(cmdline, cur->str) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static inline int is_chosen_pid(struct mem_metrics *ctx, const char *proc_path)
{
    char *pid;
    pid_t my_pid = getpid();
    pid_t ppid;
    struct mk_list *head = NULL;
    struct flb_slist_entry *cur;

    if (is_empty_choice(ctx->chosen_pid)) {
        return FLB_FALSE;
    }

    pid = strrchr(proc_path, '/');
    if (pid == NULL) {
        return FLB_FALSE;
    }
    pid++;

    mk_list_foreach(head, ctx->chosen_pid) {
        cur = mk_list_entry(head, struct flb_slist_entry, _head);
        if (strcmp(pid, cur->str) == 0) {
            return FLB_TRUE;
        }
        // special case for self and 0
        if (strcmp(cur->str, "self") == 0 || strcmp(cur->str, "0") == 0) {
            ppid = (pid_t) strtoul(pid, NULL, 10);
            if (ppid == my_pid) {
                return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
}

static inline int is_chosen_pid_self(struct mem_metrics *ctx)
{
    struct mk_list *head = NULL;
    struct flb_slist_entry *cur;

    if (ctx->chosen_pid == NULL) {
        return FLB_FALSE;
    }

    if (mk_list_size(ctx->chosen_pid) != 1) {
        return FLB_FALSE;
    }

    mk_list_foreach(head, ctx->chosen_pid) {
        cur = mk_list_entry(head, struct flb_slist_entry, _head);
        // special case for self and 0
        if (strcmp(cur->str, "self") == 0 || strcmp(cur->str, "0") == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int is_chosen(struct mem_metrics *ctx, const char *proc_path)
{
    // choose all processes if no filters are set.
    if (is_empty_choice(ctx->chosen_cmd) &&
        is_empty_choice(ctx->chosen_exec) &&
        is_empty_choice(ctx->chosen_pid)) {
        return FLB_TRUE;
    }

    if (is_chosen_exec(ctx, proc_path) == FLB_TRUE) {
        return FLB_TRUE;
    }

    if (is_chosen_cmd(ctx, proc_path) == FLB_TRUE) {
        return FLB_TRUE;
    }

    if (is_chosen_pid(ctx, proc_path) == FLB_TRUE) {
        return FLB_TRUE;
    }

    // filters are set and none have been chosen.
    return FLB_FALSE;
}

static void mmtx_parse_proc(struct mem_metrics *ctx, uint64_t ts, const char *proc_path)
{
    char real_path[2048];
    struct mk_list *lines;
    struct mk_list *head = NULL;
    int rc;
    struct flb_split_entry *cur = NULL;
    char *sep;
    uint64_t val;
    int fd;
    char *pid;
    char buf[2048];


    if (is_chosen(ctx, proc_path) == FLB_FALSE) {
        return;
    }

    pid = strrchr(proc_path, '/');
    if (pid == NULL) {
        return;
    }
    pid++;

    snprintf(real_path, sizeof(real_path) - 1, "%s/smaps_rollup", proc_path);
    fd = open(real_path, O_RDONLY);
    if (fd == -1) {
        return;
    }

    rc = read(fd, buf, sizeof(buf)-1);
    if (rc == -1) {
        close(fd);
        return;
    }
    close(fd);
    buf[rc] = '\0';

    lines = flb_utils_split(buf, '\n', 21);
    if (lines == NULL) {
        return;
    }

    mk_list_foreach(head, lines) {
        cur = mk_list_entry(head, struct flb_split_entry, _head);
        sep = strchr(cur->value, ':');
        if (sep == NULL) {
            continue;
        }
        val = strtoul(sep+1, NULL, 10);

        if (strncasecmp(cur->value, "Rss:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->rss, ts, val, 1, (char *[]){ pid });
        }

        if (strncasecmp(cur->value, "Pss:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->pss, ts, val, 2, (char *[]){ pid, "clean" });
        }
        if (strncasecmp(cur->value, "Pss_Dirty:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->pss, ts, val, 2, (char *[]){ pid, "dirty" });
        }
        if (strncasecmp(cur->value, "Pss_Anon:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->pss, ts, val, 2, (char *[]){ pid, "anon" });
        }
        if (strncasecmp(cur->value, "Pss_File:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->pss, ts, val, 2, (char *[]){ pid, "file" });
        }
        if (strncasecmp(cur->value, "Pss_Shmem:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->pss, ts, val, 2, (char *[]){ pid, "shmem" });
        }

        if (strncasecmp(cur->value, "Shared_Clean:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->shared, ts, val, 2, (char *[]){ pid, "clean" });
        }
        if (strncasecmp(cur->value, "Shared_Dirty:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->shared, ts, val, 2, (char *[]){ pid, "dirty" });
        }

        if (strncasecmp(cur->value, "Private_Clean:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->private, ts, val, 2, (char *[]){ pid, "clean" });
        }
        if (strncasecmp(cur->value, "Private_Dirty:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->private, ts, val, 2, (char *[]){ pid, "dirty" });
        }

        if (strncasecmp(cur->value, "Referenced:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->referenced, ts, val, 1, (char *[]){ pid });
        }
        if (strncasecmp(cur->value, "Anonymous:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->anonymous, ts, val, 1, (char *[]){ pid });
        }
        if (strncasecmp(cur->value, "LazyFree:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->lazy_free, ts, val, 1, (char *[]){ pid });
        }
        if (strncasecmp(cur->value, "AnonHugePages:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->anon_huge_pages, ts, val, 1, (char *[]){ pid });
        }
        if (strncasecmp(cur->value, "ShmemPmdMapped:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->shmem_pmd_mapped, ts, val, 1, (char *[]){ pid });
        }
        if (strncasecmp(cur->value, "FilePmdMapped:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->file_pmd_mapped, ts, val, 1, (char *[]){ pid });
        }
        if (strncasecmp(cur->value, "Shared_Hugetlb:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->shared_hugetlb, ts, val, 1, (char *[]){ pid });
        }
        if (strncasecmp(cur->value, "Private_Hugetlb:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->private_hugetlb, ts, val, 1, (char *[]){ pid });
        }
        if (strncasecmp(cur->value, "Swap:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->swap, ts, val, 1, (char *[]){ pid });
        }
        if (strncasecmp(cur->value, "SwapPss:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->swap_pss, ts, val, 1, (char *[]){ pid });
        }
        if (strncasecmp(cur->value, "Locked:", sep - cur->value) == 0) {
            cmt_gauge_set(ctx->locked, ts, val, 1, (char *[]){ pid });
        }
    }
    flb_utils_split_free(lines);
}


static int mmtx_utils_path_scan_procs(struct mem_metrics *ctx, uint64_t ts)
{
    int i;
    int ret;
    glob_t globbuf;
    struct stat st;
    char real_path[2048];


    /* Safe reset for globfree() */
    globbuf.gl_pathv = NULL;

    /* Scan the real path */
    snprintf(real_path, sizeof(real_path) - 1, "%s/[0-9]*", ctx->procfs_path);
    ret = glob(real_path, GLOB_TILDE | GLOB_ERR, NULL, &globbuf);
    if (ret != 0) {
        switch (ret) {
        case GLOB_NOSPACE:
            flb_plg_error(ctx->ins, "no memory space available");
            return -1;
        case GLOB_ABORTED:
            flb_plg_error(ctx->ins, "read error, check permissions: %s", real_path);
            return -1;;
        case GLOB_NOMATCH:
            ret = stat(real_path, &st);
            if (ret == -1) {
                flb_plg_debug(ctx->ins, "cannot read info from: %s", real_path);
            }
            else {
                ret = access(real_path, R_OK);
                if (ret == -1 && errno == EACCES) {
                    flb_plg_error(ctx->ins, "NO read access for path: %s", real_path);
                }
                else {
                    flb_plg_debug(ctx->ins, "NO matches for path: %s", real_path);
                }
            }
            return -1;
        }
    }

    if (globbuf.gl_pathc <= 0) {
        globfree(&globbuf);
        return -1;
    }

    /* For every entry found, generate an output list */
    for (i = 0; i < globbuf.gl_pathc; i++) {
        ret = stat(globbuf.gl_pathv[i], &st);
        if (ret != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            mmtx_parse_proc(ctx, ts, globbuf.gl_pathv[i]);
        }
    }

    globfree(&globbuf);
    return 0;
}

static int cb_collector_time(struct flb_input_instance *ins,
                             struct flb_config *config, void *in_context)
{
    struct mem_metrics *ctx = (struct mem_metrics *)in_context;
    if (is_chosen_pid_self(ctx)) {
        mmtx_parse_proc(ctx, cfl_time_now(), "/proc/self");
    } else {
    	mmtx_utils_path_scan_procs(ctx, cfl_time_now());
    }
    flb_input_metrics_append(ins, NULL, 0, ctx->cmt);
    FLB_INPUT_RETURN(0);
}

#define MEM_METRICS_GAUGE_INIT(a, b) \
    ctx->a = cmt_gauge_create(ctx->cmt, "node", "smaps_rollup", #a, (b), \
                                  1, (char *[]) {"pid"}); \
    if (ctx->a == NULL) { \
        flb_plg_error(ctx->ins, "unable to allocate gauge: "#a); \
        goto gauge_error; \
    }

#define MEM_METRICS_GAUGE_INIT_TYPED(a, b) \
    ctx->a = cmt_gauge_create(ctx->cmt, "node", "smaps_rollup", #a, (b), \
                                  2, (char *[]) {"pid", "type"}); \
    if (ctx->a == NULL) { \
        flb_plg_error(ctx->ins, "unable to allocate gauge: "#a); \
        goto gauge_error; \
    }

/* Initialize plugin */
static int cb_mem_metrics_init(struct flb_input_instance *ins,
                               struct flb_config *config, void *data)
{
    int ret;
    struct mem_metrics *ctx = NULL;

    ctx = flb_calloc(1, sizeof(struct mem_metrics));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        return -1;
    }
    ctx->ins = ins;

    flb_input_set_context(ins, ctx);

    ctx->cmt = cmt_create();

    MEM_METRICS_GAUGE_INIT(rss, "RSS");
    MEM_METRICS_GAUGE_INIT_TYPED(pss, "PSS");
    MEM_METRICS_GAUGE_INIT_TYPED(shared, "Shared Memory");
    MEM_METRICS_GAUGE_INIT_TYPED(private, "Private Memory");
    MEM_METRICS_GAUGE_INIT(referenced, "Referenced Memory");
    MEM_METRICS_GAUGE_INIT(anonymous, "Anonymous Memory");
    MEM_METRICS_GAUGE_INIT(lazy_free, "Lazy Free Memory");
    MEM_METRICS_GAUGE_INIT(anon_huge_pages, "Anonymous Huge Pages");
    MEM_METRICS_GAUGE_INIT(shmem_pmd_mapped, "Shared PMD Mapped");
    MEM_METRICS_GAUGE_INIT(file_pmd_mapped, "File PMD Mapped");
    MEM_METRICS_GAUGE_INIT(shared_hugetlb, "Shared HugeTLB");
    MEM_METRICS_GAUGE_INIT(private_hugetlb, "Private HugeTLB");
    MEM_METRICS_GAUGE_INIT(swap, "Swap Memory");
    MEM_METRICS_GAUGE_INIT(swap_pss, "Swap PSS Memory");
    MEM_METRICS_GAUGE_INIT(locked, "Locked Memory");

    /* unit test 0: collector_time */
    ret = flb_input_set_collector_time(ins, cb_collector_time,
                                       ctx->interval_sec, ctx->interval_nsec,
                                       config);
    if (ret < 0) {
        cmt_destroy(ctx->cmt);
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
gauge_error:
    cmt_destroy(ctx->cmt);
    flb_free(ctx);
    return -1;
}

static int cb_mem_metrics_exit(void *data, struct flb_config *config)
{
    struct mem_metrics *ctx = data;

    cmt_destroy(ctx->cmt);
    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "proc_path", "/proc",
     0, FLB_TRUE, offsetof(struct mem_metrics, procfs_path),
     "The path of the proc pseudo filesystem, default: /proc"
    },
    {
     FLB_CONFIG_MAP_CLIST_1, "filter_exec", NULL,
     0, FLB_TRUE, offsetof(struct mem_metrics, chosen_exec),
     "Filter for a single executable"
    },
    {
     FLB_CONFIG_MAP_CLIST_1, "filter_cmd", NULL,
     0, FLB_TRUE, offsetof(struct mem_metrics, chosen_cmd),
     "Filter by the command line"
    },
    {
      FLB_CONFIG_MAP_CLIST_1, "filter_pid", NULL,
      0, FLB_TRUE, offsetof(struct mem_metrics, chosen_pid),
      "Filter by PID"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct mem_metrics, interval_sec),
      "Set the interval seconds between events generation"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct mem_metrics, interval_nsec),
      "Set the nanoseconds interval (sub seconds)"
    },

   /* EOF */
   {0}
};

struct flb_input_plugin in_mem_metrics_plugin = {
    .name         = "mem_metrics",
    .description  = "Full Memory Metrics for Linux",
    .cb_init      = cb_mem_metrics_init,
    .cb_pre_run   = NULL,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = cb_mem_metrics_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_CORO | FLB_INPUT_THREADED
};
