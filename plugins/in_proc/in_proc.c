/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <glob.h>
#include <libgen.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>

#include "in_proc.h"

struct flb_in_proc_mem_offset mem_linux[] = {
    {
        "Peak",
        "mem.VmPeak",
        offsetof(struct flb_in_proc_mem_linux, vmpeak)
    },
    {
        "Size",
        "mem.VmSize",
        offsetof(struct flb_in_proc_mem_linux, vmsize)
    },
    {
        "Lck",
        "mem.VmLck",
        offsetof(struct flb_in_proc_mem_linux, vmlck)
    },
    {
        "HWM",
        "mem.VmHWM",
        offsetof(struct flb_in_proc_mem_linux, vmhwm)
    },
    {
        "RSS",
        "mem.VmRSS",
        offsetof(struct flb_in_proc_mem_linux, vmrss)
    },
    {
        "Data",
        "mem.VmData",
        offsetof(struct flb_in_proc_mem_linux, vmdata)
    },
    {
        "Stk",
        "mem.VmStk",
        offsetof(struct flb_in_proc_mem_linux, vmstk)
    },
    {
        "Exe",
        "mem.VmExe",
        offsetof(struct flb_in_proc_mem_linux, vmexe)
    },
    {
        "Lib",
        "mem.VmLib",
        offsetof(struct flb_in_proc_mem_linux, vmlib)
    },
    {
        "PTE",
        "mem.VmPTE",
        offsetof(struct flb_in_proc_mem_linux, vmpte)
    },
    {
        "Swap",
        "mem.VmSwap",
        offsetof(struct flb_in_proc_mem_linux, vmswap)
    },
    {NULL, NULL, 0}/* end of array */
};



static pid_t get_pid_from_procname_linux(struct flb_in_proc_config *ctx,
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

static int configure(struct flb_in_proc_config *ctx,
                     struct flb_input_instance *in)
{
    int ret;

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(in, "unable to load configuration");
        return -1;
    }
    
    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
        ctx->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
    }

    if (ctx->proc_name != NULL && strcmp(ctx->proc_name, "") != 0) {
        ctx->len_proc_name = strlen(ctx->proc_name);
    }

    return 0;
}

static int get_pid_status(pid_t pid)
{
    int ret =  kill(pid, 0);
    return ((ret != ESRCH)  && (ret != EPERM) && (ret != ESRCH));
}

static int generate_record_linux(struct flb_input_instance *i_ins,
                                 struct flb_config *config, void *in_context,
                                 struct flb_in_proc_mem_linux *mem_stat,
                                 uint64_t fds)
{
    int i;
    int ret;
    struct flb_in_proc_config *ctx = in_context;

    if (ctx->alive == FLB_TRUE && ctx->alert == FLB_TRUE) {
        return 0;
    }

    ret = flb_log_event_encoder_begin_record(ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(
                ctx->log_encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("alive"),
                FLB_LOG_EVENT_BOOLEAN_VALUE(ctx->alive),
                /* proc name */
                FLB_LOG_EVENT_CSTRING_VALUE("proc_name"),
                FLB_LOG_EVENT_CSTRING_VALUE(ctx->proc_name),
                /* pid */
                FLB_LOG_EVENT_CSTRING_VALUE("pid"),
                FLB_LOG_EVENT_INT64_VALUE(ctx->pid));
    }

    /* memory */
    if (ctx->mem == FLB_TRUE) {
        char *str = NULL;
        uint64_t *val = NULL;
        for (i = 0;
             mem_linux[i].key != NULL &&
             ret == FLB_EVENT_ENCODER_SUCCESS;
             i++) {
            str = mem_linux[i].msgpack_key;
            val = (uint64_t*)((char*)mem_stat + mem_linux[i].offset);

            ret = flb_log_event_encoder_append_body_values(
                    ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(str),
                    FLB_LOG_EVENT_UINT64_VALUE(*val));
        }
    }

    /* file descriptor */
    if (ctx->fds) {
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    ctx->log_encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("fd"),
                    FLB_LOG_EVENT_UINT64_VALUE(fds));
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(i_ins, NULL, 0,
                             ctx->log_encoder->output_buffer,
                             ctx->log_encoder->output_length);
        ret = 0;
    }
    else {
        flb_plg_error(i_ins, "log event encoding error : %d", ret);

        ret = -1;
    }

    flb_log_event_encoder_reset(ctx->log_encoder);

    return ret;
}

static void update_alive(struct flb_in_proc_config *ctx)
{
    if (ctx->pid >= 0 && get_pid_status(ctx->pid)) {
        ctx->alive = FLB_TRUE;
    }
    else {
        ctx->alive = FLB_FALSE;
    }
}

static void mem_linux_clear(struct flb_in_proc_mem_linux *mem_stat)
{
    int i;
    uint64_t *temp = NULL;
    for (i=0;mem_linux[i].key != NULL;i++) {
        temp   = (uint64_t*)((char*)mem_stat + mem_linux[i].offset);
        *temp  = 0;
    }
}

static int update_mem_linux(struct flb_in_proc_config *ctx,
                            struct flb_in_proc_mem_linux *mem_stat)
{
    int ret  = -1;
    int i;
    char path[PATH_MAX] = {0};
    char str_name[32] = {0};
    char *line = NULL;
    char *fmt = NULL;
    char *buf = NULL;
    ssize_t count;
    size_t len = 256;
    uint64_t mem_size;
    uint64_t *temp = NULL;
    FILE *fp  = NULL;

    snprintf(path, sizeof(path), "/proc/%d/status",ctx->pid);
    fp = fopen(path, "r");

    if (fp == NULL) {
        flb_plg_error(ctx->ins, "open error: %s", path);
        mem_linux_clear(mem_stat);
        return -1;
    }

    line = (char*)flb_malloc(len);
    while(1) {
        count = getline(&line, &len, fp);
        if (count < 0) {
            break;
        }

        /* VmPeak:	   14860 kB */
        fmt = "Vm%s"; /* e.g. "Peak:" */
        memset(str_name, '\0', sizeof(str_name));
        ret = sscanf(line, fmt, str_name);
        if (ret < 1) {
            continue;
        }
        /* replace : -> NULL char*/
        if ((buf = strchr(str_name, ':')) != NULL) {
            *buf = '\0';
        }

        /* calcurate size */
        mem_size = 0;
        for (i=0;line[i] != '\0';i++) {
            if (line[i] >= 0x30 && line[i] <= 0x39 /* is number*/) {
                mem_size *= 10;
                mem_size += line[i] - 0x30;
            }
        }

        for (i=0;mem_linux[i].key != NULL;i++) {
            if (!strcmp(str_name, mem_linux[i].key)) {
                temp   = (uint64_t*)((char*)mem_stat + mem_linux[i].offset);
                *temp  = mem_size * 1000; /* kB size */
                break;
            }
        }
    }
    flb_free(line);
    fclose(fp);
    return ret;
}

static int update_fds_linux(struct flb_in_proc_config *ctx,
                            uint64_t *fds)
{
    DIR *dirp = NULL;
    struct dirent *entry = NULL;
    char path[PATH_MAX] = {0};

    *fds = 0;

    snprintf(path, sizeof(path), "/proc/%d/fd", ctx->pid);
    dirp = opendir(path);
    if (dirp == NULL) {
        perror("opendir");
        flb_plg_error(ctx->ins, "opendir error %s", path);
        return -1;
    }

    entry = readdir(dirp);
    while (entry != NULL) {
        *fds += 1;/* should we check entry->d_name ? */
        entry = readdir(dirp);
    }
    *fds -= 2; /* '.' and '..' */
    closedir(dirp);

    return 0;
}

static int in_proc_collect_linux(struct flb_input_instance *i_ins,
                           struct flb_config *config, void *in_context)
{
    uint64_t fds = 0;
    struct flb_in_proc_config *ctx = in_context;
    struct flb_in_proc_mem_linux mem;

    if (ctx->proc_name != NULL){
        ctx->pid = get_pid_from_procname_linux(ctx, ctx->proc_name);
        update_alive(ctx);

        if (ctx->mem == FLB_TRUE && ctx->alive == FLB_TRUE) {
            mem_linux_clear(&mem);
            update_mem_linux(ctx, &mem);
        }
        if (ctx->fds == FLB_TRUE && ctx->alive == FLB_TRUE) {
            update_fds_linux(ctx, &fds);
        }
        generate_record_linux(i_ins, config, in_context, &mem, fds);
    }

    return 0;
}

static int in_proc_collect(struct flb_input_instance *i_ins,
                           struct flb_config *config, void *in_context)
{
    return in_proc_collect_linux(i_ins, config, in_context);
}

static int in_proc_init(struct flb_input_instance *in,
                          struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_proc_config *ctx = NULL;
    (void) data;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_in_proc_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->alert = FLB_FALSE;
    ctx->mem   = FLB_TRUE;
    ctx->fds   = FLB_TRUE;
    ctx->proc_name = NULL;
    ctx->pid = -1;
    ctx->ins = in;

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ctx->log_encoder == NULL) {
        flb_plg_error(in, "event encoder initialization error");
        flb_free(ctx);

        return -1;
    }

    configure(ctx, in);

    if (ctx->proc_name == NULL) {
        flb_plg_error(ctx->ins, "'proc_name' is not set");
        flb_free(ctx);
        return -1;
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set our collector based on time */
    ret = flb_input_set_collector_time(in,
                                       in_proc_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set collector for Proc input plugin");
        flb_free(ctx);
        return -1;
    }

    return 0;
}

static int in_proc_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_proc_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->log_encoder != NULL) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

    /* Destroy context */
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_in_proc_config, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_in_proc_config, interval_nsec),
      "Set the collector interval (nanoseconds)"
    },
    {
     FLB_CONFIG_MAP_BOOL, "alert", "false",
     0, FLB_TRUE, offsetof(struct flb_in_proc_config, alert),
     "Only generate alerts if process is down"
    },
    {
     FLB_CONFIG_MAP_BOOL, "mem", "true",
     0, FLB_TRUE, offsetof(struct flb_in_proc_config, mem),
     "Append memory usage to record"
    },
    {
     FLB_CONFIG_MAP_BOOL, "fd", "true",
     0, FLB_TRUE, offsetof(struct flb_in_proc_config, fds),
     "Append fd count to record"
    },
    {
     FLB_CONFIG_MAP_STR, "proc_name", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_proc_config, proc_name),
     "Define process name to health check"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_proc_plugin = {
    .name         = "proc",
    .description  = "Check Process health",
    .cb_init      = in_proc_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_proc_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_proc_exit,
    .config_map   = config_map,
    .flags        = 0,
};
