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

#include <msgpack.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_utils.h>

#include "in_proc.h"

static pid_t get_pid_from_procname_linux(const char* proc)
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

    if ((ret_glb = glob("/proc/*/cmdline", 0 ,NULL,&glb) != 0)) {
        switch(ret_glb){
        case GLOB_NOSPACE:
            flb_warn("[%s] glob: no space", FLB_IN_PROC_NAME);
            break;
        case GLOB_NOMATCH:
            flb_warn("[%s] glob: no match", FLB_IN_PROC_NAME);
            break;
        case GLOB_ABORTED:
            flb_warn("[%s] glob: aborted", FLB_IN_PROC_NAME);
            break;
        default:
            flb_warn("[%s] glob: other error", FLB_IN_PROC_NAME);
        }
        return ret;
    }

    for(i=0; i<glb.gl_pathc; i++){
        fd = open(glb.gl_pathv[i], O_RDONLY);
        if (fd<0) {
            continue;
        }
        count = read(fd, &cmdname, FLB_CMD_LEN);
        if (count<=0){
            close(fd);
            continue;
        }
        cmdname[FLB_CMD_LEN-1] = '\0';
        bname = basename(cmdname);

        if (strncmp(proc, (const char*)bname, FLB_CMD_LEN) == 0) {
            sscanf((const char*)glb.gl_pathv[i],"/proc/%ld/cmdline",&ret_scan);
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
    char *pval = NULL;

    /* interval settings */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        ctx->interval_sec = atoi(pval);
    }
    else {
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    }

    pval = flb_input_get_property("interval_nsec", in);
    if (pval != NULL && atoi(pval) >= 0) {
        ctx->interval_nsec = atoi(pval);
    }
    else {
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    if (ctx->interval_sec <= 0 && ctx->interval_nsec <= 0) {
        /* Illegal settings. Override them. */
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
        ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;
    }

    pval = flb_input_get_property("alert", in);
    if (pval) {
        if (strcasecmp(pval, "true") == 0 || strcasecmp(pval, "on") == 0) {
            ctx->alert = FLB_TRUE;
        }
    }

    pval = flb_input_get_property("proc_name", in);
    if (pval) {
        ctx->proc_name = (char*)flb_malloc(FLB_CMD_LEN);
        if (ctx->proc_name == NULL) {
            return -1;
        }
        strncpy(ctx->proc_name, pval, FLB_CMD_LEN);
        ctx->proc_name[FLB_CMD_LEN-1] = '\0';
        ctx->len_proc_name = strlen(ctx->proc_name);
    }

    return 0;
}

static int get_pid_status(pid_t pid)
{
    int ret =  kill(pid, 0);
    return ((ret != ESRCH)  && (ret != EPERM) && (ret != ESRCH));
}

static int collect_proc(struct flb_input_instance *i_ins,
                        struct flb_config *config, void *in_context)
{
    uint8_t alive = FLB_FALSE;
    struct flb_in_proc_config *ctx = in_context;

    ctx->pid = get_pid_from_procname_linux(ctx->proc_name);

    if (ctx->pid >= 0 && get_pid_status(ctx->pid)) {
        alive = FLB_TRUE;
    }

    if (alive == FLB_TRUE && ctx->alert == FLB_TRUE) {
        return 0;
    }

    /*
     * Store the new data into the MessagePack buffer,
     */
    msgpack_pack_array(&i_ins->mp_pck, 2);
    msgpack_pack_uint64(&i_ins->mp_pck, time(NULL));

    /* 3 = alive, proc_name, pid */
    msgpack_pack_map(&i_ins->mp_pck, 3);

    /* Status */
    msgpack_pack_bin(&i_ins->mp_pck, 5);
    msgpack_pack_bin_body(&i_ins->mp_pck, "alive", 5);

    if (alive) {
        msgpack_pack_true(&i_ins->mp_pck);
    }
    else {
        msgpack_pack_false(&i_ins->mp_pck);
    }

    /* proc name */
    msgpack_pack_bin(&i_ins->mp_pck, strlen("proc_name"));
    msgpack_pack_bin_body(&i_ins->mp_pck, "proc_name", strlen("proc_name"));
    msgpack_pack_bin(&i_ins->mp_pck, ctx->len_proc_name);
    msgpack_pack_bin_body(&i_ins->mp_pck, ctx->proc_name, ctx->len_proc_name);

    /* pid */
    msgpack_pack_bin(&i_ins->mp_pck, strlen("pid"));
    msgpack_pack_bin_body(&i_ins->mp_pck, "pid", strlen("pid"));
    msgpack_pack_int64(&i_ins->mp_pck, ctx->pid);

    return 0;
}

static int in_proc_collect(struct flb_input_instance *i_ins,
                           struct flb_config *config, void *in_context)
{
    struct flb_in_proc_config *ctx = in_context;

    if (ctx->proc_name != NULL){
        collect_proc(i_ins, config, in_context);
    }

    return 0;
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
        perror("calloc");
        return -1;
    }
    ctx->alert = FLB_FALSE;
    ctx->proc_name = NULL;
    ctx->pid = -1;

    configure(ctx, in);

    if (ctx->proc_name == NULL) {
        flb_error("[%s] \"proc_name\" is NULL",FLB_IN_PROC_NAME);
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
        flb_utils_error_c("Could not set collector for Proc input plugin");
    }

    return 0;
}

static int in_proc_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_proc_config *ctx = data;

    /* Destroy context */
    flb_free(ctx->proc_name);
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_proc_plugin = {
    .name         = "proc",
    .description  = "Check Process health",
    .cb_init      = in_proc_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_proc_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_proc_exit,
    .flags        = 0,
};
