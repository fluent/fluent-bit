/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

#include <msgpack.h>

#include "in_cpu.h"

struct flb_input_plugin in_cpu_plugin;

static inline void snapshot_key_format(int cpus, struct cpu_snapshot *snap_arr)
{
    int i;
    struct cpu_snapshot *snap;

    snap = &snap_arr[0];
    memcpy(snap->k_cpu.name, "cpu", 3);
    snap->k_cpu.name[3] = '\0';

    for (i = 1; i <= cpus; i++) {
        snap = (struct cpu_snapshot *) &snap_arr[i];
        CPU_KEY_FORMAT(snap, cpu, i);
        CPU_KEY_FORMAT(snap, user, i);
        CPU_KEY_FORMAT(snap, system, i);
    }
}

static int snapshots_init(int cpus, struct cpu_stats *cstats)
{
    cstats->snap_a = flb_calloc(1, sizeof(struct cpu_snapshot) * (cpus + 1));
    if (!cstats->snap_a) {
        perror("malloc");
        return -1;
    }

    cstats->snap_b = flb_malloc(sizeof(struct cpu_snapshot) * (cpus + 1));
    if (!cstats->snap_b) {
        perror("malloc");
        return -1;
    }

    /* Initialize each array */
    snapshot_key_format(cpus, cstats->snap_a);
    snapshot_key_format(cpus, cstats->snap_b);
    cstats->snap_active = CPU_SNAP_ACTIVE_A;
    return 0;
}

static inline void snapshots_switch(struct cpu_stats *cstats)
{
    if (cstats->snap_active == CPU_SNAP_ACTIVE_A) {
        cstats->snap_active = CPU_SNAP_ACTIVE_B;
    }
    else {
        cstats->snap_active = CPU_SNAP_ACTIVE_A;
    }
}

/* Retrieve CPU load from the system (through ProcFS) */
static inline double proc_cpu_load(int cpus, struct cpu_stats *cstats)
{
    int i;
    int ret;
    char line[255];
    size_t len = 0;
    char *fmt;
    FILE *f;
    struct cpu_snapshot *s;
    struct cpu_snapshot *snap_arr;

    f = fopen("/proc/stat", "r");
    if (f == NULL) {
        return -1;
    }

    if (cstats->snap_active == CPU_SNAP_ACTIVE_A) {
        snap_arr = cstats->snap_a;
    }
    else {
        snap_arr = cstats->snap_b;
    }

    /* Always read (n_cpus + 1) lines */
    for (i = 0; i <= cpus; i++) {
        if (fgets(line, sizeof(line) - 1, f)) {
            len = strlen(line);
            if (line[len - 1] == '\n') {
                line[--len] = 0;
                if (len && line[len - 1] == '\r') {
                    line[--len] = 0;
                }
            }

            s = &snap_arr[i];
            if (i == 0) {
                fmt = " cpu  %lu %lu %lu %lu %lu";
                ret = sscanf(line,
                             fmt,
                             &s->v_user,
                             &s->v_nice,
                             &s->v_system,
                             &s->v_idle,
                             &s->v_iowait);
                if (ret < 5) {
                    fclose(f);
                    return -1;
                }
            }
            else {
                fmt = " %s %lu %lu %lu %lu %lu";
                ret = sscanf(line,
                             fmt,
                             &s->v_cpuid,
                             &s->v_user,
                             &s->v_nice,
                             &s->v_system,
                             &s->v_idle,
                             &s->v_iowait);
                if (ret <= 5) {
                    fclose(f);
                    return -1;
                }
            }
        }
        else {
            break;
        }
    }

    fclose(f);
    return 0;
}

/* Init CPU input */
static int in_cpu_init(struct flb_input_instance *in,
                       struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_cpu_config *ctx;
    (void) data;
    char *pval = NULL;

    /* Allocate space for the configuration */
    ctx = flb_calloc(1, sizeof(struct flb_in_cpu_config));
    if (!ctx) {
        perror("calloc");
        return -1;
    }
    ctx->i_ins = in;

    /* Gather number of processors and CPU ticks */
    ctx->n_processors = sysconf(_SC_NPROCESSORS_ONLN);
    ctx->cpu_ticks    = sysconf(_SC_CLK_TCK);

    /* Collection time setting */
    pval = flb_input_get_property("interval_sec", in);
    if (pval != NULL && atoi(pval) > 0) {
        ctx->interval_sec = atoi(pval);
    }
    else {
        ctx->interval_sec = DEFAULT_INTERVAL_SEC;
    }
    ctx->interval_nsec = DEFAULT_INTERVAL_NSEC;

    /* Initialize buffers for CPU stats */
    ret = snapshots_init(ctx->n_processors, &ctx->cstats);
    if (ret != 0) {
        flb_free(ctx);
        return -1;
    }

    /* Get CPU load, ready to be updated once fired the calc callback */
    ret = proc_cpu_load(ctx->n_processors, &ctx->cstats);
    if (ret != 0) {
        flb_error("[cpu] Could not obtain CPU data");
        flb_free(ctx);
        return -1;
    }
    ctx->cstats.snap_active = CPU_SNAP_ACTIVE_B;

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set our collector based on time, CPU usage every 1 second */
    ret = flb_input_set_collector_time(in,
                                       in_cpu_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_error("[in_cpu] Could not set collector for CPU input plugin");
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

/*
 * Given the two snapshots, calculate the % used in user and kernel space,
 * it returns the active snapshot.
 */
struct cpu_snapshot *snapshot_percent(struct cpu_stats *cstats,
                                      struct flb_in_cpu_config *ctx)
{
    int i;
    unsigned long sum_pre;
    unsigned long sum_now;
    struct cpu_snapshot *arr_pre = cstats->snap_b;
    struct cpu_snapshot *arr_now = cstats->snap_a;
    struct cpu_snapshot *snap_pre = NULL;
    struct cpu_snapshot *snap_now = NULL;

    if (cstats->snap_active == CPU_SNAP_ACTIVE_A) {
        arr_now = cstats->snap_a;
        arr_pre = cstats->snap_b;
    }
    else if (cstats->snap_active == CPU_SNAP_ACTIVE_B) {
        arr_now = cstats->snap_b;
        arr_pre = cstats->snap_a;
    }

    for (i = 0; i <= ctx->n_processors; i++) {
        snap_pre = &arr_pre[i];
        snap_now = &arr_now[i];

        /* Calculate overall CPU usage (user space + kernel space */
        sum_pre = (snap_pre->v_user + snap_pre->v_nice + snap_pre->v_system);
        sum_now = (snap_now->v_user + snap_now->v_nice + snap_now->v_system);

        if (i == 0) {
            snap_now->p_cpu = CPU_METRIC_SYS_AVERAGE(sum_pre, sum_now, ctx);
        }
        else {
            snap_now->p_cpu = CPU_METRIC_USAGE(sum_pre, sum_now, ctx);
        }

        /* User space CPU% */
        sum_pre = (snap_pre->v_user + snap_pre->v_nice);
        sum_now = (snap_now->v_user + snap_now->v_nice);
        if (i == 0) {
            snap_now->p_user = CPU_METRIC_SYS_AVERAGE(sum_pre, sum_now, ctx);
        }
        else {
            snap_now->p_user = CPU_METRIC_USAGE(sum_pre, sum_now, ctx);
        }

        /* Kernel space CPU% */
        if (i == 0) {
            snap_now->p_system = CPU_METRIC_SYS_AVERAGE(snap_pre->v_system,
                                                        snap_now->v_system,
                                                        ctx);
        }
        else {
            snap_now->p_system = CPU_METRIC_USAGE(snap_pre->v_system,
                                                  snap_now->v_system,
                                                  ctx);
        }

#ifdef FLB_TRACE
        if (i == 0) {
            flb_trace("cpu[all] all=%s%f%s user=%s%f%s system=%s%f%s",
                      ANSI_BOLD, snap_now->p_cpu, ANSI_RESET,
                      ANSI_BOLD, snap_now->p_user, ANSI_RESET,
                      ANSI_BOLD, snap_now->p_system, ANSI_RESET);
        }
        else {
            flb_trace("cpu[i=%i] all=%f user=%f system=%f",
                      i-1, snap_now->p_cpu,
                      snap_now->p_user, snap_now->p_system);
        }
#endif
    }

    return arr_now;
}


/* Callback to gather CPU usage between now and previous snapshot */
int in_cpu_collect(struct flb_input_instance *i_ins,
                   struct flb_config *config, void *in_context)
{
    int i;
    int ret;
    struct flb_in_cpu_config *ctx = in_context;
    struct cpu_stats *cstats = &ctx->cstats;
    struct cpu_snapshot *s;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    (void) config;

    /* Get the current CPU usage */
    ret = proc_cpu_load(ctx->n_processors, cstats);
    if (ret != 0) {
        return -1;
    }

    s = snapshot_percent(cstats, ctx);

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Store the new data into the MessagePack buffer,
     */
    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, (ctx->n_processors * 3 ) + 3);

    /* All CPU */
    msgpack_pack_str(&mp_pck, 5);
    msgpack_pack_str_body(&mp_pck, "cpu_p", 5);
    msgpack_pack_double(&mp_pck, s[0].p_cpu);

    /* User space CPU % */
    msgpack_pack_str(&mp_pck, 6);
    msgpack_pack_str_body(&mp_pck, "user_p", 6);
    msgpack_pack_double(&mp_pck, s[0].p_user);

    /* System CPU % */
    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "system_p", 8);
    msgpack_pack_double(&mp_pck, s[0].p_system);

    for (i = 1; i < ctx->n_processors + 1; i++) {
        struct cpu_snapshot *e = &s[i];

        CPU_PACK_SNAP(e, cpu);
        CPU_PACK_SNAP(e, user);
        CPU_PACK_SNAP(e, system);
    }

    snapshots_switch(cstats);
    flb_trace("[in_cpu] CPU %0.2f%%", s->p_cpu);

    flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

static void in_cpu_pause(void *data, struct flb_config *config)
{
    struct flb_in_cpu_config *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->i_ins);
}

static void in_cpu_resume(void *data, struct flb_config *config)
{
    struct flb_in_cpu_config *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->i_ins);
}

static int in_cpu_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_cpu_config *ctx = data;
    struct cpu_stats *cs;

    /* Release snapshots */
    cs = &ctx->cstats;
    flb_free(cs->snap_a);
    flb_free(cs->snap_b);

    /* done */
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_cpu_plugin = {
    .name         = "cpu",
    .description  = "CPU Usage",
    .cb_init      = in_cpu_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_cpu_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_cpu_pause,
    .cb_resume    = in_cpu_resume,
    .cb_exit      = in_cpu_exit
};
