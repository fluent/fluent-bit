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
#include <stdlib.h>
#include <unistd.h>
#include <math.h>

#include <msgpack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_stats.h>

#include "in_cpu.h"

struct flb_input_plugin in_cpu_plugin;

/* Retrieve CPU load from the system (through ProcFS) */
static inline double proc_cpu_load(int cpus, struct cpu_stats *cstats)
{
    int i;
    int ret;
    int fd;
    int cpu_id=-1;
    double total;
    double user, nice, system, idle, iowait, irq, softirq;
    ssize_t read;
    char *line = NULL;
    size_t len = 0;
    char *fmt;
    FILE *f;
    struct cpu_snapshot *s;

    f = fopen("/proc/stat", "r");
    if (f == NULL) {
        return -1;
    }

    /* Always read (n_cpus + 1) lines */
    for (i = 0; i <= cpus; i++) {
        read = getline(&line, &len, f);
        if (read == -1) {
            break;
        }

        s = &cstats->info[i];
        if (i == 0) {
            fmt = " cpu  %lf %lf %lf %lf %lf %lf %lf";
            ret = sscanf(line,
                         fmt,
                         &s->val_user,
                         &s->val_nice,
                         &s->val_system,
                         &s->val_idle,
                         &s->val_iowait,
                         &s->val_irq,
                         &s->val_softirq);
        }
        else {
            fmt = " %s %lf %lf %lf %lf %lf %lf %lf";
            ret = sscanf(line,
                         fmt,
                         &s->val_cpuid,
                         &s->val_user,
                         &s->val_nice,
                         &s->val_system,
                         &s->val_idle,
                         &s->val_iowait,
                         &s->val_irq,
                         &s->val_softirq);
        }

        if (ret < 7) {
            fclose(f);
            return -1;
        }
    }

    if (line) {
        free(line);
    }

    fclose(f);
    s = &cstats->info[0];
    total = (s->val_user + s->val_nice + s->val_system);

    return total;
}

/* Init CPU input */
int in_cpu_init(struct flb_config *config)
{
    int i;
    int ret;
    int len;
    double total;
    struct flb_in_cpu_config *ctx;
    struct cpu_stats *cstats;
    struct cpu_snapshot *snap;

    /* Allocate space for the configuration */
    ctx = malloc(sizeof(struct flb_in_cpu_config));
    if (!ctx) {
        perror("malloc");
        return -1;
    }

    /* Gather number of processors and CPU ticks */
    ctx->n_processors = sysconf(_SC_NPROCESSORS_ONLN);
    ctx->cpu_ticks    = sysconf(_SC_CLK_TCK);

    /* Initialize buffers for CPU stats */
    cstats = &ctx->cstats;
    cstats->info = malloc(sizeof(struct cpu_snapshot) * (ctx->n_processors + 1));
    if (!cstats->info) {
        perror("malloc");
        return -1;
    }

    for (i = 1; i <= ctx->n_processors; i++) {
        snap = &cstats->info[i];

        CPU_KEY_FORMAT(snap, user, i);
        CPU_KEY_FORMAT(snap, nice, i);
        CPU_KEY_FORMAT(snap, system, i);
        CPU_KEY_FORMAT(snap, idle, i);
        CPU_KEY_FORMAT(snap, iowait, i);
        CPU_KEY_FORMAT(snap, irq, i);
        CPU_KEY_FORMAT(snap, softirq, i);
    }


    /* initialize MessagePack buffers */
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    /* Get CPU load, ready to be updated once fired the calc callback */
    total = proc_cpu_load(ctx->n_processors, &ctx->cstats);
    if (total == -1) {
        flb_utils_error_c("Could not obtain CPU data");
    }
    ctx->cstats.load_pre = total;

    /* Set the context */
    ret = flb_input_set_context("cpu", ctx, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for CPU input plugin");
    }

    /* Set our collector based on time, CPU usage every 1 second */
    ret = flb_input_set_collector_time("cpu",
                                       in_cpu_collect,
                                       IN_CPU_COLLECT_SEC,
                                       IN_CPU_COLLECT_NSEC,
                                       config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for CPU input plugin");
    }

    return 0;
}

static inline int key_field(char *buf,
                            char *cpu, int c_len,
                            char *field, int f_len)
{
    int len = 0;

    strncpy(buf, cpu, c_len);
    len = c_len;

    buf[len] = '.';
    len++;

    strncpy(buf + len, field, f_len);
    len += f_len;

    buf[len] = '\0';
    return len;
}


/* Callback to gather CPU usage between now and previous snapshot */
int in_cpu_collect(struct flb_config *config, void *in_context)
{
    int i;
    int maps;
    int len;
    double usage;
    double total;
    (void) config;
    struct flb_in_cpu_config *ctx = in_context;
    struct cpu_stats *cstats = &ctx->cstats;
    struct cpu_snapshot *s;

    /* Get the current CPU usage */
    total = proc_cpu_load(ctx->n_processors, cstats);
    cstats->load_now = total;

    /* Calculate the difference between the two samples */
    usage = fabs(cstats->load_now - cstats->load_pre) / ctx->cpu_ticks;
    total = (usage * 100) / ctx->n_processors;

    /* Put current load back */
    cstats->load_pre = cstats->load_now;

    /*
     * Store the new data into the MessagePack buffer,
     */
    msgpack_pack_array(&ctx->mp_pck, 2);
    msgpack_pack_uint64(&ctx->mp_pck, time(NULL));

    msgpack_pack_map(&ctx->mp_pck, (ctx->n_processors * 7 ) + 1);
    msgpack_pack_bin(&ctx->mp_pck, 3);
    msgpack_pack_bin_body(&ctx->mp_pck, "cpu", 3);
    msgpack_pack_double(&ctx->mp_pck, total);

    for (i = 1; i < ctx->n_processors + 1; i++) {
        s = &cstats->info[i];

        CPU_PACK_SNAP(s, user);
        CPU_PACK_SNAP(s, nice);
        CPU_PACK_SNAP(s, system);
        CPU_PACK_SNAP(s, idle);
        CPU_PACK_SNAP(s, iowait);
        CPU_PACK_SNAP(s, irq);
        CPU_PACK_SNAP(s, softirq);
    }

    flb_debug("[in_cpu] CPU %0.2f%%", total);

    flb_stats_update(in_cpu_plugin.stats_fd, 0, 1);
    return 0;
}

void *in_cpu_flush(void *in_context, int *size)
{
    char *buf;
    msgpack_sbuffer *sbuf;
    struct flb_in_cpu_config *ctx = in_context;

    sbuf = &ctx->mp_sbuf;
    *size = sbuf->size;
    buf = malloc(sbuf->size);
    if (!buf) {
        return NULL;
    }

    /* set a new buffer and re-initialize our MessagePack context */
    memcpy(buf, sbuf->data, sbuf->size);
    msgpack_sbuffer_destroy(&ctx->mp_sbuf);
    msgpack_sbuffer_init(&ctx->mp_sbuf);
    msgpack_packer_init(&ctx->mp_pck, &ctx->mp_sbuf, msgpack_sbuffer_write);

    ctx->data_idx = 0;

    return buf;
}

/* Plugin reference */
struct flb_input_plugin in_cpu_plugin = {
    .name         = "cpu",
    .description  = "CPU Usage",
    .cb_init      = in_cpu_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_cpu_collect,
    .cb_flush_buf = in_cpu_flush
};
