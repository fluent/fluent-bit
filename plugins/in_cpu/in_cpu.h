/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#ifndef FLB_IN_CPU_H
#define FLB_IN_CPU_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>

/* Default collection time: every 1 second (0 nanoseconds) */
#define DEFAULT_INTERVAL_SEC    1
#define DEFAULT_INTERVAL_NSEC   0
#define IN_CPU_KEY_LEN       16

struct cpu_key {
    uint8_t length;
    char name[IN_CPU_KEY_LEN];
};

struct cpu_snapshot {
    /* data snapshots */
    char          v_cpuid[8];
    unsigned long v_user;
    unsigned long v_nice;
    unsigned long v_system;
    unsigned long v_idle;
    unsigned long v_iowait;

    /* percent values */
    double p_cpu;           /* Overall CPU usage        */
    double p_user;          /* user space (user + nice) */
    double p_system;        /* kernel space percent     */

    /* necessary... */
    struct cpu_key k_cpu;
    struct cpu_key k_user;
    struct cpu_key k_system;
};

#define CPU_SNAP_ACTIVE_A    0
#define CPU_SNAP_ACTIVE_B    1

struct cpu_stats {
    uint8_t snap_active;

    /* CPU snapshots, we always keep two snapshots */
    struct cpu_snapshot *snap_a;
    struct cpu_snapshot *snap_b;
};

/* CPU Input configuration & context */
struct flb_in_cpu_config {
    /* setup */
    int n_processors;   /* number of core processors  */
    int cpu_ticks;      /* CPU ticks (Kernel setting) */
    int coll_fd;        /* collector id/fd            */
    int interval_sec;    /* interval collection time (Second) */
    int interval_nsec;   /* interval collection time (Nanosecond) */
    struct cpu_stats cstats;
    struct flb_input_instance *i_ins;
};


#define CPU_KEY_FORMAT(s, key, i)                                   \
    s->k_##key.length = snprintf(s->k_##key.name,                   \
                                 IN_CPU_KEY_LEN,                    \
                                 "cpu%i.p_%s", i - 1, #key)

#define CPU_PACK_SNAP(s, key)                                           \
    msgpack_pack_str(&mp_pck, s->k_##key.length);                       \
    msgpack_pack_str_body(&mp_pck, s->k_##key.name, s->k_##key.length); \
    msgpack_pack_double(&mp_pck, s->p_##key)

#define ULL_ABS(a, b)  (a > b) ? a - b : b - a

/*
 * This routine calculate the average CPU utilization of the system, it
 * takes in consideration the number CPU cores, so it return a value
 * between 0 and 100 based on 'capacity'.
 */
static inline double CPU_METRIC_SYS_AVERAGE(unsigned long pre, unsigned long now,
                                            struct flb_in_cpu_config *ctx)
{
    double diff;
    double total = 0;

    if (pre == now) {
        return 0.0;
    }

    diff = ULL_ABS(now, pre);
    total = (((diff / ctx->cpu_ticks) * 100) / ctx->n_processors) / ctx->interval_sec;

    return total;
}

/* Returns the CPU % utilization of a given CPU core */
static inline double CPU_METRIC_USAGE(unsigned long pre, unsigned long now,
                                      struct flb_in_cpu_config *ctx)
{
    double diff;
    double total = 0;

    if (pre == now) {
        return 0.0;
    }

    diff = ULL_ABS(now, pre);
    total = ((diff * 100) / ctx->cpu_ticks) / ctx->interval_sec;
    return total;
}

int in_cpu_pre_run(void *in_context, struct flb_config *config);
int in_cpu_collect(struct flb_input_instance *i_ins,
                   struct flb_config *config, void *in_context);
void *in_cpu_flush(void *in_context, size_t *size);

extern struct flb_input_plugin in_cpu_plugin;

#endif
