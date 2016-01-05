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

#ifndef FLB_IN_CPU_H
#define FLB_IN_CPU_H

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_utils.h>

/* Collection time: every 1 second (0 nanoseconds) */
#define IN_CPU_COLLECT_SEC    1
#define IN_CPU_COLLECT_NSEC   0
#define IN_CPU_KEY_LEN       16

struct cpu_key {
    size_t length;
    char name[IN_CPU_KEY_LEN];
};

struct cpu_snapshot {
    char   val_cpuid[8];
    double val_user;
    double val_nice;
    double val_system;
    double val_idle;
    double val_iowait;
    double val_irq;
    double val_softirq;

    /* necessary... */
    struct cpu_key key_user;
    struct cpu_key key_nice;
    struct cpu_key key_system;
    struct cpu_key key_idle;
    struct cpu_key key_iowait;
    struct cpu_key key_irq;
    struct cpu_key key_softirq;
};

#define CPU_KEY_FORMAT(s, key, i)                                   \
    s->key_##key.length = snprintf(s->key_##key.name,               \
                                   IN_CPU_KEY_LEN,                  \
                                   "cpu%i.%s", i - 1, #key);

#define CPU_PACK_SNAP(s, key)                                           \
    msgpack_pack_bin(&ctx->mp_pck, s->key_##key.length);                \
    msgpack_pack_bin_body(&ctx->mp_pck, s->key_##key.name, s->key_##key.length); \
    msgpack_pack_double(&ctx->mp_pck, s->val_##key)

struct cpu_stats {
    /* runtime data */
    double load_now;    /* CPU load now               */
    double load_pre;    /* CPU load previously        */

    /* CPU snapshots */
    struct cpu_snapshot *info;
};

/* CPU Input configuration & context */
struct flb_in_cpu_config {
    /* setup */
    int n_processors;   /* number of core processors  */
    int cpu_ticks;      /* CPU ticks (Kernel setting) */

    /* Buffered data */
    int data_idx;       /* next position available    */

    struct cpu_stats cstats;

    /* MessagePack buffers */
    msgpack_packer  mp_pck;
    msgpack_sbuffer mp_sbuf;
};

int in_cpu_init(struct flb_config *config);
int in_cpu_pre_run(void *in_context, struct flb_config *config);
int in_cpu_collect(struct flb_config *config, void *in_context);
void *in_cpu_flush(void *in_context, int *size);

extern struct flb_input_plugin in_cpu_plugin;

#endif
