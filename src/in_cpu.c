/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/in_cpu.h>

/* Retrieve CPU load from the system (through ProcFS) */
static inline double proc_cpu_load()
{
    int ret;
    double user, nice, system, idle, iowait, irq, softirq;
    FILE *f;

    f = fopen("/proc/stat", "r");
    if (f == NULL) {
        return -1;
    }

    ret = fscanf(f, " cpu %lf %lf %lf %lf %lf %lf %lf",
                 &user, &nice, &system, &idle, &iowait, &irq, &softirq);
    if (ret != 7) {
        return -1;
    }
    fclose(f);

    return (user + nice + system);
}

/* Init CPU input */
int in_cpu_init(struct flb_config *config)
{
    int ret;
    struct flb_in_cpu_config *cpu_config;

    /* Allocate space for the configuration */
    cpu_config = malloc(sizeof(struct flb_in_cpu_config));
    if (!cpu_config) {
        return -1;
    }

    /* Gather number of processors and CPU ticks */
    cpu_config->n_processors = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_config->cpu_ticks    = sysconf(_SC_CLK_TCK);

    /* Get CPU load, ready to be updated once fired the calc callback */
    cpu_config->load_pre = proc_cpu_load();

    /* Set the context */
    ret = flb_input_set_context("cpu", cpu_config, config);
    if (ret == -1) {
        flb_utils_error_c("Could not set configuration for CPU input plugin");
    }

    /* Set our collector, CPU usage every 1 second */
    ret = flb_input_set_collector("cpu",
                                  in_cpu_collect,
                                  IN_CPU_COLLECT_SEC,
                                  IN_CPU_COLLECT_NSEC,
                                  config);
    if (ret == -1) {
        flb_utils_error_c("Could not set collector for CPU input plugin");
    }

        return 0;
}

/* Callback to gather CPU usage between now and previous snapshot */
int in_cpu_collect(void *in_context)
{
    double usage;
    double total;
    struct flb_in_cpu_config *in_ctx = in_context;

    /* Get the current CPU usage */
    in_ctx->load_now = proc_cpu_load();

    /* Calculate the difference between the two samples */
    usage = fabs(in_ctx->load_now - in_ctx->load_pre) / in_ctx->cpu_ticks;
    total = (usage * 100) / in_ctx->n_processors;

    /* Put current load back */
    in_ctx->load_pre = in_ctx->load_now;

    flb_debug("in_cpu: CPU %0.2f%%", total);
}
