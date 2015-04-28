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

#include <msgpack.h>
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
    struct flb_in_cpu_config *ctx;

    /* Allocate space for the configuration */
    ctx = malloc(sizeof(struct flb_in_cpu_config));
    if (!ctx) {
        return -1;
    }

    /* Gather number of processors and CPU ticks */
    ctx->n_processors = sysconf(_SC_NPROCESSORS_ONLN);
    ctx->cpu_ticks    = sysconf(_SC_CLK_TCK);

    /* We need to prepare our buffer */
    ctx->data_idx   = 0;
    ctx->data_size  = config->flush;
    ctx->data_array = malloc(sizeof(struct in_cpu_data) * ctx->data_size);
    if (!ctx->data_array) {
        flb_utils_error_c("Could not create data array for CPU input plugin");
    }

    /* Get CPU load, ready to be updated once fired the calc callback */
    ctx->load_pre = proc_cpu_load();

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

/* Callback invoked after setup but before to join the main loop */
int in_cpu_pre_run(void *in_context, struct flb_config *config)
{
    struct flb_in_cpu_config *ctx = in_context;

    /* Tag */
    ctx->tag_len = snprintf(ctx->tag, sizeof(ctx->tag) - 1,
                            "%s.cpu", config->tag);
    if (ctx->tag_len == -1) {
        flb_utils_error_c("Could not set custom tag on CPU input plugin");
    }

    return 0;
}

/* Callback to gather CPU usage between now and previous snapshot */
int in_cpu_collect(struct flb_config *config, void *in_context)
{
    double usage;
    double total;
    (void) config;
    struct flb_in_cpu_config *ctx = in_context;
    struct in_cpu_data *buf;

    /* Get the current CPU usage */
    ctx->load_now = proc_cpu_load();

    /* Calculate the difference between the two samples */
    usage = fabs(ctx->load_now - ctx->load_pre) / ctx->cpu_ticks;
    total = (usage * 100) / ctx->n_processors;

    /* Put current load back */
    ctx->load_pre = ctx->load_now;

    /* Register the value into the buffer */
    if (ctx->data_idx == ctx->data_size) {
        ctx->data_idx = 0;
    }
    buf = &ctx->data_array[ctx->data_idx];
    buf->time      = time(NULL);
    buf->cpu_usage = total;

    ctx->data_idx++;
    flb_debug("[in_cpu] CPU %0.2f%% (buffer=%i)", total, ctx->data_idx - 1);

    return 0;
}

void *in_cpu_flush(void *in_context, int *size)
{
    int i;
    char *buf;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;
    struct flb_in_cpu_config *ctx = in_context;
    struct in_cpu_data *data;

    /* initialize buffers */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&pck, 2);

    /* Tag */
    msgpack_pack_raw(&pck, ctx->tag_len);
    msgpack_pack_raw_body(&pck, ctx->tag, ctx->tag_len);

    /* Primary Array: ['TAG', [ */
    msgpack_pack_array(&pck, ctx->data_idx);

    /* Pack each data_array entry */
    for (i = 0; i < ctx->data_idx; i++) {
        data = &ctx->data_array[i];
        msgpack_pack_array(&pck, 2);
        msgpack_pack_uint64(&pck, data->time);

        msgpack_pack_map(&pck, 1);
        msgpack_pack_raw(&pck, 3);
        msgpack_pack_raw_body(&pck, "cpu", 3);
        msgpack_pack_double(&pck, data->cpu_usage);
    }

    *size = sbuf.size;
    buf = malloc(sbuf.size);
    memcpy(buf, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);

    ctx->data_idx = 0;

    return buf;
}

/* Plugin reference */
struct flb_input_plugin in_cpu_plugin = {
    .name         = "cpu",
    .description  = "CPU Usage",
    .cb_init      = in_cpu_init,
    .cb_pre_run   = in_cpu_pre_run,
    .cb_collect   = in_cpu_collect,
    .cb_flush_buf = in_cpu_flush
};
