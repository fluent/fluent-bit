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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log_event.h>
#include <fluent-bit/flb_kernel.h>
#include <fluent-bit/flb_pack.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "mem.h"
#include "proc.h"

struct flb_input_plugin in_mem_plugin;

static int in_mem_collect(struct flb_input_instance *i_ins,
                          struct flb_config *config, void *in_context);

static uint64_t get_proc_meminfo_memavailable()
{
    char *buffer;
    size_t len = 0;

    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) {
        return -1;
    }

    do {
        ssize_t n = getline(&buffer, &len, f);

        if (n == -1) {
            free(buffer);
            fclose(f);
            return -1;
        }

        if (strncmp(buffer, "MemAvailable:", strlen("MemAvailable:"))==0) {
            uint64_t ret = atoll(buffer + strlen("MemAvailable:"));  /* Kb */
            free(buffer);
            fclose(f);
            return ret;
        }
    }
    while (true);
}

static uint64_t calc_kb(unsigned long amount, unsigned int unit)
{
    unsigned long long bytes = amount;

    /*
     * Recent Linux versions return memory/swap sizes as multiples
     * of a certain size unit. See sysinfo(2) for details.
     */
    if (unit > 1) {
        bytes = bytes * unit;
    }

    bytes = bytes / 1024;

    return (uint64_t) bytes;
}

static int mem_calc(struct flb_in_mem_info *m_info)
{
    int ret;
    struct sysinfo info;
    uint64_t meminfo_memavailable;

    ret = sysinfo(&info);
    if (ret == -1) {
        flb_errno();
        return -1;
    }

    /* set values in KBs */
    m_info->mem_total     = calc_kb(info.totalram, info.mem_unit);
    m_info->mem_free      = calc_kb(info.freeram, info.mem_unit);
    m_info->mem_used      = m_info->mem_total - m_info->mem_free;

    m_info->swap_total    = calc_kb(info.totalswap, info.mem_unit);
    m_info->swap_free     = calc_kb(info.freeswap, info.mem_unit);
    m_info->swap_used     = m_info->swap_total - m_info->swap_free;

    /* use MemAvailable from /proc/meminfo if possible (linux 3.14+ specific). */
    meminfo_memavailable = get_proc_meminfo_memavailable();
    if (meminfo_memavailable != -1) {
        m_info->mem_free = meminfo_memavailable;
    }

    return 0;
}

static int in_mem_init(struct flb_input_instance *in,
                       struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_mem_config *ctx;
    (void) data;

    /* Initialize context */
    ctx = flb_malloc(sizeof(struct flb_in_mem_config));
    if (!ctx) {
        return -1;
    }
    ctx->idx = 0;
    ctx->pid = 0;
    ctx->page_size = sysconf(_SC_PAGESIZE);
    ctx->ins = in;
    
    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *)ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Collection time setting */
    if (ctx->interval_sec <= 0) {
        ctx->interval_sec = atoi(DEFAULT_INTERVAL_SEC);
    }
    if (ctx->interval_nsec <= 0) {
        ctx->interval_nsec = atoi(DEFAULT_INTERVAL_NSEC);
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set the collector */
    ret = flb_input_set_collector_time(in,
                                       in_mem_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set collector for memory input plugin");
        return -1;
    }

    ret = flb_log_event_encoder_init(&ctx->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "error initializing event encoder : %d", ret);

        return -1;
    }

    return 0;
}

static int in_mem_collect(struct flb_input_instance *i_ins,
                          struct flb_config *config, void *in_context)
{
    int ret;
    struct proc_task *task = NULL;
    struct flb_in_mem_config *ctx = in_context;
    struct flb_in_mem_info info;

    if (ctx->pid) {
        task = proc_stat(ctx->pid, ctx->page_size);
        if (!task) {
            flb_plg_warn(ctx->ins, "could not measure PID %i", ctx->pid);
            ctx->pid = 0;
        }
    }

    ret = mem_calc(&info);

    if (ret == -1) {
        if (task) {
            proc_free(task);
        }
        return -1;
    }

    ret = flb_log_event_encoder_begin_record(&ctx->log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(
                &ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(
                &ctx->log_encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("Mem.total"),
                FLB_LOG_EVENT_UINT64_VALUE(info.mem_total),

                FLB_LOG_EVENT_CSTRING_VALUE("Mem.used"),
                FLB_LOG_EVENT_UINT64_VALUE(info.mem_used),

                FLB_LOG_EVENT_CSTRING_VALUE("Mem.free"),
                FLB_LOG_EVENT_UINT64_VALUE(info.mem_free),

                FLB_LOG_EVENT_CSTRING_VALUE("Swap.total"),
                FLB_LOG_EVENT_UINT64_VALUE(info.swap_total),

                FLB_LOG_EVENT_CSTRING_VALUE("Swap.used"),
                FLB_LOG_EVENT_UINT64_VALUE(info.swap_used),

                FLB_LOG_EVENT_CSTRING_VALUE("Swap.free"),
                FLB_LOG_EVENT_UINT64_VALUE(info.swap_free));
    }

    if (task != NULL &&
        ret == FLB_EVENT_ENCODER_SUCCESS) {
        /* RSS bytes */

        ret = flb_log_event_encoder_append_body_values(
                &ctx->log_encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("proc_bytes"),
                FLB_LOG_EVENT_UINT64_VALUE(task->proc_rss),

                FLB_LOG_EVENT_CSTRING_VALUE("proc_hr"),
                FLB_LOG_EVENT_UINT64_VALUE(task->proc_rss_hr));

        proc_free(task);
    }

    flb_plg_trace(ctx->ins, "memory total=%lu kb, used=%lu kb, free=%lu kb",
                  info.mem_total, info.mem_used, info.mem_free);
    flb_plg_trace(ctx->ins, "swap total=%lu kb, used=%lu kb, free=%lu kb",
                  info.swap_total, info.swap_used, info.swap_free);
    ++ctx->idx;

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(&ctx->log_encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(i_ins, NULL, 0,
                             ctx->log_encoder.output_buffer,
                             ctx->log_encoder.output_length);

        ret = 0;
    }
    else {
        flb_plg_error(i_ins, "Error encoding record : %d", ret);

        ret = -1;
    }

    flb_log_event_encoder_reset(&ctx->log_encoder);

    return 0;
}

static int in_mem_exit(void *data, struct flb_config *config)
{
    (void) *config;
    struct flb_in_mem_config *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_log_event_encoder_destroy(&ctx->log_encoder);

    /* done */
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_INT, "interval_sec", DEFAULT_INTERVAL_SEC,
      0, FLB_TRUE, offsetof(struct flb_in_mem_config, interval_sec),
      "Set the collector interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", DEFAULT_INTERVAL_NSEC,
      0, FLB_TRUE, offsetof(struct flb_in_mem_config, interval_nsec),
      "Set the collector interval (subseconds)"
    },
    {
      FLB_CONFIG_MAP_INT, "pid", "0",
      0, FLB_TRUE, offsetof(struct flb_in_mem_config, pid),
      "Set the PID of the process to measure"
    },
    /* EOF */
    {0}
};

struct flb_input_plugin in_mem_plugin = {
    .name         = "mem",
    .description  = "Memory Usage",
    .cb_init      = in_mem_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_mem_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_mem_exit,
    .config_map   = config_map
};
