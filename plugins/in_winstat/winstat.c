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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>

#include <psapi.h>

struct stat_cache {
    int64_t processes;
    int64_t threads;
    int64_t handles;
    int64_t commit_total;
    int64_t commit_limit;
    int64_t kernel_total;
    int64_t kernel_paged;
    int64_t kernel_nonpaged;
    int64_t physical_available;
    int64_t physical_total;
    int64_t physical_used;
    uint64_t idletime;
    uint64_t kerneltime;
    uint64_t usertime;
    uint64_t cpu_idle;
    uint64_t cpu_user;
    uint64_t cpu_kernel;
    float cpu_utilization;
    char uptime_human[32];
    uint64_t uptime_msec;
};

struct flb_winstat {
    int coll_fd;
    int interval_sec;
    int interval_nsec;
    struct flb_input_instance *ins;
    struct stat_cache cache;
};

#define filetime64(ft) \
    ((((uint64_t) (ft)->dwHighDateTime) << 32) + (ft)->dwLowDateTime)

#define KB(n, page) ((n) * (page) / 1024)

static int query_processor(struct stat_cache *cache)
{
    uint64_t prev_idletime = cache->idletime;
    uint64_t prev_usertime = cache->usertime;
    uint64_t prev_kerneltime = cache->kerneltime;
    FILETIME idletime;
    FILETIME kerneltime;
    FILETIME usertime;
    uint64_t total;

    if (!GetSystemTimes(&idletime, &kerneltime, &usertime)) {
        return -1;
    }
    cache->idletime = filetime64(&idletime);
    cache->kerneltime = filetime64(&kerneltime) - cache->idletime;
    cache->usertime = filetime64(&usertime);

    cache->cpu_idle = cache->idletime - prev_idletime;
    cache->cpu_user = cache->usertime - prev_usertime;
    cache->cpu_kernel = cache->kerneltime - prev_kerneltime;

    total = cache->cpu_user + cache->cpu_kernel + cache->cpu_idle;
    cache->cpu_utilization = 100 - 100.0 * cache->cpu_idle / total;

    return 0;
}

static int query_performance_info(struct stat_cache *cache)
{
    PERFORMANCE_INFORMATION perf;

    if (!GetPerformanceInfo(&perf, sizeof(perf))) {
        return -1;
    }

    cache->processes = perf.ProcessCount;
    cache->threads = perf.ThreadCount;
    cache->handles = perf.HandleCount;

    cache->physical_total = KB(perf.PhysicalTotal, perf.PageSize);
    cache->physical_available = KB(perf.PhysicalAvailable, perf.PageSize);
    cache->physical_used  = cache->physical_total - cache->physical_available;

    cache->commit_total = KB(perf.CommitTotal, perf.PageSize);
    cache->commit_limit = KB(perf.CommitLimit, perf.PageSize);

    cache->kernel_total = KB(perf.KernelTotal, perf.PageSize);
    cache->kernel_paged = KB(perf.KernelPaged, perf.PageSize);
    cache->kernel_nonpaged = KB(perf.KernelNonpaged, perf.PageSize);
    return 0;
}

static int query_uptime(struct stat_cache *cache)
{
    int ret;

    cache->uptime_msec = GetTickCount64();

    /* Emulate Windows Task Manager (DD:HH:MM:SS) */
    ret = sprintf_s(cache->uptime_human, 32, "%d:%02d:%02d:%02d",
                    (int) (cache->uptime_msec / 1000 / 60 / 60 / 24),
                    (int) ((cache->uptime_msec / 1000 / 60 / 60) % 24),
                    (int) ((cache->uptime_msec / 1000 / 60) % 60),
                    (int) ((cache->uptime_msec / 1000) % 60));
    if (ret == -1) {
        return -1;
    }
    return 0;
}

/*
 * Input Plugin API
 */
static int in_winstat_collect(struct flb_input_instance *in,
                              struct flb_config *config, void *data)
{
    struct flb_winstat *ctx = data;
    struct stat_cache *cache = &ctx->cache;
    int uptime_len;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* Query Windows metrics */
    if (query_performance_info(cache)) {
        flb_plg_error(ctx->ins, "cannot query Performance info");
        return -1;
    }

    if (query_processor(cache)) {
        flb_plg_error(ctx->ins, "cannot query Processor info");
        return -1;
    }

    if (query_uptime(cache)) {
        flb_plg_error(ctx->ins, "cannot query uptime");
        return -1;
    }

    /* Pack the data */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_pack_time_now(&mp_pck);
    msgpack_pack_map(&mp_pck, 17);

    /* Processes/Threads/Handles */
    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "processes", 9);
    msgpack_pack_int64(&mp_pck, cache->processes);

    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "threads", 7);
    msgpack_pack_int64(&mp_pck, cache->threads);

    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "handles", 7);
    msgpack_pack_int64(&mp_pck, cache->handles);

    /* System performance info */
    msgpack_pack_str(&mp_pck, 14);
    msgpack_pack_str_body(&mp_pck, "physical_total", 14);
    msgpack_pack_int64(&mp_pck, cache->physical_total);

    msgpack_pack_str(&mp_pck, 13);
    msgpack_pack_str_body(&mp_pck, "physical_used", 13);
    msgpack_pack_int64(&mp_pck, cache->physical_used);

    msgpack_pack_str(&mp_pck, 18);
    msgpack_pack_str_body(&mp_pck, "physical_available", 18);
    msgpack_pack_int64(&mp_pck, cache->physical_available);

    msgpack_pack_str(&mp_pck, 12);
    msgpack_pack_str_body(&mp_pck, "commit_total", 12);
    msgpack_pack_int64(&mp_pck, cache->commit_total);

    msgpack_pack_str(&mp_pck, 12);
    msgpack_pack_str_body(&mp_pck, "commit_limit", 12);
    msgpack_pack_int64(&mp_pck, cache->commit_limit);

    msgpack_pack_str(&mp_pck, 12);
    msgpack_pack_str_body(&mp_pck, "kernel_total", 12);
    msgpack_pack_int64(&mp_pck, cache->kernel_total);

    msgpack_pack_str(&mp_pck, 12);
    msgpack_pack_str_body(&mp_pck, "kernel_paged", 12);
    msgpack_pack_int64(&mp_pck, cache->kernel_paged);

    msgpack_pack_str(&mp_pck, 15);
    msgpack_pack_str_body(&mp_pck, "kernel_nonpaged", 15);
    msgpack_pack_int64(&mp_pck, cache->kernel_nonpaged);

    /* Processors */
    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "cpu_user", 8);
    msgpack_pack_uint64(&mp_pck, cache->cpu_user);

    msgpack_pack_str(&mp_pck, 8);
    msgpack_pack_str_body(&mp_pck, "cpu_idle", 8);
    msgpack_pack_uint64(&mp_pck, cache->cpu_idle);

    msgpack_pack_str(&mp_pck, 10);
    msgpack_pack_str_body(&mp_pck, "cpu_kernel", 10);
    msgpack_pack_uint64(&mp_pck, cache->cpu_kernel);

    msgpack_pack_str(&mp_pck, 15);
    msgpack_pack_str_body(&mp_pck, "cpu_utilization", 15);
    msgpack_pack_float(&mp_pck, cache->cpu_utilization);

    /* Uptime */
    msgpack_pack_str(&mp_pck, 11);
    msgpack_pack_str_body(&mp_pck, "uptime_msec", 11);
    msgpack_pack_uint64(&mp_pck, cache->uptime_msec);

    uptime_len = strlen(cache->uptime_human);
    msgpack_pack_str(&mp_pck, 12);
    msgpack_pack_str_body(&mp_pck, "uptime_human", 12);
    msgpack_pack_str(&mp_pck, uptime_len);
    msgpack_pack_str_body(&mp_pck, cache->uptime_human, uptime_len);

    flb_input_log_append(in, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

static int in_winstat_init(struct flb_input_instance *in,
                           struct flb_config *config, void *data)
{
    int ret;
    struct flb_winstat *ctx;

    /* Initialize context */
    ctx = flb_calloc(1, sizeof(struct flb_winstat));
    if (!ctx) {
        return -1;
    }
    ctx->ins = in;

    /* Load the config map */
    ret = flb_input_config_map_set(in, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Preload CPU usage */
    if (query_processor(&ctx->cache)) {
        flb_plg_warn(ctx->ins, "cannot preload CPU times.");
    }

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Set the collector */
    ret = flb_input_set_collector_time(in,
                                       in_winstat_collect,
                                       ctx->interval_sec,
                                       ctx->interval_nsec,
                                       config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not set up a collector");
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

static int in_winstat_exit(void *data, struct flb_config *config)
{
    struct flb_winstat *ctx = data;
    flb_free(ctx);
    return 0;
}

static void in_winstat_pause(void *data, struct flb_config *config)
{
    struct flb_winstat *ctx = data;
    flb_input_collector_pause(ctx->coll_fd, ctx->ins);
}

static void in_winstat_resume(void *data, struct flb_config *config)
{
    struct flb_winstat *ctx = data;
    flb_input_collector_resume(ctx->coll_fd, ctx->ins);
}

static struct flb_config_map config_map[] = {
    {
      FLB_CONFIG_MAP_TIME, "interval_sec", "1s",
      0, FLB_TRUE, offsetof(struct flb_winstat, interval_sec),
      "Set the emitter interval"
    },
    {
      FLB_CONFIG_MAP_INT, "interval_nsec", "0",
      0, FLB_TRUE, offsetof(struct flb_winstat, interval_nsec),
      "Set the emitter interval (sub seconds)"
    },
    {0}
};

struct flb_input_plugin in_winstat_plugin = {
    .name         = "winstat",
    .description  = "Windows System Statistics",
    .cb_init      = in_winstat_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_winstat_collect,
    .cb_flush_buf = NULL,
    .cb_pause     = in_winstat_pause,
    .cb_resume    = in_winstat_resume,
    .cb_exit      = in_winstat_exit,
    .config_map   = config_map
};
