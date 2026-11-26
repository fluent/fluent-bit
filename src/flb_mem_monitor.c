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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_scheduler.h>
#include <fluent-bit/flb_mem_monitor.h>

#ifdef FLB_HAVE_METRICS
#include <fluent-bit/flb_metrics.h>
#endif

#include <cfl/cfl_time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#endif

#if !defined(FLB_HAVE_JEMALLOC) && defined(__GLIBC__)
#include <malloc.h>
#endif

#define MEM_MONITOR_PATH_MAX        4096

/* a control group value this large means that no limit has been set */
#define MEM_MONITOR_CGROUP_NO_LIMIT 0x7000000000000000ULL

const char *flb_mem_monitor_state_name(int state)
{
    switch (state) {
    case FLB_MEM_MONITOR_NORMAL:
        return "normal";
    case FLB_MEM_MONITOR_RECLAIM:
        return "reclaim";
    case FLB_MEM_MONITOR_THROTTLE:
        return "throttle";
    case FLB_MEM_MONITOR_REFUSE:
        return "refuse";
    }

    return "unknown";
}

int flb_mem_monitor_parse_size(const char *value, uint64_t total, uint64_t *out)
{
    char *end;
    size_t len;
    double percent;
    int64_t bytes;

    if (value == NULL || out == NULL) {
        return -1;
    }

    len = strlen(value);
    while (len > 0 && isspace((unsigned char) value[len - 1])) {
        len--;
    }

    if (len == 0) {
        return -1;
    }

    if (value[len - 1] == '%') {
        errno = 0;
        percent = strtod(value, &end);
        if (errno != 0 || end == value) {
            return -1;
        }

        while (isspace((unsigned char) *end)) {
            end++;
        }

        if (end != value + len - 1) {
            return -1;
        }

        if (!(percent > 0.0) || percent > 100.0 || total == 0) {
            return -1;
        }

        *out = (uint64_t) ((double) total * (percent / 100.0));
        if (*out == 0) {
            return -1;
        }

        return 0;
    }

    bytes = flb_utils_size_to_bytes(value);
    if (bytes <= 0) {
        return -1;
    }

    *out = (uint64_t) bytes;
    return 0;
}

#ifdef __linux__
static int read_uint64_file(const char *path, uint64_t *out)
{
    char *end;
    char buf[64];
    FILE *fp;
    unsigned long long value;

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    if (fgets(buf, sizeof(buf), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    errno = 0;
    value = strtoull(buf, &end, 10);
    if (errno != 0 || end == buf) {
        /* not a number, e.g: 'max' */
        return -1;
    }

    *out = (uint64_t) value;
    return 0;
}

/*
 * Walk a control group directory up to 'base' and keep the lowest limit
 * found in 'file_name': a parent group can be more restrictive than the
 * group the process lives in.
 */
static int cgroup_walk_limit(const char *base, const char *path,
                             const char *file_name, uint64_t *limit)
{
    int ret;
    int found = FLB_FALSE;
    char *sep;
    char dir[MEM_MONITOR_PATH_MAX];
    char file[MEM_MONITOR_PATH_MAX + 64];
    size_t base_len;
    uint64_t value;
    uint64_t lowest = 0;
    struct stat st;

    base_len = strlen(base);

    ret = snprintf(dir, sizeof(dir), "%s%s", base, path);
    if (ret < 0 || (size_t) ret >= sizeof(dir)) {
        return -1;
    }

    /*
     * The path reported for the process might not be visible from the
     * mounted hierarchy (e.g: containers without a cgroup namespace), in
     * that case the mount point itself represents the process group.
     */
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        snprintf(dir, sizeof(dir), "%s", base);
    }

    while (1) {
        snprintf(file, sizeof(file), "%s/%s", dir, file_name);

        ret = read_uint64_file(file, &value);
        if (ret == 0 && value > 0 && value < MEM_MONITOR_CGROUP_NO_LIMIT) {
            if (found == FLB_FALSE || value < lowest) {
                lowest = value;
            }
            found = FLB_TRUE;
        }

        if (strlen(dir) <= base_len) {
            break;
        }

        sep = strrchr(dir, '/');
        if (sep == NULL || (size_t) (sep - dir) < base_len) {
            break;
        }
        *sep = '\0';
    }

    if (found == FLB_FALSE) {
        return -1;
    }

    *limit = lowest;
    return 0;
}
#endif

int flb_mem_monitor_cgroup_limit(const char *proc_cgroup_path,
                                 const char *cgroup_root, uint64_t *limit)
{
#ifdef __linux__
    int ret;
    int found = FLB_FALSE;
    char *path;
    char *controllers;
    char line[MEM_MONITOR_PATH_MAX];
    char base[MEM_MONITOR_PATH_MAX];
    size_t len;
    uint64_t value;
    uint64_t lowest = 0;
    FILE *fp;

    if (proc_cgroup_path == NULL || cgroup_root == NULL || limit == NULL) {
        return -1;
    }

    fp = fopen(proc_cgroup_path, "r");
    if (fp == NULL) {
        return -1;
    }

    /* every line has the format 'hierarchy-id:controllers:path' */
    while (fgets(line, sizeof(line), fp) != NULL) {
        len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        controllers = strchr(line, ':');
        if (controllers == NULL) {
            continue;
        }
        controllers++;

        path = strchr(controllers, ':');
        if (path == NULL) {
            continue;
        }
        *path++ = '\0';

        if (path[0] != '/') {
            continue;
        }

        /* a single slash is the root of the hierarchy */
        if (path[1] == '\0') {
            path++;
        }

        if (controllers[0] == '\0') {
            /* cgroup v2: unified hierarchy */
            ret = snprintf(base, sizeof(base), "%s", cgroup_root);
            if (ret < 0 || (size_t) ret >= sizeof(base)) {
                continue;
            }
            ret = cgroup_walk_limit(base, path, "memory.max", &value);
        }
        else if (strstr(controllers, "memory") != NULL) {
            /* cgroup v1: memory controller hierarchy */
            ret = snprintf(base, sizeof(base), "%s/memory", cgroup_root);
            if (ret < 0 || (size_t) ret >= sizeof(base)) {
                continue;
            }
            ret = cgroup_walk_limit(base, path, "memory.limit_in_bytes", &value);
        }
        else {
            continue;
        }

        if (ret == 0) {
            if (found == FLB_FALSE || value < lowest) {
                lowest = value;
            }
            found = FLB_TRUE;
        }
    }
    fclose(fp);

    if (found == FLB_FALSE) {
        return -1;
    }

    *limit = lowest;
    return 0;
#else
    (void) proc_cgroup_path;
    (void) cgroup_root;
    (void) limit;

    return -1;
#endif
}

int flb_mem_monitor_system_limit(uint64_t *limit)
{
#ifdef __linux__
    int ret;
    uint64_t total;
    uint64_t cgroup_limit;
    struct sysinfo info;

    if (limit == NULL) {
        return -1;
    }

    if (sysinfo(&info) != 0) {
        return -1;
    }
    total = (uint64_t) info.totalram * (uint64_t) info.mem_unit;

    ret = flb_mem_monitor_cgroup_limit("/proc/self/cgroup", "/sys/fs/cgroup",
                                       &cgroup_limit);
    if (ret == 0 && cgroup_limit < total) {
        total = cgroup_limit;
    }

    if (total == 0) {
        return -1;
    }

    *limit = total;
    return 0;
#else
    (void) limit;

    return -1;
#endif
}

/*
 * Anonymous resident memory: resident pages minus the ones backed by files
 * or shared memory. File backed pages (e.g: filesystem chunks mapped in
 * memory) are left out on purpose, the kernel can reclaim them on demand.
 */
int flb_mem_monitor_process_usage(uint64_t *usage)
{
#ifdef __linux__
    int ret;
    long page_size;
    unsigned long size;
    unsigned long resident;
    unsigned long shared;
    FILE *fp;

    if (usage == NULL) {
        return -1;
    }

    fp = fopen("/proc/self/statm", "r");
    if (fp == NULL) {
        return -1;
    }

    ret = fscanf(fp, "%lu %lu %lu", &size, &resident, &shared);
    fclose(fp);

    if (ret != 3) {
        return -1;
    }

    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return -1;
    }

    if (shared > resident) {
        shared = resident;
    }

    *usage = (uint64_t) (resident - shared) * (uint64_t) page_size;
    return 0;
#else
    (void) usage;

    return -1;
#endif
}

static int cb_usage_default(struct flb_mem_monitor *mm, uint64_t *usage)
{
    (void) mm;

    return flb_mem_monitor_process_usage(usage);
}

/* Ask the allocator to give unused memory back to the operating system */
static int cb_reclaim_default(struct flb_mem_monitor *mm)
{
#if defined(FLB_HAVE_JEMALLOC)
    char name[64];

    (void) mm;

    snprintf(name, sizeof(name), "arena.%u.purge", (unsigned int) MALLCTL_ARENAS_ALL);
    if (mallctl(name, NULL, NULL, NULL, 0) != 0) {
        return -1;
    }

    return 0;
#elif defined(__GLIBC__)
    (void) mm;

    if (malloc_trim(0) != 1) {
        return -1;
    }

    return 0;
#else
    (void) mm;

    return -1;
#endif
}

int flb_mem_monitor_set_limits(struct flb_mem_monitor *mm,
                               uint64_t limit, uint64_t spike_reserve)
{
    uint64_t reserve_max;

    if (mm == NULL || limit == 0 || spike_reserve == 0) {
        return -1;
    }

    reserve_max = (uint64_t) ((double) limit *
                              (FLB_MEM_MONITOR_SPIKE_RESERVE_MAX / 100.0));
    if (spike_reserve > reserve_max) {
        return -1;
    }

    mm->limit = limit;
    mm->spike_reserve = spike_reserve;

    /*
     * All thresholds derive from the spike reserve, with the default
     * reserve (20% of the limit) they are placed at 70%, 80% and 95%.
     */
    mm->threshold_throttle = limit - spike_reserve;
    mm->threshold_reclaim = mm->threshold_throttle - (spike_reserve / 2);
    mm->threshold_refuse = limit - (spike_reserve / 4);
    mm->hysteresis = spike_reserve / 4;

    return 0;
}

static uint64_t state_threshold(struct flb_mem_monitor *mm, int state)
{
    switch (state) {
    case FLB_MEM_MONITOR_RECLAIM:
        return mm->threshold_reclaim;
    case FLB_MEM_MONITOR_THROTTLE:
        return mm->threshold_throttle;
    case FLB_MEM_MONITOR_REFUSE:
        return mm->threshold_refuse;
    }

    return 0;
}

int flb_mem_monitor_state_next(struct flb_mem_monitor *mm, int state,
                               uint64_t usage)
{
    int target;

    if (usage >= mm->threshold_refuse) {
        target = FLB_MEM_MONITOR_REFUSE;
    }
    else if (usage >= mm->threshold_throttle) {
        target = FLB_MEM_MONITOR_THROTTLE;
    }
    else if (usage >= mm->threshold_reclaim) {
        target = FLB_MEM_MONITOR_RECLAIM;
    }
    else {
        target = FLB_MEM_MONITOR_NORMAL;
    }

    /* escalate right away */
    if (target >= state) {
        return target;
    }

    /*
     * Step down one state at a time, and only once the usage is below the
     * entry threshold of that state by the hysteresis margin. This avoids
     * flapping when the usage sits right on a threshold.
     */
    while (state > target && usage + mm->hysteresis < state_threshold(mm, state)) {
        state--;
    }

    return state;
}

static int input_should_pause(struct flb_input_instance *ins, int state)
{
    /* internal inputs (e.g: emitters) only relay data of the other inputs */
    if (ins->p == NULL || (ins->p->flags & FLB_INPUT_PRIVATE) != 0) {
        return FLB_FALSE;
    }

    if (state >= FLB_MEM_MONITOR_REFUSE) {
        return FLB_TRUE;
    }

    /*
     * Network servers are the last ones to be paused: their senders might
     * not be able to hold the data, while the other inputs can simply read
     * it later from the source.
     */
    if (state >= FLB_MEM_MONITOR_THROTTLE &&
        (ins->p->flags & FLB_INPUT_NET_SERVER) == 0) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static void inputs_apply_state(struct flb_mem_monitor *mm)
{
    int paused = 0;
    struct mk_list *head;
    struct flb_input_instance *ins;
    struct flb_config *config = mm->config;

    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);

        if (input_should_pause(ins, mm->state) == FLB_TRUE) {
            if (ins->mem_monitor_status == FLB_INPUT_RUNNING) {
                flb_warn("[mem monitor] input %s paused (memory usage over limit)",
                         flb_input_name(ins));

                /* do not pause twice an input that is paused by other reason */
                if (flb_input_paused(ins) == FLB_FALSE) {
                    flb_input_pause(ins);
                }
                ins->mem_monitor_status = FLB_INPUT_PAUSED;
            }
            paused++;
        }
        else if (ins->mem_monitor_status == FLB_INPUT_PAUSED) {
            ins->mem_monitor_status = FLB_INPUT_RUNNING;

            /* resume only if there are no other reasons to remain paused */
            if (flb_input_paused(ins) == FLB_FALSE) {
                flb_input_resume(ins);
                flb_info("[mem monitor] input %s resumed", flb_input_name(ins));
            }
        }
    }

    mm->paused_inputs = paused;
}

static void reclaim_try(struct flb_mem_monitor *mm)
{
    int ret;
    uint64_t now;
    uint64_t before;
    uint64_t after;

    if (mm->cb_reclaim == NULL) {
        return;
    }

    now = cfl_time_now();
    if (mm->reclaim_last != 0 && now - mm->reclaim_last < mm->reclaim_interval) {
        return;
    }

    before = mm->usage;
    mm->reclaim_last = now;
    mm->reclaim_count++;

    ret = mm->cb_reclaim(mm);
    if (ret == 0 && mm->cb_usage(mm, &after) == 0) {
        mm->usage = after;

        /* an effective reclaim released at least 1% of the limit */
        if (before > after && before - after >= mm->limit / 100) {
            mm->reclaim_interval = FLB_MEM_MONITOR_RECLAIM_INTERVAL_MIN;
            return;
        }
    }

    /* nothing relevant was released: wait longer before trying again */
    mm->reclaim_interval *= 2;
    if (mm->reclaim_interval > FLB_MEM_MONITOR_RECLAIM_INTERVAL_MAX) {
        mm->reclaim_interval = FLB_MEM_MONITOR_RECLAIM_INTERVAL_MAX;
    }
}

int flb_mem_monitor_check(struct flb_mem_monitor *mm)
{
    int ret;
    int next;
    char usage_str[32];
    char limit_str[32];
    uint64_t usage;
    struct flb_config *config;

    if (mm == NULL || mm->enabled == FLB_FALSE) {
        return 0;
    }

    /* once the service is stopping the engine owns the inputs state */
    config = mm->config;
    if (config->is_running == FLB_FALSE || config->is_ingestion_active == FLB_FALSE ||
        config->is_shutting_down == FLB_TRUE) {
        return 0;
    }

    ret = mm->cb_usage(mm, &usage);
    if (ret != 0) {
        return -1;
    }
    mm->usage = usage;

    next = flb_mem_monitor_state_next(mm, mm->state, usage);
    if (next != mm->state) {
        flb_utils_bytes_to_human_readable_size((size_t) usage,
                                               usage_str, sizeof(usage_str));
        flb_utils_bytes_to_human_readable_size((size_t) mm->limit,
                                               limit_str, sizeof(limit_str));

        if (next > mm->state) {
            flb_warn("[mem monitor] state changed from '%s' to '%s' "
                     "(usage=%s, limit=%s)",
                     flb_mem_monitor_state_name(mm->state),
                     flb_mem_monitor_state_name(next), usage_str, limit_str);
        }
        else {
            flb_info("[mem monitor] state changed from '%s' to '%s' "
                     "(usage=%s, limit=%s)",
                     flb_mem_monitor_state_name(mm->state),
                     flb_mem_monitor_state_name(next), usage_str, limit_str);
        }
        mm->state = next;
    }

    if (mm->state >= FLB_MEM_MONITOR_RECLAIM) {
        reclaim_try(mm);
    }

    inputs_apply_state(mm);

    return 0;
}

static void cb_mem_monitor_check(struct flb_config *config, void *data)
{
    (void) config;

    flb_mem_monitor_check((struct flb_mem_monitor *) data);
}

#ifdef FLB_HAVE_METRICS
static int metrics_create(struct flb_mem_monitor *mm)
{
    mm->cmt = cmt_create();
    if (mm->cmt == NULL) {
        return -1;
    }

    mm->cmt_usage_bytes = cmt_gauge_create(mm->cmt,
                                           "fluentbit", "memory", "usage_bytes",
                                           "Anonymous resident memory used by "
                                           "the process in bytes.",
                                           0, (char *[]) { NULL });

    mm->cmt_limit_bytes = cmt_gauge_create(mm->cmt,
                                           "fluentbit", "memory", "limit_bytes",
                                           "Configured memory limit in bytes, "
                                           "zero if no limit is set.",
                                           0, (char *[]) { NULL });

    mm->cmt_pressure = cmt_gauge_create(mm->cmt,
                                        "fluentbit", "memory", "pressure",
                                        "Memory usage divided by the memory "
                                        "limit.",
                                        0, (char *[]) { NULL });

    mm->cmt_state = cmt_gauge_create(mm->cmt,
                                     "fluentbit", "memory", "state",
                                     "Memory monitor state: 0=normal, "
                                     "1=reclaim, 2=throttle, 3=refuse.",
                                     0, (char *[]) { NULL });

    mm->cmt_paused_inputs = cmt_gauge_create(mm->cmt,
                                             "fluentbit", "memory",
                                             "paused_inputs",
                                             "Number of inputs paused by the "
                                             "memory monitor.",
                                             0, (char *[]) { NULL });

    mm->cmt_reclaims_total = cmt_counter_create(mm->cmt,
                                                "fluentbit", "memory",
                                                "reclaims_total",
                                                "Number of times the allocator "
                                                "was asked to release memory.",
                                                0, (char *[]) { NULL });

    if (mm->cmt_usage_bytes == NULL || mm->cmt_limit_bytes == NULL ||
        mm->cmt_pressure == NULL || mm->cmt_state == NULL ||
        mm->cmt_paused_inputs == NULL || mm->cmt_reclaims_total == NULL) {
        cmt_destroy(mm->cmt);
        mm->cmt = NULL;
        return -1;
    }

    return 0;
}

int flb_mem_monitor_metrics_update(struct flb_mem_monitor *mm)
{
    double pressure = 0.0;
    uint64_t ts;
    uint64_t usage;

    if (mm == NULL || mm->cmt == NULL) {
        return -1;
    }

    /* without a limit there is no periodic check: sample on demand */
    if (mm->enabled == FLB_FALSE && mm->cb_usage(mm, &usage) == 0) {
        mm->usage = usage;
    }

    if (mm->enabled == FLB_TRUE && mm->limit > 0) {
        pressure = (double) mm->usage / (double) mm->limit;
    }

    ts = cfl_time_now();

    cmt_gauge_set(mm->cmt_usage_bytes, ts, (double) mm->usage,
                  0, (char *[]) { NULL });
    cmt_gauge_set(mm->cmt_limit_bytes, ts,
                  mm->enabled == FLB_TRUE ? (double) mm->limit : 0.0,
                  0, (char *[]) { NULL });
    cmt_gauge_set(mm->cmt_pressure, ts, pressure, 0, (char *[]) { NULL });
    cmt_gauge_set(mm->cmt_state, ts, (double) mm->state, 0, (char *[]) { NULL });
    cmt_gauge_set(mm->cmt_paused_inputs, ts, (double) mm->paused_inputs,
                  0, (char *[]) { NULL });
    cmt_counter_set(mm->cmt_reclaims_total, ts, (double) mm->reclaim_count,
                    0, (char *[]) { NULL });

    return 0;
}
#endif

/* Resolve the service properties into the limits used by the monitor */
static int config_apply(struct flb_mem_monitor *mm, struct flb_config *config)
{
    int ret;
    double interval;
    char limit_str[32];
    char throttle_str[32];
    char refuse_str[32];
    uint64_t total = 0;
    uint64_t limit;
    uint64_t reserve;
    uint64_t usage;

    interval = config->mem_check_interval;
    if (interval <= 0.0) {
        interval = FLB_MEM_MONITOR_CHECK_INTERVAL;
    }
    else if (interval < FLB_MEM_MONITOR_CHECK_INTERVAL_MIN) {
        flb_warn("[mem monitor] memory.check_interval is too low, using %.2f "
                 "seconds", FLB_MEM_MONITOR_CHECK_INTERVAL_MIN);
        interval = FLB_MEM_MONITOR_CHECK_INTERVAL_MIN;
    }
    mm->check_interval_ms = (int) (interval * 1000.0);

    if (config->mem_limit == NULL) {
        if (config->mem_spike_reserve != NULL) {
            flb_warn("[mem monitor] memory.spike_reserve has no effect without "
                     "memory.limit");
        }
        return 0;
    }

    /* unknown on platforms without support, percentages cannot be used there */
    flb_mem_monitor_system_limit(&total);

    ret = flb_mem_monitor_parse_size(config->mem_limit, total, &limit);
    if (ret != 0) {
        flb_error("[mem monitor] invalid memory.limit value '%s'",
                  config->mem_limit);
        return -1;
    }

    if (config->mem_spike_reserve != NULL) {
        ret = flb_mem_monitor_parse_size(config->mem_spike_reserve, limit, &reserve);
        if (ret != 0) {
            flb_error("[mem monitor] invalid memory.spike_reserve value '%s'",
                      config->mem_spike_reserve);
            return -1;
        }
    }
    else {
        reserve = (uint64_t) ((double) limit *
                              (FLB_MEM_MONITOR_SPIKE_RESERVE_PERCENT / 100.0));
    }

    ret = flb_mem_monitor_set_limits(mm, limit, reserve);
    if (ret != 0) {
        flb_error("[mem monitor] memory.spike_reserve must be greater than zero "
                  "and not exceed %.0f%% of memory.limit",
                  FLB_MEM_MONITOR_SPIKE_RESERVE_MAX);
        return -1;
    }

    ret = mm->cb_usage(mm, &usage);
    if (ret != 0) {
        flb_warn("[mem monitor] process memory usage is not available on this "
                 "platform, memory.limit will not be enforced");
        return 0;
    }
    mm->usage = usage;
    mm->enabled = FLB_TRUE;

    flb_utils_bytes_to_human_readable_size((size_t) mm->limit,
                                           limit_str, sizeof(limit_str));
    flb_utils_bytes_to_human_readable_size((size_t) mm->threshold_throttle,
                                           throttle_str, sizeof(throttle_str));
    flb_utils_bytes_to_human_readable_size((size_t) mm->threshold_refuse,
                                           refuse_str, sizeof(refuse_str));

    flb_info("[mem monitor] limit=%s, throttle at %s, refuse at %s, "
             "check_interval=%dms",
             limit_str, throttle_str, refuse_str, mm->check_interval_ms);

    if (total > 0 && mm->limit > total) {
        flb_warn("[mem monitor] memory.limit is higher than the memory "
                 "available to the process");
    }

    if (usage >= mm->threshold_throttle) {
        flb_warn("[mem monitor] memory usage at startup is already over the "
                 "throttle threshold, memory.limit might be too low");
    }

    return 0;
}

struct flb_mem_monitor *flb_mem_monitor_create(struct flb_config *config)
{
    int ret;
    struct flb_mem_monitor *mm;

    mm = flb_calloc(1, sizeof(struct flb_mem_monitor));
    if (mm == NULL) {
        flb_errno();
        return NULL;
    }

    mm->config = config;
    mm->enabled = FLB_FALSE;
    mm->state = FLB_MEM_MONITOR_NORMAL;
    mm->cb_usage = cb_usage_default;
    mm->cb_reclaim = cb_reclaim_default;
    mm->reclaim_interval = FLB_MEM_MONITOR_RECLAIM_INTERVAL_MIN;

#ifdef FLB_HAVE_METRICS
    ret = metrics_create(mm);
    if (ret != 0) {
        flb_error("[mem monitor] could not create metrics context");
        flb_free(mm);
        return NULL;
    }
#endif

    ret = config_apply(mm, config);
    if (ret != 0) {
        flb_mem_monitor_destroy(mm);
        return NULL;
    }

    return mm;
}

int flb_mem_monitor_start(struct flb_mem_monitor *mm)
{
    int ret;

    if (mm == NULL || mm->enabled == FLB_FALSE || mm->timer != NULL) {
        return 0;
    }

    ret = flb_sched_timer_cb_create(mm->config->sched, FLB_SCHED_TIMER_CB_PERM,
                                    mm->check_interval_ms,
                                    cb_mem_monitor_check, mm, &mm->timer);
    if (ret == -1) {
        flb_error("[mem monitor] could not schedule the periodic check");
        mm->timer = NULL;
        return -1;
    }

    return 0;
}

void flb_mem_monitor_destroy(struct flb_mem_monitor *mm)
{
    if (mm == NULL) {
        return;
    }

    if (mm->timer != NULL) {
        flb_sched_timer_cb_destroy(mm->timer);
        mm->timer = NULL;
    }

#ifdef FLB_HAVE_METRICS
    if (mm->cmt != NULL) {
        cmt_destroy(mm->cmt);
    }
#endif

    flb_free(mm);
}
