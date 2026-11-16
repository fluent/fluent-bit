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

#ifndef FLB_MEM_MONITOR_H
#define FLB_MEM_MONITOR_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>

#include <stdint.h>

/*
 * Memory monitor
 * ==============
 * Tracks the memory used by the process against a user defined budget
 * (service property 'memory.limit') and reacts in stages before the operating
 * system has to intervene:
 *
 *  - NORMAL  : usage is below every threshold, nothing to do.
 *  - RECLAIM : ask the memory allocator to return unused pages to the system.
 *  - THROTTLE: pause the inputs that can wait without losing data (inputs
 *              that are not network servers, e.g: tail).
 *  - REFUSE  : pause every input, network servers included.
 *
 * The limit is a soft one: usage is sampled on a timer, so a burst between
 * two samples can overshoot. The 'memory.spike_reserve' property defines the
 * headroom kept below the limit to absorb those bursts.
 */

/* Monitor states, ordered by severity */
#define FLB_MEM_MONITOR_NORMAL     0
#define FLB_MEM_MONITOR_RECLAIM    1
#define FLB_MEM_MONITOR_THROTTLE   2
#define FLB_MEM_MONITOR_REFUSE     3

/* Default values */
#define FLB_MEM_MONITOR_SPIKE_RESERVE_PERCENT   20.0
#define FLB_MEM_MONITOR_SPIKE_RESERVE_MAX       50.0
#define FLB_MEM_MONITOR_CHECK_INTERVAL          0.5     /* seconds */
#define FLB_MEM_MONITOR_CHECK_INTERVAL_MIN      0.05    /* seconds */

/* Minimum and maximum time between two reclaim attempts (nanoseconds) */
#define FLB_MEM_MONITOR_RECLAIM_INTERVAL_MIN    5000000000ULL
#define FLB_MEM_MONITOR_RECLAIM_INTERVAL_MAX    60000000000ULL

struct flb_mem_monitor;

/* Returns 0 and sets the number of bytes in use, or -1 on error */
typedef int (*flb_mem_monitor_usage_cb)(struct flb_mem_monitor *mm,
                                        uint64_t *usage);

/* Returns 0 if memory was released back to the system, or -1 otherwise */
typedef int (*flb_mem_monitor_reclaim_cb)(struct flb_mem_monitor *mm);

struct flb_mem_monitor {
    int enabled;                    /* is the limit being enforced ?      */
    int state;                      /* current FLB_MEM_MONITOR_* state    */
    int check_interval_ms;          /* sampling period in milliseconds    */
    int paused_inputs;              /* inputs paused by the monitor       */

    uint64_t limit;                 /* memory budget in bytes             */
    uint64_t spike_reserve;         /* headroom kept below the limit      */
    uint64_t usage;                 /* last sampled usage in bytes        */

    /* state thresholds, derived from limit and spike_reserve */
    uint64_t threshold_reclaim;
    uint64_t threshold_throttle;
    uint64_t threshold_refuse;
    uint64_t hysteresis;

    /* reclaim pacing */
    uint64_t reclaim_last;          /* timestamp of last attempt (ns)     */
    uint64_t reclaim_interval;      /* current wait between attempts (ns) */
    uint64_t reclaim_count;         /* number of reclaim attempts         */

    /* callbacks: replaceable so tests can drive the monitor */
    flb_mem_monitor_usage_cb cb_usage;
    flb_mem_monitor_reclaim_cb cb_reclaim;
    void *cb_data;

    struct flb_sched_timer *timer;
    struct flb_config *config;

#ifdef FLB_HAVE_METRICS
    struct cmt *cmt;
    struct cmt_gauge *cmt_usage_bytes;
    struct cmt_gauge *cmt_limit_bytes;
    struct cmt_gauge *cmt_pressure;
    struct cmt_gauge *cmt_state;
    struct cmt_gauge *cmt_paused_inputs;
    struct cmt_counter *cmt_reclaims_total;
#endif
};

struct flb_mem_monitor *flb_mem_monitor_create(struct flb_config *config);
void flb_mem_monitor_destroy(struct flb_mem_monitor *mm);

/* Register the periodic check in the engine scheduler (if enabled) */
int flb_mem_monitor_start(struct flb_mem_monitor *mm);

/* Take one sample, update the state and apply it to the inputs */
int flb_mem_monitor_check(struct flb_mem_monitor *mm);

/* Set limit and reserve, compute thresholds. Returns -1 on invalid values */
int flb_mem_monitor_set_limits(struct flb_mem_monitor *mm,
                               uint64_t limit, uint64_t spike_reserve);

/* Compute the state that follows 'state' for a given usage (pure function) */
int flb_mem_monitor_state_next(struct flb_mem_monitor *mm, int state,
                               uint64_t usage);

const char *flb_mem_monitor_state_name(int state);

/*
 * Parse a size that can be expressed in bytes ('512M') or as a percentage
 * of 'total' ('80%'). Returns 0 on success, -1 on invalid input.
 */
int flb_mem_monitor_parse_size(const char *value, uint64_t total, uint64_t *out);

/* Anonymous resident memory of the running process */
int flb_mem_monitor_process_usage(uint64_t *usage);

/* Memory available to the process: min(control group limit, system memory) */
int flb_mem_monitor_system_limit(uint64_t *limit);

/*
 * Resolve the control group memory limit using the given process cgroup
 * file (e.g: /proc/self/cgroup) and cgroup filesystem root
 * (e.g: /sys/fs/cgroup). Returns 0 if a limit was found, -1 if there is none.
 */
int flb_mem_monitor_cgroup_limit(const char *proc_cgroup_path,
                                 const char *cgroup_root, uint64_t *limit);

#ifdef FLB_HAVE_METRICS
/* Refresh the metrics context before it gets exported */
int flb_mem_monitor_metrics_update(struct flb_mem_monitor *mm);
#endif

#endif
