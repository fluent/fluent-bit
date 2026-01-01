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
#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <unistd.h>

/*
 * See kernel documentation for a description:
 * https://www.kernel.org/doc/html/latest/filesystems/proc.html
 *
 * user: normal processes executing in user mode
 * nice: niced processes executing in user mode
 * system: processes executing in kernel mode
 * idle: twiddling thumbs
 * iowait: In a word, iowait stands for waiting for I/O to complete. But there are several problems:
 * irq: servicing interrupts
 * softirq: servicing softirqs
 * steal: involuntary wait
 * guest: running a normal guest
 * guest_nice: running a niced guest
 *
 * Ensure to pick the correct version of the documentation, older versions here:
 * https://github.com/torvalds/linux/tree/master/Documentation
 */
struct cpu_stat_info {
    double user;
    double nice;
    double system;
    double idle;
    double iowait;
    double irq;
    double softirq;
    double steal;
    double guest;
    double guest_nice;
};

/*
 * Thermal throttle stats, reads /sys/devices/system/cpu/cpu*
 * ----------------------------------------------------------
 */
static inline int cpu_thermal_init(struct flb_ne *ctx)
{
    struct cmt_counter *c;

    c = cmt_counter_create(ctx->cmt, "node", "cpu", "core_throttles_total",
                           "Number of times this CPU core has been throttled.",
                           2, (char *[]) {"core", "package"});
    if (!c) {
        return -1;
    }
    ctx->cpu_core_throttles = c;


    c = cmt_counter_create(ctx->cmt, "node", "cpu", "package_throttles_total",
                           "Number of times this CPU package has been throttled.",
                           1, (char *[]) {"package"});
    if (!c) {
        return -1;
    }
    ctx->cpu_package_throttles = c;

    return 0;
}

static int cpu_thermal_update(struct flb_ne *ctx, uint64_t ts)
{
    int ret;
    uint64_t core_id = 0;
    uint64_t physical_package_id = 0;
    uint64_t core_throttle_count;
    uint64_t package_throttle_count;
    char tmp1[32];
    char tmp2[32];
    struct mk_list *head;
    struct mk_list list;
    struct flb_slist_entry *entry;
    const char *pattern = "/devices/system/cpu/cpu[0-9]*";

    ret = ne_utils_path_scan(ctx, ctx->path_sysfs, pattern, NE_SCAN_DIR, &list);
    if (ret != 0) {
        return -1;
    }

    if (mk_list_size(&list) == 0) {
        return 0;
    }

    /* Process entries */
    mk_list_foreach(head, &list) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        /* Core ID */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str,
                                        "topology", "core_id",
                                        &core_id);
        if (ret != 0) {
            continue;
        }

        /* Physical ID */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str,
                                        "topology", "physical_package_id",
                                        &physical_package_id);
        if (ret != 0) {
            continue;
        }

        /* Package Metric: node_cpu_core_throttles_total */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str,
                                        "thermal_throttle", "core_throttle_count",
                                        &core_throttle_count);
        if (ret != 0) {
            flb_plg_debug(ctx->ins,
                          "CPU is missing core_throttle_count: %s",
                          entry->str);
        }
        else {
            snprintf(tmp1, sizeof(tmp1) -1, "%" PRIu64, core_id);
            snprintf(tmp2, sizeof(tmp2) -1, "%" PRIu64, physical_package_id);

            /* Set new value */
            cmt_counter_set(ctx->cpu_core_throttles, ts,
                            (double) core_throttle_count,
                            2, (char *[]) {tmp1, tmp2});
        }

        /* Package Metric: node_cpu_package_throttles_total */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str,
                                        "thermal_throttle", "package_throttle_count",
                                        &package_throttle_count);
        if (ret != 0) {
            flb_plg_debug(ctx->ins,
                          "CPU is missing package_throttle_count: %s",
                          entry->str);
        }
        else {
            /* Set new value */
            cmt_counter_set(ctx->cpu_package_throttles, ts,
                            (double) package_throttle_count,
                            1, (char *[]) {tmp2});
        }
    }
    flb_slist_destroy(&list);

    /*
     * FIXME: continue fixing this:
     *
     * https://github.com/prometheus/node_exporter/blob/master/collector/cpu_linux.go#L194
    */

    return 0;
}

/*
 * CPU stats, reads /proc/stat
 * ---------------------------
 */
static inline int cpu_stat_init(struct flb_ne *ctx)
{
    struct cmt_counter *c;

    c = cmt_counter_create(ctx->cmt, "node", "cpu", "seconds_total",
                           "Seconds the CPUs spent in each mode.",
                           2, (char *[]) {"cpu", "mode"});
    if (!c) {
        return -1;
    }
    ctx->cpu_seconds = c;

    c = cmt_counter_create(ctx->cmt, "node", "cpu", "guest_seconds_total",
                           "Seconds the CPUs spent in guests (VMs) for each mode.",
                           2, (char *[]) {"cpu", "mode"});
    if (!c) {
        return -1;
    }
    ctx->cpu_guest_seconds = c;

    return 0;
}

static int stat_line(char *line, struct cpu_stat_info *st)
{
    int ret;
    double user_hz = sysconf(_SC_CLK_TCK);
    const char *cpu_fmt = "%lf %lf %lf %lf %lf %lf %lf %lf %lf %lf";

    ret = sscanf(line, cpu_fmt,
                 &st->user,
                 &st->nice,
                 &st->system,
                 &st->idle,
                 &st->iowait,
                 &st->irq,
                 &st->softirq,
                 &st->steal,
                 &st->guest,
                 &st->guest_nice);

    /* On some older kernels the 'guest_nice' value may be missing */
    if (ret < 9) {
        return -1;
    }
    /* Ensure we zero initialise it */
    if ( ret == 9 ) {
        st->guest_nice = 0;
    }

    /* Convert to seconds based on USER_HZ kernel param */
    st->user /= user_hz;
    st->nice /= user_hz;
    st->system /= user_hz;
    st->idle /= user_hz;
    st->iowait /= user_hz;
    st->irq /= user_hz;
    st->softirq /= user_hz;
    st->steal /= user_hz;
    st->guest /= user_hz;
    st->guest_nice /= user_hz;

    return 0;
}

static int cpu_stat_set_metrics(struct flb_ne *ctx, char *cpu_id,
                                struct cpu_stat_info *st, uint64_t ts)
{

    /* CPU seconds */
    cmt_counter_set(ctx->cpu_seconds, ts,
                    st->idle,
                    2, (char *[]) {cpu_id, "idle"});

    cmt_counter_set(ctx->cpu_seconds, ts,
                    st->iowait,
                    2, (char *[]) {cpu_id, "iowait"});

    cmt_counter_set(ctx->cpu_seconds, ts,
                    st->irq,
                    2, (char *[]) {cpu_id, "irq"});

    cmt_counter_set(ctx->cpu_seconds, ts,
                    st->nice,
                    2, (char *[]) {cpu_id, "nice"});

    cmt_counter_set(ctx->cpu_seconds, ts,
                    st->softirq,
                    2, (char *[]) {cpu_id, "softirq"});


    cmt_counter_set(ctx->cpu_seconds, ts,
                    st->steal,
                    2, (char *[]) {cpu_id, "steal"});

    cmt_counter_set(ctx->cpu_seconds, ts,
                    st->system,
                    2, (char *[]) {cpu_id, "system"});

    cmt_counter_set(ctx->cpu_seconds, ts,
                    st->user,
                    2, (char *[]) {cpu_id, "user"});

    /* CPU Guest Seconds */
    cmt_counter_set(ctx->cpu_guest_seconds, ts,
                    st->guest,
                    2, (char *[]) {cpu_id, "user"});

    cmt_counter_set(ctx->cpu_guest_seconds, ts,
                    st->guest_nice,
                    2, (char *[]) {cpu_id, "nice"});

    return 0;
}

static int cpu_stat_update(struct flb_ne *ctx, uint64_t ts)
{
    int len;
    int ret;
    char *p;
    char tmp[32];
    struct mk_list list;
    struct mk_list *head;
    struct flb_slist_entry *line;
    struct cpu_stat_info st = {0};

    ret = ne_utils_file_read_lines(ctx->path_procfs, "/stat", &list);
    if (ret == -1) {
        return -1;
    }

    mk_list_foreach(head, &list) {
        line = mk_list_entry(head, struct flb_slist_entry, _head);

        if (strncmp(line->str, "cpu ", 4) == 0) {
            /* CPU total, we skip this state since we care only about per core stats */
            continue;
        }
        else if (strncmp(line->str, "cpu", 3) == 0) {
            /* CPU ID (per core) */
            p = strchr(line->str  + 3, ' ');
            len = p - (line->str + 3);
            memcpy(tmp, line->str + 3, len);
            tmp[len] = '\0';

            /* Capture metrics */
            ret = stat_line(p, &st);
            if (ret != 0) {
                flb_plg_error(ctx->ins,
                              "could not process line: %s", line->str);
                continue;
            }

            /* Update our counters */
            cpu_stat_set_metrics(ctx, tmp, &st, ts);
        }
    }

    flb_slist_destroy(&list);
    return 0;
}

static int ne_cpu_init(struct flb_ne *ctx)
{
    int ret;

    /* CPU Thermal */
    ret = cpu_thermal_init(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not initialize cpu_thermal metrics");
        return -1;
    }

    /* CPU Stats */
    ret = cpu_stat_init(ctx);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "could not initialize cpu_stat metrics");
        return -1;
    }
    cpu_stat_init(ctx);
    return 0;
}

static int ne_cpu_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    uint64_t ts;
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    ts = cfl_time_now();

    cpu_thermal_update(ctx, ts);
    cpu_stat_update(ctx, ts);

    return 0;
}

struct flb_ne_collector cpu_collector = {
    .name = "cpu",
    .cb_init = ne_cpu_init,
    .cb_update = ne_cpu_update,
    .cb_exit = NULL
};
