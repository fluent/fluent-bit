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

static int cpufreq_init(struct flb_ne *ctx)
{
    struct cmt_gauge *g;

    /* node_cpu_frequency_hertz */
    g = cmt_gauge_create(ctx->cmt, "node", "cpu", "frequency_hertz",
                         "Current cpu thread frequency in hertz.",
                         1, (char *[]) {"cpu"});
    if (!g) {
        return -1;
    }
    ctx->cpu_freq_hertz = g;

    /* node_cpu_frequency_max_hertz */
    g = cmt_gauge_create(ctx->cmt, "node", "cpu", "frequency_max_hertz",
                         "Maximum cpu thread frequency in hertz.",
                         1, (char *[]) {"cpu"});
    if (!g) {
        return -1;
    }
    ctx->cpu_freq_max_hertz = g;

    /* node_cpu_frequency_min_hertz */
    g = cmt_gauge_create(ctx->cmt, "node", "cpu", "frequency_min_hertz",
                         "Minimum cpu thread frequency in hertz.",
                         1, (char *[]) {"cpu"});
    if (!g) {
        return -1;
    }
    ctx->cpu_freq_min_hertz = g;

    /* node_cpu_scaling_frequency_hertz */
    g = cmt_gauge_create(ctx->cmt, "node", "cpu", "scaling_frequency_hertz",
                         "Current scaled CPU thread frequency in hertz.",
                         1, (char *[]) {"cpu"});
    if (!g) {
        return -1;
    }
    ctx->cpu_scaling_freq_hertz = g;

    /* node_cpu_scaling_frequency_max_hertz */
    g = cmt_gauge_create(ctx->cmt, "node", "cpu", "scaling_frequency_max_hertz",
                         "Maximum scaled CPU thread frequency in hertz.",
                         1, (char *[]) {"cpu"});
    if (!g) {
        return -1;
    }
    ctx->cpu_scaling_freq_max_hertz = g;

    /* node_cpu_scaling_frequency_min_hertz */
    g = cmt_gauge_create(ctx->cmt, "node", "cpu", "scaling_frequency_min_hertz",
                         "Minimum scaled CPU thread frequency in hertz.",
                         1, (char *[]) {"cpu"});
    if (!g) {
        return -1;
    }
    ctx->cpu_scaling_freq_min_hertz = g;

    return 0;
}

static int cpufreq_update(struct flb_ne *ctx)
{
    int ret;
    int len;
    uint64_t ts;
    uint64_t val;
    char *cpu_id;
    struct mk_list list;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    const char *pattern = "/devices/system/cpu/cpu[0-9]*";

    ret = ne_utils_path_scan(ctx, ctx->path_sysfs, pattern, NE_SCAN_DIR, &list);
    if (ret != 0) {
        return -1;
    }

    if (mk_list_size(&list) == 0) {
        return 0;
    }

    ts = cfl_time_now();

    /* Process entries */
    mk_list_foreach(head, &list) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        /* Locate CPU ID string */
        len = flb_sds_len(entry->str);
        cpu_id = entry->str + len;
        while (*cpu_id != 'u') cpu_id--;
        cpu_id++;

        /* node_cpu_frequency_hertz */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str, "cpufreq", "cpuinfo_cur_freq",
                                        &val);
        if (ret == 0) {
            cmt_gauge_set(ctx->cpu_freq_hertz, ts,
                          (double) (val * 1000.0),
                          1, (char *[]) {cpu_id});
        }

        /* node_cpu_frequency_max_hertz */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str, "cpufreq", "cpuinfo_max_freq",
                                        &val);
        if (ret == 0) {
            cmt_gauge_set(ctx->cpu_freq_max_hertz, ts,
                          (double) (val * 1000.0),
                          1, (char *[]) {cpu_id});
        }

        /* node_cpu_frequency_min_hertz */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str, "cpufreq", "cpuinfo_min_freq",
                                        &val);
        if (ret == 0) {
            cmt_gauge_set(ctx->cpu_freq_min_hertz, ts,
                          (double) (val * 1000.0),
                          1, (char *[]) {cpu_id});
        }


        /* node_cpu_scaling_frequency_hertz */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str, "cpufreq", "scaling_cur_freq",
                                        &val);
        if (ret == 0) {
            cmt_gauge_set(ctx->cpu_scaling_freq_hertz, ts,
                          ((double) val) * 1000.0,
                          1, (char *[]) {cpu_id});
        }

        /* node_cpu_scaling_frequency_max_hertz */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str, "cpufreq", "scaling_max_freq",
                                        &val);
        if (ret == 0) {
            cmt_gauge_set(ctx->cpu_scaling_freq_max_hertz, ts,
                          (double) (val * 1000.0),
                          1, (char *[]) {cpu_id});
        }

        /* node_cpu_frequency_min_hertz */
        ret = ne_utils_file_read_uint64(ctx->path_sysfs,
                                        entry->str, "cpufreq", "scaling_min_freq",
                                        &val);
        if (ret == 0) {
            cmt_gauge_set(ctx->cpu_scaling_freq_min_hertz, ts,
                          (double) (val * 1000.0),
                          1, (char *[]) {cpu_id});
        }
    }

    flb_slist_destroy(&list);
    return 0;
}

static int ne_cpufreq_init(struct flb_ne *ctx)
{
    cpufreq_init(ctx);
    return 0;
}

static int ne_cpufreq_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    struct flb_ne *ctx = (struct flb_ne *)in_context;
    cpufreq_update(ctx);
    return 0;
}

struct flb_ne_collector cpufreq_collector = {
    .name = "cpufreq",
    .cb_init = ne_cpufreq_init,
    .cb_update = ne_cpufreq_update,
    .cb_exit = NULL
};
