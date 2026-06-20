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
#include <fluent-bit/flb_hash_table.h>

#include <fluent-bit/flb_input_plugin.h>

#include "ne.h"
#include "ne_utils.h"

#include <sys/types.h>
#include <sys/sysctl.h>

#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_host.h>

static int meminfo_configure(struct flb_ne *ctx)
{
    struct cmt_counter *c;
    struct cmt_gauge *g;

    g = cmt_gauge_create(ctx->cmt, "node", "meminfo", "free_bytes",
                         "memory information for free in bytes",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->darwin_free_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "node", "meminfo", "active_bytes",
                         "memory information for active in bytes",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->darwin_active_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "node", "meminfo", "compressed_bytes",
                         "meminfo information for compressored pages in bytes",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->darwin_compressed_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "node", "meminfo", "inactive_bytes",
                         "meminfo information for inactive in bytes",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->darwin_inactive_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "node", "meminfo", "internal_bytes",
                         "meminfo information for internal in bytes",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->darwin_internal_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "node", "meminfo", "wired_bytes",
                         "meminfo information for wire in bytes",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->darwin_wired_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "node", "meminfo", "purgeable_bytes",
                         "meminfo information for purgeable in bytes",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->darwin_purgeable_bytes = g;

    c = cmt_counter_create(ctx->cmt, "node", "meminfo", "pageins_bytes",
                           "meminfo information for pageins in bytes",
                           0, NULL);
    if (!c) {
        return -1;
    }
    ctx->darwin_pageins_bytes = c;

    c = cmt_counter_create(ctx->cmt, "node", "meminfo", "pageouts_bytes",
                           "meminfo information for pageouts in bytes",
                           0, NULL);
    if (!c) {
        return -1;
    }
    ctx->darwin_pageouts_bytes = c;

    g = cmt_gauge_create(ctx->cmt, "node", "meminfo", "swap_used_bytes",
                         "meminfo information for swap_used in bytes",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->darwin_swap_used_bytes = g;

    g = cmt_gauge_create(ctx->cmt, "node", "meminfo", "swap_total_bytes",
                         "meminfo information for swap_total in bytes",
                         0, NULL);
    if (!g) {
        return -1;
    }
    ctx->darwin_swap_total_bytes = g;

    c = cmt_counter_create(ctx->cmt, "node", "meminfo", "total_bytes",
                           "meminfo information for total in bytes",
                           0, NULL);
    if (!c) {
        return -1;
    }
    ctx->darwin_total_bytes = c;

    return 0;
}

static int meminfo_update(struct flb_ne *ctx, uint64_t ts)
{
    mach_port_t host_port;
    mach_msg_type_number_t host_size;
    vm_statistics64_data_t vm_stat;
    kern_return_t err;
    vm_size_t page_size;
    struct xsw_usage swap;
    uint64_t ps;
    int64_t total;
    int mib[2];
    size_t len;

    host_port = mach_host_self();
    host_size = sizeof(vm_statistics_data_t) / sizeof(integer_t);

    err = host_statistics64(host_port, HOST_VM_INFO, (host_info_t)&vm_stat, &host_size);

    if (err != KERN_SUCCESS) {
        flb_plg_error(ctx->ins, "host_statistics() is failed with error = %d", err);
        mach_port_deallocate(mach_task_self(), host_port);
        return -1;
    }

    host_page_size(host_port, &page_size);

    ps = (uint64_t)page_size;

    mib[0] = CTL_HW;
    mib[1] = HW_MEMSIZE;
    len = sizeof(int64_t);
    sysctl(mib, 2, &total, &len, NULL, 0);

    mib[0] = CTL_VM;
    mib[1] = VM_SWAPUSAGE;
    len = sizeof(struct xsw_usage);
    sysctl(mib, 2, &swap, &len, NULL, 0);

    cmt_gauge_set(ctx->darwin_free_bytes, ts,
                  ps * vm_stat.free_count, 0, NULL);

    cmt_gauge_set(ctx->darwin_compressed_bytes, ts,
                  ps * vm_stat.compressor_page_count, 0, NULL);

    cmt_gauge_set(ctx->darwin_active_bytes, ts,
                  ps * vm_stat.active_count, 0, NULL);

    cmt_gauge_set(ctx->darwin_inactive_bytes, ts,
                  ps * vm_stat.inactive_count, 0, NULL);

    cmt_gauge_set(ctx->darwin_internal_bytes, ts,
                  ps * vm_stat.internal_page_count, 0, NULL);

    cmt_gauge_set(ctx->darwin_wired_bytes, ts,
                  ps * vm_stat.wire_count, 0, NULL);

    cmt_gauge_set(ctx->darwin_purgeable_bytes, ts,
                  ps * vm_stat.purgeable_count, 0, NULL);

    cmt_counter_set(ctx->darwin_pageins_bytes, ts,
                    ps * vm_stat.pageins, 0, NULL);

    cmt_counter_set(ctx->darwin_pageouts_bytes, ts,
                    ps * vm_stat.pageouts, 0, NULL);

    cmt_gauge_set(ctx->darwin_swap_used_bytes, ts,
                    (double)swap.xsu_used, 0, NULL);

    cmt_gauge_set(ctx->darwin_swap_total_bytes, ts,
                    (double)swap.xsu_total, 0, NULL);

    cmt_counter_set(ctx->darwin_total_bytes, ts,
                    (double)total, 0, NULL);

    mach_port_deallocate(mach_task_self(), host_port);

    return 0;
}

static int ne_meminfo_init(struct flb_ne *ctx)
{
    meminfo_configure(ctx);
    return 0;
}

static int ne_meminfo_update(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    uint64_t ts;
    struct flb_ne *ctx = (struct flb_ne *)in_context;

    ts = cfl_time_now();

    meminfo_update(ctx, ts);
    return 0;
}

static int ne_meminfo_exit(struct flb_ne *ctx)
{
    return 0;
}

struct flb_ne_collector meminfo_collector = {
    .name = "meminfo",
    .cb_init = ne_meminfo_init,
    .cb_update = ne_meminfo_update,
    .cb_exit = ne_meminfo_exit
};
