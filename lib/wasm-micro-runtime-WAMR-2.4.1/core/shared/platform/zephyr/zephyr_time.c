/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"

uint64
os_time_get_boot_us()
{
    return k_uptime_get() * 1000;
}

uint64
os_time_thread_cputime_us(void)
{
    /* On certain boards, enabling userspace could impact the collection of
     * thread runtime statistics */
#ifdef CONFIG_THREAD_RUNTIME_STATS
    k_tid_t tid;
    struct k_thread_runtime_stats stats;
    uint32 clock_freq;
    uint64 cpu_cycles, time_in_us = 0;

    tid = k_current_get();
    if (k_thread_runtime_stats_get(tid, &stats) == 0) {
        cpu_cycles = stats.execution_cycles;
        clock_freq = CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC;
        time_in_us = (cpu_cycles * 1000000) / clock_freq;
    }

    return time_in_us;
#else
    return os_time_get_boot_us();
#endif
}
