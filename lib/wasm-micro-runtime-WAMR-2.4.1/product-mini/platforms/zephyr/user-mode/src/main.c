/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>

#include <zephyr/version.h>
#include <zephyr/app_memory/app_memdomain.h>

#define MAIN_THREAD_STACK_SIZE 2048
#define MAIN_THREAD_PRIORITY 5

static struct k_thread iwasm_user_mode_thread;
K_THREAD_STACK_DEFINE(iwasm_user_mode_thread_stack, MAIN_THREAD_STACK_SIZE);

extern struct k_mem_partition z_libc_partition;
K_APPMEM_PARTITION_DEFINE(wamr_partition);

/* WAMR memory domain */
struct k_mem_domain wamr_domain;

extern void
iwasm_main(void *arg1, void *arg2, void *arg3);

bool
iwasm_user_mode(void)
{
    struct k_mem_partition *wamr_domain_parts[] = { &wamr_partition,
                                                    &z_libc_partition };

    printk("wamr_partition start addr: %ld, size: %zu\n", wamr_partition.start,
           wamr_partition.size);

    /* Initialize the memory domain with single WAMR partition */
    if (k_mem_domain_init(&wamr_domain, 2, wamr_domain_parts) != 0) {
        printk("Failed to initialize memory domain.\n");
        return false;
    }

    k_tid_t tid =
        k_thread_create(&iwasm_user_mode_thread, iwasm_user_mode_thread_stack,
                        MAIN_THREAD_STACK_SIZE, iwasm_main, NULL, NULL, NULL,
                        MAIN_THREAD_PRIORITY, K_USER, K_FOREVER);

    /* Grant WAMR memory domain access to user mode thread */
    if (k_mem_domain_add_thread(&wamr_domain, tid) != 0) {
        printk("Failed to add memory domain to thread.\n");
        return false;
    }

#if KERNEL_VERSION_NUMBER < 0x040000 /* version 4.0.0 */
    /* k_thread_start is a legacy API for compatibility. Modern Zephyr threads
     * are initialized in the "sleeping" state and do not need special handling
     * for "start".*/
    k_thread_start(tid);
#else
    /* wakes up thread from sleeping */
    k_wakeup(tid);
#endif

    return tid ? true : false;
}

#if KERNEL_VERSION_NUMBER < 0x030400 /* version 3.4.0 */
void
main(void)
{
    iwasm_user_mode();
}
#else
int
main(void)
{
    iwasm_user_mode();
    return 0;
}
#endif
