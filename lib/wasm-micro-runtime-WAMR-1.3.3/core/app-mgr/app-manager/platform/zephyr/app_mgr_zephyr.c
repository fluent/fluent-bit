/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "app_manager.h"
#include "bh_platform.h"
#include <autoconf.h>

#if KERNEL_VERSION_NUMBER < 0x030200 /* version 3.2.0 */
#include <zephyr.h>
#include <kernel.h>
#else
#include <zephyr/kernel.h>
#endif

#if 0
#include <sigverify.h>
#endif
typedef struct k_timer_watchdog {
    struct k_timer timer;
    watchdog_timer *wd_timer;
} k_timer_watchdog;

void *
app_manager_timer_create(void (*timer_callback)(void *),
                         watchdog_timer *wd_timer)
{
    struct k_timer_watchdog *timer =
        APP_MGR_MALLOC(sizeof(struct k_timer_watchdog));

    if (timer) {
        k_timer_init(&timer->timer, (void (*)(struct k_timer *))timer_callback,
                     NULL);
        timer->wd_timer = wd_timer;
    }

    return timer;
}

void
app_manager_timer_destroy(void *timer)
{
    APP_MGR_FREE(timer);
}

void
app_manager_timer_start(void *timer, int timeout)
{
    k_timer_start(timer, Z_TIMEOUT_MS(timeout), Z_TIMEOUT_MS(0));
}

void
app_manager_timer_stop(void *timer)
{
    k_timer_stop(timer);
}

watchdog_timer *
app_manager_get_wd_timer_from_timer_handle(void *timer)
{
    return ((k_timer_watchdog *)timer)->wd_timer;
}
#if 0
int app_manager_signature_verify(const uint8_t *file, unsigned int file_len,
        const uint8_t *signature, unsigned int sig_size)
{
    return signature_verify(file, file_len, signature, sig_size);
}
#endif
