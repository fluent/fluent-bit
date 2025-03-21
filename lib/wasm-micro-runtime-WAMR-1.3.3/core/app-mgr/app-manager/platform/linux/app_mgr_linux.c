/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "app_manager.h"

void *
app_manager_timer_create(void (*timer_callback)(void *),
                         watchdog_timer *wd_timer)
{
    /* TODO */
    return NULL;
}

void
app_manager_timer_destroy(void *timer)
{
    /* TODO */
}

void
app_manager_timer_start(void *timer, int timeout)
{
    /* TODO */
}

void
app_manager_timer_stop(void *timer)
{
    /* TODO */
}

watchdog_timer *
app_manager_get_wd_timer_from_timer_handle(void *timer)
{
    /* TODO */
    return NULL;
}

int
app_manager_signature_verify(const uint8_t *file, unsigned int file_len,
                             const uint8_t *signature, unsigned int sig_size)
{
    return 1;
}
