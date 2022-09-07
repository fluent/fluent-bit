/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * Copyright (C) 2020 TU Bergakademie Freiberg Karl Fessel
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include <ztimer64.h>
#include <kernel_defines.h>

#if IS_USED(MODULE_ZTIMER64_USEC)
uint64
os_time_get_boot_microsecond()
{
    return ztimer64_now(ZTIMER64_USEC);
}
#elif IS_USED(MODULE_ZTIMER64_MSEC)
uint64
os_time_get_boot_microsecond()
{
    return ztimer64_now(ZTIMER64_MSEC) * 1000;
}
#else
#ifdef __GNUC__
__attribute__((weak)) uint64
os_time_get_boot_microsecond();
#endif
uint64
os_time_get_boot_microsecond()
{
    static uint64_t times;
    return ++times;
}
#endif
