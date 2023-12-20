/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"

uint64
os_time_get_boot_microsecond()
{
    TickType_t ticks = xTaskGetTickCount();
    return (uint64)1000 * 1000 / configTICK_RATE_HZ * ticks;
}
