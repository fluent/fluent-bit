/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

int
bh_platform_init()
{
    return 0;
}

void
bh_platform_destroy()
{}

int
os_printf(const char *format, ...)
{
    int ret = 0;
    va_list ap;

    va_start(ap, format);
    ret += vprintf(format, ap);
    va_end(ap);

    return ret;
}

int
os_vprintf(const char *format, va_list ap)
{
    return vprintf(format, ap);
}

uint64
os_time_get_boot_microsecond(void)
{
    return (uint64)esp_timer_get_time();
}

uint8 *
os_thread_get_stack_boundary(void)
{
#if defined(CONFIG_FREERTOS_USE_TRACE_FACILITY)
    TaskStatus_t pxTaskStatus;
    vTaskGetInfo(xTaskGetCurrentTaskHandle(), &pxTaskStatus, pdTRUE, eInvalid);
    return pxTaskStatus.pxStackBase;
#else // !defined(CONFIG_FREERTOS_USE_TRACE_FACILITY)
    return NULL;
#endif
}

int
os_usleep(uint32 usec)
{
    return usleep(usec);
}
