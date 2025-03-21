/*
 * Copyright (c) 2021, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef RTTHREAD_PLATFORM_INTERNAL_H
#define RTTHREAD_PLATFORM_INTERNAL_H

#include <rtthread.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <ctype.h>

#if defined(WASM_ENABLE_AOT)
#if defined(RTT_WAMR_BUILD_TARGET_THUMB)
#define BUILD_TARGET "thumbv4t"
#elif defined(RTT_WAMR_BUILD_TARGET_ARMV7)
#define BUILD_TARGET "armv7"
#elif defined(RTT_WAMR_BUILD_TARGET_ARMV6)
#define BUILD_TARGET "armv6"
#elif defined(RTT_WAMR_BUILD_TARGET_ARMV4)
#define BUILD_TARGET "armv4"
#elif defined(RTT_WAMR_BUILD_TARGET_X86_32)
#define BUILD_TARGET "X86_32"
#else
#error "unsupported aot platform."
#endif
#endif /* WASM_ENABLE_AOT */

typedef rt_thread_t korp_tid;
typedef struct rt_mutex korp_mutex;
typedef struct rt_thread korp_cond;
typedef struct rt_thread korp_thread;
typedef unsigned int korp_sem;

/* korp_rwlock is used in platform_api_extension.h,
   we just define the type to make the compiler happy */
typedef struct {
    int dummy;
} korp_rwlock;

typedef rt_uint8_t uint8_t;
typedef rt_int8_t int8_t;
typedef rt_uint16_t uint16_t;
typedef rt_int16_t int16_t;
typedef rt_uint64_t uint64_t;
typedef rt_int64_t int64_t;

/* The below types are used in platform_api_extension.h,
   we just define them to make the compiler happy */
typedef int os_file_handle;
typedef void *os_dir_stream;
typedef int os_raw_file_handle;

static inline os_file_handle
os_get_invalid_handle()
{
    return -1;
}

#endif /* RTTHREAD_PLATFORM_INTERNAL_H */
