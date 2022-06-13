/*
 * Copyright (C) 2020 XiaoMi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>
#include <sys/mman.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BH_PLATFORM_NUTTX
#define BH_PLATFORM_NUTTX
#endif

typedef pthread_t korp_tid;
typedef pthread_mutex_t korp_mutex;
typedef pthread_cond_t korp_cond;
typedef pthread_t korp_thread;

#define BH_APPLET_PRESERVED_STACK_SIZE (2 * BH_KB)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 100

#define os_printf printf
#define os_vprintf vprintf

#if defined(CONFIG_LIBC_DLFCN)
#define BH_HAS_DLFCN 1
#else
#define BH_HAS_DLFCN 0
#endif

/* On NuttX, time_t is uint32_t */
#define BH_TIME_T_MAX 0xffffffff

#ifdef __cplusplus
}
#endif

#endif /* end of _BH_PLATFORM_H */
