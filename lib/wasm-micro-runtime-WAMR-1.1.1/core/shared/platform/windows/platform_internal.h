/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <sys/timeb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <malloc.h>
#include <process.h>
#include <winsock2.h>
#include <windows.h>
#include <basetsd.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BH_PLATFORM_WINDOWS
#define BH_PLATFORM_WINDOWS
#endif

#ifdef _MSC_VER
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#endif /* #ifdef _MSC_VER */

/* Stack size of applet threads's native part.  */
#define BH_APPLET_PRESERVED_STACK_SIZE (32 * 1024)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 0

typedef SSIZE_T ssize_t;

typedef void *korp_thread;
typedef void *korp_tid;
typedef void *korp_mutex;
typedef void *korp_sem;

struct os_thread_wait_node;
typedef struct os_thread_wait_node *os_thread_wait_list;
typedef struct korp_cond {
    korp_mutex wait_list_lock;
    os_thread_wait_list thread_wait_list;
} korp_cond;

#define bh_socket_t SOCKET

unsigned
os_getpagesize();
void *
os_mem_commit(void *ptr, size_t size, int flags);
void
os_mem_decommit(void *ptr, size_t size);

#define os_thread_local_attribute __declspec(thread)

#define strncasecmp _strnicmp
#define strcasecmp _stricmp

#if WASM_DISABLE_HW_BOUND_CHECK == 0
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64)

#include <setjmp.h>

#define OS_ENABLE_HW_BOUND_CHECK

typedef jmp_buf korp_jmpbuf;

#define os_setjmp setjmp
#define os_longjmp longjmp

int
os_thread_signal_init();

void
os_thread_signal_destroy();

bool
os_thread_signal_inited();

#define os_signal_unmask() (void)0
#define os_sigreturn() (void)0

#endif /* end of BUILD_TARGET_X86_64/AMD_64 */
#endif /* end of WASM_DISABLE_HW_BOUND_CHECK */

#ifdef __cplusplus
}
#endif

#endif /* end of _PLATFORM_INTERNAL_H */
