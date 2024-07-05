/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * Copyright (C) 2023 Dylibso.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdarg.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <semaphore.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sched.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BH_PLATFORM_COSMOPOLITAN
#define BH_PLATFORM_COSMOPOLITAN
#endif

/* Stack size of applet threads's native part.  */
#define BH_APPLET_PRESERVED_STACK_SIZE (32 * 1024)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 0

typedef pthread_t korp_tid;
typedef pthread_mutex_t korp_mutex;
typedef pthread_cond_t korp_cond;
typedef pthread_t korp_thread;
typedef sem_t korp_sem;

#define OS_THREAD_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

#define os_thread_local_attribute __thread

#define bh_socket_t int

typedef int os_file_handle;
typedef DIR *os_dir_stream;
typedef int os_raw_file_handle;

#if WASM_DISABLE_WRITE_GS_BASE == 0
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64)
#define os_writegsbase(base_addr)                                 \
    do {                                                          \
        uint64 __gs_value = (uint64)(uintptr_t)base_addr;         \
        asm volatile("wrgsbase %0" ::"r"(__gs_value) : "memory"); \
    } while (0)
#if 0
/* _writegsbase_u64 also works, but need to add -mfsgsbase flag for gcc */
#include <immintrin.h>
#define os_writegsbase(base_addr) \
    _writegsbase_u64(((uint64)(uintptr_t)base_addr))
#endif
#endif
#endif

#if WASM_DISABLE_HW_BOUND_CHECK == 0
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64)            \
    || defined(BUILD_TARGET_AARCH64) || defined(BUILD_TARGET_RISCV64_LP64D) \
    || defined(BUILD_TARGET_RISCV64_LP64)

#include <setjmp.h>

#define OS_ENABLE_HW_BOUND_CHECK

typedef jmp_buf korp_jmpbuf;

#define os_setjmp setjmp
#define os_longjmp longjmp
#define os_alloca alloca

#define os_getpagesize getpagesize

typedef void (*os_signal_handler)(void *sig_addr);

int
os_thread_signal_init(os_signal_handler handler);

void
os_thread_signal_destroy();

bool
os_thread_signal_inited();

void
os_signal_unmask();

void
os_sigreturn();
#endif /* end of BUILD_TARGET_X86_64/AMD_64/AARCH64/RISCV64 */
#endif /* end of WASM_DISABLE_HW_BOUND_CHECK */

#ifdef __cplusplus
}
#endif

#endif /* end of _PLATFORM_INTERNAL_H */
