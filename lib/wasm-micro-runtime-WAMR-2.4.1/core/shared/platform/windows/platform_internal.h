/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

/*
 * Suppress the noisy warnings:
 * winbase.h: warning C5105: macro expansion producing 'defined' has
 * undefined behavior
 */
#pragma warning(disable : 5105)
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
#include <winapifamily.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <basetsd.h>
#include <signal.h>

#include "platform_wasi_types.h"

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

typedef struct {
    SRWLOCK lock;
    bool exclusive;
} korp_rwlock;

/**
 * Create the mutex when os_mutex_lock is called, and no need to
 * CloseHandle() for the static lock's lifetime, since
 * "The system closes the handle automatically when the process
 *  terminates. The mutex object is destroyed when its last
 *  handle has been closed."
 * Refer to:
 *   https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexa
 */
#define OS_THREAD_MUTEX_INITIALIZER NULL

struct os_thread_wait_node;
typedef struct os_thread_wait_node *os_thread_wait_list;
typedef struct korp_cond {
    korp_mutex wait_list_lock;
    os_thread_wait_list thread_wait_list;
    struct os_thread_wait_node *thread_wait_list_end;
} korp_cond;

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

typedef enum os_memory_order {
    os_memory_order_relaxed,
    os_memory_order_consume,
    os_memory_order_acquire,
    os_memory_order_release,
    os_memory_order_acq_rel,
    os_memory_order_seq_cst,
} os_memory_order;

void
bh_atomic_thread_fence(int mem_order);

#define os_atomic_thread_fence bh_atomic_thread_fence

typedef enum windows_handle_type {
    windows_handle_type_socket,
    windows_handle_type_file
} windows_handle_type;

typedef enum windows_access_mode {
    windows_access_mode_read = 1 << 0,
    windows_access_mode_write = 1 << 1
} windows_access_mode;

typedef struct windows_handle {
    windows_handle_type type;
    __wasi_fdflags_t fdflags;
    windows_access_mode access_mode;
    union {
        HANDLE handle;
        SOCKET socket;
    } raw;
} windows_handle;

typedef struct windows_dir_stream {
    // Enough space for the wide filename and the info struct itself
    char info_buf[PATH_MAX * sizeof(wchar_t) + sizeof(FILE_ID_BOTH_DIR_INFO)];
    char current_entry_name[PATH_MAX];
    // An offset into info_buf to read the next entry from
    DWORD cursor;
    int cookie;
    windows_handle *handle;
} windows_dir_stream;

typedef windows_dir_stream *os_dir_stream;

#if WASM_ENABLE_UVWASI == 0
typedef windows_handle *os_file_handle;
typedef HANDLE os_raw_file_handle;
#else
typedef uint32_t os_file_handle;
typedef uint32_t os_raw_file_handle;
#endif

#define bh_socket_t windows_handle *

// UWP apps do not have stdout/stderr handles so provide a default
// implementation of vprintf on debug builds so output from WASI libc is sent to
// the debugger and not lost completely.
#if !defined(BH_VPRINTF) && !defined(NDEBUG) && WINAPI_PARTITION_DESKTOP == 0
#define BH_VPRINTF uwp_print_to_debugger
#define UWP_DEFAULT_VPRINTF
#endif

static inline os_file_handle
os_get_invalid_handle(void)
{
#if WASM_ENABLE_UVWASI == 0
    return NULL;
#else
    return -1;
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* end of _PLATFORM_INTERNAL_H */
