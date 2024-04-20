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
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <android/log.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BH_PLATFORM_ANDROID
#define BH_PLATFORM_ANDROID
#endif

/* Stack size of applet threads's native part.  */
#define BH_APPLET_PRESERVED_STACK_SIZE (32 * 1024)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 0

typedef pthread_t korp_tid;
typedef pthread_mutex_t korp_mutex;
typedef pthread_cond_t korp_cond;
typedef pthread_t korp_thread;
typedef pthread_rwlock_t korp_rwlock;
typedef sem_t korp_sem;

#define OS_THREAD_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

#define os_thread_local_attribute __thread

#define bh_socket_t int

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

#define os_getpagesize getpagesize

typedef long int __syscall_slong_t;

#if __ANDROID_API__ < 19

int
futimens(int __dir_fd, const struct timespec __times[2]);

#endif

#if __ANDROID_API__ < 21

int
posix_fallocate(int __fd, off_t __offset, off_t __length);

int
posix_fadvise(int fd, off_t offset, off_t len, int advice);

int
linkat(int __old_dir_fd, const char *__old_path, int __new_dir_fd,
       const char *__new_path, int __flags);

int
symlinkat(const char *__old_path, int __new_dir_fd, const char *__new_path);

ssize_t
readlinkat(int __dir_fd, const char *__path, char *__buf, size_t __buf_size);

#endif

#if __ANDROID_API__ < 23

long
telldir(DIR *__dir);

void
seekdir(DIR *__dir, long __location);

#endif

ssize_t
preadv(int __fd, const struct iovec *__iov, int __count, off_t __offset);

ssize_t
pwritev(int __fd, const struct iovec *__iov, int __count, off_t __offset);

typedef int os_file_handle;
typedef DIR *os_dir_stream;
typedef int os_raw_file_handle;

static inline os_file_handle
os_get_invalid_handle()
{
    return -1;
}

#ifdef __cplusplus
}
#endif

#endif /* end of _PLATFORM_INTERNAL_H */
