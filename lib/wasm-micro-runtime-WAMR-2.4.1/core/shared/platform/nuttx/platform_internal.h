/*
 * Copyright (C) 2020 XiaoMi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <semaphore.h>

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
typedef pthread_rwlock_t korp_rwlock;
typedef sem_t korp_sem;

#define os_getpagesize getpagesize

#define OS_THREAD_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

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

/*
 * NuttX doesn't have O_DIRECTORY or directory open.
 * REVISIT: maybe this is safer to be disabled at higher level.
 */
#if !defined(O_DIRECTORY)
#define O_DIRECTORY 0
#endif

#if !defined(O_NOFOLLOW)
#define O_NOFOLLOW 0
#endif

#undef CONFIG_HAS_ISATTY
#ifdef CONFIG_SERIAL_TERMIOS
#define CONFIG_HAS_ISATTY 1
#else
#define CONFIG_HAS_ISATTY 0
#endif

#define BUILTIN_LIBC_BUFFERED_PRINTF 1
#define BUILTIN_LIBC_BUFFERED_PRINT_SIZE 128
#define BUILTIN_LIBC_BUFFERED_PRINT_PREFIX

/*
 * NuttX doesn't have openat family.
 */

/* If AT_FDCWD is provided, maybe we have openat family */
#if !defined(AT_FDCWD)

int
openat(int fd, const char *path, int oflags, ...);
int
fstatat(int fd, const char *path, struct stat *buf, int flag);
int
mkdirat(int fd, const char *path, mode_t mode);
ssize_t
readlinkat(int fd, const char *path, char *buf, size_t bufsize);
int
linkat(int fd1, const char *path1, int fd2, const char *path2, int flag);
int
renameat(int fromfd, const char *from, int tofd, const char *to);
int
symlinkat(const char *target, int fd, const char *path);
int
unlinkat(int fd, const char *path, int flag);
int
utimensat(int fd, const char *path, const struct timespec ts[2], int flag);
#define AT_SYMLINK_NOFOLLOW 0
#define AT_SYMLINK_FOLLOW 0
#define AT_REMOVEDIR 0

#endif /* !defined(AT_FDCWD) */

/*
 * NuttX doesn't have fdopendir.
 */

DIR *
fdopendir(int fd);

#if WASM_DISABLE_WAKEUP_BLOCKING_OP == 0
#define OS_ENABLE_WAKEUP_BLOCKING_OP
#endif
void
os_set_signal_number_for_blocking_op(int signo);

typedef int os_file_handle;
typedef DIR *os_dir_stream;
typedef int os_raw_file_handle;

static inline os_file_handle
os_get_invalid_handle(void)
{
    return -1;
}

#ifdef __cplusplus
}
#endif

#endif /* end of _BH_PLATFORM_H */
