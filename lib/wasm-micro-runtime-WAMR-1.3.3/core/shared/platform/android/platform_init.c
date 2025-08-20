/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

#define API_NOT_SUPPORT_ERROR(API, VERSION)                                   \
    __android_log_print(ANDROID_LOG_ERROR, "wasm_runtime::",                  \
                        "%s() is only supported when __ANDROID_API__ >= %s.", \
                        #API, #VERSION);

int
bh_platform_init()
{
    return 0;
}

void
bh_platform_destroy()
{}

int
os_printf(const char *fmt, ...)
{
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = __android_log_vprint(ANDROID_LOG_INFO, "wasm_runtime::", fmt, ap);
    va_end(ap);

    return ret;
}

int
os_vprintf(const char *fmt, va_list ap)
{
    return __android_log_vprint(ANDROID_LOG_INFO, "wasm_runtime::", fmt, ap);
}

#if __ANDROID_API__ < 19

int
futimens(int __dir_fd, const struct timespec __times[2])
{
    API_NOT_SUPPORT_ERROR(futimens, 19);
    return -1;
}

#endif

#if __ANDROID_API__ < 21

int
posix_fallocate(int __fd, off_t __offset, off_t __length)
{
    API_NOT_SUPPORT_ERROR(posix_fallocate, 21);
    return -1;
}

int
posix_fadvise(int fd, off_t offset, off_t len, int advice)
{
    API_NOT_SUPPORT_ERROR(posix_fadvise, 21);
    return -1;
}

int
linkat(int __old_dir_fd, const char *__old_path, int __new_dir_fd,
       const char *__new_path, int __flags)
{
    API_NOT_SUPPORT_ERROR(linkat, 21);
    return -1;
}

int
symlinkat(const char *__old_path, int __new_dir_fd, const char *__new_path)
{
    API_NOT_SUPPORT_ERROR(symlinkat, 21);
    return -1;
}

ssize_t
readlinkat(int __dir_fd, const char *__path, char *__buf, size_t __buf_size)
{
    API_NOT_SUPPORT_ERROR(readlinkat, 21);
    return -1;
}

int
accept4(int __fd, struct sockaddr *__addr, socklen_t *__addr_length,
        int __flags)
{
    API_NOT_SUPPORT_ERROR(accept4, 21);
    return -1;
}

int
dup3(int oldfd, int newfd, int cloexec)
{
    API_NOT_SUPPORT_ERROR(dup3, 21);
    return -1;
}

int
pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock_id)
{
    API_NOT_SUPPORT_ERROR(pthread_condattr_setclock, 21);
    return -1;
}

int
epoll_create1(int flags)
{
    API_NOT_SUPPORT_ERROR(epoll_create1, 21);
    return -1;
}

int
epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout,
            const sigset_t *sigmask)
{
    API_NOT_SUPPORT_ERROR(epoll_pwait, 21);
    return -1;
}

int
inotify_init1(int flags)
{
    API_NOT_SUPPORT_ERROR(inotify_init1, 21);
    return -1;
}

#endif

#if __ANDROID_API__ < 23

long
telldir(DIR *__dir)
{
    API_NOT_SUPPORT_ERROR(telldir, 23);
    return -1;
}

void
seekdir(DIR *__dir, long __location)
{
    API_NOT_SUPPORT_ERROR(seekdir, 23);
}

#endif

#if __ANDROID_API__ < 24

ssize_t
preadv(int __fd, const struct iovec *__iov, int __count, off_t __offset)
{
    API_NOT_SUPPORT_ERROR(preadv, 24);
    return -1;
}

ssize_t
pwritev(int __fd, const struct iovec *__iov, int __count, off_t __offset)
{
    API_NOT_SUPPORT_ERROR(pwritev, 24);
    return -1;
}

#endif
