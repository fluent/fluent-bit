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

/* Below parts of readv & writev are ported from Nuttx, under Apache License
 * v2.0 */

ssize_t
readv(int fildes, const struct iovec *iov, int iovcnt)
{
    ssize_t ntotal;
    ssize_t nread;
    size_t remaining;
    uint8_t *buffer;
    int i;

    /* Process each entry in the struct iovec array */

    for (i = 0, ntotal = 0; i < iovcnt; i++) {
        /* Ignore zero-length reads */

        if (iov[i].iov_len > 0) {
            buffer = iov[i].iov_base;
            remaining = iov[i].iov_len;

            /* Read repeatedly as necessary to fill buffer */

            do {
                /* NOTE:  read() is a cancellation point */

                nread = read(fildes, buffer, remaining);

                /* Check for a read error */

                if (nread < 0) {
                    return nread;
                }

                /* Check for an end-of-file condition */

                else if (nread == 0) {
                    return ntotal;
                }

                /* Update pointers and counts in order to handle partial
                 * buffer reads.
                 */

                buffer += nread;
                remaining -= nread;
                ntotal += nread;
            } while (remaining > 0);
        }
    }

    return ntotal;
}

ssize_t
writev(int fildes, const struct iovec *iov, int iovcnt)
{
    ssize_t ntotal;
    ssize_t nwritten;
    size_t remaining;
    uint8_t *buffer;
    int i;

    /* Process each entry in the struct iovec array */

    for (i = 0, ntotal = 0; i < iovcnt; i++) {
        /* Ignore zero-length writes */

        if (iov[i].iov_len > 0) {
            buffer = iov[i].iov_base;
            remaining = iov[i].iov_len;

            /* Write repeatedly as necessary to write the entire buffer */

            do {
                /* NOTE:  write() is a cancellation point */

                nwritten = write(fildes, buffer, remaining);

                /* Check for a write error */

                if (nwritten < 0) {
                    return ntotal ? ntotal : -1;
                }

                /* Update pointers and counts in order to handle partial
                 * buffer writes.
                 */

                buffer += nwritten;
                remaining -= nwritten;
                ntotal += nwritten;
            } while (remaining > 0);
        }
    }

    return ntotal;
}

int
openat(int fd, const char *path, int oflags, ...)
{
    errno = ENOSYS;
    return -1;
}

int
fstatat(int fd, const char *path, struct stat *buf, int flag)
{
    errno = ENOSYS;
    return -1;
}

int
mkdirat(int fd, const char *path, mode_t mode)
{
    errno = ENOSYS;
    return -1;
}

ssize_t
readlinkat(int fd, const char *path, char *buf, size_t bufsize)
{
    errno = EINVAL;
    return -1;
}

int
linkat(int fd1, const char *path1, int fd2, const char *path2, int flag)
{
    errno = ENOSYS;
    return -1;
}

int
renameat(int fromfd, const char *from, int tofd, const char *to)
{
    errno = ENOSYS;
    return -1;
}

int
symlinkat(const char *target, int fd, const char *path)
{
    errno = ENOSYS;
    return -1;
}

int
unlinkat(int fd, const char *path, int flag)
{
    errno = ENOSYS;
    return -1;
}

int
utimensat(int fd, const char *path, const struct timespec ts[2], int flag)
{
    errno = ENOSYS;
    return -1;
}

DIR *
fdopendir(int fd)
{
    errno = ENOSYS;
    return NULL;
}

#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(4, 4, 2)
int
ftruncate(int fd, off_t length)
{
    errno = ENOSYS;
    return -1;
}
#endif

int
futimens(int fd, const struct timespec times[2])
{
    errno = ENOSYS;
    return -1;
}

int
nanosleep(const struct timespec *req, struct timespec *rem)
{
    errno = ENOSYS;
    return -1;
}