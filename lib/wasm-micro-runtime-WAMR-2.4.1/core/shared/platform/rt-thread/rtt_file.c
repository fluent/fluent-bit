/*
 * Copyright 2024 Sony Semiconductor Solutions Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdint.h>

struct iovec {
    void *iov_base;
    size_t iov_len;
};

ssize_t
readv(int fd, const struct iovec *iov, int iovcnt)
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

                nread = read(fd, buffer, remaining);

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
writev(int fd, const struct iovec *iov, int iovcnt)
{
    uint16_t i, num;
    int length;

    num = 0;
    for (i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > 0) {
            length = write(fd, iov[i].iov_base, iov[i].iov_len);
            if (length != iov[i].iov_len)
                return errno;

            num += iov[i].iov_len;
        }
    }
    return num;
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
utimensat(int fd, const char *path, const struct timespec *ts, int flag)
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

int
fdatasync(int fd)
{
    errno = ENOSYS;
    return -1;
}

ssize_t
preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    errno = ENOSYS;
    return 0;
}

ssize_t
pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    errno = ENOSYS;
    return 0;
}

char *
realpath(char *path, char *resolved_path)
{
    errno = ENOSYS;
    return NULL;
}

int
futimens(int fd, const struct timespec *times)
{
    errno = ENOSYS;
    return -1;
}

int
posix_fallocate(int __fd, off_t __offset, off_t __length)
{
    errno = ENOSYS;
    return -1;
}

os_raw_file_handle
os_invalid_raw_handle(void)
{
    return -1;
}
