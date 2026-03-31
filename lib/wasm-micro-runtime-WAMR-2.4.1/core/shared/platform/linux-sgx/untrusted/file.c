/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sched.h>
#include <poll.h>
#include <errno.h>

int
ocall_open(const char *pathname, int flags, bool has_mode, unsigned mode)
{
    if (has_mode) {
        return open(pathname, flags, (mode_t)mode);
    }
    else {
        return open(pathname, flags);
    }
}

int
ocall_openat(int dirfd, const char *pathname, int flags, bool has_mode,
             unsigned mode)
{
    if (has_mode) {
        return openat(dirfd, pathname, flags, (mode_t)mode);
    }
    else {
        return openat(dirfd, pathname, flags);
    }
}

int
ocall_close(int fd)
{
    return close(fd);
}

ssize_t
ocall_read(int fd, void *buf, size_t read_size)
{
    if (buf != NULL) {
        return read(fd, buf, read_size);
    }
    else {
        return -1;
    }
}

off_t
ocall_lseek(int fd, off_t offset, int whence)
{
    return lseek(fd, offset, whence);
}

int
ocall_ftruncate(int fd, off_t length)
{
    return ftruncate(fd, length);
}

int
ocall_fsync(int fd)
{
    return fsync(fd);
}

int
ocall_fdatasync(int fd)
{
    return fdatasync(fd);
}

int
ocall_isatty(int fd)
{
    return isatty(fd);
}

void
ocall_fdopendir(int fd, void **dirp)
{
    if (dirp) {
        *(DIR **)dirp = fdopendir(fd);
    }
}

void *
ocall_readdir(void *dirp)
{
    DIR *p_dirp = (DIR *)dirp;
    return readdir(p_dirp);
}

void
ocall_rewinddir(void *dirp)
{
    DIR *p_dirp = (DIR *)dirp;
    if (p_dirp) {
        rewinddir(p_dirp);
    }
}

void
ocall_seekdir(void *dirp, long loc)
{
    DIR *p_dirp = (DIR *)dirp;

    if (p_dirp) {
        seekdir(p_dirp, loc);
    }
}

long
ocall_telldir(void *dirp)
{
    DIR *p_dirp = (DIR *)dirp;
    if (p_dirp) {
        return telldir(p_dirp);
    }
    return -1;
}

int
ocall_closedir(void *dirp)
{
    DIR *p_dirp = (DIR *)dirp;
    if (p_dirp) {
        return closedir(p_dirp);
    }
    return -1;
}

int
ocall_stat(const char *pathname, void *buf, unsigned int buf_len)
{
    return stat(pathname, (struct stat *)buf);
}

int
ocall_fstat(int fd, void *buf, unsigned int buf_len)
{
    return fstat(fd, (struct stat *)buf);
}

int
ocall_fstatat(int dirfd, const char *pathname, void *buf, unsigned int buf_len,
              int flags)
{
    return fstatat(dirfd, pathname, (struct stat *)buf, flags);
}

int
ocall_mkdirat(int dirfd, const char *pathname, unsigned mode)
{
    return mkdirat(dirfd, pathname, (mode_t)mode);
}

int
ocall_link(const char *oldpath, const char *newpath)
{
    return link(oldpath, newpath);
}

int
ocall_linkat(int olddirfd, const char *oldpath, int newdirfd,
             const char *newpath, int flags)
{
    return linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

int
ocall_unlinkat(int dirfd, const char *pathname, int flags)
{
    return unlinkat(dirfd, pathname, flags);
}

ssize_t
ocall_readlink(const char *pathname, char *buf, size_t bufsiz)
{
    return readlink(pathname, buf, bufsiz);
}

ssize_t
ocall_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    return readlinkat(dirfd, pathname, buf, bufsiz);
}

int
ocall_renameat(int olddirfd, const char *oldpath, int newdirfd,
               const char *newpath)
{
    return renameat(olddirfd, oldpath, newdirfd, newpath);
}

int
ocall_symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    return symlinkat(target, newdirfd, linkpath);
}

int
ocall_ioctl(int fd, unsigned long request, void *arg, unsigned int arg_len)
{
    /* support just int *arg temporally */
    return ioctl(fd, request, (int *)arg);
}

int
ocall_fcntl(int fd, int cmd)
{
    return fcntl(fd, cmd);
}

int
ocall_fcntl_long(int fd, int cmd, long arg)
{
    return fcntl(fd, cmd, arg);
}

ssize_t
ocall_readv(int fd, char *iov_buf, unsigned int buf_size, int iovcnt,
            bool has_offset, off_t offset)
{
    struct iovec *iov = (struct iovec *)iov_buf;
    ssize_t ret;
    int i;

    for (i = 0; i < iovcnt; i++) {
        iov[i].iov_base = iov_buf + (unsigned)(uintptr_t)iov[i].iov_base;
    }

    if (has_offset)
        ret = preadv(fd, iov, iovcnt, offset);
    else
        ret = readv(fd, iov, iovcnt);

    return ret;
}

ssize_t
ocall_writev(int fd, char *iov_buf, unsigned int buf_size, int iovcnt,
             bool has_offset, off_t offset)
{
    struct iovec *iov = (struct iovec *)iov_buf;
    int i;
    ssize_t ret;

    for (i = 0; i < iovcnt; i++) {
        iov[i].iov_base = iov_buf + (unsigned)(uintptr_t)iov[i].iov_base;
    }

    if (has_offset)
        ret = pwritev(fd, iov, iovcnt, offset);
    else
        ret = writev(fd, iov, iovcnt);

    return ret;
}

int
ocall_realpath(const char *path, char *buf, unsigned int buf_len)
{
    char *val = NULL;
    val = realpath(path, buf);
    if (val != NULL) {
        return 0;
    }
    return -1;
}

int
ocall_posix_fallocate(int fd, off_t offset, off_t len)
{
    return posix_fallocate(fd, offset, len);
}

int
ocall_poll(void *fds, unsigned nfds, int timeout, unsigned int fds_len)
{
    return poll((struct pollfd *)fds, (nfds_t)nfds, timeout);
}

int
ocall_getopt(int argc, char *argv_buf, unsigned int argv_buf_len,
             const char *optstring)
{
    int ret;
    int i;
    char **argv = (char **)argv_buf;

    for (i = 0; i < argc; i++) {
        argv[i] = argv_buf + (uintptr_t)argv[i];
    }

    return getopt(argc, argv, optstring);
}

int
ocall_sched_yield()
{
    return sched_yield();
}

int
ocall_get_errno()
{
    return errno;
}
