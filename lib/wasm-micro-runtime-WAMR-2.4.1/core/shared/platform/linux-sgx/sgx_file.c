/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "sgx_error.h"
#include "sgx_file.h"

#if WASM_ENABLE_SGX_IPFS != 0
#include "sgx_ipfs.h"
#endif

#ifndef SGX_DISABLE_WASI

#define TRACE_FUNC() os_printf("undefined %s\n", __FUNCTION__)
#define TRACE_OCALL_FAIL() os_printf("ocall %s failed!\n", __FUNCTION__)

/** fd **/
int
ocall_open(int *p_fd, const char *pathname, int flags, bool has_mode,
           unsigned mode);

int
ocall_openat(int *p_fd, int dirfd, const char *pathname, int flags,
             bool has_mode, unsigned mode);

int
ocall_read(ssize_t *p_ret, int fd, void *buf, size_t read_size);

int
ocall_close(int *p_ret, int fd);

int
ocall_lseek(off_t *p_ret, int fd, off_t offset, int whence);

int
ocall_ftruncate(int *p_ret, int fd, off_t length);

int
ocall_fsync(int *p_ret, int fd);

int
ocall_fdatasync(int *p_ret, int fd);

int
ocall_isatty(int *p_ret, int fd);
/** fd end  **/

/** DIR **/
int
ocall_fdopendir(int fd, void **p_dirp);

int
ocall_readdir(void **p_dirent, void *dirp);

int
ocall_rewinddir(void *dirp);

int
ocall_seekdir(void *dirp, long loc);

int
ocall_telldir(long *p_dir, void *dirp);

int
ocall_closedir(int *p_ret, void *dirp);
/** DIR end **/

/** stat **/
int
ocall_stat(int *p_ret, const char *pathname, void *buf, unsigned int buf_len);
int
ocall_fstat(int *p_ret, int fd, void *buf, unsigned int buf_len);
int
ocall_fstatat(int *p_ret, int dirfd, const char *pathname, void *buf,
              unsigned int buf_len, int flags);
/** stat end **/

/** link **/
int
ocall_mkdirat(int *p_ret, int dirfd, const char *pathname, unsigned mode);
int
ocall_link(int *p_ret, const char *oldpath, const char *newpath);
int
ocall_linkat(int *p_ret, int olddirfd, const char *oldpath, int newdirfd,
             const char *newpath, int flags);
int
ocall_unlinkat(int *p_ret, int dirfd, const char *pathname, int flags);
int
ocall_readlink(ssize_t *p_ret, const char *pathname, char *buf, size_t bufsiz);
int
ocall_readlinkat(ssize_t *p_ret, int dirfd, const char *pathname, char *buf,
                 size_t bufsiz);
int
ocall_renameat(int *p_ret, int olddirfd, const char *oldpath, int newdirfd,
               const char *newpath);
int
ocall_symlinkat(int *p_ret, const char *target, int newdirfd,
                const char *linkpath);
/** link end **/

/** control **/
int
ocall_ioctl(int *p_ret, int fd, unsigned long request, void *arg,
            unsigned int arg_len);
int
ocall_fcntl(int *p_ret, int fd, int cmd);
int
ocall_fcntl_long(int *p_ret, int fd, int cmd, long arg);
/** control end **/

/** **/
int
ocall_realpath(int *p_ret, const char *path, char *buf, unsigned int buf_len);
int
ocall_posix_fallocate(int *p_ret, int fd, off_t offset, off_t len);
int
ocall_poll(int *p_ret, void *fds, unsigned nfds, int timeout,
           unsigned int fds_len);
int
ocall_getopt(int *p_ret, int argc, char *argv_buf, unsigned int argv_buf_len,
             const char *optstring);
int
ocall_sched_yield(int *p_ret);

/** struct iovec **/
ssize_t
ocall_readv(ssize_t *p_ret, int fd, char *iov_buf, unsigned int buf_size,
            int iovcnt, bool has_offset, off_t offset);
ssize_t
ocall_writev(ssize_t *p_ret, int fd, char *iov_buf, unsigned int buf_size,
             int iovcnt, bool has_offset, off_t offset);
/** iovec end **/

int
ocall_get_errno(int *p_ret);

int
open(const char *pathname, int flags, ...)
{
    int fd;
    bool has_mode = false;
    mode_t mode = 0;

    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        has_mode = true;
    }

    if (SGX_SUCCESS != ocall_open(&fd, pathname, flags, has_mode, mode)) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (fd >= 0 && (flags & O_CLOEXEC))
        fcntl(fd, F_SETFD, FD_CLOEXEC);

    if (fd == -1)
        errno = get_errno();
    return fd;
}

int
openat(int dirfd, const char *pathname, int flags, ...)
{
    int fd;
    bool has_mode = false;
    mode_t mode = 0;

    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        has_mode = true;
    }

    if (SGX_SUCCESS
        != ocall_openat(&fd, dirfd, pathname, flags, has_mode, mode)) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (fd >= 0 && (flags & O_CLOEXEC))
        fcntl(fd, F_SETFD, FD_CLOEXEC);

    if (fd == -1)
        errno = get_errno();

#if WASM_ENABLE_SGX_IPFS != 0
    struct stat sb;
    int ret = fstatat(dirfd, pathname, &sb, 0);
    if (ret < 0) {
        if (ocall_close(&ret, fd) != SGX_SUCCESS) {
            TRACE_OCALL_FAIL();
        }
        return -1;
    }

    // Ony files are managed by SGX IPFS
    if (S_ISREG(sb.st_mode)) {
        // When WAMR uses Intel SGX IPFS to enabled, it opens a second
        // file descriptor to interact with the secure file.
        // The first file descriptor opened earlier is used to interact
        // with the metadata of the file (e.g., time, flags, etc.).
        void *file_ptr = ipfs_fopen(fd, flags);
        if (file_ptr == NULL) {
            if (ocall_close(&ret, fd) != SGX_SUCCESS) {
                TRACE_OCALL_FAIL();
            }
            return -1;
        }
    }
#endif

    return fd;
}

int
close(int fd)
{
    int ret;

#if WASM_ENABLE_SGX_IPFS != 0
    // Close the IPFS file pointer in addition of the file descriptor
    ret = ipfs_close(fd);
    if (ret == -1)
        errno = get_errno();
#endif

    if (ocall_close(&ret, fd) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
    if (ret == -1)
        errno = get_errno();
    return ret;
}

ssize_t
read(int fd, void *buf, size_t size)
{
    ssize_t ret;
    int size_read_max = 2048, size_read, total_size_read = 0, count, i;
    char *p = buf;

    if (buf == NULL) {
        TRACE_FUNC();
        return -1;
    }

    count = (size + size_read_max - 1) / size_read_max;
    for (i = 0; i < count; i++) {
        size_read = (i < count - 1) ? size_read_max : size - size_read_max * i;

        if (ocall_read(&ret, fd, p, size_read) != SGX_SUCCESS) {
            TRACE_OCALL_FAIL();
            return -1;
        }
        if (ret == -1) {
            /* read failed */
            errno = get_errno();
            return -1;
        }

        p += ret;
        total_size_read += ret;

        if (ret < size_read)
            /* end of file */
            break;
    }
    return total_size_read;
}

DIR *
fdopendir(int fd)
{
    DIR *result = NULL;

    result = (DIR *)BH_MALLOC(sizeof(DIR));
    if (!result)
        return NULL;

    if (ocall_fdopendir(fd, (void **)result) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        BH_FREE(result);
        return NULL;
    }

    if ((void *)*result == NULL) { /* opendir failed */
        TRACE_FUNC();
        BH_FREE(result);
        errno = get_errno();
        return NULL;
    }

    return result;
}

struct dirent *
readdir(DIR *dirp)
{
    struct dirent *result;

    if (dirp == NULL)
        return NULL;

    if (ocall_readdir((void **)&result, (void *)*dirp) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return NULL;
    }

    if (!result)
        errno = get_errno();
    return result;
}

void
rewinddir(DIR *dirp)
{
    if (ocall_rewinddir((void *)*dirp) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
    }
}

void
seekdir(DIR *dirp, long loc)
{
    if (ocall_seekdir((void *)*dirp, loc) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
    }
}

long
telldir(DIR *dirp)
{
    long ret;

    if (ocall_telldir(&ret, (void *)*dirp) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
closedir(DIR *dirp)
{
    int ret;

    if (ocall_closedir(&ret, (void *)*dirp) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
    BH_FREE(dirp);
    if (ret == -1)
        errno = get_errno();
    return ret;
}

static ssize_t
readv_internal(int fd, const struct iovec *iov, int iovcnt, bool has_offset,
               off_t offset)
{
    ssize_t ret, size_left;
    struct iovec *iov1;
    int i;
    char *p;
    uint64 total_size = sizeof(struct iovec) * (uint64)iovcnt;

    if (iov == NULL || iovcnt < 1)
        return -1;

    for (i = 0; i < iovcnt; i++) {
        total_size += iov[i].iov_len;
    }

    if (total_size >= UINT32_MAX)
        return -1;

#if WASM_ENABLE_SGX_IPFS != 0
    if (fd > 2) {
        return ipfs_read(fd, iov, iovcnt, has_offset, offset);
    }
#endif

    iov1 = BH_MALLOC((uint32)total_size);

    if (iov1 == NULL)
        return -1;

    memset(iov1, 0, (uint32)total_size);

    p = (char *)(uintptr_t)(sizeof(struct iovec) * iovcnt);

    for (i = 0; i < iovcnt; i++) {
        iov1[i].iov_len = iov[i].iov_len;
        iov1[i].iov_base = p;
        p += iov[i].iov_len;
    }

    if (ocall_readv(&ret, fd, (char *)iov1, (uint32)total_size, iovcnt,
                    has_offset, offset)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        BH_FREE(iov1);
        return -1;
    }

    p = (char *)(uintptr_t)(sizeof(struct iovec) * iovcnt);

    size_left = ret;
    for (i = 0; i < iovcnt; i++) {
        if (size_left > iov[i].iov_len) {
            memcpy(iov[i].iov_base, (uintptr_t)p + (char *)iov1,
                   iov[i].iov_len);
            p += iov[i].iov_len;
            size_left -= iov[i].iov_len;
        }
        else {
            memcpy(iov[i].iov_base, (uintptr_t)p + (char *)iov1, size_left);
            break;
        }
    }

    BH_FREE(iov1);
    if (ret == -1)
        errno = get_errno();
    return ret;
}

static ssize_t
writev_internal(int fd, const struct iovec *iov, int iovcnt, bool has_offset,
                off_t offset)
{
    ssize_t ret;
    struct iovec *iov1;
    int i;
    char *p;
    uint64 total_size = sizeof(struct iovec) * (uint64)iovcnt;

    if (iov == NULL || iovcnt < 1)
        return -1;

    for (i = 0; i < iovcnt; i++) {
        total_size += iov[i].iov_len;
    }

    if (total_size >= UINT32_MAX)
        return -1;

#if WASM_ENABLE_SGX_IPFS != 0
    if (fd > 2) {
        return ipfs_write(fd, iov, iovcnt, has_offset, offset);
    }
#endif

    iov1 = BH_MALLOC((uint32)total_size);

    if (iov1 == NULL)
        return -1;

    memset(iov1, 0, (uint32)total_size);

    p = (char *)(uintptr_t)(sizeof(struct iovec) * iovcnt);

    for (i = 0; i < iovcnt; i++) {
        iov1[i].iov_len = iov[i].iov_len;
        iov1[i].iov_base = p;
        memcpy((uintptr_t)p + (char *)iov1, iov[i].iov_base, iov[i].iov_len);
        p += iov[i].iov_len;
    }

    if (ocall_writev(&ret, fd, (char *)iov1, (uint32)total_size, iovcnt,
                     has_offset, offset)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        BH_FREE(iov1);
        return -1;
    }

    BH_FREE(iov1);
    if (ret == -1)
        errno = get_errno();
    return ret;
}

ssize_t
readv(int fd, const struct iovec *iov, int iovcnt)
{
    return readv_internal(fd, iov, iovcnt, false, 0);
}

ssize_t
writev(int fd, const struct iovec *iov, int iovcnt)
{
    return writev_internal(fd, iov, iovcnt, false, 0);
}

ssize_t
preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    return readv_internal(fd, iov, iovcnt, true, offset);
}

ssize_t
pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    return writev_internal(fd, iov, iovcnt, true, offset);
}

off_t
lseek(int fd, off_t offset, int whence)
{
    off_t ret;

#if WASM_ENABLE_SGX_IPFS != 0
    ret = ipfs_lseek(fd, offset, whence);
#else
    if (ocall_lseek(&ret, fd, (long)offset, whence) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
    if (ret == -1)
        errno = get_errno();
#endif

    return ret;
}

int
ftruncate(int fd, off_t length)
{
    int ret;

#if WASM_ENABLE_SGX_IPFS != 0
    ret = ipfs_ftruncate(fd, length);
#else
    if (ocall_ftruncate(&ret, fd, length) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
    if (ret == -1)
        errno = get_errno();
#endif

    return ret;
}

int
stat(const char *pathname, struct stat *statbuf)
{
    int ret;

    if (statbuf == NULL)
        return -1;

    if (ocall_stat(&ret, pathname, (void *)statbuf, sizeof(struct stat))
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
fstat(int fd, struct stat *statbuf)
{
    int ret;

    if (statbuf == NULL)
        return -1;

    if (ocall_fstat(&ret, fd, (void *)statbuf, sizeof(struct stat))
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    int ret;

    if (statbuf == NULL)
        return -1;

    if (ocall_fstatat(&ret, dirfd, pathname, (void *)statbuf,
                      sizeof(struct stat), flags)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
fsync(int fd)
{
    int ret;

#if WASM_ENABLE_SGX_IPFS != 0
    ret = ipfs_fflush(fd);
#else
    if (ocall_fsync(&ret, fd) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
    if (ret == -1)
        errno = get_errno();
#endif

    return ret;
}

int
fdatasync(int fd)
{
    int ret;

#if WASM_ENABLE_SGX_IPFS != 0
    ret = ipfs_fflush(fd);
#else
    if (ocall_fdatasync(&ret, fd) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
    if (ret == -1)
        errno = get_errno();
#endif

    return ret;
}

int
mkdirat(int dirfd, const char *pathname, mode_t mode)
{
    int ret;

    if (ocall_mkdirat(&ret, dirfd, pathname, mode) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
link(const char *oldpath, const char *newpath)
{
    int ret;

    if (ocall_link(&ret, oldpath, newpath) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath,
       int flags)
{
    int ret;

    if (ocall_linkat(&ret, olddirfd, oldpath, newdirfd, newpath, flags)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
unlinkat(int dirfd, const char *pathname, int flags)
{
    int ret;

    if (ocall_unlinkat(&ret, dirfd, pathname, flags) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

ssize_t
readlink(const char *pathname, char *buf, size_t bufsiz)
{
    ssize_t ret;

    if (buf == NULL)
        return -1;

    if (ocall_readlink(&ret, pathname, buf, bufsiz) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

ssize_t
readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    ssize_t ret;

    if (buf == NULL)
        return -1;

    if (ocall_readlinkat(&ret, dirfd, pathname, buf, bufsiz) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    int ret;

    if (ocall_symlinkat(&ret, target, newdirfd, linkpath) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    int ret;

    if (ocall_renameat(&ret, olddirfd, oldpath, newdirfd, newpath)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
ioctl(int fd, unsigned long request, ...)
{
    int ret;
    va_list args;

    switch (request) {
        case FIONREAD:
            va_start(args, request);
            int *arg = (int *)va_arg(args, int *);
            if (ocall_ioctl(&ret, fd, request, arg, sizeof(*arg))
                != SGX_SUCCESS) {
                TRACE_OCALL_FAIL();
                va_end(args);
                return -1;
            }
            va_end(args);
            break;

        default:
            os_printf("ioctl failed: unknown request", request);
            return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
fcntl(int fd, int cmd, ... /* arg */)
{
    int ret;
    va_list args;

    switch (cmd) {
        case F_GETFD:
        case F_GETFL:
            if (ocall_fcntl(&ret, fd, cmd) != SGX_SUCCESS) {
                TRACE_OCALL_FAIL();
                return -1;
            }
            break;

        case F_DUPFD:
        case F_SETFD:
        case F_SETFL:
            va_start(args, cmd);
            long arg_1 = (long)va_arg(args, long);
            if (ocall_fcntl_long(&ret, fd, cmd, arg_1) != SGX_SUCCESS) {
                TRACE_OCALL_FAIL();
                va_end(args);
                return -1;
            }
            va_end(args);
            break;

        default:
            os_printf("fcntl failed: unknown cmd %d.\n", cmd);
            return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
isatty(int fd)
{
    int ret;

    if (ocall_isatty(&ret, fd) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
    if (ret == 0)
        errno = get_errno();
    return ret;
}

char *
realpath(const char *path, char *resolved_path)
{
    int ret;
    char buf[PATH_MAX] = { 0 };

    if (ocall_realpath(&ret, path, buf, PATH_MAX) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return (char *)NULL;
    }

    if (ret != 0)
        return (char *)NULL;

    if (resolved_path) {
        strcpy(resolved_path, buf);
    }
    else {
        resolved_path = BH_MALLOC(strlen(buf) + 1);
        if (resolved_path == NULL)
            return NULL;
        strcpy(resolved_path, buf);
    }

    return resolved_path;
}

int
posix_fallocate(int fd, off_t offset, off_t len)
{
    int ret;

#if WASM_ENABLE_SGX_IPFS != 0
    ret = ipfs_posix_fallocate(fd, offset, len);
#else
    if (ocall_posix_fallocate(&ret, fd, offset, len) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
#endif

    return ret;
}

int
poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int ret;

    if (fds == NULL)
        return -1;

    if (ocall_poll(&ret, fds, nfds, timeout, sizeof(*fds) * nfds)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
getopt(int argc, char *const argv[], const char *optstring)
{
    int ret;
    char **argv1;
    char *p;
    int i;
    uint64 total_size = sizeof(char *) * (uint64)argc;

    for (i = 0; i < argc; i++) {
        total_size += strlen(argv[i]) + 1;
    }

    if (total_size >= UINT32_MAX)
        return -1;

    argv1 = BH_MALLOC((uint32)total_size);

    if (argv1 == NULL)
        return -1;

    p = (char *)(uintptr_t)(sizeof(char *) * argc);

    for (i = 0; i < argc; i++) {
        argv1[i] = p;
        strcpy((char *)argv1 + (uintptr_t)p, argv[i]);
        p += ((uintptr_t)strlen(argv[i]) + 1);
    }

    if (ocall_getopt(&ret, argc, (char *)argv1, total_size, optstring)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        BH_FREE(argv1);
        return -1;
    }

    BH_FREE(argv1);
    if (ret == -1)
        errno = get_errno();
    return ret;
}

int
sched_yield(void)
{
    int ret;

    if (ocall_sched_yield(&ret) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
    if (ret == -1)
        errno = get_errno();
    return ret;
}

ssize_t
getrandom(void *buf, size_t buflen, unsigned int flags)
{
    sgx_status_t ret;

    if (!buf || buflen > INT32_MAX || flags != 0) {
        errno = EINVAL;
        return -1;
    }

    ret = sgx_read_rand(buf, buflen);
    if (ret != SGX_SUCCESS) {
        errno = EFAULT;
        return -1;
    }

    return (ssize_t)buflen;
}

#define RDRAND_RETRIES 3

static int
rdrand64_step(uint64 *seed)
{
    uint8 ok;
    __asm__ volatile("rdseed %0; setc %1" : "=r"(*seed), "=qm"(ok));
    return (int)ok;
}

static int
rdrand64_retry(uint64 *rand, uint32 retries)
{
    uint32 count = 0;

    while (count++ <= retries) {
        if (rdrand64_step(rand)) {
            return -1;
        }
    }
    return 0;
}

static uint32
rdrand_get_bytes(uint8 *dest, uint32 n)
{
    uint8 *head_start = dest, *tail_start = NULL;
    uint64 *block_start;
    uint32 count, ltail, lhead, lblock;
    uint64 i, temp_rand;

    /* Get the address of the first 64-bit aligned block in the
       destination buffer. */
    if (((uintptr_t)head_start & (uintptr_t)7) == 0) {
        /* already 8-byte aligned */
        block_start = (uint64 *)head_start;
        lhead = 0;
        lblock = n & ~7;
    }
    else {
        /* next 8-byte aligned */
        block_start = (uint64 *)(((uintptr_t)head_start + 7) & ~(uintptr_t)7);
        lhead = (uint32)((uintptr_t)block_start - (uintptr_t)head_start);
        lblock = (n - lhead) & ~7;
    }

    /* Compute the number of 64-bit blocks and the remaining number
       of bytes (the tail) */
    ltail = n - lblock - lhead;
    if (ltail > 0) {
        tail_start = (uint8 *)block_start + lblock;
    }

    /* Populate the starting, mis-aligned section (the head) */
    if (lhead > 0) {
        if (!rdrand64_retry(&temp_rand, RDRAND_RETRIES)) {
            return 0;
        }
        memcpy(head_start, &temp_rand, lhead);
    }

    /* Populate the central, aligned blocks */
    count = lblock / 8;
    for (i = 0; i < count; i++, block_start++) {
        if (!rdrand64_retry(block_start, RDRAND_RETRIES)) {
            return i * 8 + lhead;
        }
    }

    /* Populate the tail */
    if (ltail > 0) {
        if (!rdrand64_retry(&temp_rand, RDRAND_RETRIES)) {
            return count * 8 + lhead;
        }

        memcpy(tail_start, &temp_rand, ltail);
    }

    return n;
}

int
getentropy(void *buffer, size_t length)
{
    uint32 size;

    if (!buffer || length > INT32_MAX) {
        errno = EINVAL;
        return -1;
    }

    if (length == 0) {
        return 0;
    }

    size = rdrand_get_bytes(buffer, (uint32)length);
    if (size != length) {
        errno = EFAULT;
        return -1;
    }

    return 0;
}

int
get_errno(void)
{
    int ret;

    if (ocall_get_errno(&ret) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }
    return ret;
}

#endif
