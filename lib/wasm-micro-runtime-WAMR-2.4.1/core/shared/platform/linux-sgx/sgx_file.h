/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SGX_FILE_H
#define _SGX_FILE_H

#include "sgx_time.h"

#ifdef __cplusplus
extern "C" {
#endif

#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4

#define FD_CLOEXEC 1

#define O_PATH 010000000
#define O_SEARCH O_PATH
#define O_EXEC O_PATH

#define O_ACCMODE (03 | O_SEARCH)
#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR 02

#define O_CREAT 0100
#define O_EXCL 0200
#define O_NOCTTY 0400
#define O_TRUNC 01000
#define O_APPEND 02000
#define O_NONBLOCK 04000
#define O_DSYNC 010000
#define O_SYNC 04010000
#define O_RSYNC 04010000
#define O_DIRECTORY 0200000
#define O_NOFOLLOW 0400000
#define O_CLOEXEC 02000000

#define O_ASYNC 020000
#define O_DIRECT 040000
#define O_LARGEFILE 0
#define O_NOATIME 01000000
#define O_PATH 010000000
#define O_TMPFILE 020200000
#define O_NDELAY O_NONBLOCK

#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFBLK 0060000
#define S_IFREG 0100000
#define S_IFIFO 0010000
#define S_IFLNK 0120000
#define S_IFSOCK 0140000

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define S_ISDIR(mode) (((mode)&S_IFMT) == S_IFDIR)
#define S_ISCHR(mode) (((mode)&S_IFMT) == S_IFCHR)
#define S_ISBLK(mode) (((mode)&S_IFMT) == S_IFBLK)
#define S_ISREG(mode) (((mode)&S_IFMT) == S_IFREG)
#define S_ISFIFO(mode) (((mode)&S_IFMT) == S_IFIFO)
#define S_ISLNK(mode) (((mode)&S_IFMT) == S_IFLNK)
#define S_ISSOCK(mode) (((mode)&S_IFMT) == S_IFSOCK)

#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14

#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_REMOVEDIR 0x200
#define AT_SYMLINK_FOLLOW 0x400

#define POLLIN 0x001
#define POLLPRI 0x002
#define POLLOUT 0x004
#define POLLERR 0x008
#define POLLHUP 0x010
#define POLLNVAL 0x020
#define POLLRDNORM 0x040
#define POLLRDBAND 0x080
#define POLLWRNORM 0x100
#define POLLWRBAND 0x200

#define FIONREAD 0x541B

#define PATH_MAX 4096

/* Special value used to indicate openat should use the current
   working directory. */
#define AT_FDCWD -100

typedef long __syscall_slong_t;

typedef unsigned long dev_t;
typedef unsigned long ino_t;
typedef unsigned mode_t;
typedef unsigned long nlink_t;
typedef unsigned socklen_t;
typedef long blksize_t;
typedef long blkcnt_t;

typedef int pid_t;
typedef unsigned gid_t;
typedef unsigned uid_t;

typedef unsigned long nfds_t;

typedef uintptr_t DIR;

struct dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256];
};

struct stat {
    dev_t st_dev;
    ino_t st_ino;
    nlink_t st_nlink;

    mode_t st_mode;
    uid_t st_uid;
    gid_t st_gid;
    unsigned int __pad0;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;

    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    long __unused[3];
};

struct iovec {
    void *iov_base;
    size_t iov_len;
};

struct pollfd {
    int fd;
    short events;
    short revents;
};

int
open(const char *pathname, int flags, ...);
int
openat(int dirfd, const char *pathname, int flags, ...);
int
close(int fd);

DIR *
fdopendir(int fd);
int
closedir(DIR *dirp);
void
rewinddir(DIR *dirp);
void
seekdir(DIR *dirp, long loc);
struct dirent *
readdir(DIR *dirp);
long
telldir(DIR *dirp);

ssize_t
read(int fd, void *buf, size_t count);
ssize_t
readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t
writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t
preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
ssize_t
pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);

off_t
lseek(int fd, off_t offset, int whence);
int
ftruncate(int fd, off_t length);

int
stat(const char *pathname, struct stat *statbuf);
int
fstat(int fd, struct stat *statbuf);
int
fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);

int
fsync(int fd);
int
fdatasync(int fd);

int
mkdirat(int dirfd, const char *pathname, mode_t mode);
int
link(const char *oldpath, const char *newpath);
int
linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath,
       int flags);
int
unlinkat(int dirfd, const char *pathname, int flags);
ssize_t
readlink(const char *pathname, char *buf, size_t bufsiz);
ssize_t
readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
int
symlinkat(const char *target, int newdirfd, const char *linkpath);
int
renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

int
ioctl(int fd, unsigned long request, ...);
int
fcntl(int fd, int cmd, ... /* arg */);

int
isatty(int fd);

char *
realpath(const char *path, char *resolved_path);

int
posix_fallocate(int fd, off_t offset, off_t len);

int
poll(struct pollfd *fds, nfds_t nfds, int timeout);

int
getopt(int argc, char *const argv[], const char *optstring);

int
sched_yield(void);

ssize_t
getrandom(void *buf, size_t buflen, unsigned int flags);

int
getentropy(void *buffer, size_t length);

int
get_errno(void);

#ifdef __cplusplus
}
#endif

#endif /* end of _SGX_FILE_H */
