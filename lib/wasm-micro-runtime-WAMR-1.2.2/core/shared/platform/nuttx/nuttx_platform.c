/*
 * Copyright (C) 2020 XiaoMi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_extension.h"
#include "platform_api_vmcore.h"

#if defined(CONFIG_ARCH_USE_TEXT_HEAP)
#include <nuttx/arch.h>
#endif

int
bh_platform_init()
{
    return 0;
}

void
bh_platform_destroy()
{}

void *
os_malloc(unsigned size)
{
    return malloc(size);
}

void *
os_realloc(void *ptr, unsigned size)
{
    return realloc(ptr, size);
}

void
os_free(void *ptr)
{
    free(ptr);
}

int
os_dumps_proc_mem_info(char *out, unsigned int size)
{
    return -1;
}

void *
os_mmap(void *hint, size_t size, int prot, int flags)
{
#if defined(CONFIG_ARCH_USE_TEXT_HEAP)
    if ((prot & MMAP_PROT_EXEC) != 0) {
        return up_textheap_memalign(sizeof(void *), size);
    }
#endif

    if ((uint64)size >= UINT32_MAX)
        return NULL;
    return malloc((uint32)size);
}

void
os_munmap(void *addr, size_t size)
{
#if defined(CONFIG_ARCH_USE_TEXT_HEAP)
    if (up_textheap_heapmember(addr)) {
        up_textheap_free(addr);
        return;
    }
#endif
    return free(addr);
}

int
os_mprotect(void *addr, size_t size, int prot)
{
    return 0;
}

void
os_dcache_flush()
{}

/* If AT_FDCWD is provided, maybe we have openat family */
#if !defined(AT_FDCWD)

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
    errno = ENOSYS;
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

#endif /* !defined(AT_FDCWD) */

#ifndef CONFIG_NET

#include <netdb.h>

int
accept(int sockfd, FAR struct sockaddr *addr, FAR socklen_t *addrlen)
{
    errno = ENOTSUP;
    return -1;
}

int
bind(int sockfd, FAR const struct sockaddr *addr, socklen_t addrlen)
{
    errno = ENOTSUP;
    return -1;
}

int
listen(int sockfd, int backlog)
{
    errno = ENOTSUP;
    return -1;
}

int
connect(int sockfd, FAR const struct sockaddr *addr, socklen_t addrlen)
{
    errno = ENOTSUP;
    return -1;
}

ssize_t
recvfrom(int sockfd, FAR void *buf, size_t len, int flags,
         FAR struct sockaddr *from, FAR socklen_t *fromlen)
{
    errno = ENOTSUP;
    return -1;
}

ssize_t
send(int sockfd, FAR const void *buf, size_t len, int flags)
{
    errno = ENOTSUP;
    return -1;
}

ssize_t
sendto(int sockfd, FAR const void *buf, size_t len, int flags,
       FAR const struct sockaddr *to, socklen_t tolen)
{
    errno = ENOTSUP;
    return -1;
}

int
socket(int domain, int type, int protocol)
{
    errno = ENOTSUP;
    return -1;
}

int
shutdown(int sockfd, int how)
{
    errno = ENOTSUP;
    return -1;
}

int
getaddrinfo(FAR const char *nodename, FAR const char *servname,
            FAR const struct addrinfo *hints, FAR struct addrinfo **res)
{
    errno = ENOTSUP;
    return -1;
}

void
freeaddrinfo(FAR struct addrinfo *ai)
{}

int
setsockopt(int sockfd, int level, int option, FAR const void *value,
           socklen_t value_len)
{
    errno = ENOTSUP;
    return -1;
}

int
getsockopt(int sockfd, int level, int option, FAR void *value,
           FAR socklen_t *value_len)
{
    errno = ENOTSUP;
    return -1;
}

int
getpeername(int sockfd, FAR struct sockaddr *addr, FAR socklen_t *addrlen)
{
    errno = ENOTSUP;
    return -1;
}

int
getsockname(int sockfd, FAR struct sockaddr *addr, FAR socklen_t *addrlen)
{
    errno = ENOTSUP;
    return -1;
}

#endif
