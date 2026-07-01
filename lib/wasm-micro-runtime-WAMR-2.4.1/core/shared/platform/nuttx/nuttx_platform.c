/*
 * Copyright (C) 2020 XiaoMi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_extension.h"
#include "platform_api_vmcore.h"

#if defined(CONFIG_ARCH_USE_TEXT_HEAP)
#include <nuttx/arch.h>
#endif

#include <nuttx/cache.h>

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
os_mmap(void *hint, size_t size, int prot, int flags, os_file_handle file)
{
    void *p;

#if defined(CONFIG_ARCH_USE_TEXT_HEAP)
    if ((prot & MMAP_PROT_EXEC) != 0) {
        p = up_textheap_memalign(sizeof(void *), size);
        if (p) {
#if (WASM_MEM_DUAL_BUS_MIRROR != 0)
            void *dp = os_get_dbus_mirror(p);
            memset(dp, 0, size);
            os_dcache_flush();
#else
            memset(p, 0, size);
#endif
        }
        return p;
    }
#endif

    if ((uint64)size >= UINT32_MAX)
        return NULL;

    /* Note: aot_loader.c assumes that os_mmap provides large enough
     * alignment for any data sections. Some sections like rodata.cst32
     * actually require alignment larger than the natural alignment
     * provided by malloc.
     *
     * Probably it's cleaner to add an explicit alignment argument to
     * os_mmap. However, it only makes sense if we change our aot format
     * to keep the necessary alignment.
     *
     * For now, let's assume 32 byte alignment is enough.
     */
    if (posix_memalign(&p, 32, size)) {
        return NULL;
    }

    /* Zero the memory which is required by os_mmap */
    memset(p, 0, size);

    return p;
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

    free(addr);
}

int
os_mprotect(void *addr, size_t size, int prot)
{
    return 0;
}

void
os_dcache_flush()
{
#if defined(CONFIG_ARCH_USE_TEXT_HEAP) \
    && defined(CONFIG_ARCH_HAVE_TEXT_HEAP_SEPARATE_DATA_ADDRESS)
    up_textheap_data_sync();
#endif
#ifndef CONFIG_BUILD_KERNEL
    up_flush_dcache_all();
#endif
}

void
os_icache_flush(void *start, size_t len)
{
#ifndef CONFIG_BUILD_KERNEL
    up_invalidate_icache((uintptr_t)start, (uintptr_t)start + len);
#endif
}

#if (WASM_MEM_DUAL_BUS_MIRROR != 0)
void *
os_get_dbus_mirror(void *ibus)
{
#if defined(CONFIG_ARCH_USE_TEXT_HEAP) \
    && defined(CONFIG_ARCH_HAVE_TEXT_HEAP_SEPARATE_DATA_ADDRESS)
    return up_textheap_data_address(ibus);
#else
    return ibus;
#endif
}
#endif

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
