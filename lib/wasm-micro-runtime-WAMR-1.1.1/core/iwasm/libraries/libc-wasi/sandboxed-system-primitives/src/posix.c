// Part of the Wasmtime Project, under the Apache License v2.0 with LLVM
// Exceptions. See
// https://github.com/bytecodealliance/wasmtime/blob/main/LICENSE for license
// information.
//
// Significant parts of this file are derived from cloudabi-utils. See
// https://github.com/bytecodealliance/wasmtime/blob/main/lib/wasi/sandboxed-system-primitives/src/LICENSE
// for license information.
//
// The upstream file contains the following copyright notice:
//
// Copyright (c) 2016-2018 Nuxi, https://nuxi.nl/

#include "ssp_config.h"
#include "bh_platform.h"
#include "wasmtime_ssp.h"
#include "locking.h"
#include "numeric_limits.h"
#include "posix.h"
#include "random.h"
#include "refcount.h"
#include "rights.h"
#include "str.h"

#if 0 /* TODO: -std=gnu99 causes compile error, comment them first */
// struct iovec must have the same layout as __wasi_iovec_t.
static_assert(offsetof(struct iovec, iov_base) ==
                  offsetof(__wasi_iovec_t, buf),
              "Offset mismatch");
static_assert(sizeof(((struct iovec *)0)->iov_base) ==
                  sizeof(((__wasi_iovec_t *)0)->buf),
              "Size mismatch");
static_assert(offsetof(struct iovec, iov_len) ==
                  offsetof(__wasi_iovec_t, buf_len),
              "Offset mismatch");
static_assert(sizeof(((struct iovec *)0)->iov_len) ==
                  sizeof(((__wasi_iovec_t *)0)->buf_len),
              "Size mismatch");
static_assert(sizeof(struct iovec) == sizeof(__wasi_iovec_t),
              "Size mismatch");

// struct iovec must have the same layout as __wasi_ciovec_t.
static_assert(offsetof(struct iovec, iov_base) ==
                  offsetof(__wasi_ciovec_t, buf),
              "Offset mismatch");
static_assert(sizeof(((struct iovec *)0)->iov_base) ==
                  sizeof(((__wasi_ciovec_t *)0)->buf),
              "Size mismatch");
static_assert(offsetof(struct iovec, iov_len) ==
                  offsetof(__wasi_ciovec_t, buf_len),
              "Offset mismatch");
static_assert(sizeof(((struct iovec *)0)->iov_len) ==
                  sizeof(((__wasi_ciovec_t *)0)->buf_len),
              "Size mismatch");
static_assert(sizeof(struct iovec) == sizeof(__wasi_ciovec_t),
              "Size mismatch");
#endif

#if defined(WASMTIME_SSP_STATIC_CURFDS)
static __thread struct fd_table *curfds;
static __thread struct fd_prestats *prestats;
static __thread struct argv_environ_values *argv_environ;
static __thread struct addr_pool *addr_pool;
#endif

// Converts a POSIX error code to a CloudABI error code.
static __wasi_errno_t
convert_errno(int error)
{
    static const __wasi_errno_t errors[] = {
#define X(v) [v] = __WASI_##v
        X(E2BIG),
        X(EACCES),
        X(EADDRINUSE),
        X(EADDRNOTAVAIL),
        X(EAFNOSUPPORT),
        X(EAGAIN),
        X(EALREADY),
        X(EBADF),
        X(EBADMSG),
        X(EBUSY),
        X(ECANCELED),
        X(ECHILD),
        X(ECONNABORTED),
        X(ECONNREFUSED),
        X(ECONNRESET),
        X(EDEADLK),
        X(EDESTADDRREQ),
        X(EDOM),
        X(EDQUOT),
        X(EEXIST),
        X(EFAULT),
        X(EFBIG),
        X(EHOSTUNREACH),
        X(EIDRM),
        X(EILSEQ),
        X(EINPROGRESS),
        X(EINTR),
        X(EINVAL),
        X(EIO),
        X(EISCONN),
        X(EISDIR),
        X(ELOOP),
        X(EMFILE),
        X(EMLINK),
        X(EMSGSIZE),
        X(EMULTIHOP),
        X(ENAMETOOLONG),
        X(ENETDOWN),
        X(ENETRESET),
        X(ENETUNREACH),
        X(ENFILE),
        X(ENOBUFS),
        X(ENODEV),
        X(ENOENT),
        X(ENOEXEC),
        X(ENOLCK),
        X(ENOLINK),
        X(ENOMEM),
        X(ENOMSG),
        X(ENOPROTOOPT),
        X(ENOSPC),
        X(ENOSYS),
#ifdef ENOTCAPABLE
        X(ENOTCAPABLE),
#endif
        X(ENOTCONN),
        X(ENOTDIR),
        X(ENOTEMPTY),
        X(ENOTRECOVERABLE),
        X(ENOTSOCK),
        X(ENOTSUP),
        X(ENOTTY),
        X(ENXIO),
        X(EOVERFLOW),
        X(EOWNERDEAD),
        X(EPERM),
        X(EPIPE),
        X(EPROTO),
        X(EPROTONOSUPPORT),
        X(EPROTOTYPE),
        X(ERANGE),
        X(EROFS),
        X(ESPIPE),
        X(ESRCH),
        X(ESTALE),
        X(ETIMEDOUT),
        X(ETXTBSY),
        X(EXDEV),
#undef X
#if EOPNOTSUPP != ENOTSUP
        [EOPNOTSUPP] = __WASI_ENOTSUP,
#endif
#if EWOULDBLOCK != EAGAIN
        [EWOULDBLOCK] = __WASI_EAGAIN,
#endif
    };
    if (error < 0 || (size_t)error >= sizeof(errors) / sizeof(errors[0])
        || errors[error] == 0)
        return __WASI_ENOSYS;
    return errors[error];
}

static bool
ns_lookup_list_search(char **list, const char *host)
{
    size_t host_len = strlen(host), suffix_len;

    while (*list) {
        if (*list[0] == '*') {
            suffix_len = strlen(*list) - 1;
            if (suffix_len <= host_len
                && strncmp(host + host_len - suffix_len, *list + 1, suffix_len)
                       == 0) {
                return true;
            }
        }
        else {
            if (strcmp(*list, host) == 0) {
                return true;
            }
        }
        list++;
    }

    return false;
}

// Converts a POSIX timespec to a CloudABI timestamp.
static __wasi_timestamp_t
convert_timespec(const struct timespec *ts)
{
    if (ts->tv_sec < 0)
        return 0;
    if ((__wasi_timestamp_t)ts->tv_sec >= UINT64_MAX / 1000000000)
        return UINT64_MAX;
    return (__wasi_timestamp_t)ts->tv_sec * 1000000000
           + (__wasi_timestamp_t)ts->tv_nsec;
}

// Converts a CloudABI clock identifier to a POSIX clock identifier.
static bool
convert_clockid(__wasi_clockid_t in, clockid_t *out)
{
    switch (in) {
        case __WASI_CLOCK_MONOTONIC:
            *out = CLOCK_MONOTONIC;
            return true;
#if defined(CLOCK_PROCESS_CPUTIME_ID)
        case __WASI_CLOCK_PROCESS_CPUTIME_ID:
            *out = CLOCK_PROCESS_CPUTIME_ID;
            return true;
#endif
        case __WASI_CLOCK_REALTIME:
            *out = CLOCK_REALTIME;
            return true;
#if defined(CLOCK_THREAD_CPUTIME_ID)
        case __WASI_CLOCK_THREAD_CPUTIME_ID:
            *out = CLOCK_THREAD_CPUTIME_ID;
            return true;
#endif
        default:
            return false;
    }
}

static void
wasi_addr_to_bh_sockaddr(const __wasi_addr_t *wasi_addr,
                         bh_sockaddr_t *sockaddr)
{
    if (wasi_addr->kind == IPv4) {
        sockaddr->addr_bufer.ipv4 = (wasi_addr->addr.ip4.addr.n0 << 24)
                                    | (wasi_addr->addr.ip4.addr.n1 << 16)
                                    | (wasi_addr->addr.ip4.addr.n2 << 8)
                                    | wasi_addr->addr.ip4.addr.n3;
        sockaddr->is_ipv4 = true;
        sockaddr->port = wasi_addr->addr.ip4.port;
    }
    else {
        sockaddr->addr_bufer.ipv6[0] = wasi_addr->addr.ip6.addr.n0;
        sockaddr->addr_bufer.ipv6[1] = wasi_addr->addr.ip6.addr.n1;
        sockaddr->addr_bufer.ipv6[2] = wasi_addr->addr.ip6.addr.n2;
        sockaddr->addr_bufer.ipv6[3] = wasi_addr->addr.ip6.addr.n3;
        sockaddr->addr_bufer.ipv6[4] = wasi_addr->addr.ip6.addr.h0;
        sockaddr->addr_bufer.ipv6[5] = wasi_addr->addr.ip6.addr.h1;
        sockaddr->addr_bufer.ipv6[6] = wasi_addr->addr.ip6.addr.h2;
        sockaddr->addr_bufer.ipv6[7] = wasi_addr->addr.ip6.addr.h3;
        sockaddr->is_ipv4 = false;
        sockaddr->port = wasi_addr->addr.ip6.port;
    }
}

// Converts an IPv6 binary address object to WASI address object.
static void
bh_sockaddr_to_wasi_addr(const bh_sockaddr_t *sockaddr,
                         __wasi_addr_t *wasi_addr)
{
    if (sockaddr->is_ipv4) {
        wasi_addr->kind = IPv4;
        wasi_addr->addr.ip4.port = sockaddr->port;
        wasi_addr->addr.ip4.addr.n0 =
            (sockaddr->addr_bufer.ipv4 & 0xFF000000) >> 24;
        wasi_addr->addr.ip4.addr.n1 =
            (sockaddr->addr_bufer.ipv4 & 0x00FF0000) >> 16;
        wasi_addr->addr.ip4.addr.n2 =
            (sockaddr->addr_bufer.ipv4 & 0x0000FF00) >> 8;
        wasi_addr->addr.ip4.addr.n3 = (sockaddr->addr_bufer.ipv4 & 0x000000FF);
    }
    else {
        wasi_addr->kind = IPv6;
        wasi_addr->addr.ip6.port = sockaddr->port;
        wasi_addr->addr.ip6.addr.n0 = sockaddr->addr_bufer.ipv6[0];
        wasi_addr->addr.ip6.addr.n1 = sockaddr->addr_bufer.ipv6[1];
        wasi_addr->addr.ip6.addr.n2 = sockaddr->addr_bufer.ipv6[2];
        wasi_addr->addr.ip6.addr.n3 = sockaddr->addr_bufer.ipv6[3];
        wasi_addr->addr.ip6.addr.h0 = sockaddr->addr_bufer.ipv6[4];
        wasi_addr->addr.ip6.addr.h1 = sockaddr->addr_bufer.ipv6[5];
        wasi_addr->addr.ip6.addr.h2 = sockaddr->addr_bufer.ipv6[6];
        wasi_addr->addr.ip6.addr.h3 = sockaddr->addr_bufer.ipv6[7];
    }
}

static void
wasi_addr_ip_to_bh_ip_addr_buffer(__wasi_addr_ip_t *addr,
                                  bh_ip_addr_buffer_t *out)
{
    if (addr->kind == IPv4) {
        out->ipv4 = htonl((addr->addr.ip4.n0 << 24) | (addr->addr.ip4.n1 << 16)
                          | (addr->addr.ip4.n2 << 8) | addr->addr.ip4.n3);
    }
    else {
        out->ipv6[0] = htons(addr->addr.ip6.n0);
        out->ipv6[1] = htons(addr->addr.ip6.n1);
        out->ipv6[2] = htons(addr->addr.ip6.n2);
        out->ipv6[3] = htons(addr->addr.ip6.n3);
        out->ipv6[4] = htons(addr->addr.ip6.h0);
        out->ipv6[5] = htons(addr->addr.ip6.h1);
        out->ipv6[6] = htons(addr->addr.ip6.h2);
        out->ipv6[7] = htons(addr->addr.ip6.h3);
    }
}

__wasi_errno_t
wasmtime_ssp_clock_res_get(__wasi_clockid_t clock_id,
                           __wasi_timestamp_t *resolution)
{
    clockid_t nclock_id;
    if (!convert_clockid(clock_id, &nclock_id))
        return __WASI_EINVAL;
    struct timespec ts;
    if (clock_getres(nclock_id, &ts) < 0)
        return convert_errno(errno);
    *resolution = convert_timespec(&ts);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_clock_time_get(__wasi_clockid_t clock_id,
                            __wasi_timestamp_t precision,
                            __wasi_timestamp_t *time)
{
    clockid_t nclock_id;
    if (!convert_clockid(clock_id, &nclock_id))
        return __WASI_EINVAL;
    struct timespec ts;
    if (clock_gettime(nclock_id, &ts) < 0)
        return convert_errno(errno);
    *time = convert_timespec(&ts);
    return 0;
}

struct fd_prestat {
    const char *dir;
};

bool
fd_prestats_init(struct fd_prestats *pt)
{
    if (!rwlock_init(&pt->lock))
        return false;
    pt->prestats = NULL;
    pt->size = 0;
    pt->used = 0;
#if defined(WASMTIME_SSP_STATIC_CURFDS)
    prestats = pt;
#endif
    return true;
}

// Grows the preopened resource table to a required lower bound and a
// minimum number of free preopened resource table entries.
static bool
fd_prestats_grow(struct fd_prestats *pt, size_t min, size_t incr)
    REQUIRES_EXCLUSIVE(pt->lock)
{
    if (pt->size <= min || pt->size < (pt->used + incr) * 2) {
        // Keep on doubling the table size until we've met our constraints.
        size_t size = pt->size == 0 ? 1 : pt->size;
        while (size <= min || size < (pt->used + incr) * 2)
            size *= 2;

        // Grow the file descriptor table's allocation.
        struct fd_prestat *prestats =
            wasm_runtime_malloc((uint32)(sizeof(*prestats) * size));
        if (prestats == NULL)
            return false;

        if (pt->prestats && pt->size > 0) {
            bh_memcpy_s(prestats, (uint32)(sizeof(*prestats) * size),
                        pt->prestats, (uint32)(sizeof(*prestats) * pt->size));
        }

        if (pt->prestats)
            wasm_runtime_free(pt->prestats);

        // Mark all new file descriptors as unused.
        for (size_t i = pt->size; i < size; ++i)
            prestats[i].dir = NULL;
        pt->prestats = prestats;
        pt->size = size;
    }
    return true;
}

// Inserts a preopened resource record into the preopened resource table.
bool
fd_prestats_insert(struct fd_prestats *pt, const char *dir, __wasi_fd_t fd)
{
    // Grow the preopened resource table if needed.
    rwlock_wrlock(&pt->lock);
    if (!fd_prestats_grow(pt, fd, 1)) {
        rwlock_unlock(&pt->lock);
        return false;
    }

    pt->prestats[fd].dir = bh_strdup(dir);
    rwlock_unlock(&pt->lock);

    if (pt->prestats[fd].dir == NULL)
        return false;

    return true;
}

// Looks up a preopened resource table entry by number.
static __wasi_errno_t
fd_prestats_get_entry(struct fd_prestats *pt, __wasi_fd_t fd,
                      struct fd_prestat **ret) REQUIRES_SHARED(pt->lock)
{
    // Test for file descriptor existence.
    if (fd >= pt->size)
        return __WASI_EBADF;
    struct fd_prestat *prestat = &pt->prestats[fd];
    if (prestat->dir == NULL)
        return __WASI_EBADF;

    *ret = prestat;
    return 0;
}

struct fd_object {
    struct refcount refcount;
    __wasi_filetype_t type;
    int number;

    union {
        // Data associated with directory file descriptors.
        struct {
            struct mutex lock;         // Lock to protect members below.
            DIR *handle;               // Directory handle.
            __wasi_dircookie_t offset; // Offset of the directory.
        } directory;
    };
};

struct fd_entry {
    struct fd_object *object;
    __wasi_rights_t rights_base;
    __wasi_rights_t rights_inheriting;
};

bool
fd_table_init(struct fd_table *ft)
{
    if (!rwlock_init(&ft->lock))
        return false;
    ft->entries = NULL;
    ft->size = 0;
    ft->used = 0;
#if defined(WASMTIME_SSP_STATIC_CURFDS)
    curfds = ft;
#endif
    return true;
}

// Looks up a file descriptor table entry by number and required rights.
static __wasi_errno_t
fd_table_get_entry(struct fd_table *ft, __wasi_fd_t fd,
                   __wasi_rights_t rights_base,
                   __wasi_rights_t rights_inheriting, struct fd_entry **ret)
    REQUIRES_SHARED(ft->lock)
{
    // Test for file descriptor existence.
    if (fd >= ft->size)
        return __WASI_EBADF;
    struct fd_entry *fe = &ft->entries[fd];
    if (fe->object == NULL)
        return __WASI_EBADF;

    // Validate rights.
    if ((~fe->rights_base & rights_base) != 0
        || (~fe->rights_inheriting & rights_inheriting) != 0)
        return __WASI_ENOTCAPABLE;
    *ret = fe;
    return 0;
}

// Grows the file descriptor table to a required lower bound and a
// minimum number of free file descriptor table entries.
static bool
fd_table_grow(struct fd_table *ft, size_t min, size_t incr)
    REQUIRES_EXCLUSIVE(ft->lock)
{
    if (ft->size <= min || ft->size < (ft->used + incr) * 2) {
        // Keep on doubling the table size until we've met our constraints.
        size_t size = ft->size == 0 ? 1 : ft->size;
        while (size <= min || size < (ft->used + incr) * 2)
            size *= 2;

        // Grow the file descriptor table's allocation.
        struct fd_entry *entries =
            wasm_runtime_malloc((uint32)(sizeof(*entries) * size));
        if (entries == NULL)
            return false;

        if (ft->entries && ft->size > 0) {
            bh_memcpy_s(entries, (uint32)(sizeof(*entries) * size), ft->entries,
                        (uint32)(sizeof(*entries) * ft->size));
        }

        if (ft->entries)
            wasm_runtime_free(ft->entries);

        // Mark all new file descriptors as unused.
        for (size_t i = ft->size; i < size; ++i)
            entries[i].object = NULL;
        ft->entries = entries;
        ft->size = size;
    }
    return true;
}

// Allocates a new file descriptor object.
static __wasi_errno_t
fd_object_new(__wasi_filetype_t type, struct fd_object **fo)
    TRYLOCKS_SHARED(0, (*fo)->refcount)
{
    *fo = wasm_runtime_malloc(sizeof(**fo));
    if (*fo == NULL)
        return __WASI_ENOMEM;
    refcount_init(&(*fo)->refcount, 1);
    (*fo)->type = type;
    (*fo)->number = -1;
    return 0;
}

// Attaches a file descriptor to the file descriptor table.
static void
fd_table_attach(struct fd_table *ft, __wasi_fd_t fd, struct fd_object *fo,
                __wasi_rights_t rights_base, __wasi_rights_t rights_inheriting)
    REQUIRES_EXCLUSIVE(ft->lock) CONSUMES(fo->refcount)
{
    assert(ft->size > fd && "File descriptor table too small");
    struct fd_entry *fe = &ft->entries[fd];
    assert(fe->object == NULL
           && "Attempted to overwrite an existing descriptor");
    fe->object = fo;
    fe->rights_base = rights_base;
    fe->rights_inheriting = rights_inheriting;
    ++ft->used;
    assert(ft->size >= ft->used * 2 && "File descriptor too full");
}

// Detaches a file descriptor from the file descriptor table.
static void
fd_table_detach(struct fd_table *ft, __wasi_fd_t fd, struct fd_object **fo)
    REQUIRES_EXCLUSIVE(ft->lock) PRODUCES((*fo)->refcount)
{
    assert(ft->size > fd && "File descriptor table too small");
    struct fd_entry *fe = &ft->entries[fd];
    *fo = fe->object;
    assert(*fo != NULL && "Attempted to detach nonexistent descriptor");
    fe->object = NULL;
    assert(ft->used > 0 && "Reference count mismatch");
    --ft->used;
}

// Determines the type of a file descriptor and its maximum set of
// rights that should be attached to it.
static __wasi_errno_t
fd_determine_type_rights(int fd, __wasi_filetype_t *type,
                         __wasi_rights_t *rights_base,
                         __wasi_rights_t *rights_inheriting)
{
    struct stat sb;
    if (fstat(fd, &sb) < 0)
        return convert_errno(errno);
    if (S_ISBLK(sb.st_mode)) {
        *type = __WASI_FILETYPE_BLOCK_DEVICE;
        *rights_base = RIGHTS_BLOCK_DEVICE_BASE;
        *rights_inheriting = RIGHTS_BLOCK_DEVICE_INHERITING;
    }
    else if (S_ISCHR(sb.st_mode)) {
        *type = __WASI_FILETYPE_CHARACTER_DEVICE;
#if CONFIG_HAS_ISATTY
        if (isatty(fd)) {
            *rights_base = RIGHTS_TTY_BASE;
            *rights_inheriting = RIGHTS_TTY_INHERITING;
        }
        else
#endif
        {
            *rights_base = RIGHTS_CHARACTER_DEVICE_BASE;
            *rights_inheriting = RIGHTS_CHARACTER_DEVICE_INHERITING;
        }
    }
    else if (S_ISDIR(sb.st_mode)) {
        *type = __WASI_FILETYPE_DIRECTORY;
        *rights_base = RIGHTS_DIRECTORY_BASE;
        *rights_inheriting = RIGHTS_DIRECTORY_INHERITING;
    }
    else if (S_ISREG(sb.st_mode)) {
        *type = __WASI_FILETYPE_REGULAR_FILE;
        *rights_base = RIGHTS_REGULAR_FILE_BASE;
        *rights_inheriting = RIGHTS_REGULAR_FILE_INHERITING;
    }
    else if (S_ISSOCK(sb.st_mode)) {
        int socktype;
        socklen_t socktypelen = sizeof(socktype);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socktype, &socktypelen) < 0)
            return convert_errno(errno);
        switch (socktype) {
            case SOCK_DGRAM:
                *type = __WASI_FILETYPE_SOCKET_DGRAM;
                break;
            case SOCK_STREAM:
                *type = __WASI_FILETYPE_SOCKET_STREAM;
                break;
            default:
                return __WASI_EINVAL;
        }
        *rights_base = RIGHTS_SOCKET_BASE;
        *rights_inheriting = RIGHTS_SOCKET_INHERITING;
    }
    else if (S_ISFIFO(sb.st_mode)) {
        *type = __WASI_FILETYPE_SOCKET_STREAM;
        *rights_base = RIGHTS_SOCKET_BASE;
        *rights_inheriting = RIGHTS_SOCKET_INHERITING;
    }
    else {
        return __WASI_EINVAL;
    }

    // Strip off read/write bits based on the access mode.
    switch (fcntl(fd, F_GETFL) & O_ACCMODE) {
        case O_RDONLY:
            *rights_base &= ~(__wasi_rights_t)__WASI_RIGHT_FD_WRITE;
            break;
        case O_WRONLY:
            *rights_base &= ~(__wasi_rights_t)__WASI_RIGHT_FD_READ;
            break;
    }
    return 0;
}

// Returns the underlying file descriptor number of a file descriptor
// object. This function can only be applied to objects that have an
// underlying file descriptor number.
static int
fd_number(const struct fd_object *fo)
{
    int number = fo->number;
    assert(number >= 0 && "fd_number() called on virtual file descriptor");
    return number;
}

#define CLOSE_NON_STD_FD(fd) \
    do {                     \
        if (fd > 2)          \
            close(fd);       \
    } while (0)

// Lowers the reference count on a file descriptor object. When the
// reference count reaches zero, its resources are cleaned up.
static void
fd_object_release(struct fd_object *fo) UNLOCKS(fo->refcount)
{
    if (refcount_release(&fo->refcount)) {
        switch (fo->type) {
            case __WASI_FILETYPE_DIRECTORY:
                // For directories we may keep track of a DIR object. Calling
                // closedir() on it also closes the underlying file descriptor.
                mutex_destroy(&fo->directory.lock);
                if (fo->directory.handle == NULL) {
                    CLOSE_NON_STD_FD(fd_number(fo));
                }
                else {
                    closedir(fo->directory.handle);
                }
                break;
            default:
                CLOSE_NON_STD_FD(fd_number(fo));
                break;
        }
        wasm_runtime_free(fo);
    }
}

// Inserts an already existing file descriptor into the file descriptor
// table.
bool
fd_table_insert_existing(struct fd_table *ft, __wasi_fd_t in, int out)
{
    __wasi_filetype_t type;
    __wasi_rights_t rights_base, rights_inheriting;
    struct fd_object *fo;
    __wasi_errno_t error;

    if (fd_determine_type_rights(out, &type, &rights_base, &rights_inheriting)
        != 0)
        return false;

    error = fd_object_new(type, &fo);
    if (error != 0)
        return false;
    fo->number = out;
    if (type == __WASI_FILETYPE_DIRECTORY) {
        if (!mutex_init(&fo->directory.lock)) {
            fd_object_release(fo);
            return false;
        }
        fo->directory.handle = NULL;
    }

    // Grow the file descriptor table if needed.
    rwlock_wrlock(&ft->lock);
    if (!fd_table_grow(ft, in, 1)) {
        rwlock_unlock(&ft->lock);
        fd_object_release(fo);
        return false;
    }

    fd_table_attach(ft, in, fo, rights_base, rights_inheriting);
    rwlock_unlock(&ft->lock);
    return true;
}

// Picks an unused slot from the file descriptor table.
static __wasi_fd_t
fd_table_unused(struct fd_table *ft) REQUIRES_SHARED(ft->lock)
{
    assert(ft->size > ft->used && "File descriptor table has no free slots");
    for (;;) {
        __wasi_fd_t fd = (__wasi_fd_t)random_uniform(ft->size);
        if (ft->entries[fd].object == NULL)
            return fd;
    }
}

// Inserts a file descriptor object into an unused slot of the file
// descriptor table.
static __wasi_errno_t
fd_table_insert(struct fd_table *ft, struct fd_object *fo,
                __wasi_rights_t rights_base, __wasi_rights_t rights_inheriting,
                __wasi_fd_t *out) REQUIRES_UNLOCKED(ft->lock)
    UNLOCKS(fo->refcount)
{
    // Grow the file descriptor table if needed.
    rwlock_wrlock(&ft->lock);
    if (!fd_table_grow(ft, 0, 1)) {
        rwlock_unlock(&ft->lock);
        fd_object_release(fo);
        return convert_errno(errno);
    }

    *out = fd_table_unused(ft);
    fd_table_attach(ft, *out, fo, rights_base, rights_inheriting);
    rwlock_unlock(&ft->lock);
    return 0;
}

// Inserts a numerical file descriptor into the file descriptor table.
static __wasi_errno_t
fd_table_insert_fd(struct fd_table *ft, int in, __wasi_filetype_t type,
                   __wasi_rights_t rights_base,
                   __wasi_rights_t rights_inheriting, __wasi_fd_t *out)
    REQUIRES_UNLOCKED(ft->lock)
{
    struct fd_object *fo;

    __wasi_errno_t error = fd_object_new(type, &fo);
    if (error != 0) {
        close(in);
        return error;
    }

    fo->number = in;
    if (type == __WASI_FILETYPE_DIRECTORY) {
        if (!mutex_init(&fo->directory.lock)) {
            fd_object_release(fo);
            return (__wasi_errno_t)-1;
        }
        fo->directory.handle = NULL;
    }
    return fd_table_insert(ft, fo, rights_base, rights_inheriting, out);
}

__wasi_errno_t
wasmtime_ssp_fd_prestat_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_prestats *prestats,
#endif
    __wasi_fd_t fd, __wasi_prestat_t *buf)
{
    rwlock_rdlock(&prestats->lock);
    struct fd_prestat *prestat;
    __wasi_errno_t error = fd_prestats_get_entry(prestats, fd, &prestat);
    if (error != 0) {
        rwlock_unlock(&prestats->lock);
        return error;
    }

    *buf = (__wasi_prestat_t){
        .pr_type = __WASI_PREOPENTYPE_DIR,
    };

    buf->u.dir.pr_name_len = strlen(prestat->dir);

    rwlock_unlock(&prestats->lock);

    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_prestat_dir_name(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_prestats *prestats,
#endif
    __wasi_fd_t fd, char *path, size_t path_len)
{
    rwlock_rdlock(&prestats->lock);
    struct fd_prestat *prestat;
    __wasi_errno_t error = fd_prestats_get_entry(prestats, fd, &prestat);
    if (error != 0) {
        rwlock_unlock(&prestats->lock);
        return error;
    }
    if (path_len != strlen(prestat->dir)) {
        rwlock_unlock(&prestats->lock);
        return EINVAL;
    }

    bh_memcpy_s(path, (uint32)path_len, prestat->dir, (uint32)path_len);

    rwlock_unlock(&prestats->lock);

    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_close(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, struct fd_prestats *prestats,
#endif
    __wasi_fd_t fd)
{
    // Don't allow closing a pre-opened resource.
    // TODO: Eventually, we do want to permit this, once libpreopen in
    // userspace is capable of removing entries from its tables as well.
    {
        rwlock_rdlock(&prestats->lock);
        struct fd_prestat *prestat;
        __wasi_errno_t error = fd_prestats_get_entry(prestats, fd, &prestat);
        rwlock_unlock(&prestats->lock);
        if (error == 0) {
            return __WASI_ENOTSUP;
        }
    }

    // Validate the file descriptor.
    struct fd_table *ft = curfds;
    rwlock_wrlock(&ft->lock);
    struct fd_entry *fe;
    __wasi_errno_t error = fd_table_get_entry(ft, fd, 0, 0, &fe);
    if (error != 0) {
        rwlock_unlock(&ft->lock);
        return error;
    }

    // Remove it from the file descriptor table.
    struct fd_object *fo;
    fd_table_detach(ft, fd, &fo);
    rwlock_unlock(&ft->lock);
    fd_object_release(fo);
    return 0;
}

// Look up a file descriptor object in a locked file descriptor table
// and increases its reference count.
static __wasi_errno_t
fd_object_get_locked(struct fd_object **fo, struct fd_table *ft, __wasi_fd_t fd,
                     __wasi_rights_t rights_base,
                     __wasi_rights_t rights_inheriting)
    TRYLOCKS_EXCLUSIVE(0, (*fo)->refcount) REQUIRES_EXCLUSIVE(ft->lock)
{
    // Test whether the file descriptor number is valid.
    struct fd_entry *fe;
    __wasi_errno_t error =
        fd_table_get_entry(ft, fd, rights_base, rights_inheriting, &fe);
    if (error != 0)
        return error;

    // Increase the reference count on the file descriptor object. A copy
    // of the rights are also stored, so callers can still access those if
    // needed.
    *fo = fe->object;
    refcount_acquire(&(*fo)->refcount);
    return 0;
}

// Temporarily locks the file descriptor table to look up a file
// descriptor object, increases its reference count and drops the lock.
static __wasi_errno_t
fd_object_get(struct fd_table *curfds, struct fd_object **fo, __wasi_fd_t fd,
              __wasi_rights_t rights_base, __wasi_rights_t rights_inheriting)
    TRYLOCKS_EXCLUSIVE(0, (*fo)->refcount)
{
    struct fd_table *ft = curfds;
    rwlock_rdlock(&ft->lock);
    __wasi_errno_t error =
        fd_object_get_locked(fo, ft, fd, rights_base, rights_inheriting);
    rwlock_unlock(&ft->lock);
    return error;
}

__wasi_errno_t
wasmtime_ssp_fd_datasync(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd)
{
    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_DATASYNC, 0);
    if (error != 0)
        return error;

#if CONFIG_HAS_FDATASYNC
    int ret = fdatasync(fd_number(fo));
#else
    int ret = fsync(fd_number(fo));
#endif
    fd_object_release(fo);
    if (ret < 0)
        return convert_errno(errno);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_pread(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, const __wasi_iovec_t *iov, size_t iovcnt,
    __wasi_filesize_t offset, size_t *nread)
{
    if (iovcnt == 0)
        return __WASI_EINVAL;

    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_READ, 0);
    if (error != 0)
        return error;

#if CONFIG_HAS_PREADV
    ssize_t len = preadv(fd_number(fo), (const struct iovec *)iov, (int)iovcnt,
                         (off_t)offset);
    fd_object_release(fo);
    if (len < 0)
        return convert_errno(errno);
    *nread = (size_t)len;
    return 0;
#else
    if (iovcnt == 1) {
        ssize_t len = pread(fd_number(fo), iov->buf, iov->buf_len, offset);
        fd_object_release(fo);
        if (len < 0)
            return convert_errno(errno);
        *nread = len;
        return 0;
    }
    else {
        // Allocate a single buffer to fit all data.
        size_t totalsize = 0;
        for (size_t i = 0; i < iovcnt; ++i)
            totalsize += iov[i].buf_len;
        char *buf = wasm_runtime_malloc(totalsize);
        if (buf == NULL) {
            fd_object_release(fo);
            return __WASI_ENOMEM;
        }

        // Perform a single read operation.
        ssize_t len = pread(fd_number(fo), buf, totalsize, offset);
        fd_object_release(fo);
        if (len < 0) {
            wasm_runtime_free(buf);
            return convert_errno(errno);
        }

        // Copy data back to vectors.
        size_t bufoff = 0;
        for (size_t i = 0; i < iovcnt; ++i) {
            if (bufoff + iov[i].buf_len < (size_t)len) {
                bh_memcpy_s(iov[i].buf, iov[i].buf_len, buf + bufoff,
                            iov[i].buf_len);
                bufoff += iov[i].buf_len;
            }
            else {
                bh_memcpy_s(iov[i].buf, iov[i].buf_len, buf + bufoff,
                            len - bufoff);
                break;
            }
        }
        wasm_runtime_free(buf);
        *nread = len;
        return 0;
    }
#endif
}

__wasi_errno_t
wasmtime_ssp_fd_pwrite(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, const __wasi_ciovec_t *iov, size_t iovcnt,
    __wasi_filesize_t offset, size_t *nwritten)
{
    if (iovcnt == 0)
        return __WASI_EINVAL;

    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_WRITE, 0);
    if (error != 0)
        return error;

    ssize_t len;
#if CONFIG_HAS_PWRITEV
    len = pwritev(fd_number(fo), (const struct iovec *)iov, (int)iovcnt,
                  (off_t)offset);
#else
    if (iovcnt == 1) {
        len = pwrite(fd_number(fo), iov->buf, iov->buf_len, offset);
    }
    else {
        // Allocate a single buffer to fit all data.
        size_t totalsize = 0;
        for (size_t i = 0; i < iovcnt; ++i)
            totalsize += iov[i].buf_len;
        char *buf = wasm_runtime_malloc(totalsize);
        if (buf == NULL) {
            fd_object_release(fo);
            return __WASI_ENOMEM;
        }
        size_t bufoff = 0;
        for (size_t i = 0; i < iovcnt; ++i) {
            bh_memcpy_s(buf + bufoff, totalsize - bufoff, iov[i].buf,
                        iov[i].buf_len);
            bufoff += iov[i].buf_len;
        }

        // Perform a single write operation.
        len = pwrite(fd_number(fo), buf, totalsize, offset);
        wasm_runtime_free(buf);
    }
#endif
    fd_object_release(fo);
    if (len < 0)
        return convert_errno(errno);
    *nwritten = (size_t)len;
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_read(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, const __wasi_iovec_t *iov, size_t iovcnt, size_t *nread)
{
    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_READ, 0);
    if (error != 0)
        return error;

    ssize_t len = readv(fd_number(fo), (const struct iovec *)iov, (int)iovcnt);
    fd_object_release(fo);
    if (len < 0)
        return convert_errno(errno);
    *nread = (size_t)len;
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_renumber(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, struct fd_prestats *prestats,
#endif
    __wasi_fd_t from, __wasi_fd_t to)
{
    // Don't allow renumbering over a pre-opened resource.
    // TODO: Eventually, we do want to permit this, once libpreopen in
    // userspace is capable of removing entries from its tables as well.
    {
        rwlock_rdlock(&prestats->lock);
        struct fd_prestat *prestat;
        __wasi_errno_t error = fd_prestats_get_entry(prestats, to, &prestat);
        if (error != 0) {
            error = fd_prestats_get_entry(prestats, from, &prestat);
        }
        rwlock_unlock(&prestats->lock);
        if (error == 0) {
            return __WASI_ENOTSUP;
        }
    }

    struct fd_table *ft = curfds;
    rwlock_wrlock(&ft->lock);
    struct fd_entry *fe_from;
    __wasi_errno_t error = fd_table_get_entry(ft, from, 0, 0, &fe_from);
    if (error != 0) {
        rwlock_unlock(&ft->lock);
        return error;
    }
    struct fd_entry *fe_to;
    error = fd_table_get_entry(ft, to, 0, 0, &fe_to);
    if (error != 0) {
        rwlock_unlock(&ft->lock);
        return error;
    }

    struct fd_object *fo;
    fd_table_detach(ft, to, &fo);
    refcount_acquire(&fe_from->object->refcount);
    fd_table_attach(ft, to, fe_from->object, fe_from->rights_base,
                    fe_from->rights_inheriting);
    fd_object_release(fo);

    // Remove the old fd from the file descriptor table.
    fd_table_detach(ft, from, &fo);
    fd_object_release(fo);
    --ft->used;

    rwlock_unlock(&ft->lock);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_seek(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_filedelta_t offset, __wasi_whence_t whence,
    __wasi_filesize_t *newoffset)
{
    int nwhence;
    switch (whence) {
        case __WASI_WHENCE_CUR:
            nwhence = SEEK_CUR;
            break;
        case __WASI_WHENCE_END:
            nwhence = SEEK_END;
            break;
        case __WASI_WHENCE_SET:
            nwhence = SEEK_SET;
            break;
        default:
            return __WASI_EINVAL;
    }

    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd,
                      offset == 0 && whence == __WASI_WHENCE_CUR
                          ? __WASI_RIGHT_FD_TELL
                          : __WASI_RIGHT_FD_SEEK | __WASI_RIGHT_FD_TELL,
                      0);
    if (error != 0)
        return error;

    off_t ret = lseek(fd_number(fo), offset, nwhence);
    fd_object_release(fo);
    if (ret < 0)
        return convert_errno(errno);
    *newoffset = (__wasi_filesize_t)ret;
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_tell(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_filesize_t *newoffset)
{
    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_TELL, 0);
    if (error != 0)
        return error;

    off_t ret = lseek(fd_number(fo), 0, SEEK_CUR);
    fd_object_release(fo);
    if (ret < 0)
        return convert_errno(errno);
    *newoffset = (__wasi_filesize_t)ret;
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_fdstat_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_fdstat_t *buf)
{
    struct fd_table *ft = curfds;
    rwlock_rdlock(&ft->lock);
    struct fd_entry *fe;
    __wasi_errno_t error = fd_table_get_entry(ft, fd, 0, 0, &fe);
    if (error != 0) {
        rwlock_unlock(&ft->lock);
        return error;
    }

    // Extract file descriptor type and rights.
    struct fd_object *fo = fe->object;
    *buf = (__wasi_fdstat_t){
        .fs_filetype = fo->type,
        .fs_rights_base = fe->rights_base,
        .fs_rights_inheriting = fe->rights_inheriting,
    };

    // Fetch file descriptor flags.
    int ret;
    switch (fo->type) {
        default:
            ret = fcntl(fd_number(fo), F_GETFL);
            break;
    }
    rwlock_unlock(&ft->lock);
    if (ret < 0)
        return convert_errno(errno);

    if ((ret & O_APPEND) != 0)
        buf->fs_flags |= __WASI_FDFLAG_APPEND;
#ifdef O_DSYNC
    if ((ret & O_DSYNC) != 0)
        buf->fs_flags |= __WASI_FDFLAG_DSYNC;
#endif
    if ((ret & O_NONBLOCK) != 0)
        buf->fs_flags |= __WASI_FDFLAG_NONBLOCK;
#ifdef O_RSYNC
    if ((ret & O_RSYNC) != 0)
        buf->fs_flags |= __WASI_FDFLAG_RSYNC;
#endif
    if ((ret & O_SYNC) != 0)
        buf->fs_flags |= __WASI_FDFLAG_SYNC;
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_fdstat_set_flags(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_fdflags_t fs_flags)
{
    int noflags = 0;
    if ((fs_flags & __WASI_FDFLAG_APPEND) != 0)
        noflags |= O_APPEND;
    if ((fs_flags & __WASI_FDFLAG_DSYNC) != 0)
#ifdef O_DSYNC
        noflags |= O_DSYNC;
#else
        noflags |= O_SYNC;
#endif
    if ((fs_flags & __WASI_FDFLAG_NONBLOCK) != 0)
        noflags |= O_NONBLOCK;
    if ((fs_flags & __WASI_FDFLAG_RSYNC) != 0)
#ifdef O_RSYNC
        noflags |= O_RSYNC;
#else
        noflags |= O_SYNC;
#endif
    if ((fs_flags & __WASI_FDFLAG_SYNC) != 0)
        noflags |= O_SYNC;

    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_FDSTAT_SET_FLAGS, 0);
    if (error != 0)
        return error;

    int ret = fcntl(fd_number(fo), F_SETFL, noflags);
    fd_object_release(fo);
    if (ret < 0)
        return convert_errno(errno);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_fdstat_set_rights(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_rights_t fs_rights_base,
    __wasi_rights_t fs_rights_inheriting)
{
    struct fd_table *ft = curfds;
    rwlock_wrlock(&ft->lock);
    struct fd_entry *fe;
    __wasi_errno_t error =
        fd_table_get_entry(ft, fd, fs_rights_base, fs_rights_inheriting, &fe);
    if (error != 0) {
        rwlock_unlock(&ft->lock);
        return error;
    }

    // Restrict the rights on the file descriptor.
    fe->rights_base = fs_rights_base;
    fe->rights_inheriting = fs_rights_inheriting;
    rwlock_unlock(&ft->lock);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_sync(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd)
{
    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_SYNC, 0);
    if (error != 0)
        return error;

    int ret = fsync(fd_number(fo));
    fd_object_release(fo);
    if (ret < 0)
        return convert_errno(errno);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_write(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, const __wasi_ciovec_t *iov, size_t iovcnt, size_t *nwritten)
{
    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_WRITE, 0);
    if (error != 0)
        return error;

#ifndef BH_VPRINTF
    ssize_t len = writev(fd_number(fo), (const struct iovec *)iov, (int)iovcnt);
#else
    ssize_t len = 0;
    /* redirect stdout/stderr output to BH_VPRINTF function */
    if (fd_number(fo) == 1 || fd_number(fo) == 2) {
        int i;
        const struct iovec *iov1 = (const struct iovec *)iov;

        for (i = 0; i < (int)iovcnt; i++, iov1++) {
            if (iov1->iov_len > 0 && iov1->iov_base) {
                char format[16];

                /* make up format string "%.ns" */
                snprintf(format, sizeof(format), "%%.%ds", (int)iov1->iov_len);
                len += (ssize_t)os_printf(format, iov1->iov_base);
            }
        }
    }
    else {
        len = writev(fd_number(fo), (const struct iovec *)iov, (int)iovcnt);
    }
#endif /* end of BH_VPRINTF */
    fd_object_release(fo);
    if (len < 0)
        return convert_errno(errno);
    *nwritten = (size_t)len;
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_advise(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_filesize_t offset, __wasi_filesize_t len,
    __wasi_advice_t advice)
{
#ifdef POSIX_FADV_NORMAL
    int nadvice;
    switch (advice) {
        case __WASI_ADVICE_DONTNEED:
            nadvice = POSIX_FADV_DONTNEED;
            break;
        case __WASI_ADVICE_NOREUSE:
            nadvice = POSIX_FADV_NOREUSE;
            break;
        case __WASI_ADVICE_NORMAL:
            nadvice = POSIX_FADV_NORMAL;
            break;
        case __WASI_ADVICE_RANDOM:
            nadvice = POSIX_FADV_RANDOM;
            break;
        case __WASI_ADVICE_SEQUENTIAL:
            nadvice = POSIX_FADV_SEQUENTIAL;
            break;
        case __WASI_ADVICE_WILLNEED:
            nadvice = POSIX_FADV_WILLNEED;
            break;
        default:
            return __WASI_EINVAL;
    }

    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_ADVISE, 0);
    if (error != 0)
        return error;

    int ret = posix_fadvise(fd_number(fo), (off_t)offset, (off_t)len, nadvice);
    fd_object_release(fo);
    if (ret != 0)
        return convert_errno(ret);
    return 0;
#else
    // Advisory information can safely be ignored if unsupported.
    switch (advice) {
        case __WASI_ADVICE_DONTNEED:
        case __WASI_ADVICE_NOREUSE:
        case __WASI_ADVICE_NORMAL:
        case __WASI_ADVICE_RANDOM:
        case __WASI_ADVICE_SEQUENTIAL:
        case __WASI_ADVICE_WILLNEED:
            break;
        default:
            return __WASI_EINVAL;
    }

    // At least check for file descriptor existence.
    struct fd_table *ft = curfds;
    rwlock_rdlock(&ft->lock);
    struct fd_entry *fe;
    __wasi_errno_t error =
        fd_table_get_entry(ft, fd, __WASI_RIGHT_FD_ADVISE, 0, &fe);
    rwlock_unlock(&ft->lock);
    return error;
#endif
}

__wasi_errno_t
wasmtime_ssp_fd_allocate(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_filesize_t offset, __wasi_filesize_t len)
{
    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_ALLOCATE, 0);
    if (error != 0)
        return error;

#if CONFIG_HAS_POSIX_FALLOCATE
    int ret = posix_fallocate(fd_number(fo), (off_t)offset, (off_t)len);
#else
    // At least ensure that the file is grown to the right size.
    // TODO(ed): See if this can somehow be implemented without any race
    // conditions. We may end up shrinking the file right now.
    struct stat sb;
    int ret = fstat(fd_number(fo), &sb);
    off_t newsize = (off_t)(offset + len);
    if (ret == 0 && sb.st_size < newsize)
        ret = ftruncate(fd_number(fo), newsize);
#endif

    fd_object_release(fo);
    if (ret != 0)
        return convert_errno(ret);
    return 0;
}

// Reads the entire contents of a symbolic link, returning the contents
// in an allocated buffer. The allocated buffer is large enough to fit
// at least one extra byte, so the caller may append a trailing slash to
// it. This is needed by path_get().
static char *
readlinkat_dup(int fd, const char *path, size_t *p_len)
{
    char *buf = NULL;
    size_t len = 32;
    size_t len_org = len;

    for (;;) {
        char *newbuf = wasm_runtime_malloc((uint32)len);

        if (newbuf == NULL) {
            if (buf)
                wasm_runtime_free(buf);
            return NULL;
        }

        if (buf != NULL) {
            bh_memcpy_s(newbuf, (uint32)len, buf, (uint32)len_org);
            wasm_runtime_free(buf);
        }

        buf = newbuf;
        ssize_t ret = readlinkat(fd, path, buf, len);
        if (ret < 0) {
            wasm_runtime_free(buf);
            return NULL;
        }
        if ((size_t)ret + 1 < len) {
            buf[ret] = '\0';
            *p_len = len;
            return buf;
        }
        len_org = len;
        len *= 2;
    }
}

// Lease to a directory, so a path underneath it can be accessed.
//
// This structure is used by system calls that operate on pathnames. In
// this environment, pathnames always consist of a pair of a file
// descriptor representing the directory where the lookup needs to start
// and the actual pathname string.
struct path_access {
    int fd;                      // Directory file descriptor.
    const char *path;            // Pathname.
    bool follow;                 // Whether symbolic links should be followed.
    char *path_start;            // Internal: pathname to free.
    struct fd_object *fd_object; // Internal: directory file descriptor object.
};

// Creates a lease to a file descriptor and pathname pair. If the
// operating system does not implement Capsicum, it also normalizes the
// pathname to ensure the target path is placed underneath the
// directory.
static __wasi_errno_t
path_get(struct fd_table *curfds, struct path_access *pa, __wasi_fd_t fd,
         __wasi_lookupflags_t flags, const char *upath, size_t upathlen,
         __wasi_rights_t rights_base, __wasi_rights_t rights_inheriting,
         bool needs_final_component)
    TRYLOCKS_EXCLUSIVE(0, pa->fd_object->refcount)
{
    char *path = str_nullterminate(upath, upathlen);
    if (path == NULL)
        return convert_errno(errno);

    // Fetch the directory file descriptor.
    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, rights_base, rights_inheriting);
    if (error != 0) {
        wasm_runtime_free(path);
        return error;
    }

#if CONFIG_HAS_CAP_ENTER
    // Rely on the kernel to constrain access to automatically constrain
    // access to files stored underneath this directory.
    pa->fd = fd_number(fo);
    pa->path = pa->path_start = path;
    pa->follow = (flags & __WASI_LOOKUP_SYMLINK_FOLLOW) != 0;
    pa->fd_object = fo;
    return 0;
#else
    // The implementation provides no mechanism to constrain lookups to a
    // directory automatically. Emulate this logic by resolving the
    // pathname manually.

    // Stack of directory file descriptors. Index 0 always corresponds
    // with the directory provided to this function. Entering a directory
    // causes a file descriptor to be pushed, while handling ".." entries
    // causes an entry to be popped. Index 0 cannot be popped, as this
    // would imply escaping the base directory.
    int fds[128];
    fds[0] = fd_number(fo);
    size_t curfd = 0;

    // Stack of pathname strings used for symlink expansion. By using a
    // stack, there is no need to concatenate any pathname strings while
    // expanding symlinks.
    char *paths[32];
    char *paths_start[32];
    paths[0] = paths_start[0] = path;
    size_t curpath = 0;
    size_t expansions = 0;
    char *symlink;
    size_t symlink_len;

    for (;;) {
        // Extract the next pathname component from 'paths[curpath]', null
        // terminate it and store it in 'file'. 'ends_with_slashes' stores
        // whether the pathname component is followed by one or more
        // trailing slashes, as this requires it to be a directory.
        char *file = paths[curpath];
        char *file_end = file + strcspn(file, "/");
        paths[curpath] = file_end + strspn(file_end, "/");
        bool ends_with_slashes = *file_end == '/';
        *file_end = '\0';

        // Test for empty pathname strings and absolute paths.
        if (file == file_end) {
            error = ends_with_slashes ? __WASI_ENOTCAPABLE : __WASI_ENOENT;
            goto fail;
        }

        if (strcmp(file, ".") == 0) {
            // Skip component.
        }
        else if (strcmp(file, "..") == 0) {
            // Pop a directory off the stack.
            if (curfd == 0) {
                // Attempted to go to parent directory of the directory file
                // descriptor.
                error = __WASI_ENOTCAPABLE;
                goto fail;
            }
            close(fds[curfd--]);
        }
        else if (curpath > 0 || *paths[curpath] != '\0'
                 || (ends_with_slashes && !needs_final_component)) {
            // A pathname component whose name we're not interested in that is
            // followed by a slash or is followed by other pathname
            // components. In other words, a pathname component that must be a
            // directory. First attempt to obtain a directory file descriptor
            // for it.
            int newdir =
#ifdef O_SEARCH
                openat(fds[curfd], file, O_SEARCH | O_DIRECTORY | O_NOFOLLOW);
#else
                openat(fds[curfd], file, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
#endif
            if (newdir != -1) {
                // Success. Push it onto the directory stack.
                if (curfd + 1 == sizeof(fds) / sizeof(fds[0])) {
                    close(newdir);
                    error = __WASI_ENAMETOOLONG;
                    goto fail;
                }
                fds[++curfd] = newdir;
            }
            else {
                // Failed to open it. Attempt symlink expansion.
                if (errno != ELOOP && errno != EMLINK && errno != ENOTDIR) {
                    error = convert_errno(errno);
                    goto fail;
                }
                symlink = readlinkat_dup(fds[curfd], file, &symlink_len);
                if (symlink != NULL)
                    goto push_symlink;

                // readlink returns EINVAL if the path isn't a symlink. In that
                // case, it's more informative to return ENOTDIR.
                if (errno == EINVAL)
                    errno = ENOTDIR;

                error = convert_errno(errno);
                goto fail;
            }
        }
        else {
            // The final pathname component. Depending on whether it ends with
            // a slash or the symlink-follow flag is set, perform symlink
            // expansion.
            if (ends_with_slashes
                || (flags & __WASI_LOOKUP_SYMLINK_FOLLOW) != 0) {
                symlink = readlinkat_dup(fds[curfd], file, &symlink_len);
                if (symlink != NULL)
                    goto push_symlink;
                if (errno != EINVAL && errno != ENOENT) {
                    error = convert_errno(errno);
                    goto fail;
                }
            }

            // Not a symlink, meaning we're done. Return the filename,
            // together with the directory containing this file.
            //
            // If the file was followed by a trailing slash, we must retain
            // it, to ensure system calls properly return ENOTDIR.
            // Unfortunately, this opens up a race condition, because this
            // means that users of path_get() will perform symlink expansion a
            // second time. There is nothing we can do to mitigate this, as
            // far as I know.
            if (ends_with_slashes)
                *file_end = '/';
            pa->path = file;
            pa->path_start = paths_start[0];
            goto success;
        }

        if (*paths[curpath] == '\0') {
            if (curpath == 0) {
                // No further pathname components to process. We may end up here
                // when called on paths like ".", "a/..", but also if the path
                // had trailing slashes and the caller is not interested in the
                // name of the pathname component.
                wasm_runtime_free(paths_start[0]);
                pa->path = ".";
                pa->path_start = NULL;
                goto success;
            }

            // Finished expanding symlink. Continue processing along the
            // original path.
            wasm_runtime_free(paths_start[curpath--]);
        }
        continue;

    push_symlink:
        // Prevent infinite loops by placing an upper limit on the number of
        // symlink expansions.
        if (++expansions == 128) {
            wasm_runtime_free(symlink);
            error = __WASI_ELOOP;
            goto fail;
        }

        if (*paths[curpath] == '\0') {
            // The original path already finished processing. Replace it by
            // this symlink entirely.
            wasm_runtime_free(paths_start[curpath]);
        }
        else if (curpath + 1 == sizeof(paths) / sizeof(paths[0])) {
            // Too many nested symlinks. Stop processing.
            wasm_runtime_free(symlink);
            error = __WASI_ELOOP;
            goto fail;
        }
        else {
            // The original path still has components left. Retain the
            // components that remain, so we can process them afterwards.
            ++curpath;
        }

        // Append a trailing slash to the symlink if the path leading up to
        // it also contained one. Otherwise we would not throw ENOTDIR if
        // the target is not a directory.
        if (ends_with_slashes)
            bh_strcat_s(symlink, (uint32)symlink_len, "/");
        paths[curpath] = paths_start[curpath] = symlink;
    }

success:
    // Return the lease. Close all directories, except the one the caller
    // needs to use.
    for (size_t i = 1; i < curfd; ++i)
        close(fds[i]);
    pa->fd = fds[curfd];
    pa->follow = false;
    pa->fd_object = fo;
    return 0;

fail:
    // Failure. Free all resources.
    for (size_t i = 1; i <= curfd; ++i)
        close(fds[i]);
    for (size_t i = 0; i <= curpath; ++i)
        wasm_runtime_free(paths_start[i]);
    fd_object_release(fo);
    return error;
#endif
}

static __wasi_errno_t
path_get_nofollow(struct fd_table *curfds, struct path_access *pa,
                  __wasi_fd_t fd, const char *path, size_t pathlen,
                  __wasi_rights_t rights_base,
                  __wasi_rights_t rights_inheriting, bool needs_final_component)
    TRYLOCKS_EXCLUSIVE(0, pa->fd_object->refcount)
{
    __wasi_lookupflags_t flags = 0;
    return path_get(curfds, pa, fd, flags, path, pathlen, rights_base,
                    rights_inheriting, needs_final_component);
}

static void
path_put(struct path_access *pa) UNLOCKS(pa->fd_object->refcount)
{
    if (pa->path_start)
        wasm_runtime_free(pa->path_start);
    if (fd_number(pa->fd_object) != pa->fd)
        close(pa->fd);
    fd_object_release(pa->fd_object);
}

__wasi_errno_t
wasmtime_ssp_path_create_directory(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, const char *path, size_t pathlen)
{
    struct path_access pa;
    __wasi_errno_t error =
        path_get_nofollow(curfds, &pa, fd, path, pathlen,
                          __WASI_RIGHT_PATH_CREATE_DIRECTORY, 0, true);
    if (error != 0)
        return error;

    int ret = mkdirat(pa.fd, pa.path, 0777);
    path_put(&pa);
    if (ret < 0)
        return convert_errno(errno);
    return 0;
}

static bool
validate_path(const char *path, struct fd_prestats *pt)
{
    size_t i;
    char path_resolved[PATH_MAX], prestat_dir_resolved[PATH_MAX];
    char *path_real, *prestat_dir_real;

    if (!(path_real = realpath(path, path_resolved)))
        /* path doesn't exist, creating a link to this file
           is allowed: if this file is to be created in
           the future, WASI will strictly check whether it
           can be created or not. */
        return true;

    for (i = 0; i < pt->size; i++) {
        if (pt->prestats[i].dir) {
            if (!(prestat_dir_real =
                      realpath(pt->prestats[i].dir, prestat_dir_resolved)))
                return false;
            if (!strncmp(path_real, prestat_dir_real, strlen(prestat_dir_real)))
                return true;
        }
    }

    return false;
}

__wasi_errno_t
wasmtime_ssp_path_link(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, struct fd_prestats *prestats,
#endif
    __wasi_fd_t old_fd, __wasi_lookupflags_t old_flags, const char *old_path,
    size_t old_path_len, __wasi_fd_t new_fd, const char *new_path,
    size_t new_path_len)
{
    struct path_access old_pa;
    __wasi_errno_t error =
        path_get(curfds, &old_pa, old_fd, old_flags, old_path, old_path_len,
                 __WASI_RIGHT_PATH_LINK_SOURCE, 0, false);
    if (error != 0)
        return error;

    struct path_access new_pa;
    error = path_get_nofollow(curfds, &new_pa, new_fd, new_path, new_path_len,
                              __WASI_RIGHT_PATH_LINK_TARGET, 0, true);
    if (error != 0) {
        path_put(&old_pa);
        return error;
    }

    rwlock_rdlock(&prestats->lock);
    if (!validate_path(old_pa.path, prestats)
        || !validate_path(new_pa.path, prestats)) {
        rwlock_unlock(&prestats->lock);
        return __WASI_EBADF;
    }
    rwlock_unlock(&prestats->lock);

    int ret = linkat(old_pa.fd, old_pa.path, new_pa.fd, new_pa.path,
                     old_pa.follow ? AT_SYMLINK_FOLLOW : 0);
    if (ret < 0 && errno == ENOTSUP && !old_pa.follow) {
        // OS X doesn't allow creating hardlinks to symbolic links.
        // Duplicate the symbolic link instead.
        size_t target_len;
        char *target = readlinkat_dup(old_pa.fd, old_pa.path, &target_len);
        if (target != NULL) {
            bh_assert(target[target_len] == '\0');
            rwlock_rdlock(&prestats->lock);
            if (!validate_path(target, prestats)) {
                rwlock_unlock(&prestats->lock);
                wasm_runtime_free(target);
                return __WASI_EBADF;
            }
            rwlock_unlock(&prestats->lock);
            ret = symlinkat(target, new_pa.fd, new_pa.path);
            wasm_runtime_free(target);
        }
    }
    path_put(&old_pa);
    path_put(&new_pa);
    if (ret < 0)
        return convert_errno(errno);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_path_open(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t dirfd, __wasi_lookupflags_t dirflags, const char *path,
    size_t pathlen, __wasi_oflags_t oflags, __wasi_rights_t fs_rights_base,
    __wasi_rights_t fs_rights_inheriting, __wasi_fdflags_t fs_flags,
    __wasi_fd_t *fd)
{
    // Rights that should be installed on the new file descriptor.
    __wasi_rights_t rights_base = fs_rights_base;
    __wasi_rights_t rights_inheriting = fs_rights_inheriting;

    // Which open() mode should be used to satisfy the needed rights.
    bool read =
        (rights_base & (__WASI_RIGHT_FD_READ | __WASI_RIGHT_FD_READDIR)) != 0;
    bool write =
        (rights_base
         & (__WASI_RIGHT_FD_DATASYNC | __WASI_RIGHT_FD_WRITE
            | __WASI_RIGHT_FD_ALLOCATE | __WASI_RIGHT_FD_FILESTAT_SET_SIZE))
        != 0;
    int noflags = write ? read ? O_RDWR : O_WRONLY : O_RDONLY;

    // Which rights are needed on the directory file descriptor.
    __wasi_rights_t needed_base = __WASI_RIGHT_PATH_OPEN;
    __wasi_rights_t needed_inheriting = rights_base | rights_inheriting;

    // Convert open flags.
    if ((oflags & __WASI_O_CREAT) != 0) {
        noflags |= O_CREAT;
        needed_base |= __WASI_RIGHT_PATH_CREATE_FILE;
    }
    if ((oflags & __WASI_O_DIRECTORY) != 0)
        noflags |= O_DIRECTORY;
    if ((oflags & __WASI_O_EXCL) != 0)
        noflags |= O_EXCL;
    if ((oflags & __WASI_O_TRUNC) != 0) {
        noflags |= O_TRUNC;
        needed_base |= __WASI_RIGHT_PATH_FILESTAT_SET_SIZE;
    }

    // Convert file descriptor flags.
    if ((fs_flags & __WASI_FDFLAG_APPEND) != 0)
        noflags |= O_APPEND;
    if ((fs_flags & __WASI_FDFLAG_DSYNC) != 0) {
#ifdef O_DSYNC
        noflags |= O_DSYNC;
#else
        noflags |= O_SYNC;
#endif
        needed_inheriting |= __WASI_RIGHT_FD_DATASYNC;
    }
    if ((fs_flags & __WASI_FDFLAG_NONBLOCK) != 0)
        noflags |= O_NONBLOCK;
    if ((fs_flags & __WASI_FDFLAG_RSYNC) != 0) {
#ifdef O_RSYNC
        noflags |= O_RSYNC;
#else
        noflags |= O_SYNC;
#endif
        needed_inheriting |= __WASI_RIGHT_FD_SYNC;
    }
    if ((fs_flags & __WASI_FDFLAG_SYNC) != 0) {
        noflags |= O_SYNC;
        needed_inheriting |= __WASI_RIGHT_FD_SYNC;
    }
    if (write && (noflags & (O_APPEND | O_TRUNC)) == 0)
        needed_inheriting |= __WASI_RIGHT_FD_SEEK;

    struct path_access pa;
    __wasi_errno_t error =
        path_get(curfds, &pa, dirfd, dirflags, path, pathlen, needed_base,
                 needed_inheriting, (oflags & __WASI_O_CREAT) != 0);
    if (error != 0)
        return error;
    if (!pa.follow)
        noflags |= O_NOFOLLOW;

    int nfd = openat(pa.fd, pa.path, noflags, 0666);
    if (nfd < 0) {
        int openat_errno = errno;
        // Linux returns ENXIO instead of EOPNOTSUPP when opening a socket.
        if (openat_errno == ENXIO) {
            struct stat sb;
            int ret = fstatat(pa.fd, pa.path, &sb,
                              pa.follow ? 0 : AT_SYMLINK_NOFOLLOW);
            path_put(&pa);
            return ret == 0 && S_ISSOCK(sb.st_mode) ? __WASI_ENOTSUP
                                                    : __WASI_ENXIO;
        }
        // Linux returns ENOTDIR instead of ELOOP when using
        // O_NOFOLLOW|O_DIRECTORY on a symlink.
        if (openat_errno == ENOTDIR
            && (noflags & (O_NOFOLLOW | O_DIRECTORY)) != 0) {
            struct stat sb;
            int ret = fstatat(pa.fd, pa.path, &sb, AT_SYMLINK_NOFOLLOW);
            if (S_ISLNK(sb.st_mode)) {
                path_put(&pa);
                return __WASI_ELOOP;
            }
            (void)ret;
        }
        path_put(&pa);
        // FreeBSD returns EMLINK instead of ELOOP when using O_NOFOLLOW on
        // a symlink.
        if (!pa.follow && openat_errno == EMLINK)
            return __WASI_ELOOP;
        return convert_errno(openat_errno);
    }
    path_put(&pa);

    // Determine the type of the new file descriptor and which rights
    // contradict with this type.
    __wasi_filetype_t type;
    __wasi_rights_t max_base, max_inheriting;
    error = fd_determine_type_rights(nfd, &type, &max_base, &max_inheriting);
    if (error != 0) {
        close(nfd);
        return error;
    }

    {
        struct stat sb;

        if (fstat(nfd, &sb) < 0) {
            close(nfd);
            return convert_errno(errno);
        }

        if (S_ISDIR(sb.st_mode))
            rights_base |= (__wasi_rights_t)RIGHTS_DIRECTORY_BASE;
        else if (S_ISREG(sb.st_mode))
            rights_base |= (__wasi_rights_t)RIGHTS_REGULAR_FILE_BASE;
    }

    return fd_table_insert_fd(curfds, nfd, type, rights_base & max_base,
                              rights_inheriting & max_inheriting, fd);
}

// Copies out directory entry metadata or filename, potentially
// truncating it in the process.
static void
fd_readdir_put(void *buf, size_t bufsize, size_t *bufused, const void *elem,
               size_t elemsize)
{
    size_t bufavail = bufsize - *bufused;
    if (elemsize > bufavail)
        elemsize = bufavail;
    bh_memcpy_s((char *)buf + *bufused, (uint32)bufavail, elem,
                (uint32)elemsize);
    *bufused += elemsize;
}

__wasi_errno_t
wasmtime_ssp_fd_readdir(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, void *buf, size_t nbyte, __wasi_dircookie_t cookie,
    size_t *bufused)
{
    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_READDIR, 0);
    if (error != 0) {
        return error;
    }

    // Create a directory handle if none has been opened yet.
    mutex_lock(&fo->directory.lock);
    DIR *dp = fo->directory.handle;
    if (dp == NULL) {
        dp = fdopendir(fd_number(fo));
        if (dp == NULL) {
            mutex_unlock(&fo->directory.lock);
            fd_object_release(fo);
            return convert_errno(errno);
        }
        fo->directory.handle = dp;
        fo->directory.offset = __WASI_DIRCOOKIE_START;
    }

    // Seek to the right position if the requested offset does not match
    // the current offset.
    if (fo->directory.offset != cookie) {
        if (cookie == __WASI_DIRCOOKIE_START)
            rewinddir(dp);
        else
            seekdir(dp, (long)cookie);
        fo->directory.offset = cookie;
    }

    *bufused = 0;
    while (*bufused < nbyte) {
        // Read the next directory entry.
        errno = 0;
        struct dirent *de = readdir(dp);
        if (de == NULL) {
            mutex_unlock(&fo->directory.lock);
            fd_object_release(fo);
            return errno == 0 || *bufused > 0 ? 0 : convert_errno(errno);
        }
        fo->directory.offset = (__wasi_dircookie_t)telldir(dp);

        // Craft a directory entry and copy that back.
        size_t namlen = strlen(de->d_name);
        __wasi_dirent_t cde = {
            .d_next = fo->directory.offset,
#if CONFIG_HAS_D_INO
            .d_ino = de->d_ino,
#else
            .d_ino = 0,
#endif
            .d_namlen = (uint32)namlen,
        };
        switch (de->d_type) {
            case DT_BLK:
                cde.d_type = __WASI_FILETYPE_BLOCK_DEVICE;
                break;
            case DT_CHR:
                cde.d_type = __WASI_FILETYPE_CHARACTER_DEVICE;
                break;
            case DT_DIR:
                cde.d_type = __WASI_FILETYPE_DIRECTORY;
                break;
            case DT_FIFO:
                cde.d_type = __WASI_FILETYPE_SOCKET_STREAM;
                break;
            case DT_LNK:
                cde.d_type = __WASI_FILETYPE_SYMBOLIC_LINK;
                break;
            case DT_REG:
                cde.d_type = __WASI_FILETYPE_REGULAR_FILE;
                break;
#ifdef DT_SOCK
            case DT_SOCK:
                // Technically not correct, but good enough.
                cde.d_type = __WASI_FILETYPE_SOCKET_STREAM;
                break;
#endif
            default:
                cde.d_type = __WASI_FILETYPE_UNKNOWN;
                break;
        }
        fd_readdir_put(buf, nbyte, bufused, &cde, sizeof(cde));
        fd_readdir_put(buf, nbyte, bufused, de->d_name, namlen);
    }
    mutex_unlock(&fo->directory.lock);
    fd_object_release(fo);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_path_readlink(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, const char *path, size_t pathlen, char *buf, size_t bufsize,
    size_t *bufused)
{
    struct path_access pa;
    __wasi_errno_t error = path_get_nofollow(
        curfds, &pa, fd, path, pathlen, __WASI_RIGHT_PATH_READLINK, 0, false);
    if (error != 0)
        return error;

    // Linux requires that the buffer size is positive. whereas POSIX does
    // not. Use a fake buffer to store the results if the size is zero.
    char fakebuf[1];
    ssize_t len = readlinkat(pa.fd, pa.path, bufsize == 0 ? fakebuf : buf,
                             bufsize == 0 ? sizeof(fakebuf) : bufsize);
    path_put(&pa);
    if (len < 0)
        return convert_errno(errno);
    *bufused = (size_t)len < bufsize ? (size_t)len : bufsize;
    return 0;
}

__wasi_errno_t
wasmtime_ssp_path_rename(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t old_fd, const char *old_path, size_t old_path_len,
    __wasi_fd_t new_fd, const char *new_path, size_t new_path_len)
{
    struct path_access old_pa;
    __wasi_errno_t error =
        path_get_nofollow(curfds, &old_pa, old_fd, old_path, old_path_len,
                          __WASI_RIGHT_PATH_RENAME_SOURCE, 0, true);
    if (error != 0)
        return error;

    struct path_access new_pa;
    error = path_get_nofollow(curfds, &new_pa, new_fd, new_path, new_path_len,
                              __WASI_RIGHT_PATH_RENAME_TARGET, 0, true);
    if (error != 0) {
        path_put(&old_pa);
        return error;
    }

    int ret = renameat(old_pa.fd, old_pa.path, new_pa.fd, new_pa.path);
    path_put(&old_pa);
    path_put(&new_pa);
    if (ret < 0) {
        return convert_errno(errno);
    }
    return 0;
}

// Converts a POSIX stat structure to a CloudABI filestat structure.
static void
convert_stat(const struct stat *in, __wasi_filestat_t *out)
{
    *out = (__wasi_filestat_t){
        .st_dev = in->st_dev,
        .st_ino = in->st_ino,
        .st_nlink = (__wasi_linkcount_t)in->st_nlink,
        .st_size = (__wasi_filesize_t)in->st_size,
        .st_atim = convert_timespec(&in->st_atim),
        .st_mtim = convert_timespec(&in->st_mtim),
        .st_ctim = convert_timespec(&in->st_ctim),
    };
}

__wasi_errno_t
wasmtime_ssp_fd_filestat_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_filestat_t *buf)
{
    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_FILESTAT_GET, 0);
    if (error != 0)
        return error;

    int ret;
    switch (fo->type) {
        default:
        {
            struct stat sb;
            ret = fstat(fd_number(fo), &sb);
            convert_stat(&sb, buf);
            break;
        }
    }
    buf->st_filetype = fo->type;
    fd_object_release(fo);
    if (ret < 0)
        return convert_errno(errno);
    return 0;
}

static void
convert_timestamp(__wasi_timestamp_t in, struct timespec *out)
{
    // Store sub-second remainder.
#if defined(__SYSCALL_SLONG_TYPE)
    out->tv_nsec = (__SYSCALL_SLONG_TYPE)(in % 1000000000);
#else
    out->tv_nsec = (long)(in % 1000000000);
#endif
    in /= 1000000000;

    // Clamp to the maximum in case it would overflow our system's time_t.
    out->tv_sec =
        (time_t)in < NUMERIC_MAX(time_t) ? (time_t)in : NUMERIC_MAX(time_t);
}

// Converts the provided timestamps and flags to a set of arguments for
// futimens() and utimensat().
static void
convert_utimens_arguments(__wasi_timestamp_t st_atim,
                          __wasi_timestamp_t st_mtim,
                          __wasi_fstflags_t fstflags, struct timespec *ts)
{
    if ((fstflags & __WASI_FILESTAT_SET_ATIM_NOW) != 0) {
        ts[0].tv_nsec = UTIME_NOW;
    }
    else if ((fstflags & __WASI_FILESTAT_SET_ATIM) != 0) {
        convert_timestamp(st_atim, &ts[0]);
    }
    else {
        ts[0].tv_nsec = UTIME_OMIT;
    }

    if ((fstflags & __WASI_FILESTAT_SET_MTIM_NOW) != 0) {
        ts[1].tv_nsec = UTIME_NOW;
    }
    else if ((fstflags & __WASI_FILESTAT_SET_MTIM) != 0) {
        convert_timestamp(st_mtim, &ts[1]);
    }
    else {
        ts[1].tv_nsec = UTIME_OMIT;
    }
}

__wasi_errno_t
wasmtime_ssp_fd_filestat_set_size(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_filesize_t st_size)
{
    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_FILESTAT_SET_SIZE, 0);
    if (error != 0)
        return error;

    int ret = ftruncate(fd_number(fo), (off_t)st_size);
    fd_object_release(fo);
    if (ret < 0)
        return convert_errno(errno);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_fd_filestat_set_times(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_timestamp_t st_atim, __wasi_timestamp_t st_mtim,
    __wasi_fstflags_t fstflags)
{
    if ((fstflags
         & ~(__WASI_FILESTAT_SET_ATIM | __WASI_FILESTAT_SET_ATIM_NOW
             | __WASI_FILESTAT_SET_MTIM | __WASI_FILESTAT_SET_MTIM_NOW))
        != 0)
        return __WASI_EINVAL;

    struct fd_object *fo;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_FD_FILESTAT_SET_TIMES, 0);
    if (error != 0)
        return error;

    struct timespec ts[2];
    convert_utimens_arguments(st_atim, st_mtim, fstflags, ts);
    int ret = futimens(fd_number(fo), ts);

    fd_object_release(fo);
    if (ret < 0)
        return convert_errno(errno);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_path_filestat_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_lookupflags_t flags, const char *path,
    size_t pathlen, __wasi_filestat_t *buf)
{
    struct path_access pa;
    __wasi_errno_t error = path_get(curfds, &pa, fd, flags, path, pathlen,
                                    __WASI_RIGHT_PATH_FILESTAT_GET, 0, false);
    if (error != 0)
        return error;

    struct stat sb;
    int ret = fstatat(pa.fd, pa.path, &sb, pa.follow ? 0 : AT_SYMLINK_NOFOLLOW);
    path_put(&pa);
    if (ret < 0)
        return convert_errno(errno);
    convert_stat(&sb, buf);

    // Convert the file type. In the case of sockets there is no way we
    // can easily determine the exact socket type.
    if (S_ISBLK(sb.st_mode))
        buf->st_filetype = __WASI_FILETYPE_BLOCK_DEVICE;
    else if (S_ISCHR(sb.st_mode))
        buf->st_filetype = __WASI_FILETYPE_CHARACTER_DEVICE;
    else if (S_ISDIR(sb.st_mode))
        buf->st_filetype = __WASI_FILETYPE_DIRECTORY;
    else if (S_ISFIFO(sb.st_mode))
        buf->st_filetype = __WASI_FILETYPE_SOCKET_STREAM;
    else if (S_ISLNK(sb.st_mode))
        buf->st_filetype = __WASI_FILETYPE_SYMBOLIC_LINK;
    else if (S_ISREG(sb.st_mode))
        buf->st_filetype = __WASI_FILETYPE_REGULAR_FILE;
    else if (S_ISSOCK(sb.st_mode))
        buf->st_filetype = __WASI_FILETYPE_SOCKET_STREAM;
    return 0;
}

__wasi_errno_t
wasmtime_ssp_path_filestat_set_times(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_lookupflags_t flags, const char *path,
    size_t pathlen, __wasi_timestamp_t st_atim, __wasi_timestamp_t st_mtim,
    __wasi_fstflags_t fstflags)
{
    if (((fstflags
          & ~(__WASI_FILESTAT_SET_ATIM | __WASI_FILESTAT_SET_ATIM_NOW
              | __WASI_FILESTAT_SET_MTIM | __WASI_FILESTAT_SET_MTIM_NOW))
         != 0)
        /* ATIM & ATIM_NOW can't be set at the same time */
        || ((fstflags & __WASI_FILESTAT_SET_ATIM) != 0
            && (fstflags & __WASI_FILESTAT_SET_ATIM_NOW) != 0)
        /* MTIM & MTIM_NOW can't be set at the same time */
        || ((fstflags & __WASI_FILESTAT_SET_MTIM) != 0
            && (fstflags & __WASI_FILESTAT_SET_MTIM_NOW) != 0))
        return __WASI_EINVAL;

    struct path_access pa;
    __wasi_errno_t error =
        path_get(curfds, &pa, fd, flags, path, pathlen,
                 __WASI_RIGHT_PATH_FILESTAT_SET_TIMES, 0, false);
    if (error != 0)
        return error;

    struct timespec ts[2];
    convert_utimens_arguments(st_atim, st_mtim, fstflags, ts);
    int ret =
        utimensat(pa.fd, pa.path, ts, pa.follow ? 0 : AT_SYMLINK_NOFOLLOW);

    path_put(&pa);
    if (ret < 0)
        return convert_errno(errno);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_path_symlink(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, struct fd_prestats *prestats,
#endif
    const char *old_path, size_t old_path_len, __wasi_fd_t fd,
    const char *new_path, size_t new_path_len)
{
    char *target = str_nullterminate(old_path, old_path_len);
    if (target == NULL)
        return convert_errno(errno);

    struct path_access pa;
    __wasi_errno_t error =
        path_get_nofollow(curfds, &pa, fd, new_path, new_path_len,
                          __WASI_RIGHT_PATH_SYMLINK, 0, true);
    if (error != 0) {
        wasm_runtime_free(target);
        return error;
    }

    rwlock_rdlock(&prestats->lock);
    if (!validate_path(target, prestats)) {
        rwlock_unlock(&prestats->lock);
        wasm_runtime_free(target);
        return __WASI_EBADF;
    }
    rwlock_unlock(&prestats->lock);

    int ret = symlinkat(target, pa.fd, pa.path);
    path_put(&pa);
    wasm_runtime_free(target);
    if (ret < 0)
        return convert_errno(errno);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_path_unlink_file(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, const char *path, size_t pathlen)
{
    struct path_access pa;
    __wasi_errno_t error = path_get_nofollow(
        curfds, &pa, fd, path, pathlen, __WASI_RIGHT_PATH_UNLINK_FILE, 0, true);
    if (error != 0)
        return error;

    int ret = unlinkat(pa.fd, pa.path, 0);
#ifndef __linux__
    // Non-Linux implementations may return EPERM when attempting to remove a
    // directory without REMOVEDIR. While that's what POSIX specifies, it's
    // less useful. Adjust this to EISDIR. It doesn't matter that this is not
    // atomic with the unlinkat, because if the file is removed and a directory
    // is created before fstatat sees it, we're racing with that change anyway
    // and unlinkat could have legitimately seen the directory if the race had
    // turned out differently.
    if (ret < 0 && errno == EPERM) {
        struct stat statbuf;
        if (fstatat(pa.fd, pa.path, &statbuf, AT_SYMLINK_NOFOLLOW) == 0
            && S_ISDIR(statbuf.st_mode)) {
            errno = EISDIR;
        }
    }
#endif
    path_put(&pa);
    if (ret < 0) {
        return convert_errno(errno);
    }
    return 0;
}

__wasi_errno_t
wasmtime_ssp_path_remove_directory(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, const char *path, size_t pathlen)
{
    struct path_access pa;
    __wasi_errno_t error =
        path_get_nofollow(curfds, &pa, fd, path, pathlen,
                          __WASI_RIGHT_PATH_REMOVE_DIRECTORY, 0, true);
    if (error != 0)
        return error;

    int ret = unlinkat(pa.fd, pa.path, AT_REMOVEDIR);
#ifndef __linux__
    // POSIX permits either EEXIST or ENOTEMPTY when the directory is not empty.
    // Map it to ENOTEMPTY.
    if (ret < 0 && errno == EEXIST) {
        errno = ENOTEMPTY;
    }
#endif
    path_put(&pa);
    if (ret < 0) {
        return convert_errno(errno);
    }
    return 0;
}

__wasi_errno_t
wasmtime_ssp_poll_oneoff(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    const __wasi_subscription_t *in, __wasi_event_t *out, size_t nsubscriptions,
    size_t *nevents) NO_LOCK_ANALYSIS
{
    // Sleeping.
    if (nsubscriptions == 1 && in[0].u.type == __WASI_EVENTTYPE_CLOCK) {
        out[0] = (__wasi_event_t){
            .userdata = in[0].userdata,
            .type = in[0].u.type,
        };
#if CONFIG_HAS_CLOCK_NANOSLEEP
        clockid_t clock_id;
        if (convert_clockid(in[0].u.u.clock.clock_id, &clock_id)) {
            struct timespec ts;
            convert_timestamp(in[0].u.u.clock.timeout, &ts);
            int ret = clock_nanosleep(
                clock_id,
                (in[0].u.u.clock.flags & __WASI_SUBSCRIPTION_CLOCK_ABSTIME) != 0
                    ? TIMER_ABSTIME
                    : 0,
                &ts, NULL);
            if (ret != 0)
                out[0].error = convert_errno(ret);
        }
        else {
            out[0].error = __WASI_ENOTSUP;
        }
#else
        switch (in[0].u.u.clock.clock_id) {
            case __WASI_CLOCK_MONOTONIC:
                if ((in[0].u.u.clock.flags & __WASI_SUBSCRIPTION_CLOCK_ABSTIME)
                    != 0) {
                    // TODO(ed): Implement.
                    fputs("Unimplemented absolute sleep on monotonic clock\n",
                          stderr);
                    out[0].error = __WASI_ENOSYS;
                }
                else {
                    // Perform relative sleeps on the monotonic clock also using
                    // nanosleep(). This is incorrect, but good enough for now.
                    struct timespec ts;
                    convert_timestamp(in[0].u.u.clock.timeout, &ts);
                    nanosleep(&ts, NULL);
                }
                break;
            case __WASI_CLOCK_REALTIME:
                if ((in[0].u.u.clock.flags & __WASI_SUBSCRIPTION_CLOCK_ABSTIME)
                    != 0) {
                    // Sleeping to an absolute point in time can only be done
                    // by waiting on a condition variable.
                    struct mutex mutex;
                    struct cond cond;

                    if (!mutex_init(&mutex))
                        return -1;
                    if (!cond_init_realtime(&cond)) {
                        mutex_destroy(&mutex);
                        return -1;
                    }
                    mutex_lock(&mutex);
                    cond_timedwait(&cond, &mutex, in[0].u.u.clock.timeout,
                                   true);
                    mutex_unlock(&mutex);
                    mutex_destroy(&mutex);
                    cond_destroy(&cond);
                }
                else {
                    // Relative sleeps can be done using nanosleep().
                    struct timespec ts;
                    convert_timestamp(in[0].u.u.clock.timeout, &ts);
                    nanosleep(&ts, NULL);
                }
                break;
            default:
                out[0].error = __WASI_ENOTSUP;
                break;
        }
#endif
        *nevents = 1;
        return 0;
    }

    // Last option: call into poll(). This can only be done in case all
    // subscriptions consist of __WASI_EVENTTYPE_FD_READ and
    // __WASI_EVENTTYPE_FD_WRITE entries. There may be up to one
    // __WASI_EVENTTYPE_CLOCK entry to act as a timeout. These are also
    // the subscriptions generate by cloudlibc's poll() and select().
    struct fd_object **fos =
        wasm_runtime_malloc((uint32)(nsubscriptions * sizeof(*fos)));
    if (fos == NULL)
        return __WASI_ENOMEM;
    struct pollfd *pfds =
        wasm_runtime_malloc((uint32)(nsubscriptions * sizeof(*pfds)));
    if (pfds == NULL) {
        wasm_runtime_free(fos);
        return __WASI_ENOMEM;
    }

    // Convert subscriptions to pollfd entries. Increase the reference
    // count on the file descriptors to ensure they remain valid across
    // the call to poll().
    struct fd_table *ft = curfds;
    rwlock_rdlock(&ft->lock);
    *nevents = 0;
    const __wasi_subscription_t *clock_subscription = NULL;
    for (size_t i = 0; i < nsubscriptions; ++i) {
        const __wasi_subscription_t *s = &in[i];
        switch (s->u.type) {
            case __WASI_EVENTTYPE_FD_READ:
            case __WASI_EVENTTYPE_FD_WRITE:
            {
                __wasi_errno_t error =
                    fd_object_get_locked(&fos[i], ft, s->u.u.fd_readwrite.fd,
                                         __WASI_RIGHT_POLL_FD_READWRITE, 0);
                if (error == 0) {
                    // Proper file descriptor on which we can poll().
                    pfds[i] = (struct pollfd){
                        .fd = fd_number(fos[i]),
                        .events = s->u.type == __WASI_EVENTTYPE_FD_READ
                                      ? POLLIN
                                      : POLLOUT,
                    };
                }
                else {
                    // Invalid file descriptor or rights missing.
                    fos[i] = NULL;
                    pfds[i] = (struct pollfd){ .fd = -1 };
                    out[(*nevents)++] = (__wasi_event_t){
                        .userdata = s->userdata,
                        .error = error,
                        .type = s->u.type,
                    };
                }
                break;
            }
            case __WASI_EVENTTYPE_CLOCK:
                if (clock_subscription == NULL
                    && (s->u.u.clock.flags & __WASI_SUBSCRIPTION_CLOCK_ABSTIME)
                           == 0) {
                    // Relative timeout.
                    fos[i] = NULL;
                    pfds[i] = (struct pollfd){ .fd = -1 };
                    clock_subscription = s;
                    break;
                }
            // Fallthrough.
            default:
                // Unsupported event.
                fos[i] = NULL;
                pfds[i] = (struct pollfd){ .fd = -1 };
                out[(*nevents)++] = (__wasi_event_t){
                    .userdata = s->userdata,
                    .error = __WASI_ENOSYS,
                    .type = s->u.type,
                };
                break;
        }
    }
    rwlock_unlock(&ft->lock);

    // Use a zero-second timeout in case we've already generated events in
    // the loop above.
    int timeout;
    if (*nevents != 0) {
        timeout = 0;
    }
    else if (clock_subscription != NULL) {
        __wasi_timestamp_t ts = clock_subscription->u.u.clock.timeout / 1000000;
        timeout = ts > INT_MAX ? -1 : (int)ts;
    }
    else {
        timeout = 1000;
    }
    int ret = poll(pfds, nsubscriptions, timeout);

    __wasi_errno_t error = 0;
    if (ret == -1) {
        error = convert_errno(errno);
    }
    else if (ret == 0 && *nevents == 0 && clock_subscription != NULL) {
        // No events triggered. Trigger the clock event.
        out[(*nevents)++] = (__wasi_event_t){
            .userdata = clock_subscription->userdata,
            .type = __WASI_EVENTTYPE_CLOCK,
        };
    }
    else {
        // Events got triggered. Don't trigger the clock event.
        for (size_t i = 0; i < nsubscriptions; ++i) {
            if (pfds[i].fd >= 0) {
                __wasi_filesize_t nbytes = 0;
                if (in[i].u.type == __WASI_EVENTTYPE_FD_READ) {
                    int l;
                    if (ioctl(fd_number(fos[i]), FIONREAD, &l) == 0)
                        nbytes = (__wasi_filesize_t)l;
                }
                if ((pfds[i].revents & POLLNVAL) != 0) {
                    // Bad file descriptor. This normally cannot occur, as
                    // referencing the file descriptor object will always ensure
                    // the descriptor is valid. Still, macOS may sometimes
                    // return this on FIFOs when reaching end-of-file.
                    out[(*nevents)++] = (__wasi_event_t){
                        .userdata = in[i].userdata,
#ifdef __APPLE__
                        .u.fd_readwrite.nbytes = nbytes,
                        .u.fd_readwrite.flags =
                            __WASI_EVENT_FD_READWRITE_HANGUP,
#else
                        .error = __WASI_EBADF,
#endif
                        .type = in[i].u.type,
                    };
                }
                else if ((pfds[i].revents & POLLERR) != 0) {
                    // File descriptor is in an error state.
                    out[(*nevents)++] = (__wasi_event_t){
                        .userdata = in[i].userdata,
                        .error = __WASI_EIO,
                        .type = in[i].u.type,
                    };
                }
                else if ((pfds[i].revents & POLLHUP) != 0) {
                    // End-of-file.
                    out[(*nevents)++] = (__wasi_event_t){
                        .userdata = in[i].userdata,
                        .type = in[i].u.type,
                        .u.fd_readwrite.nbytes = nbytes,
                        .u.fd_readwrite.flags =
                            __WASI_EVENT_FD_READWRITE_HANGUP,
                    };
                }
                else if ((pfds[i].revents & (POLLIN | POLLOUT)) != 0) {
                    // Read or write possible.
                    out[(*nevents)++] = (__wasi_event_t){
                        .userdata = in[i].userdata,
                        .type = in[i].u.type,
                        .u.fd_readwrite.nbytes = nbytes,
                    };
                }
            }
        }
    }

    for (size_t i = 0; i < nsubscriptions; ++i)
        if (fos[i] != NULL)
            fd_object_release(fos[i]);
    wasm_runtime_free(fos);
    wasm_runtime_free(pfds);
    return error;
}

#if 0
/**
 * We throw exception in libc-wasi wrapper function wasi_proc_exit()
 * but not call this function.
 */
void wasmtime_ssp_proc_exit(
    __wasi_exitcode_t rval
) {
  _Exit((int32)rval);
}
#endif

__wasi_errno_t
wasmtime_ssp_proc_raise(__wasi_signal_t sig)
{
    static const int signals[] = {
#define X(v) [__WASI_##v] = v
#if defined(SIGABRT)
        X(SIGABRT),
#endif
#if defined(SIGALRM)
        X(SIGALRM),
#endif
#if defined(SIGBUS)
        X(SIGBUS),
#endif
#if defined(SIGCHLD)
        X(SIGCHLD),
#endif
#if defined(SIGCONT)
        X(SIGCONT),
#endif
#if defined(SIGFPE)
        X(SIGFPE),
#endif
#if defined(SIGHUP)
        X(SIGHUP),
#endif
#if defined(SIGILL)
        X(SIGILL),
#endif
#if defined(SIGINT)
        X(SIGINT),
#endif
#if defined(SIGKILL)
        X(SIGKILL),
#endif
#if defined(SIGPIPE)
        X(SIGPIPE),
#endif
#if defined(SIGQUIT)
        X(SIGQUIT),
#endif
#if defined(SIGSYS)
        X(SIGSEGV),
#endif
#if defined(SIGSTOP)
        X(SIGSTOP),
#endif
#if defined(SIGSYS)
        X(SIGSYS),
#endif
#if defined(SIGTERM)
        X(SIGTERM),
#endif
#if defined(SIGTRAP)
        X(SIGTRAP),
#endif
#if defined(SIGTSTP)
        X(SIGTSTP),
#endif
#if defined(SIGTTIN)
        X(SIGTTIN),
#endif
#if defined(SIGTTOU)
        X(SIGTTOU),
#endif
#if defined(SIGURG)
        X(SIGURG),
#endif
#if defined(SIGUSR1)
        X(SIGUSR1),
#endif
#if defined(SIGUSR2)
        X(SIGUSR2),
#endif
#if defined(SIGVTALRM)
        X(SIGVTALRM),
#endif
#if defined(SIGXCPU)
        X(SIGXCPU),
#endif
#if defined(SIGXFSZ)
        X(SIGXFSZ),
#endif
#undef X
    };
    if (sig >= sizeof(signals) / sizeof(signals[0]) || signals[sig] == 0)
        return __WASI_EINVAL;

#if CONFIG_TLS_USE_GSBASE
    // TLS on OS X depends on installing a SIGSEGV handler. Reset SIGSEGV
    // to the default action before raising.
    if (sig == __WASI_SIGSEGV) {
        struct sigaction sa = {
            .sa_handler = SIG_DFL,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, NULL);
    }
#endif

    if (raise(signals[sig]) < 0)
        return convert_errno(errno);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_random_get(void *buf, size_t nbyte)
{
    random_buf(buf, nbyte);
    return 0;
}

__wasi_errno_t
wasi_ssp_sock_accept(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_fdflags_t flags, __wasi_fd_t *fd_new)
{
    __wasi_filetype_t wasi_type;
    __wasi_rights_t max_base, max_inheriting;
    struct fd_object *fo;
    bh_socket_t new_sock = -1;
    int ret;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_ACCEPT, 0);
    if (error != __WASI_ESUCCESS) {
        goto fail;
    }

    ret = os_socket_accept(fd_number(fo), &new_sock, NULL, NULL);
    fd_object_release(fo);
    if (BHT_OK != ret) {
        error = convert_errno(errno);
        goto fail;
    }

    error = fd_determine_type_rights(new_sock, &wasi_type, &max_base,
                                     &max_inheriting);
    if (error != __WASI_ESUCCESS) {
        goto fail;
    }

    error = fd_table_insert_fd(curfds, new_sock, wasi_type, max_base,
                               max_inheriting, fd_new);
    if (error != __WASI_ESUCCESS) {
        /* released in fd_table_insert_fd() */
        new_sock = -1;
        goto fail;
    }

    return __WASI_ESUCCESS;

fail:
    if (-1 != new_sock) {
        os_socket_close(new_sock);
    }
    return error;
}

__wasi_errno_t
wasi_ssp_sock_addr_local(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_addr_t *addr)
{
    struct fd_object *fo;
    bh_sockaddr_t bh_addr;
    int ret;

    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_ADDR_LOCAL, 0);
    if (error != __WASI_ESUCCESS)
        return error;

    ret = os_socket_addr_local(fd_number(fo), &bh_addr);
    fd_object_release(fo);
    if (ret != BHT_OK) {
        return convert_errno(errno);
    }

    bh_sockaddr_to_wasi_addr(&bh_addr, addr);

    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasi_ssp_sock_addr_remote(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_addr_t *addr)
{
    struct fd_object *fo;
    bh_sockaddr_t bh_addr;
    int ret;

    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_ADDR_LOCAL, 0);
    if (error != __WASI_ESUCCESS)
        return error;

    ret = os_socket_addr_remote(fd_number(fo), &bh_addr);
    fd_object_release(fo);
    if (ret != BHT_OK) {
        return convert_errno(errno);
    }

    bh_sockaddr_to_wasi_addr(&bh_addr, addr);

    return __WASI_ESUCCESS;
}

static bool
wasi_addr_to_string(const __wasi_addr_t *addr, char *buf, size_t buflen)
{
    if (addr->kind == IPv4) {
        const char *format = "%u.%u.%u.%u";

        assert(buflen >= 16);

        snprintf(buf, buflen, format, addr->addr.ip4.addr.n0,
                 addr->addr.ip4.addr.n1, addr->addr.ip4.addr.n2,
                 addr->addr.ip4.addr.n3);

        return true;
    }
    else if (addr->kind == IPv6) {
        const char *format = "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x";
        __wasi_addr_ip6_t ipv6 = addr->addr.ip6.addr;

        assert(buflen >= 40);

        snprintf(buf, buflen, format, ipv6.n0, ipv6.n1, ipv6.n2, ipv6.n3,
                 ipv6.h0, ipv6.h1, ipv6.h2, ipv6.h3);

        return true;
    }

    return false;
}

__wasi_errno_t
wasi_ssp_sock_bind(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, struct addr_pool *addr_pool,
#endif
    __wasi_fd_t fd, __wasi_addr_t *addr)
{
    char buf[48] = { 0 };
    struct fd_object *fo;
    __wasi_errno_t error;
    int port = addr->kind == IPv4 ? addr->addr.ip4.port : addr->addr.ip6.port;
    int ret;

    if (!wasi_addr_to_string(addr, buf, sizeof(buf))) {
        return __WASI_EPROTONOSUPPORT;
    }

    if (!addr_pool_search(addr_pool, buf)) {
        return __WASI_EACCES;
    }

    error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_BIND, 0);
    if (error != __WASI_ESUCCESS)
        return error;

    ret = os_socket_bind(fd_number(fo), buf, &port);
    fd_object_release(fo);
    if (BHT_OK != ret) {
        return convert_errno(errno);
    }

    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasi_ssp_sock_addr_resolve(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, char **ns_lookup_list,
#endif
    const char *host, const char *service, __wasi_addr_info_hints_t *hints,
    __wasi_addr_info_t *addr_info, __wasi_size_t addr_info_size,
    __wasi_size_t *max_info_size)
{
    bh_addr_info_t *wamr_addr_info =
        wasm_runtime_malloc(addr_info_size * sizeof(bh_addr_info_t));
    uint8_t hints_is_ipv4 = hints->family == INET4;
    uint8_t hints_is_tcp = hints->type == SOCKET_STREAM;
    size_t _max_info_size;
    size_t actual_info_size;

    if (!ns_lookup_list_search(ns_lookup_list, host)) {
        return __WASI_EACCES;
    }

    if (!wamr_addr_info) {
        return __WASI_ENOMEM;
    }

    int ret = os_socket_addr_resolve(
        host, service, hints->hints_enabled ? &hints_is_tcp : NULL,
        hints->hints_enabled ? &hints_is_ipv4 : NULL, wamr_addr_info,
        addr_info_size, &_max_info_size);

    if (ret != BHT_OK) {
        wasm_runtime_free(wamr_addr_info);
        return convert_errno(errno);
    }

    *max_info_size = _max_info_size;
    actual_info_size =
        addr_info_size < *max_info_size ? addr_info_size : *max_info_size;

    for (size_t i = 0; i < actual_info_size; i++) {
        addr_info[i].type =
            wamr_addr_info[i].is_tcp ? SOCKET_STREAM : SOCKET_DGRAM;
        bh_sockaddr_to_wasi_addr(&wamr_addr_info[i].sockaddr,
                                 &addr_info[i].addr);
    }

    wasm_runtime_free(wamr_addr_info);
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasi_ssp_sock_connect(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, struct addr_pool *addr_pool,
#endif
    __wasi_fd_t fd, __wasi_addr_t *addr)
{
    char buf[48] = { 0 };
    struct fd_object *fo;
    __wasi_errno_t error;
    int ret;

    if (!wasi_addr_to_string(addr, buf, sizeof(buf))) {
        return __WASI_EPROTONOSUPPORT;
    }

    if (!addr_pool_search(addr_pool, buf)) {
        return __WASI_EACCES;
    }

    error = fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_BIND, 0);
    if (error != __WASI_ESUCCESS)
        return error;

    ret = os_socket_connect(fd_number(fo), buf,
                            addr->kind == IPv4 ? addr->addr.ip4.port
                                               : addr->addr.ip6.port);
    fd_object_release(fo);
    if (BHT_OK != ret) {
        return convert_errno(errno);
    }

    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasi_ssp_sock_listen(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_size_t backlog)
{
    struct fd_object *fo;
    int ret;
    __wasi_errno_t error =
        fd_object_get(curfds, &fo, fd, __WASI_RIGHT_SOCK_LISTEN, 0);
    if (error != __WASI_ESUCCESS)
        return error;

    ret = os_socket_listen(fd_number(fo), backlog);
    fd_object_release(fo);
    if (BHT_OK != ret) {
        return convert_errno(errno);
    }

    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasi_ssp_sock_open(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t poolfd, __wasi_address_family_t af, __wasi_sock_type_t socktype,
    __wasi_fd_t *sockfd)
{
    bh_socket_t sock;
    bool is_tcp = SOCKET_DGRAM == socktype ? false : true;
    bool is_ipv4 = INET6 == af ? false : true;
    int ret;
    __wasi_filetype_t wasi_type;
    __wasi_rights_t max_base, max_inheriting;
    __wasi_errno_t error;

    (void)poolfd;

    ret = os_socket_create(&sock, is_ipv4, is_tcp);
    if (BHT_OK != ret) {
        return convert_errno(errno);
    }

    error =
        fd_determine_type_rights(sock, &wasi_type, &max_base, &max_inheriting);
    if (error != __WASI_ESUCCESS) {
        os_socket_close(sock);
        return error;
    }

    if (SOCKET_DGRAM == socktype) {
        assert(wasi_type == __WASI_FILETYPE_SOCKET_DGRAM);
    }
    else {
        assert(wasi_type == __WASI_FILETYPE_SOCKET_STREAM);
    }

    // TODO: base rights and inheriting rights ?
    error = fd_table_insert_fd(curfds, sock, wasi_type, max_base,
                               max_inheriting, sockfd);
    if (error != __WASI_ESUCCESS) {
        return error;
    }

    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_recv(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock, void *buf, size_t buf_len, size_t *recv_len)
{
    __wasi_addr_t src_addr;

    return wasmtime_ssp_sock_recv_from(curfds, sock, buf, buf_len, 0, &src_addr,
                                       recv_len);
}

__wasi_errno_t
wasmtime_ssp_sock_recv_from(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock, void *buf, size_t buf_len, __wasi_riflags_t ri_flags,
    __wasi_addr_t *src_addr, size_t *recv_len)
{
    struct fd_object *fo;
    __wasi_errno_t error;
    bh_sockaddr_t sockaddr;
    int ret;

    error = fd_object_get(curfds, &fo, sock, __WASI_RIGHT_FD_READ, 0);
    if (error != 0) {
        return error;
    }

    ret = os_socket_recv_from(fd_number(fo), buf, buf_len, 0, &sockaddr);
    fd_object_release(fo);
    if (-1 == ret) {
        return convert_errno(errno);
    }

    bh_sockaddr_to_wasi_addr(&sockaddr, src_addr);

    *recv_len = (size_t)ret;
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_send(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock, const void *buf, size_t buf_len, size_t *sent_len)
{
    struct fd_object *fo;
    __wasi_errno_t error;
    int ret;

    error = fd_object_get(curfds, &fo, sock, __WASI_RIGHT_FD_WRITE, 0);
    if (error != 0) {
        return error;
    }

    ret = os_socket_send(fd_number(fo), buf, buf_len);
    fd_object_release(fo);
    if (-1 == ret) {
        return convert_errno(errno);
    }

    *sent_len = (size_t)ret;
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_send_to(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, struct addr_pool *addr_pool,
#endif
    __wasi_fd_t sock, const void *buf, size_t buf_len,
    __wasi_siflags_t si_flags, const __wasi_addr_t *dest_addr, size_t *sent_len)
{
    char addr_buf[48] = { 0 };
    struct fd_object *fo;
    __wasi_errno_t error;
    int ret;
    bh_sockaddr_t sockaddr;

    if (!wasi_addr_to_string(dest_addr, addr_buf, sizeof(addr_buf))) {
        return __WASI_EPROTONOSUPPORT;
    }

    if (!addr_pool_search(addr_pool, addr_buf)) {
        return __WASI_EACCES;
    }

    error = fd_object_get(curfds, &fo, sock, __WASI_RIGHT_FD_WRITE, 0);
    if (error != 0) {
        return error;
    }

    wasi_addr_to_bh_sockaddr(dest_addr, &sockaddr);

    ret = os_socket_send_to(fd_number(fo), buf, buf_len, 0, &sockaddr);
    fd_object_release(fo);
    if (-1 == ret) {
        return convert_errno(errno);
    }

    *sent_len = (size_t)ret;
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_shutdown(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock)
{
    struct fd_object *fo;
    __wasi_errno_t error;
    int ret;

    error = fd_object_get(curfds, &fo, sock, 0, 0);
    if (error != 0)
        return error;

    ret = os_socket_shutdown(fd_number(fo));
    fd_object_release(fo);
    if (BHT_OK != ret)
        return convert_errno(errno);

    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sched_yield(void)
{
    if (sched_yield() < 0)
        return convert_errno(errno);
    return 0;
}

__wasi_errno_t
wasmtime_ssp_args_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *argv_environ,
#endif
    char **argv, char *argv_buf)
{
    for (size_t i = 0; i < argv_environ->argc; ++i) {
        argv[i] =
            argv_buf + (argv_environ->argv_list[i] - argv_environ->argv_buf);
    }
    argv[argv_environ->argc] = NULL;
    bh_memcpy_s(argv_buf, (uint32)argv_environ->argv_buf_size,
                argv_environ->argv_buf, (uint32)argv_environ->argv_buf_size);
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_args_sizes_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *argv_environ,
#endif
    size_t *argc, size_t *argv_buf_size)
{
    *argc = argv_environ->argc;
    *argv_buf_size = argv_environ->argv_buf_size;
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_environ_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *argv_environ,
#endif
    char **environ, char *environ_buf)
{
    for (size_t i = 0; i < argv_environ->environ_count; ++i) {
        environ[i] =
            environ_buf
            + (argv_environ->environ_list[i] - argv_environ->environ_buf);
    }
    environ[argv_environ->environ_count] = NULL;
    bh_memcpy_s(environ_buf, (uint32)argv_environ->environ_buf_size,
                argv_environ->environ_buf,
                (uint32)argv_environ->environ_buf_size);
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_environ_sizes_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *argv_environ,
#endif
    size_t *environ_count, size_t *environ_buf_size)
{
    *environ_count = argv_environ->environ_count;
    *environ_buf_size = argv_environ->environ_buf_size;
    return __WASI_ESUCCESS;
}

bool
argv_environ_init(struct argv_environ_values *argv_environ, char *argv_buf,
                  size_t argv_buf_size, char **argv_list, size_t argc,
                  char *environ_buf, size_t environ_buf_size,
                  char **environ_list, size_t environ_count)
{
    memset(argv_environ, 0, sizeof(struct argv_environ_values));

    argv_environ->argv_buf = argv_buf;
    argv_environ->argv_buf_size = argv_buf_size;
    argv_environ->argv_list = argv_list;
    argv_environ->argc = argc;
    argv_environ->environ_buf = environ_buf;
    argv_environ->environ_buf_size = environ_buf_size;
    argv_environ->environ_list = environ_list;
    argv_environ->environ_count = environ_count;
    return true;
}

void
argv_environ_destroy(struct argv_environ_values *argv_environ)
{}

void
fd_table_destroy(struct fd_table *ft)
{
    if (ft->entries) {
        for (uint32 i = 0; i < ft->size; i++) {
            if (ft->entries[i].object != NULL) {
                fd_object_release(ft->entries[i].object);
            }
        }
        rwlock_destroy(&ft->lock);
        wasm_runtime_free(ft->entries);
    }
}

void
fd_prestats_destroy(struct fd_prestats *pt)
{
    if (pt->prestats) {
        for (uint32 i = 0; i < pt->size; i++) {
            if (pt->prestats[i].dir != NULL) {
                wasm_runtime_free((void *)pt->prestats[i].dir);
            }
        }
        rwlock_destroy(&pt->lock);
        wasm_runtime_free(pt->prestats);
    }
}

bool
addr_pool_init(struct addr_pool *addr_pool)
{
    memset(addr_pool, 0, sizeof(*addr_pool));

    return true;
}

bool
addr_pool_insert(struct addr_pool *addr_pool, const char *addr, uint8 mask)
{
    struct addr_pool *cur = addr_pool;
    struct addr_pool *next;
    bh_ip_addr_buffer_t target;

    if (!addr_pool) {
        return false;
    }

    if (!(next = wasm_runtime_malloc(sizeof(struct addr_pool)))) {
        return false;
    }

    next->next = NULL;
    next->mask = mask;

    if (os_socket_inet_network(true, addr, &target) != BHT_OK) {
        // If parsing IPv4 fails, try IPv6
        if (os_socket_inet_network(false, addr, &target) != BHT_OK) {
            wasm_runtime_free(next);
            return false;
        }
        next->type = IPv6;
        bh_memcpy_s(next->addr.ip6, sizeof(next->addr.ip6), target.ipv6,
                    sizeof(target.ipv6));
    }
    else {
        next->type = IPv4;
        next->addr.ip4 = target.ipv4;
    }

    /* attach with */
    while (cur->next) {
        cur = cur->next;
    }
    cur->next = next;
    return true;
}

static inline size_t
min(size_t a, size_t b)
{
    return a > b ? b : a;
}

static void
init_address_mask(uint8_t *buf, size_t buflen, size_t mask)
{
    size_t element_size = sizeof(uint8_t) * 8;

    for (size_t i = 0; i < buflen; i++) {
        if (mask <= i * element_size) {
            buf[i] = 0;
        }
        else {
            size_t offset = min(mask - i * element_size, element_size);
            buf[i] = (~0u) << (element_size - offset);
        }
    }
}

/* target must be in network byte order */
static bool
compare_address(const struct addr_pool *addr_pool_entry,
                bh_ip_addr_buffer_t *target)
{
    uint8_t maskbuf[16] = { 0 };
    uint8_t basebuf[16] = { 0 };
    size_t addr_size;
    uint8_t max_addr_mask;

    if (addr_pool_entry->type == IPv4) {
        uint32_t addr_ip4 = htonl(addr_pool_entry->addr.ip4);
        bh_memcpy_s(basebuf, sizeof(addr_ip4), &addr_ip4, sizeof(addr_ip4));
        addr_size = 4;
    }
    else {
        uint16_t partial_addr_ip6;
        for (int i = 0; i < 8; i++) {
            partial_addr_ip6 = htons(addr_pool_entry->addr.ip6[i]);
            bh_memcpy_s(&basebuf[i * sizeof(partial_addr_ip6)],
                        sizeof(partial_addr_ip6), &partial_addr_ip6,
                        sizeof(partial_addr_ip6));
        }
        addr_size = 16;
    }
    max_addr_mask = addr_size * 8;

    /* IPv4 0.0.0.0 or IPv6 :: means any address */
    if (basebuf[0] == 0 && !memcmp(basebuf, basebuf + 1, addr_size - 1)) {
        return true;
    }

    /* No support for invalid mask value */
    if (addr_pool_entry->mask > max_addr_mask) {
        return false;
    }

    init_address_mask(maskbuf, addr_size, addr_pool_entry->mask);

    for (size_t i = 0; i < addr_size; i++) {
        uint8_t addr_mask = target->data[i] & maskbuf[i];
        uint8_t range_mask = basebuf[i] & maskbuf[i];
        if (addr_mask != range_mask) {
            return false;
        }
    }

    return true;
}

bool
addr_pool_search(struct addr_pool *addr_pool, const char *addr)
{
    struct addr_pool *cur = addr_pool->next;
    bh_ip_addr_buffer_t target;
    __wasi_addr_type_t addr_type;

    if (os_socket_inet_network(true, addr, &target) != BHT_OK) {
        size_t i;

        if (os_socket_inet_network(false, addr, &target) != BHT_OK) {
            return false;
        }
        addr_type = IPv6;
        for (i = 0; i < sizeof(target.ipv6) / sizeof(target.ipv6[0]); i++) {
            target.ipv6[i] = htons(target.ipv6[i]);
        }
    }
    else {
        addr_type = IPv4;
        target.ipv4 = htonl(target.ipv4);
    }

    while (cur) {
        if (cur->type == addr_type && compare_address(cur, &target)) {
            return true;
        }

        cur = cur->next;
    }

    return false;
}

void
addr_pool_destroy(struct addr_pool *addr_pool)
{
    struct addr_pool *cur = addr_pool->next;

    while (cur) {
        struct addr_pool *next = cur->next;
        wasm_runtime_free(cur);
        cur = next;
    }
}

#ifndef WASMTIME_SSP_STATIC_CURFDS
#define WASMTIME_SSP_PASSTHROUGH_FD_TABLE struct fd_table *curfds,
#else
#define WASMTIME_SSP_PASSTHROUGH_FD_TABLE
#endif

// Defines a function that passes through the socket option to the OS
// implementation
#define WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(FUNC_NAME, OPTION_TYPE) \
    __wasi_errno_t wasmtime_ssp_sock_##FUNC_NAME(                      \
        WASMTIME_SSP_PASSTHROUGH_FD_TABLE __wasi_fd_t sock,            \
        OPTION_TYPE option)                                            \
    {                                                                  \
        struct fd_object *fo;                                          \
        __wasi_errno_t error;                                          \
        int ret;                                                       \
        error = fd_object_get(curfds, &fo, sock, 0, 0);                \
        if (error != 0)                                                \
            return error;                                              \
        ret = os_socket_##FUNC_NAME(fd_number(fo), option);            \
        fd_object_release(fo);                                         \
        if (BHT_OK != ret)                                             \
            return convert_errno(errno);                               \
        return __WASI_ESUCCESS;                                        \
    }

WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_send_timeout, uint64)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_send_timeout, uint64 *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_recv_timeout, uint64)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_recv_timeout, uint64 *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_send_buf_size, size_t)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_send_buf_size, size_t *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_recv_buf_size, size_t)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_recv_buf_size, size_t *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_broadcast, bool)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_broadcast, bool *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_keep_alive, bool)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_keep_alive, bool *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_reuse_addr, bool)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_reuse_addr, bool *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_reuse_port, bool)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_reuse_port, bool *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_tcp_no_delay, bool)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_tcp_no_delay, bool *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_tcp_quick_ack, bool)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_tcp_quick_ack, bool *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_tcp_keep_idle, uint32)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_tcp_keep_idle, uint32 *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_tcp_keep_intvl, uint32)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_tcp_keep_intvl, uint32 *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_tcp_fastopen_connect, bool)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_tcp_fastopen_connect, bool *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_ip_ttl, uint8_t)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_ip_ttl, uint8_t *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_ip_multicast_ttl, uint8_t)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_ip_multicast_ttl, uint8_t *)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(set_ipv6_only, bool)
WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION(get_ipv6_only, bool *)

#undef WASMTIME_SSP_PASSTHROUGH_FD_TABLE
#undef WASMTIME_SSP_PASSTHROUGH_SOCKET_OPTION

__wasi_errno_t
wasmtime_ssp_sock_set_linger(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock, bool is_enabled, int linger_s)
{
    struct fd_object *fo;
    __wasi_errno_t error;
    int ret;
    error = fd_object_get(curfds, &fo, sock, 0, 0);
    if (error != 0)
        return error;

    ret = os_socket_set_linger(fd_number(fo), is_enabled, linger_s);
    fd_object_release(fo);
    if (BHT_OK != ret)
        return convert_errno(errno);
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_get_linger(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock, bool *is_enabled, int *linger_s)
{
    struct fd_object *fo;
    __wasi_errno_t error;
    int ret;
    error = fd_object_get(curfds, &fo, sock, 0, 0);
    if (error != 0)
        return error;

    ret = os_socket_get_linger(fd_number(fo), is_enabled, linger_s);
    fd_object_release(fo);
    if (BHT_OK != ret)
        return convert_errno(errno);

    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_set_ip_add_membership(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock, __wasi_addr_ip_t *imr_multiaddr, uint32_t imr_interface)
{
    struct fd_object *fo;
    __wasi_errno_t error;
    int ret;
    bh_ip_addr_buffer_t addr_info;
    bool is_ipv6;
    error = fd_object_get(curfds, &fo, sock, 0, 0);
    if (error != 0)
        return error;

    wasi_addr_ip_to_bh_ip_addr_buffer(imr_multiaddr, &addr_info);
    is_ipv6 = imr_multiaddr->kind == IPv6;
    ret = os_socket_set_ip_add_membership(fd_number(fo), &addr_info,
                                          imr_interface, is_ipv6);
    fd_object_release(fo);
    if (BHT_OK != ret)
        return convert_errno(errno);
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_set_ip_drop_membership(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock, __wasi_addr_ip_t *imr_multiaddr, uint32_t imr_interface)
{
    struct fd_object *fo;
    __wasi_errno_t error;
    int ret;
    bh_ip_addr_buffer_t addr_info;
    bool is_ipv6;
    error = fd_object_get(curfds, &fo, sock, 0, 0);
    if (error != 0)
        return error;

    wasi_addr_ip_to_bh_ip_addr_buffer(imr_multiaddr, &addr_info);
    is_ipv6 = imr_multiaddr->kind == IPv6;
    ret = os_socket_set_ip_drop_membership(fd_number(fo), &addr_info,
                                           imr_interface, is_ipv6);
    fd_object_release(fo);
    if (BHT_OK != ret)
        return convert_errno(errno);
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_set_ip_multicast_loop(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock, bool ipv6, bool is_enabled)
{
    struct fd_object *fo;
    __wasi_errno_t error;
    int ret;
    error = fd_object_get(curfds, &fo, sock, 0, 0);
    if (error != 0)
        return error;

    ret = os_socket_set_ip_multicast_loop(fd_number(fo), ipv6, is_enabled);
    fd_object_release(fo);
    if (BHT_OK != ret)
        return convert_errno(errno);
    return __WASI_ESUCCESS;
}

__wasi_errno_t
wasmtime_ssp_sock_get_ip_multicast_loop(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock, bool ipv6, bool *is_enabled)
{
    struct fd_object *fo;
    __wasi_errno_t error;
    int ret;
    error = fd_object_get(curfds, &fo, sock, 0, 0);
    if (error != 0)
        return error;

    ret = os_socket_get_ip_multicast_loop(fd_number(fo), ipv6, is_enabled);
    fd_object_release(fo);
    if (BHT_OK != ret)
        return convert_errno(errno);

    return __WASI_ESUCCESS;
}
