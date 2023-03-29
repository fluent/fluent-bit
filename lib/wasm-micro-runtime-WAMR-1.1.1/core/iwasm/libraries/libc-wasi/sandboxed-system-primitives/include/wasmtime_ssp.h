/*
 * Part of the Wasmtime Project, under the Apache License v2.0 with
 * LLVM Exceptions. See
 *   https://github.com/bytecodealliance/wasmtime/blob/main/LICENSE
 * for license information.
 *
 * This file declares an interface similar to WASI, but augmented to expose
 * some implementation details such as the curfds arguments that we pass
 * around to avoid storing them in TLS.
 */

/**
 * The defitions of type, macro and structure in this file should be
 * consistent with those in wasi-libc:
 * https://github.com/WebAssembly/wasi-libc/blob/main/libc-bottom-half/headers/public/wasi/api.h
 */

#ifndef WASMTIME_SSP_H
#define WASMTIME_SSP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* clang-format off */

#ifdef __cplusplus
#ifndef _Static_assert
#define _Static_assert static_assert
#endif /* _Static_assert */

#ifndef _Alignof
#define _Alignof alignof
#endif /* _Alignof */

#ifndef _Noreturn
#define _Noreturn [[ noreturn ]]
#endif /* _Noreturn */
extern "C" {
#endif

_Static_assert(_Alignof(int8_t) == 1, "non-wasi data layout");
_Static_assert(_Alignof(uint8_t) == 1, "non-wasi data layout");
_Static_assert(_Alignof(int16_t) == 2, "non-wasi data layout");
_Static_assert(_Alignof(uint16_t) == 2, "non-wasi data layout");
_Static_assert(_Alignof(int32_t) == 4, "non-wasi data layout");
_Static_assert(_Alignof(uint32_t) == 4, "non-wasi data layout");
#if 0
_Static_assert(_Alignof(int64_t) == 8, "non-wasi data layout");
_Static_assert(_Alignof(uint64_t) == 8, "non-wasi data layout");
#endif

typedef uint32_t __wasi_size_t;
_Static_assert(_Alignof(__wasi_size_t) == 4, "non-wasi data layout");

typedef uint8_t __wasi_advice_t;
#define __WASI_ADVICE_NORMAL     (0)
#define __WASI_ADVICE_SEQUENTIAL (1)
#define __WASI_ADVICE_RANDOM     (2)
#define __WASI_ADVICE_WILLNEED   (3)
#define __WASI_ADVICE_DONTNEED   (4)
#define __WASI_ADVICE_NOREUSE    (5)

typedef uint32_t __wasi_clockid_t;
#define __WASI_CLOCK_REALTIME           (0)
#define __WASI_CLOCK_MONOTONIC          (1)
#define __WASI_CLOCK_PROCESS_CPUTIME_ID (2)
#define __WASI_CLOCK_THREAD_CPUTIME_ID  (3)

typedef uint64_t __wasi_device_t;

typedef uint64_t __wasi_dircookie_t;
#define __WASI_DIRCOOKIE_START (0)

typedef uint32_t __wasi_dirnamlen_t;

typedef uint16_t __wasi_errno_t;
#define __WASI_ESUCCESS        (0)
#define __WASI_E2BIG           (1)
#define __WASI_EACCES          (2)
#define __WASI_EADDRINUSE      (3)
#define __WASI_EADDRNOTAVAIL   (4)
#define __WASI_EAFNOSUPPORT    (5)
#define __WASI_EAGAIN          (6)
#define __WASI_EALREADY        (7)
#define __WASI_EBADF           (8)
#define __WASI_EBADMSG         (9)
#define __WASI_EBUSY           (10)
#define __WASI_ECANCELED       (11)
#define __WASI_ECHILD          (12)
#define __WASI_ECONNABORTED    (13)
#define __WASI_ECONNREFUSED    (14)
#define __WASI_ECONNRESET      (15)
#define __WASI_EDEADLK         (16)
#define __WASI_EDESTADDRREQ    (17)
#define __WASI_EDOM            (18)
#define __WASI_EDQUOT          (19)
#define __WASI_EEXIST          (20)
#define __WASI_EFAULT          (21)
#define __WASI_EFBIG           (22)
#define __WASI_EHOSTUNREACH    (23)
#define __WASI_EIDRM           (24)
#define __WASI_EILSEQ          (25)
#define __WASI_EINPROGRESS     (26)
#define __WASI_EINTR           (27)
#define __WASI_EINVAL          (28)
#define __WASI_EIO             (29)
#define __WASI_EISCONN         (30)
#define __WASI_EISDIR          (31)
#define __WASI_ELOOP           (32)
#define __WASI_EMFILE          (33)
#define __WASI_EMLINK          (34)
#define __WASI_EMSGSIZE        (35)
#define __WASI_EMULTIHOP       (36)
#define __WASI_ENAMETOOLONG    (37)
#define __WASI_ENETDOWN        (38)
#define __WASI_ENETRESET       (39)
#define __WASI_ENETUNREACH     (40)
#define __WASI_ENFILE          (41)
#define __WASI_ENOBUFS         (42)
#define __WASI_ENODEV          (43)
#define __WASI_ENOENT          (44)
#define __WASI_ENOEXEC         (45)
#define __WASI_ENOLCK          (46)
#define __WASI_ENOLINK         (47)
#define __WASI_ENOMEM          (48)
#define __WASI_ENOMSG          (49)
#define __WASI_ENOPROTOOPT     (50)
#define __WASI_ENOSPC          (51)
#define __WASI_ENOSYS          (52)
#define __WASI_ENOTCONN        (53)
#define __WASI_ENOTDIR         (54)
#define __WASI_ENOTEMPTY       (55)
#define __WASI_ENOTRECOVERABLE (56)
#define __WASI_ENOTSOCK        (57)
#define __WASI_ENOTSUP         (58)
#define __WASI_ENOTTY          (59)
#define __WASI_ENXIO           (60)
#define __WASI_EOVERFLOW       (61)
#define __WASI_EOWNERDEAD      (62)
#define __WASI_EPERM           (63)
#define __WASI_EPIPE           (64)
#define __WASI_EPROTO          (65)
#define __WASI_EPROTONOSUPPORT (66)
#define __WASI_EPROTOTYPE      (67)
#define __WASI_ERANGE          (68)
#define __WASI_EROFS           (69)
#define __WASI_ESPIPE          (70)
#define __WASI_ESRCH           (71)
#define __WASI_ESTALE          (72)
#define __WASI_ETIMEDOUT       (73)
#define __WASI_ETXTBSY         (74)
#define __WASI_EXDEV           (75)
#define __WASI_ENOTCAPABLE     (76)

typedef uint16_t __wasi_eventrwflags_t;
#define __WASI_EVENT_FD_READWRITE_HANGUP (0x0001)

typedef uint8_t __wasi_eventtype_t;
#define __WASI_EVENTTYPE_CLOCK          (0)
#define __WASI_EVENTTYPE_FD_READ        (1)
#define __WASI_EVENTTYPE_FD_WRITE       (2)

typedef uint32_t __wasi_exitcode_t;

typedef uint32_t __wasi_fd_t;

typedef uint16_t __wasi_fdflags_t;
#define __WASI_FDFLAG_APPEND   (0x0001)
#define __WASI_FDFLAG_DSYNC    (0x0002)
#define __WASI_FDFLAG_NONBLOCK (0x0004)
#define __WASI_FDFLAG_RSYNC    (0x0008)
#define __WASI_FDFLAG_SYNC     (0x0010)

typedef int64_t __wasi_filedelta_t;

typedef uint64_t __wasi_filesize_t;

typedef uint8_t __wasi_filetype_t;
#define __WASI_FILETYPE_UNKNOWN          (0)
#define __WASI_FILETYPE_BLOCK_DEVICE     (1)
#define __WASI_FILETYPE_CHARACTER_DEVICE (2)
#define __WASI_FILETYPE_DIRECTORY        (3)
#define __WASI_FILETYPE_REGULAR_FILE     (4)
#define __WASI_FILETYPE_SOCKET_DGRAM     (5)
#define __WASI_FILETYPE_SOCKET_STREAM    (6)
#define __WASI_FILETYPE_SYMBOLIC_LINK    (7)

typedef uint16_t __wasi_fstflags_t;
#define __WASI_FILESTAT_SET_ATIM     (0x0001)
#define __WASI_FILESTAT_SET_ATIM_NOW (0x0002)
#define __WASI_FILESTAT_SET_MTIM     (0x0004)
#define __WASI_FILESTAT_SET_MTIM_NOW (0x0008)

typedef uint64_t __wasi_inode_t;

typedef uint64_t __wasi_linkcount_t __attribute__((aligned(8)));

typedef uint32_t __wasi_lookupflags_t;
#define __WASI_LOOKUP_SYMLINK_FOLLOW (0x00000001)

typedef uint16_t __wasi_oflags_t;
#define __WASI_O_CREAT     (0x0001)
#define __WASI_O_DIRECTORY (0x0002)
#define __WASI_O_EXCL      (0x0004)
#define __WASI_O_TRUNC     (0x0008)

typedef uint16_t __wasi_riflags_t;
#define __WASI_SOCK_RECV_PEEK    (0x0001)
#define __WASI_SOCK_RECV_WAITALL (0x0002)

typedef uint64_t __wasi_rights_t;

/**
 * Observe that WASI defines rights in the plural form
 * TODO: refactor to use RIGHTS instead of RIGHT
 */
#define __WASI_RIGHT_FD_DATASYNC ((__wasi_rights_t)(UINT64_C(1) << 0))
#define __WASI_RIGHT_FD_READ ((__wasi_rights_t)(UINT64_C(1) << 1))
#define __WASI_RIGHT_FD_SEEK ((__wasi_rights_t)(UINT64_C(1) << 2))
#define __WASI_RIGHT_FD_FDSTAT_SET_FLAGS ((__wasi_rights_t)(UINT64_C(1) << 3))
#define __WASI_RIGHT_FD_SYNC ((__wasi_rights_t)(UINT64_C(1) << 4))
#define __WASI_RIGHT_FD_TELL ((__wasi_rights_t)(UINT64_C(1) << 5))
#define __WASI_RIGHT_FD_WRITE ((__wasi_rights_t)(UINT64_C(1) << 6))
#define __WASI_RIGHT_FD_ADVISE ((__wasi_rights_t)(UINT64_C(1) << 7))
#define __WASI_RIGHT_FD_ALLOCATE ((__wasi_rights_t)(UINT64_C(1) << 8))
#define __WASI_RIGHT_PATH_CREATE_DIRECTORY ((__wasi_rights_t)(UINT64_C(1) << 9))
#define __WASI_RIGHT_PATH_CREATE_FILE ((__wasi_rights_t)(UINT64_C(1) << 10))
#define __WASI_RIGHT_PATH_LINK_SOURCE ((__wasi_rights_t)(UINT64_C(1) << 11))
#define __WASI_RIGHT_PATH_LINK_TARGET ((__wasi_rights_t)(UINT64_C(1) << 12))
#define __WASI_RIGHT_PATH_OPEN ((__wasi_rights_t)(UINT64_C(1) << 13))
#define __WASI_RIGHT_FD_READDIR ((__wasi_rights_t)(UINT64_C(1) << 14))
#define __WASI_RIGHT_PATH_READLINK ((__wasi_rights_t)(UINT64_C(1) << 15))
#define __WASI_RIGHT_PATH_RENAME_SOURCE ((__wasi_rights_t)(UINT64_C(1) << 16))
#define __WASI_RIGHT_PATH_RENAME_TARGET ((__wasi_rights_t)(UINT64_C(1) << 17))
#define __WASI_RIGHT_PATH_FILESTAT_GET ((__wasi_rights_t)(UINT64_C(1) << 18))
#define __WASI_RIGHT_PATH_FILESTAT_SET_SIZE ((__wasi_rights_t)(UINT64_C(1) << 19))
#define __WASI_RIGHT_PATH_FILESTAT_SET_TIMES ((__wasi_rights_t)(UINT64_C(1) << 20))
#define __WASI_RIGHT_FD_FILESTAT_GET ((__wasi_rights_t)(UINT64_C(1) << 21))
#define __WASI_RIGHT_FD_FILESTAT_SET_SIZE ((__wasi_rights_t)(UINT64_C(1) << 22))
#define __WASI_RIGHT_FD_FILESTAT_SET_TIMES ((__wasi_rights_t)(UINT64_C(1) << 23))
#define __WASI_RIGHT_PATH_SYMLINK ((__wasi_rights_t)(UINT64_C(1) << 24))
#define __WASI_RIGHT_PATH_REMOVE_DIRECTORY ((__wasi_rights_t)(UINT64_C(1) << 25))
#define __WASI_RIGHT_PATH_UNLINK_FILE ((__wasi_rights_t)(UINT64_C(1) << 26))
#define __WASI_RIGHT_POLL_FD_READWRITE ((__wasi_rights_t)(UINT64_C(1) << 27))
#define __WASI_RIGHT_SOCK_CONNECT ((__wasi_rights_t)(UINT64_C(1) << 28))
#define __WASI_RIGHT_SOCK_LISTEN ((__wasi_rights_t)(UINT64_C(1) << 29))
#define __WASI_RIGHT_SOCK_BIND ((__wasi_rights_t)(UINT64_C(1) << 30))
#define __WASI_RIGHT_SOCK_ACCEPT ((__wasi_rights_t)(UINT64_C(1) << 31))
#define __WASI_RIGHT_SOCK_RECV ((__wasi_rights_t)(UINT64_C(1) << 32))
#define __WASI_RIGHT_SOCK_SEND ((__wasi_rights_t)(UINT64_C(1) << 33))
#define __WASI_RIGHT_SOCK_ADDR_LOCAL ((__wasi_rights_t)(UINT64_C(1) << 34))
#define __WASI_RIGHT_SOCK_ADDR_REMOTE ((__wasi_rights_t)(UINT64_C(1) << 35))
#define __WASI_RIGHT_SOCK_RECV_FROM ((__wasi_rights_t)(UINT64_C(1) << 36))
#define __WASI_RIGHT_SOCK_SEND_TO ((__wasi_rights_t)(UINT64_C(1) << 37))

typedef uint16_t __wasi_roflags_t;
#define __WASI_SOCK_RECV_DATA_TRUNCATED (0x0001)

typedef uint8_t __wasi_sdflags_t;
#define __WASI_SHUT_RD (0x01)
#define __WASI_SHUT_WR (0x02)

typedef uint16_t __wasi_siflags_t;

typedef uint8_t __wasi_signal_t;
// 0 is reserved; POSIX has special semantics for kill(pid, 0).
#define __WASI_SIGHUP    (1)
#define __WASI_SIGINT    (2)
#define __WASI_SIGQUIT   (3)
#define __WASI_SIGILL    (4)
#define __WASI_SIGTRAP   (5)
#define __WASI_SIGABRT   (6)
#define __WASI_SIGBUS    (7)
#define __WASI_SIGFPE    (8)
#define __WASI_SIGKILL   (9)
#define __WASI_SIGUSR1   (10)
#define __WASI_SIGSEGV   (11)
#define __WASI_SIGUSR2   (12)
#define __WASI_SIGPIPE   (13)
#define __WASI_SIGALRM   (14)
#define __WASI_SIGTERM   (15)
#define __WASI_SIGCHLD   (16)
#define __WASI_SIGCONT   (17)
#define __WASI_SIGSTOP   (18)
#define __WASI_SIGTSTP   (19)
#define __WASI_SIGTTIN   (20)
#define __WASI_SIGTTOU   (21)
#define __WASI_SIGURG    (22)
#define __WASI_SIGXCPU   (23)
#define __WASI_SIGXFSZ   (24)
#define __WASI_SIGVTALRM (25)
#define __WASI_SIGPROF   (26)
#define __WASI_SIGWINCH  (27)
#define __WASI_SIGPOLL   (28)
#define __WASI_SIGPWR    (29)
#define __WASI_SIGSYS    (30)

typedef uint16_t __wasi_subclockflags_t;
#define __WASI_SUBSCRIPTION_CLOCK_ABSTIME (0x0001)

typedef uint64_t __wasi_timestamp_t;

typedef uint64_t __wasi_userdata_t;

typedef uint8_t __wasi_whence_t;
#define __WASI_WHENCE_SET (0)
#define __WASI_WHENCE_CUR (1)
#define __WASI_WHENCE_END (2)

typedef uint8_t __wasi_preopentype_t;
#define __WASI_PREOPENTYPE_DIR              (0)

struct fd_table;
struct fd_prestats;
struct argv_environ_values;
struct addr_pool;

typedef struct __wasi_dirent_t {
    __wasi_dircookie_t d_next;
    __wasi_inode_t d_ino;
    __wasi_dirnamlen_t d_namlen;
    __wasi_filetype_t d_type;
} __wasi_dirent_t __attribute__((aligned(8)));
_Static_assert(offsetof(__wasi_dirent_t, d_next) == 0, "non-wasi data layout");
_Static_assert(offsetof(__wasi_dirent_t, d_ino) == 8, "non-wasi data layout");
_Static_assert(offsetof(__wasi_dirent_t, d_namlen) == 16, "non-wasi data layout");
_Static_assert(offsetof(__wasi_dirent_t, d_type) == 20, "non-wasi data layout");
_Static_assert(sizeof(__wasi_dirent_t) == 24, "non-wasi data layout");
_Static_assert(_Alignof(__wasi_dirent_t) == 8, "non-wasi data layout");

typedef struct __wasi_event_t {
    __wasi_userdata_t userdata;
    __wasi_errno_t error;
    __wasi_eventtype_t type;
    uint8_t __paddings[5];
    union __wasi_event_u {
        struct __wasi_event_u_fd_readwrite_t {
            __wasi_filesize_t nbytes;
            __wasi_eventrwflags_t flags;
            uint8_t __paddings[6];
        } fd_readwrite;
    } u;
} __wasi_event_t __attribute__((aligned(8)));
_Static_assert(offsetof(__wasi_event_t, userdata) == 0, "non-wasi data layout");
_Static_assert(offsetof(__wasi_event_t, error) == 8, "non-wasi data layout");
_Static_assert(offsetof(__wasi_event_t, type) == 10, "non-wasi data layout");
_Static_assert(
    offsetof(__wasi_event_t, u.fd_readwrite.nbytes) == 16, "non-wasi data layout");
_Static_assert(
    offsetof(__wasi_event_t, u.fd_readwrite.flags) == 24, "non-wasi data layout");
_Static_assert(sizeof(__wasi_event_t) == 32, "non-wasi data layout");
_Static_assert(_Alignof(__wasi_event_t) == 8, "non-wasi data layout");

typedef struct __wasi_prestat_t {
    __wasi_preopentype_t pr_type;
    union __wasi_prestat_u {
        struct __wasi_prestat_u_dir_t {
            size_t pr_name_len;
        } dir;
    } u;
} __wasi_prestat_t;
_Static_assert(offsetof(__wasi_prestat_t, pr_type) == 0, "non-wasi data layout");
_Static_assert(sizeof(void *) != 4 ||
    offsetof(__wasi_prestat_t, u.dir.pr_name_len) == 4, "non-wasi data layout");
_Static_assert(sizeof(void *) != 8 ||
    offsetof(__wasi_prestat_t, u.dir.pr_name_len) == 8, "non-wasi data layout");
_Static_assert(sizeof(void *) != 4 ||
    sizeof(__wasi_prestat_t) == 8, "non-wasi data layout");
_Static_assert(sizeof(void *) != 8 ||
    sizeof(__wasi_prestat_t) == 16, "non-wasi data layout");
_Static_assert(sizeof(void *) != 4 ||
    _Alignof(__wasi_prestat_t) == 4, "non-wasi data layout");
_Static_assert(sizeof(void *) != 8 ||
    _Alignof(__wasi_prestat_t) == 8, "non-wasi data layout");

typedef struct __wasi_fdstat_t {
    __wasi_filetype_t fs_filetype;
    __wasi_fdflags_t fs_flags;
    uint8_t __paddings[4];
    __wasi_rights_t fs_rights_base;
    __wasi_rights_t fs_rights_inheriting;
} __wasi_fdstat_t __attribute__((aligned(8)));
_Static_assert(
    offsetof(__wasi_fdstat_t, fs_filetype) == 0, "non-wasi data layout");
_Static_assert(offsetof(__wasi_fdstat_t, fs_flags) == 2, "non-wasi data layout");
_Static_assert(
    offsetof(__wasi_fdstat_t, fs_rights_base) == 8, "non-wasi data layout");
_Static_assert(
    offsetof(__wasi_fdstat_t, fs_rights_inheriting) == 16,
    "non-wasi data layout");
_Static_assert(sizeof(__wasi_fdstat_t) == 24, "non-wasi data layout");
_Static_assert(_Alignof(__wasi_fdstat_t) == 8, "non-wasi data layout");

typedef struct __wasi_filestat_t {
    __wasi_device_t st_dev;
    __wasi_inode_t st_ino;
    __wasi_filetype_t st_filetype;
    __wasi_linkcount_t st_nlink;
    __wasi_filesize_t st_size;
    __wasi_timestamp_t st_atim;
    __wasi_timestamp_t st_mtim;
    __wasi_timestamp_t st_ctim;
} __wasi_filestat_t __attribute__((aligned(8)));
_Static_assert(offsetof(__wasi_filestat_t, st_dev) == 0, "non-wasi data layout");
_Static_assert(offsetof(__wasi_filestat_t, st_ino) == 8, "non-wasi data layout");
_Static_assert(
    offsetof(__wasi_filestat_t, st_filetype) == 16, "non-wasi data layout");
_Static_assert(
    offsetof(__wasi_filestat_t, st_nlink) == 24, "non-wasi data layout");
_Static_assert(
    offsetof(__wasi_filestat_t, st_size) == 32, "non-wasi data layout");
_Static_assert(
    offsetof(__wasi_filestat_t, st_atim) == 40, "non-wasi data layout");
_Static_assert(
    offsetof(__wasi_filestat_t, st_mtim) == 48, "non-wasi data layout");
_Static_assert(
    offsetof(__wasi_filestat_t, st_ctim) == 56, "non-wasi data layout");
_Static_assert(sizeof(__wasi_filestat_t) == 64, "non-wasi data layout");
_Static_assert(_Alignof(__wasi_filestat_t) == 8, "non-wasi data layout");

typedef struct __wasi_ciovec_t {
    const void *buf;
    size_t buf_len;
} __wasi_ciovec_t;
_Static_assert(offsetof(__wasi_ciovec_t, buf) == 0, "non-wasi data layout");
_Static_assert(sizeof(void *) != 4 ||
    offsetof(__wasi_ciovec_t, buf_len) == 4, "non-wasi data layout");
_Static_assert(sizeof(void *) != 8 ||
    offsetof(__wasi_ciovec_t, buf_len) == 8, "non-wasi data layout");
_Static_assert(sizeof(void *) != 4 ||
    sizeof(__wasi_ciovec_t) == 8, "non-wasi data layout");
_Static_assert(sizeof(void *) != 8 ||
    sizeof(__wasi_ciovec_t) == 16, "non-wasi data layout");
_Static_assert(sizeof(void *) != 4 ||
    _Alignof(__wasi_ciovec_t) == 4, "non-wasi data layout");
_Static_assert(sizeof(void *) != 8 ||
    _Alignof(__wasi_ciovec_t) == 8, "non-wasi data layout");

typedef struct __wasi_iovec_t {
    void *buf;
    size_t buf_len;
} __wasi_iovec_t;
_Static_assert(offsetof(__wasi_iovec_t, buf) == 0, "non-wasi data layout");
_Static_assert(sizeof(void *) != 4 ||
    offsetof(__wasi_iovec_t, buf_len) == 4, "non-wasi data layout");
_Static_assert(sizeof(void *) != 8 ||
    offsetof(__wasi_iovec_t, buf_len) == 8, "non-wasi data layout");
_Static_assert(sizeof(void *) != 4 ||
    sizeof(__wasi_iovec_t) == 8, "non-wasi data layout");
_Static_assert(sizeof(void *) != 8 ||
    sizeof(__wasi_iovec_t) == 16, "non-wasi data layout");
_Static_assert(sizeof(void *) != 4 ||
    _Alignof(__wasi_iovec_t) == 4, "non-wasi data layout");
_Static_assert(sizeof(void *) != 8 ||
    _Alignof(__wasi_iovec_t) == 8, "non-wasi data layout");

/**
 * The contents of a `subscription` when type is `eventtype::clock`.
 */
typedef struct __wasi_subscription_clock_t {
    /**
     * The clock against which to compare the timestamp.
     */
    __wasi_clockid_t clock_id;

    uint8_t __paddings1[4];

    /**
     * The absolute or relative timestamp.
     */
    __wasi_timestamp_t timeout;

    /**
     * The amount of time that the implementation may wait additionally
     * to coalesce with other events.
     */
    __wasi_timestamp_t precision;

    /**
     * Flags specifying whether the timeout is absolute or relative
     */
    __wasi_subclockflags_t flags;

    uint8_t __paddings2[4];

} __wasi_subscription_clock_t __attribute__((aligned(8)));

_Static_assert(sizeof(__wasi_subscription_clock_t) == 32, "witx calculated size");
_Static_assert(_Alignof(__wasi_subscription_clock_t) == 8, "witx calculated align");
_Static_assert(offsetof(__wasi_subscription_clock_t, clock_id) == 0, "witx calculated offset");
_Static_assert(offsetof(__wasi_subscription_clock_t, timeout) == 8, "witx calculated offset");
_Static_assert(offsetof(__wasi_subscription_clock_t, precision) == 16, "witx calculated offset");
_Static_assert(offsetof(__wasi_subscription_clock_t, flags) == 24, "witx calculated offset");

/**
 * The contents of a `subscription` when type is type is
 * `eventtype::fd_read` or `eventtype::fd_write`.
 */
typedef struct __wasi_subscription_fd_readwrite_t {
    /**
     * The file descriptor on which to wait for it to become ready for reading or writing.
     */
    __wasi_fd_t fd;

} __wasi_subscription_fd_readwrite_t;

_Static_assert(sizeof(__wasi_subscription_fd_readwrite_t) == 4, "witx calculated size");
_Static_assert(_Alignof(__wasi_subscription_fd_readwrite_t) == 4, "witx calculated align");
_Static_assert(offsetof(__wasi_subscription_fd_readwrite_t, fd) == 0, "witx calculated offset");

/**
 * The contents of a `subscription`.
 */
typedef union __wasi_subscription_u_u_t {
    __wasi_subscription_clock_t clock;
    __wasi_subscription_fd_readwrite_t fd_readwrite;
} __wasi_subscription_u_u_t ;

typedef struct __wasi_subscription_u_t {
    __wasi_eventtype_t type;
    __wasi_subscription_u_u_t u;
} __wasi_subscription_u_t __attribute__((aligned(8)));

_Static_assert(sizeof(__wasi_subscription_u_t) == 40, "witx calculated size");
_Static_assert(_Alignof(__wasi_subscription_u_t) == 8, "witx calculated align");
_Static_assert(offsetof(__wasi_subscription_u_t, u) == 8, "witx calculated union offset");
_Static_assert(sizeof(__wasi_subscription_u_u_t) == 32, "witx calculated union size");
_Static_assert(_Alignof(__wasi_subscription_u_u_t) == 8, "witx calculated union align");

/**
 * Subscription to an event.
 */
typedef struct __wasi_subscription_t {
    /**
     * User-provided value that is attached to the subscription in the
     * implementation and returned through `event::userdata`.
     */
    __wasi_userdata_t userdata;

    /**
     * The type of the event to which to subscribe, and its contents
     */
    __wasi_subscription_u_t u;

} __wasi_subscription_t;

_Static_assert(sizeof(__wasi_subscription_t) == 48, "witx calculated size");
_Static_assert(_Alignof(__wasi_subscription_t) == 8, "witx calculated align");
_Static_assert(offsetof(__wasi_subscription_t, userdata) == 0, "witx calculated offset");
_Static_assert(offsetof(__wasi_subscription_t, u) == 8, "witx calculated offset");

/* keep syncing with wasi_socket_ext.h */
typedef enum {
    SOCKET_DGRAM = 0,
    SOCKET_STREAM,
} __wasi_sock_type_t;

typedef uint16_t __wasi_ip_port_t;

typedef enum { IPv4 = 0, IPv6 } __wasi_addr_type_t;

/* n0.n1.n2.n3 */
typedef struct __wasi_addr_ip4_t {
    uint8_t n0;
    uint8_t n1;
    uint8_t n2;
    uint8_t n3;
} __wasi_addr_ip4_t;

typedef struct __wasi_addr_ip4_port_t {
    __wasi_addr_ip4_t addr;
    __wasi_ip_port_t port;
} __wasi_addr_ip4_port_t;

typedef struct __wasi_addr_ip6_t {
    uint16_t n0;
    uint16_t n1;
    uint16_t n2;
    uint16_t n3;
    uint16_t h0;
    uint16_t h1;
    uint16_t h2;
    uint16_t h3;
} __wasi_addr_ip6_t;

typedef struct __wasi_addr_ip6_port_t {
    __wasi_addr_ip6_t addr;
    __wasi_ip_port_t port;
} __wasi_addr_ip6_port_t;

typedef struct __wasi_addr_ip_t {
    __wasi_addr_type_t kind;
    union {
        __wasi_addr_ip4_t ip4;
        __wasi_addr_ip6_t ip6;
    } addr;
} __wasi_addr_ip_t;

typedef struct __wasi_addr_t {
    __wasi_addr_type_t kind;
    union {
        __wasi_addr_ip4_port_t ip4;
        __wasi_addr_ip6_port_t ip6;
    } addr;
} __wasi_addr_t;

typedef enum { INET4 = 0, INET6 } __wasi_address_family_t;

typedef struct __wasi_addr_info_t {
    __wasi_addr_t addr;
    __wasi_sock_type_t type;
} __wasi_addr_info_t;

typedef struct __wasi_addr_info_hints_t {
   __wasi_sock_type_t type;
   __wasi_address_family_t family;
   // this is to workaround lack of optional parameters
   uint8_t hints_enabled;
} __wasi_addr_info_hints_t;

#if defined(WASMTIME_SSP_WASI_API)
#define WASMTIME_SSP_SYSCALL_NAME(name) \
    asm("__wasi_" #name)
#else
#define WASMTIME_SSP_SYSCALL_NAME(name)
#endif

__wasi_errno_t wasmtime_ssp_args_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *arg_environ,
#endif
    char **argv,
    char *argv_buf
) WASMTIME_SSP_SYSCALL_NAME(args_get) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_args_sizes_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *arg_environ,
#endif
    size_t *argc,
    size_t *argv_buf_size
) WASMTIME_SSP_SYSCALL_NAME(args_sizes_get) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_clock_res_get(
    __wasi_clockid_t clock_id,
    __wasi_timestamp_t *resolution
) WASMTIME_SSP_SYSCALL_NAME(clock_res_get) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_clock_time_get(
    __wasi_clockid_t clock_id,
    __wasi_timestamp_t precision,
    __wasi_timestamp_t *time
) WASMTIME_SSP_SYSCALL_NAME(clock_time_get) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_environ_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *arg_environ,
#endif
    char **environ,
    char *environ_buf
) WASMTIME_SSP_SYSCALL_NAME(environ_get) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_environ_sizes_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct argv_environ_values *arg_environ,
#endif
    size_t *environ_count,
    size_t *environ_buf_size
) WASMTIME_SSP_SYSCALL_NAME(environ_sizes_get) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_prestat_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_prestats *prestats,
#endif
    __wasi_fd_t fd,
    __wasi_prestat_t *buf
) WASMTIME_SSP_SYSCALL_NAME(fd_prestat_get) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_prestat_dir_name(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_prestats *prestats,
#endif
    __wasi_fd_t fd,
    char *path,
    size_t path_len
) WASMTIME_SSP_SYSCALL_NAME(fd_prestat_dir_name) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_close(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
    struct fd_prestats *prestats,
#endif
    __wasi_fd_t fd
) WASMTIME_SSP_SYSCALL_NAME(fd_close) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_datasync(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd
) WASMTIME_SSP_SYSCALL_NAME(fd_datasync) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_pread(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    const __wasi_iovec_t *iovs,
    size_t iovs_len,
    __wasi_filesize_t offset,
    size_t *nread
) WASMTIME_SSP_SYSCALL_NAME(fd_pread) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_pwrite(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    const __wasi_ciovec_t *iovs,
    size_t iovs_len,
    __wasi_filesize_t offset,
    size_t *nwritten
) WASMTIME_SSP_SYSCALL_NAME(fd_pwrite) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_read(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    const __wasi_iovec_t *iovs,
    size_t iovs_len,
    size_t *nread
) WASMTIME_SSP_SYSCALL_NAME(fd_read) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_renumber(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
    struct fd_prestats *prestats,
#endif
    __wasi_fd_t from,
    __wasi_fd_t to
) WASMTIME_SSP_SYSCALL_NAME(fd_renumber) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_seek(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_filedelta_t offset,
    __wasi_whence_t whence,
    __wasi_filesize_t *newoffset
) WASMTIME_SSP_SYSCALL_NAME(fd_seek) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_tell(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_filesize_t *newoffset
) WASMTIME_SSP_SYSCALL_NAME(fd_tell) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_fdstat_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_fdstat_t *buf
) WASMTIME_SSP_SYSCALL_NAME(fd_fdstat_get) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_fdstat_set_flags(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_fdflags_t flags
) WASMTIME_SSP_SYSCALL_NAME(fd_fdstat_set_flags) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_fdstat_set_rights(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_rights_t fs_rights_base,
    __wasi_rights_t fs_rights_inheriting
) WASMTIME_SSP_SYSCALL_NAME(fd_fdstat_set_rights) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_sync(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd
) WASMTIME_SSP_SYSCALL_NAME(fd_sync) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_write(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    const __wasi_ciovec_t *iovs,
    size_t iovs_len,
    size_t *nwritten
) WASMTIME_SSP_SYSCALL_NAME(fd_write) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_advise(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_filesize_t offset,
    __wasi_filesize_t len,
    __wasi_advice_t advice
) WASMTIME_SSP_SYSCALL_NAME(fd_advise) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_allocate(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_filesize_t offset,
    __wasi_filesize_t len
) WASMTIME_SSP_SYSCALL_NAME(fd_allocate) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_path_create_directory(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    const char *path,
    size_t path_len
) WASMTIME_SSP_SYSCALL_NAME(path_create_directory) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_path_link(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
    struct fd_prestats *prestats,
#endif
    __wasi_fd_t old_fd,
    __wasi_lookupflags_t old_flags,
    const char *old_path,
    size_t old_path_len,
    __wasi_fd_t new_fd,
    const char *new_path,
    size_t new_path_len
) WASMTIME_SSP_SYSCALL_NAME(path_link) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_path_open(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t dirfd,
    __wasi_lookupflags_t dirflags,
    const char *path,
    size_t path_len,
    __wasi_oflags_t oflags,
    __wasi_rights_t fs_rights_base,
    __wasi_rights_t fs_rights_inheriting,
    __wasi_fdflags_t fs_flags,
    __wasi_fd_t *fd
) WASMTIME_SSP_SYSCALL_NAME(path_open) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_readdir(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    void *buf,
    size_t buf_len,
    __wasi_dircookie_t cookie,
    size_t *bufused
) WASMTIME_SSP_SYSCALL_NAME(fd_readdir) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_path_readlink(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    const char *path,
    size_t path_len,
    char *buf,
    size_t buf_len,
    size_t *bufused
) WASMTIME_SSP_SYSCALL_NAME(path_readlink) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_path_rename(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t old_fd,
    const char *old_path,
    size_t old_path_len,
    __wasi_fd_t new_fd,
    const char *new_path,
    size_t new_path_len
) WASMTIME_SSP_SYSCALL_NAME(path_rename) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_filestat_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_filestat_t *buf
) WASMTIME_SSP_SYSCALL_NAME(fd_filestat_get) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_filestat_set_times(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_timestamp_t st_atim,
    __wasi_timestamp_t st_mtim,
    __wasi_fstflags_t fstflags
) WASMTIME_SSP_SYSCALL_NAME(fd_filestat_set_times) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_fd_filestat_set_size(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_filesize_t st_size
) WASMTIME_SSP_SYSCALL_NAME(fd_filestat_set_size) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_path_filestat_get(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_lookupflags_t flags,
    const char *path,
    size_t path_len,
    __wasi_filestat_t *buf
) WASMTIME_SSP_SYSCALL_NAME(path_filestat_get) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_path_filestat_set_times(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    __wasi_lookupflags_t flags,
    const char *path,
    size_t path_len,
    __wasi_timestamp_t st_atim,
    __wasi_timestamp_t st_mtim,
    __wasi_fstflags_t fstflags
) WASMTIME_SSP_SYSCALL_NAME(path_filestat_set_times) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_path_symlink(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
    struct fd_prestats *prestats,
#endif
    const char *old_path,
    size_t old_path_len,
    __wasi_fd_t fd,
    const char *new_path,
    size_t new_path_len
) WASMTIME_SSP_SYSCALL_NAME(path_symlink) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_path_unlink_file(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    const char *path,
    size_t path_len
) WASMTIME_SSP_SYSCALL_NAME(path_unlink_file) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_path_remove_directory(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd,
    const char *path,
    size_t path_len
) WASMTIME_SSP_SYSCALL_NAME(path_remove_directory) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_poll_oneoff(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    const __wasi_subscription_t *in,
    __wasi_event_t *out,
    size_t nsubscriptions,
    size_t *nevents
) WASMTIME_SSP_SYSCALL_NAME(poll_oneoff) __attribute__((__warn_unused_result__));

#if 0
/**
 * We throw exception in libc-wasi wrapper function wasi_proc_exit()
 * but not call this function.
 */
_Noreturn void wasmtime_ssp_proc_exit(
    __wasi_exitcode_t rval
) WASMTIME_SSP_SYSCALL_NAME(proc_exit);
#endif

__wasi_errno_t wasmtime_ssp_proc_raise(
    __wasi_signal_t sig
) WASMTIME_SSP_SYSCALL_NAME(proc_raise) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_random_get(
    void *buf,
    size_t buf_len
) WASMTIME_SSP_SYSCALL_NAME(random_get) __attribute__((__warn_unused_result__));

__wasi_errno_t
wasi_ssp_sock_accept(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_fdflags_t flags, __wasi_fd_t *fd_new
) __attribute__((__warn_unused_result__));

__wasi_errno_t
wasi_ssp_sock_addr_local(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_addr_t *addr
) __attribute__((__warn_unused_result__));

__wasi_errno_t
wasi_ssp_sock_addr_remote(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_addr_t *addr
) __attribute__((__warn_unused_result__));

__wasi_errno_t
wasi_ssp_sock_open(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t poolfd, __wasi_address_family_t af, __wasi_sock_type_t socktype,
    __wasi_fd_t *sockfd
) __attribute__((__warn_unused_result__));

__wasi_errno_t
wasi_ssp_sock_bind(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, struct addr_pool *addr_pool,
#endif
    __wasi_fd_t fd, __wasi_addr_t *addr
) __attribute__((__warn_unused_result__));

__wasi_errno_t
wasi_ssp_sock_addr_resolve(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, char **ns_lookup_list,
#endif
    const char *host, const char* service,
    __wasi_addr_info_hints_t *hints, __wasi_addr_info_t *addr_info,
    __wasi_size_t addr_info_size, __wasi_size_t *max_info_size
) __attribute__((__warn_unused_result__));

__wasi_errno_t
wasi_ssp_sock_connect(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, struct addr_pool *addr_pool,
#endif
    __wasi_fd_t fd, __wasi_addr_t *addr
) __attribute__((__warn_unused_result__));

__wasi_errno_t
wasi_ssp_sock_listen(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t fd, __wasi_size_t backlog
) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_recv(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    void *buf,
    size_t buf_len,
    size_t *recv_len
) WASMTIME_SSP_SYSCALL_NAME(sock_recv) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_recv_from(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    void *buf,
    size_t buf_len,
    __wasi_riflags_t ri_flags,
    __wasi_addr_t *src_addr,
    size_t *recv_len
) WASMTIME_SSP_SYSCALL_NAME(sock_recv_from) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_send(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    const void *buf,
    size_t buf_len,
    size_t *sent_len
) WASMTIME_SSP_SYSCALL_NAME(sock_send) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_send_to(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds, struct addr_pool *addr_pool,
#endif
    __wasi_fd_t sock,
    const void *buf,
    size_t buf_len,
    __wasi_siflags_t si_flags,
    const __wasi_addr_t *dest_addr,
    size_t *sent_len
) WASMTIME_SSP_SYSCALL_NAME(sock_send_to) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_shutdown(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock
) WASMTIME_SSP_SYSCALL_NAME(sock_shutdown) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_recv_timeout(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint64_t timeout_us
) WASMTIME_SSP_SYSCALL_NAME(sock_set_recv_timeout) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_recv_timeout(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint64_t *timeout_us
) WASMTIME_SSP_SYSCALL_NAME(sock_get_recv_timeout) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_send_timeout(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint64_t timeout_us
) WASMTIME_SSP_SYSCALL_NAME(sock_set_send_timeout) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_send_timeout(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint64_t *timeout_us
) WASMTIME_SSP_SYSCALL_NAME(sock_get_send_timeout) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_send_buf_size(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    size_t bufsiz
) WASMTIME_SSP_SYSCALL_NAME(sock_set_send_buf_size) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_send_buf_size(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    size_t *bufsiz
) WASMTIME_SSP_SYSCALL_NAME(sock_get_send_buf_size) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_recv_buf_size(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    size_t bufsiz
) WASMTIME_SSP_SYSCALL_NAME(sock_set_recv_buf_size) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_recv_buf_size(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    size_t *bufsiz
) WASMTIME_SSP_SYSCALL_NAME(sock_get_recv_buf_size) __attribute__((__warn_unused_result__));


__wasi_errno_t wasmtime_ssp_sock_set_keep_alive(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_set_keep_alive) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_keep_alive(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool *is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_get_keep_alive) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_reuse_addr(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_set_reuse_addr) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_reuse_addr(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool *is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_get_reuse_addr) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_reuse_port(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_set_reuse_port) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_reuse_port(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool *is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_get_reuse_port) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_linger(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool is_enabled,
    int linger_s
) WASMTIME_SSP_SYSCALL_NAME(sock_set_linger) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_linger(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock, bool *is_enabled, int *linger_s
) WASMTIME_SSP_SYSCALL_NAME(sock_get_linger) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_broadcast(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_set_broadcast) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_broadcast(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool *is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_get_broadcast) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_tcp_no_delay(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_set_tcp_no_delay) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_tcp_no_delay(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool *is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_get_tcp_no_delay) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_tcp_quick_ack(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_set_tcp_quick_ack) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_tcp_quick_ack(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool *is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_get_tcp_quick_ack) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_tcp_keep_idle(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint32_t time_s
) WASMTIME_SSP_SYSCALL_NAME(sock_set_tcp_keep_idle) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_tcp_keep_idle(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint32_t *time_s
) WASMTIME_SSP_SYSCALL_NAME(sock_get_tcp_keep_idle) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_tcp_keep_intvl(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint32_t time_s
) WASMTIME_SSP_SYSCALL_NAME(sock_set_tcp_keep_intvl) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_tcp_keep_intvl(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint32_t *time_s
) WASMTIME_SSP_SYSCALL_NAME(sock_get_tcp_keep_intvl) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_tcp_fastopen_connect(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_set_tcp_fastopen_connect) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_tcp_fastopen_connect(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool *is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_get_tcp_fastopen_connect) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_ip_multicast_loop(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool ipv6,
    bool is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_set_ip_multicast_loop) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_ip_multicast_loop(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool ipv6,
    bool *is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_get_ip_multicast_loop) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_ip_add_membership(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    __wasi_addr_ip_t *imr_multiaddr,
    uint32_t imr_interface
) WASMTIME_SSP_SYSCALL_NAME(sock_set_ip_add_membership) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_ip_drop_membership(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    __wasi_addr_ip_t *imr_multiaddr,
    uint32_t imr_interface
) WASMTIME_SSP_SYSCALL_NAME(sock_set_ip_drop_membership) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_ip_ttl(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint8_t ttl_s
) WASMTIME_SSP_SYSCALL_NAME(sock_set_ip_ttl) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_ip_ttl(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint8_t *ttl_s
) WASMTIME_SSP_SYSCALL_NAME(sock_get_ip_ttl) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_ip_multicast_ttl(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint8_t ttl_s
) WASMTIME_SSP_SYSCALL_NAME(sock_set_ip_multicast_ttl) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_ip_multicast_ttl(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    uint8_t *ttl_s
) WASMTIME_SSP_SYSCALL_NAME(sock_get_ip_multicast_ttl) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_set_ipv6_only(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_set_ipv6_only) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sock_get_ipv6_only(
#if !defined(WASMTIME_SSP_STATIC_CURFDS)
    struct fd_table *curfds,
#endif
    __wasi_fd_t sock,
    bool *is_enabled
) WASMTIME_SSP_SYSCALL_NAME(sock_get_ipv6_only) __attribute__((__warn_unused_result__));

__wasi_errno_t wasmtime_ssp_sched_yield(void)
    WASMTIME_SSP_SYSCALL_NAME(sched_yield) __attribute__((__warn_unused_result__));

#ifdef __cplusplus
}
#endif

#undef WASMTIME_SSP_SYSCALL_NAME

/* clang-format on */

#endif /* end of WASMTIME_SSP_H */
