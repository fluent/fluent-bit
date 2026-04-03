#ifndef TRACE_EVENTS_H
#define TRACE_EVENTS_H

#include <linux/limits.h>
#include <linux/types.h>  // For __u32, __u64, etc.

#define TASK_COMM_LEN 16
#define VFS_PATH_MAX 256

enum event_type {
    EVENT_TYPE_EXECVE,
    EVENT_TYPE_SIGNAL,
    EVENT_TYPE_MEM,   // For memory operations
    EVENT_TYPE_BIND,  // Added event type for bind operations
    EVENT_TYPE_VFS,
    EVENT_TYPE_LISTEN,
    EVENT_TYPE_ACCEPT,
    EVENT_TYPE_CONNECT,
};

enum vfs_op {
    VFS_OP_OPENAT,
};

/* Define memory operation types */
enum memop {
    MEMOP_MALLOC,
    MEMOP_FREE,
    MEMOP_CALLOC,
    MEMOP_REALLOC,
    MEMOP_REALLOC_FREE,
    MEMOP_MMAP,
    MEMOP_MUNMAP,
    MEMOP_POSIX_MEMALIGN,
    MEMOP_ALIGNED_ALLOC,
    MEMOP_VALLOC,
    MEMOP_MEMALIGN,
    MEMOP_PVALLOC,
};

struct event_common {
    __u64 timestamp_raw;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 mntns_id;
    char comm[TASK_COMM_LEN];
};

struct execve_event {
    __u32 tpid;
    char filename[PATH_MAX];
    char argv[256];
    __u32 argc;
};

struct signal_event {
    __u32 tpid;
    int sig_raw;
    int error_raw;
};

struct mem_event {
    enum memop operation;
    __u64 addr;
    __u64 size;
};

struct bind_event {
    struct {
        __u16 port;
        __u8 version;
        __u8 proto_raw;
        union {
            __u32 v4;
            __u32 v6[4];
        } addr_raw;
    } addr;                        // Address information
    __u32 bound_dev_if;            // Device the socket is bound to
    __u32 opts_raw;                // Bind options (reuseaddr, reuseport, etc.)
    int error_raw;                 // Error code for the bind operation
};

struct vfs_event {
    enum vfs_op operation;
    char path[VFS_PATH_MAX];
    __u32 flags;
    __u32 mode;
    int fd;
    int error_raw;
};

struct tcp_addr {
    __u16 port;
    __u8 version;
    __u8 proto_raw;
    union {
        __u32 v4;
        __u32 v6[4];
    } addr_raw;
};

struct listen_event {
    int fd;
    int backlog;
    int error_raw;
};

struct accept_event {
    int fd;
    int new_fd;
    struct tcp_addr peer;
    int error_raw;
};

struct connect_event {
    int fd;
    struct tcp_addr remote;
    int error_raw;
};

struct event {
    enum event_type type;           // Type of event (execve, signal, mem, bind)
    struct event_common common;     // Common fields for all events
    union {
        struct execve_event execve;
        struct signal_event signal;
        struct mem_event mem;
        struct bind_event bind;
        struct vfs_event vfs;
        struct listen_event listen;
        struct accept_event accept;
        struct connect_event connect;
    } details;
};

#endif // TRACE_EVENTS_H
