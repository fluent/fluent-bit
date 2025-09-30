#ifndef TRACE_EVENTS_H
#define TRACE_EVENTS_H

#include <linux/limits.h>
#include <linux/types.h>  // For __u32, __u64, etc.

#define TASK_COMM_LEN 16

enum event_type {
    EVENT_TYPE_EXECVE,
    EVENT_TYPE_SIGNAL,
    EVENT_TYPE_MEM,   // For memory operations
    EVENT_TYPE_BIND,  // Added event type for bind operations
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

/* Common fields for all events */
struct event_common {
    __u64 timestamp_raw;           // Event timestamp in nanoseconds
    __u32 pid;                     // Process ID
    __u32 tid;                     // Thread ID
    __u32 uid;                     // User ID
    __u32 gid;                     // Group ID
    __u64 mntns_id;                // Mount namespace ID
    char comm[TASK_COMM_LEN];      // Command name (process name)
};

/* Specific fields for execve events */
struct execve_event {
    __u32 tpid;                    // Target Process ID (for execve)
    char filename[PATH_MAX];       // Filename being executed
    char argv[256];                // Arguments (simplified for example)
    __u32 argc;                    // Argument count
};

/* Specific fields for signal events */
struct signal_event {
    __u32 tpid;                    // Target Process ID (for signal)
    int sig_raw;                   // Signal number
    int error_raw;                 // Error code (for failed syscalls)
};

/* Specific fields for memory operations */
struct mem_event {
    enum memop operation;          // Memory operation type (malloc, free, etc.)
    __u64 addr;                    // Address of the operation
    __u64 size;                    // Size of the memory operation (for malloc)
};

/* Specific fields for bind events */
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

/* The main event structure */
struct event {
    enum event_type type;           // Type of event (execve, signal, mem, bind)
    struct event_common common;     // Common fields for all events
    union {
        struct execve_event execve;
        struct signal_event signal;
        struct mem_event mem;       // Memory event details
        struct bind_event bind;     // Bind event details
    } details;                      // Event-specific details
};

#endif // TRACE_EVENTS_H
