#ifndef TRACE_EVENTS_H
#define TRACE_EVENTS_H

#include <linux/limits.h>
#include <linux/types.h>  // For __u32, __u64, etc.

#define TASK_COMM_LEN 16

enum event_type {
    EVENT_TYPE_EXECVE,
    EVENT_TYPE_SIGNAL,
};

/* Common fields for all events */
struct event_common {
    __u64 timestamp_raw;           // Event timestamp in nanoseconds
    __u32 pid;                     // Process ID
    __u32 tid;                     // Thread ID
    __u32 uid;                     // User ID
    __u32 gid;                     // Group ID
    __u64 mntns_id;
    char comm[TASK_COMM_LEN];       // Command name (process name)
};

/* Specific fields for execve events */
struct execve_event {
    __u32 tpid;                    // Target Process ID (for execve)
    char filename[PATH_MAX];        // Filename being executed
    char argv[256];                 // Arguments (simplified for example)
    __u32 argc;                    // Argument count
};

/* Specific fields for signal events */
struct signal_event {
    __u32 tpid;                    // Target Process ID (for signal)
    int sig_raw;                   // Signal number
    int error_raw;                 // Error code (for failed syscalls)
};

/* The main event structure */
struct event {
    enum event_type type;           // Type of event (execve, signal)
    struct event_common common;     // Common fields for all events
    union {
        struct execve_event execve;
        struct signal_event signal;
    } details;                      // Event-specific details
};

#endif // TRACE_EVENTS_H
