#include <vmlinux.h>

#define _LINUX_TYPES_H        // Prevent redefinition of linux/types.h
#define _LINUX_POSIX_TYPES_H  // Prevent redefinition of linux/posix_types.h

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "common/events.h"

#define ARGSIZE 128
#define MAX_ARGS 20

/* Per-CPU array to avoid large stack allocations */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);  // Only need one entry per CPU
    __type(key, u32);
    __type(value, struct event);  // The large event structure
} exec_events_buffer SEC(".maps");

/* Hash map to track execve events in progress */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u32);  // Points to the index of exec_events_buffer map
} exec_events SEC(".maps");

/* Ring buffer for reporting events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8192);
} events SEC(".maps");

static __always_inline int handle_execve_entry(void *ctx, const char **args)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    /* Get a pointer to the event buffer from the per-CPU array */
    u32 key = 0;
    struct event *ev = bpf_map_lookup_elem(&exec_events_buffer, &key);
    if (!ev)
        return 0;  // Error: unable to find event buffer

    /* Initialize common event data manually */
    ev->type = EVENT_TYPE_EXECVE;
    ev->common.pid = pid;
    ev->common.tid = tid;
    ev->common.uid = bpf_get_current_uid_gid();
    ev->common.gid = bpf_get_current_uid_gid() >> 32;
    ev->common.timestamp_raw = bpf_ktime_get_boot_ns();
    bpf_get_current_comm(&ev->common.comm, sizeof(ev->common.comm));

    /* Get task_struct to gather parent info */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ev->details.execve.tpid = BPF_CORE_READ(task, real_parent, tgid);

    /* Capture the first few arguments, one at a time */
    int i;
    #pragma unroll
    for (i = 0; i < MAX_ARGS; i++) {
        const char *argp;
        int ret = bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
        if (ret || !argp)
            break;

        /* Report each argument individually to avoid exceeding stack limits */
        bpf_probe_read_user_str(&ev->details.execve.argv, ARGSIZE, argp);
        ev->details.execve.argc = i;  // Record argument index

        /* Submit the current argument via ring buffer */
        bpf_ringbuf_output(&events, ev, sizeof(*ev), 0);
    }

    /* Add the event to the exec_events map */
    bpf_map_update_elem(&exec_events, &tid, &key, BPF_ANY);

    return 0;
}

/* Hook for sys_enter_execve tracepoint */
SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct syscall_trace_enter *ctx)
{
    const char **args = (const char **)(ctx->args[1]);
    return handle_execve_entry(ctx, args);
}

/* Hook for sched_process_exec tracepoint, triggered after a successful execve */
SEC("tracepoint/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    u32 pid = ctx->old_pid;
    u32 *key = bpf_map_lookup_elem(&exec_events, &pid);
    if (!key)
        return 0;

    struct event *ev = bpf_map_lookup_elem(&exec_events_buffer, key);
    if (!ev)
        return 0;

    /* Submit final event via ring buffer */
    bpf_ringbuf_output(&events, ev, sizeof(*ev), 0);

    /* Clean up the entry from exec_events map */
    bpf_map_delete_elem(&exec_events, &pid);
    return 0;
}

/* Hook for sys_exit_execve tracepoint, triggered after execve returns */
SEC("tracepoint/syscalls/sys_exit_execve")
int sys_exit_execve(struct syscall_trace_exit *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    if (ctx->ret != 0) {
        /* Cleanup map entry if execve failed */
        bpf_map_delete_elem(&exec_events, &pid);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
