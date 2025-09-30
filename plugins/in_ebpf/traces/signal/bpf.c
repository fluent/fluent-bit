// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021~2022 Hengqi Chen */
#define __TARGET_ARCH_x86_64

#include <vmlinux.h>

#define _LINUX_TYPES_H        // Prevent redefinition of linux/types.h
#define _LINUX_POSIX_TYPES_H  // Prevent redefinition of linux/posix_types.h

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#include "common/events.h" 


struct value {
    gadget_mntns_id mntns_id;
    int sig;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct value);
} values SEC(".maps");

// Define the ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8192);
} events SEC(".maps");

// 	struct {					\
// 		__uint(type, BPF_MAP_TYPE_RINGBUF);	\
// 		__uint(max_entries, size);		\
// 	} name SEC(".maps");		

// GADGET_TRACER_MAP(events, 1024 * 256);

/* Helper to handle signal entry */
static int handle_signal_entry(pid_t tpid, int sig) {
    struct value v = {};
    __u64 pid_tgid;
    __u32 pid, tid;
    u64 mntns_id;

    mntns_id = gadget_get_mntns_id();
    if (gadget_should_discard_mntns_id(mntns_id))
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;
    tid = (__u32)pid_tgid;

    v.sig = sig;
    v.mntns_id = mntns_id;
    bpf_map_update_elem(&values, &tid, &v, BPF_ANY);
    return 0;
}

/* Helper to handle signal exit */
static int handle_signal_exit(void *ctx, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 tid = (__u32)pid_tgid;
    struct event *eventp;
    struct value *vp;

    vp = bpf_map_lookup_elem(&values, &tid);
    if (!vp)
        return 0;

    eventp = gadget_reserve_buf(&events, sizeof(*eventp));
    if (!eventp)
        return 0;

    /* Populate the event with data */
    eventp->common.timestamp_raw = bpf_ktime_get_boot_ns();
    eventp->common.pid = pid_tgid >> 32;
    eventp->common.tid = tid;
    eventp->common.uid = (u32)uid_gid;
    eventp->common.gid = (u32)(uid_gid >> 32);
    eventp->common.mntns_id = vp->mntns_id;
    bpf_get_current_comm(eventp->common.comm, sizeof(eventp->common.comm));

    eventp->type = EVENT_TYPE_SIGNAL;  // Set the event type
    eventp->details.signal.tpid = eventp->common.pid;  // Set target pid
    eventp->details.signal.sig_raw = vp->sig;  // Signal number
    eventp->details.signal.error_raw = -ret;  // Error code

    /* Submit the event */
    gadget_submit_buf(ctx, &events, eventp, sizeof(*eventp));
    bpf_map_delete_elem(&values, &tid);

    return 0;
}

/* Tracepoints for kill signal */
SEC("tracepoint/syscalls/sys_enter_kill")
int ig_sig_kill_e(struct syscall_trace_enter *ctx) {
    pid_t tpid = (pid_t)ctx->args[0];
    int sig = (int)ctx->args[1];

    return handle_signal_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int ig_sig_kill_x(struct syscall_trace_exit *ctx) {
    return handle_signal_exit(ctx, ctx->ret);
}

/* Tracepoints for tkill signal */
SEC("tracepoint/syscalls/sys_enter_tkill")
int ig_sig_tkill_e(struct syscall_trace_enter *ctx) {
    pid_t tpid = (pid_t)ctx->args[0];
    int sig = (int)ctx->args[1];

    return handle_signal_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_tkill")
int ig_sig_tkill_x(struct syscall_trace_exit *ctx) {
    return handle_signal_exit(ctx, ctx->ret);
}

/* Tracepoints for tgkill signal */
SEC("tracepoint/syscalls/sys_enter_tgkill")
int ig_sig_tgkill_e(struct syscall_trace_enter *ctx) {
    pid_t tpid = (pid_t)ctx->args[1];
    int sig = (int)ctx->args[2];

    return handle_signal_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_tgkill")
int ig_sig_tgkill_x(struct syscall_trace_exit *ctx) {
    return handle_signal_exit(ctx, ctx->ret);
}

/* Tracepoint for signal_generate */
SEC("tracepoint/signal/signal_generate")
int ig_sig_generate(struct trace_event_raw_signal_generate *ctx) {
    struct event *event;
    pid_t tpid = ctx->pid;
    int ret = ctx->errno;
    int sig = ctx->sig;
    __u64 pid_tgid;
    __u32 pid;
    u64 mntns_id;
    __u64 uid_gid = bpf_get_current_uid_gid();

    mntns_id = gadget_get_mntns_id();
    if (gadget_should_discard_mntns_id(mntns_id))
        return 0;

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;

    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
        return 0;

    /* Populate the event with data */
    event->common.timestamp_raw = bpf_ktime_get_boot_ns();
    event->common.pid = pid;
    event->common.tid = (__u32)pid_tgid;
    event->common.uid = (u32)uid_gid;
    event->common.gid = (u32)(uid_gid >> 32);
    event->common.mntns_id = mntns_id;
    bpf_get_current_comm(event->common.comm, sizeof(event->common.comm));

    event->type = EVENT_TYPE_SIGNAL;
    event->details.signal.tpid = tpid;
    event->details.signal.sig_raw = sig;
    event->details.signal.error_raw = -ret;

    /* Submit the event */
    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
