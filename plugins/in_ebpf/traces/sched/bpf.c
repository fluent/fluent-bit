// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#define __TARGET_ARCH_x86_64

#include <vmlinux.h>

#define _LINUX_TYPES_H
#define _LINUX_POSIX_TYPES_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/mntns_filter.h>

#include "common/events.h"

struct wakeup_info {
    __u64 wakeup_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct wakeup_info);
} wakeup_by_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int track_wakeup(__u32 pid)
{
    struct wakeup_info info = {0};

    if (pid == 0) {
        return 0;
    }

    info.wakeup_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_by_pid, &pid, &info, BPF_ANY);

    return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int trace_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    return track_wakeup((__u32) ctx->pid);
}

SEC("tracepoint/sched/sched_wakeup_new")
int trace_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
    return track_wakeup((__u32) ctx->pid);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(trace_sched_switch, bool preempt, struct task_struct *prev,
             struct task_struct *next, unsigned int prev_state)
{
    struct sched_sample *event;
    struct wakeup_info *wakeup;
    __u64 now_ns;
    __u32 next_pid = 0;
    __u32 prev_pid = 0;
    int prev_prio = 0;
    int next_prio = 0;
    __u64 mntns_id;
    const struct cred *next_cred;
    __u32 uid = 0;
    __u32 gid = 0;

    bpf_core_read(&next_pid, sizeof(next_pid), &next->pid);
    bpf_core_read(&prev_pid, sizeof(prev_pid), &prev->pid);
    bpf_core_read(&prev_prio, sizeof(prev_prio), &prev->prio);
    bpf_core_read(&next_prio, sizeof(next_prio), &next->prio);

    if (next_pid == 0) {
        return 0;
    }

    mntns_id = BPF_CORE_READ(next, nsproxy, mnt_ns, ns.inum);
    if (gadget_should_discard_mntns_id(mntns_id)) {
        return 0;
    }

    now_ns = bpf_ktime_get_ns();
    next_cred = BPF_CORE_READ(next, real_cred);
    if (next_cred) {
        uid = BPF_CORE_READ(next_cred, uid.val);
        gid = BPF_CORE_READ(next_cred, gid.val);
    }

    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }

    event->type = EVENT_TYPE_SCHED;
    event->common.timestamp_raw = bpf_ktime_get_boot_ns();
    event->common.pid = next_pid;
    event->common.tid = next_pid;
    event->common.uid = uid;
    event->common.gid = gid;
    event->common.mntns_id = mntns_id;
    bpf_core_read(event->common.comm, sizeof(event->common.comm), &next->comm);

    event->details.prev_pid = prev_pid;
    event->details.prev_prio = prev_prio;
    event->details.prev_state = prev_state;
    event->details.next_pid = next_pid;
    event->details.next_prio = next_prio;
    event->details.cpu = bpf_get_smp_processor_id();
    event->details.wakeup_tracked = 0;
    event->details.runq_latency_ns = 0;

    wakeup = bpf_map_lookup_elem(&wakeup_by_pid, &next_pid);
    if (wakeup) {
        event->details.wakeup_tracked = 1;
        if (now_ns > wakeup->wakeup_ns) {
            event->details.runq_latency_ns = now_ns - wakeup->wakeup_ns;
        }
        bpf_map_delete_elem(&wakeup_by_pid, &next_pid);
    }

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
