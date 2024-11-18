/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
/* Copyright (c) 2024 The Inspektor Gadget authors */

#define __TARGET_ARCH_x86

#include <vmlinux.h>

#define _LINUX_TYPES_H        // Prevent redefinition of linux/types.h
#define _LINUX_POSIX_TYPES_H  // Prevent redefinition of linux/posix_types.h

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#include "common/events.h"

#define MAX_ENTRIES 10240

GADGET_TRACER_MAP(events, 1024 * 256);

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct socket *);
} sockets SEC(".maps");

static int handle_bind_entry(struct pt_regs *ctx, struct socket *socket) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    bpf_map_update_elem(&sockets, &tid, &socket, BPF_ANY);
    return 0;
}

static int handle_bind_exit(struct pt_regs *ctx, short ver) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 uid_gid = bpf_get_current_uid_gid();
    u64 mntns_id;
    struct socket **socketp, *socket;
    struct inet_sock *inet_sock;
    struct sock *sock;
    struct event *event;
    int ret;

    socketp = bpf_map_lookup_elem(&sockets, &tid);
    if (!socketp)
        return 0;

    mntns_id = gadget_get_mntns_id();
    if (gadget_should_discard_mntns_id(mntns_id))
        goto cleanup;

    ret = PT_REGS_RC(ctx); // This line causes the issue
    socket = *socketp;
    sock = BPF_CORE_READ(socket, sk);
    inet_sock = (struct inet_sock *)sock;

    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event)
        goto cleanup;

    /* Fill common fields */
    event->common.pid = pid;
    event->common.tid = tid;
    event->common.uid = (u32)uid_gid;
    event->common.gid = (u32)(uid_gid >> 32);
    event->common.mntns_id = mntns_id;
    event->type = EVENT_TYPE_BIND;
    event->common.timestamp_raw = bpf_ktime_get_boot_ns();
    bpf_get_current_comm(&event->common.comm, sizeof(event->common.comm));

    /* Fill bind-specific fields */
    event->details.bind.bound_dev_if = BPF_CORE_READ(sock, __sk_common.skc_bound_dev_if);
    event->details.bind.error_raw = ret;
    event->details.bind.addr.version = ver;
    event->details.bind.addr.port = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));
    event->details.bind.addr.proto_raw = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);

    if (ver == 4) {
        bpf_probe_read_kernel(&event->details.bind.addr.addr_raw.v4,
                              sizeof(event->details.bind.addr.addr_raw.v4),
                              &inet_sock->inet_saddr);
    } else {
        bpf_probe_read_kernel(
            &event->details.bind.addr.addr_raw.v6,
            sizeof(event->details.bind.addr.addr_raw.v6),
            sock->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    }

    /* Submit the event */
    gadget_submit_buf(ctx, &events, event, sizeof(*event));

cleanup:
    bpf_map_delete_elem(&sockets, &tid);
    return 0;
}

SEC("kprobe/inet_bind")
int BPF_KPROBE(bind_ipv4_entry, struct socket *socket) {
    return handle_bind_entry(ctx, socket);
}

SEC("kretprobe/inet_bind")
int BPF_KRETPROBE(bind_ipv4_exit) {
    return handle_bind_exit(ctx, 4);
}

SEC("kprobe/inet6_bind")
int BPF_KPROBE(bind_ipv6_entry, struct socket *socket) {
    return handle_bind_entry(ctx, socket);
}

SEC("kretprobe/inet6_bind")
int BPF_KRETPROBE(bind_ipv6_exit) {
    return handle_bind_exit(ctx, 6);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
