// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>

#define _LINUX_TYPES_H
#define _LINUX_POSIX_TYPES_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#include "common/events.h"

#ifndef AF_UNSPEC
#define AF_UNSPEC 0
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define MAX_ENTRIES 10240

struct listen_args {
    int fd;
    int backlog;
    gadget_mntns_id mntns_id;
};

struct accept_args {
    int fd;
    const struct sockaddr *upeer_sockaddr;
    __u32 addrlen;
    gadget_mntns_id mntns_id;
};

struct connect_args {
    int fd;
    __u32 addrlen;
    struct tcp_addr remote;
    gadget_mntns_id mntns_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct listen_args);
} listens SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct accept_args);
} accepts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct connect_args);
} connects SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

static __always_inline void fill_common(struct event *event, __u64 mntns_id)
{
    __u64 pid_tgid;
    __u64 uid_gid;

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();

    event->common.timestamp_raw = bpf_ktime_get_boot_ns();
    event->common.pid = (__u32) (pid_tgid >> 32);
    event->common.tid = (__u32) pid_tgid;
    event->common.uid = (__u32) uid_gid;
    event->common.gid = (__u32) (uid_gid >> 32);
    event->common.mntns_id = mntns_id;
    bpf_get_current_comm(event->common.comm, sizeof(event->common.comm));
}

static __always_inline void parse_sockaddr(const struct sockaddr *addr,
                                           __u32 addrlen,
                                           struct tcp_addr *out)
{
    int ret;
    sa_family_t family;

    if (!out) {
        return;
    }

    __builtin_memset(out, 0, sizeof(*out));

    if (!addr || addrlen < sizeof(sa_family_t)) {
        return;
    }

    family = AF_UNSPEC;
    ret = bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
    if (ret != 0) {
        return;
    }

    if (family == AF_INET) {
        struct sockaddr_in in4 = {};

        if (addrlen < sizeof(in4)) {
            return;
        }

        ret = bpf_probe_read_user(&in4, sizeof(in4), addr);
        if (ret != 0) {
            return;
        }

        out->version = 4;
        out->port = bpf_ntohs(in4.sin_port);
        out->addr_raw.v4 = in4.sin_addr.s_addr;
    }
    else if (family == AF_INET6) {
        struct sockaddr_in6 in6 = {};

        if (addrlen < sizeof(in6)) {
            return;
        }

        ret = bpf_probe_read_user(&in6, sizeof(in6), addr);
        if (ret != 0) {
            return;
        }

        out->version = 6;
        out->port = bpf_ntohs(in6.sin6_port);
        __builtin_memcpy(out->addr_raw.v6,
                         &in6.sin6_addr.in6_u.u6_addr32,
                         sizeof(out->addr_raw.v6));
    }
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_tcp_listen_enter(struct syscall_trace_enter *ctx)
{
    __u32 tid;
    __u64 pid_tgid;
    __u64 mntns_id;
    struct listen_args args = {};

    mntns_id = gadget_get_mntns_id();
    if (gadget_should_discard_mntns_id(mntns_id)) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;

    args.fd = (int) ctx->args[0];
    args.backlog = (int) ctx->args[1];
    args.mntns_id = mntns_id;

    bpf_map_update_elem(&listens, &tid, &args, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_listen")
int trace_tcp_listen_exit(struct syscall_trace_exit *ctx)
{
    __u32 tid;
    __u64 pid_tgid;
    struct listen_args *args;
    struct event *event;

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;

    args = bpf_map_lookup_elem(&listens, &tid);
    if (!args) {
        return 0;
    }

    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        bpf_map_delete_elem(&listens, &tid);
        return 0;
    }

    fill_common(event, args->mntns_id);

    event->type = EVENT_TYPE_LISTEN;
    event->details.listen.fd = args->fd;
    event->details.listen.backlog = args->backlog;
    event->details.listen.error_raw = ctx->ret < 0 ? -ctx->ret : 0;

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    bpf_map_delete_elem(&listens, &tid);

    return 0;
}

static __always_inline int handle_accept_enter(struct syscall_trace_enter *ctx)
{
    __u32 tid;
    __u64 pid_tgid;
    __u64 mntns_id;
    int addrlen_val;
    int *upeer_addrlen;
    struct accept_args args = {};

    mntns_id = gadget_get_mntns_id();
    if (gadget_should_discard_mntns_id(mntns_id)) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;

    args.fd = (int) ctx->args[0];
    args.upeer_sockaddr = (const struct sockaddr *) ctx->args[1];
    args.mntns_id = mntns_id;
    args.addrlen = 0;

    upeer_addrlen = (int *) ctx->args[2];
    if (upeer_addrlen) {
        addrlen_val = 0;
        if (bpf_probe_read_user(&addrlen_val, sizeof(addrlen_val), upeer_addrlen) == 0 &&
            addrlen_val > 0) {
            args.addrlen = (__u32) addrlen_val;
        }
    }

    bpf_map_update_elem(&accepts, &tid, &args, BPF_ANY);

    return 0;
}

static __always_inline int handle_accept_exit(struct syscall_trace_exit *ctx)
{
    __u32 tid;
    __u64 pid_tgid;
    struct accept_args *args;
    struct event *event;

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;

    args = bpf_map_lookup_elem(&accepts, &tid);
    if (!args) {
        return 0;
    }

    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        bpf_map_delete_elem(&accepts, &tid);
        return 0;
    }

    fill_common(event, args->mntns_id);

    event->type = EVENT_TYPE_ACCEPT;
    event->details.accept.fd = args->fd;
    event->details.accept.new_fd = (int) ctx->ret;
    event->details.accept.error_raw = ctx->ret < 0 ? -ctx->ret : 0;
    if (ctx->ret >= 0) {
        parse_sockaddr(args->upeer_sockaddr, args->addrlen,
                       &event->details.accept.peer);
    }

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    bpf_map_delete_elem(&accepts, &tid);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_tcp_accept_enter(struct syscall_trace_enter *ctx)
{
    return handle_accept_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_tcp_accept_exit(struct syscall_trace_exit *ctx)
{
    return handle_accept_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_tcp_accept4_enter(struct syscall_trace_enter *ctx)
{
    return handle_accept_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_tcp_accept4_exit(struct syscall_trace_exit *ctx)
{
    return handle_accept_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_tcp_connect_enter(struct syscall_trace_enter *ctx)
{
    __u32 tid;
    __u64 pid_tgid;
    __u64 mntns_id;
    struct connect_args args = {};
    const struct sockaddr *uservaddr;

    mntns_id = gadget_get_mntns_id();
    if (gadget_should_discard_mntns_id(mntns_id)) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;

    args.fd = (int) ctx->args[0];
    uservaddr = (const struct sockaddr *) ctx->args[1];
    args.addrlen = (__u32) ctx->args[2];
    args.mntns_id = mntns_id;
    parse_sockaddr(uservaddr, args.addrlen, &args.remote);

    bpf_map_update_elem(&connects, &tid, &args, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_tcp_connect_exit(struct syscall_trace_exit *ctx)
{
    __u32 tid;
    __u64 pid_tgid;
    struct connect_args *args;
    struct event *event;

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;

    args = bpf_map_lookup_elem(&connects, &tid);
    if (!args) {
        return 0;
    }

    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        bpf_map_delete_elem(&connects, &tid);
        return 0;
    }

    fill_common(event, args->mntns_id);

    event->type = EVENT_TYPE_CONNECT;
    event->details.connect.fd = args->fd;
    event->details.connect.remote = args->remote;
    event->details.connect.error_raw = ctx->ret < 0 ? -ctx->ret : 0;

    gadget_submit_buf(ctx, &events, event, sizeof(*event));
    bpf_map_delete_elem(&connects, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
