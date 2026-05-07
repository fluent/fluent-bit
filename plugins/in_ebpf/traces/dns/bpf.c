// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>

#define _LINUX_TYPES_H
#define _LINUX_POSIX_TYPES_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#include "common/events.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef DNS_PORT
#define DNS_PORT 53
#endif

#define DNS_HEADER_SIZE 12

struct dns_query_key {
    __u32 pid;
    __s32 fd;
    __u16 txid;
};

struct dns_socket_key {
    __u32 pid;
    __s32 fd;
};

struct dns_query_state {
    __u64 start_ns;
    __u64 mntns_id;
    __u16 txid;
    __u16 query_raw_len;
    __u8 query_raw[DNS_QUERY_RAW_MAX];
};

struct dns_recv_args {
    int fd;
    const void *buf;
};

struct dns_connect_args {
    int fd;
    __u16 family;
    __u16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct dns_query_key);
    __type(value, struct dns_query_state);
} dns_queries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct dns_recv_args);
} dns_recv SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct dns_connect_args);
} dns_connect_pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct dns_socket_key);
    __type(value, __u64);
} dns_sockets SEC(".maps");

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

static __always_inline int parse_dns_query_header(const void *payload, __u64 len,
                                                  __u16 *txid)
{
    __u8 header[DNS_HEADER_SIZE];
    __u16 flags;
    __u16 qdcount;

    if (len < DNS_HEADER_SIZE) {
        return -1;
    }

    if (bpf_probe_read_user(header, sizeof(header), payload) != 0) {
        return -1;
    }

    *txid = ((__u16) header[0] << 8) | header[1];
    flags = ((__u16) header[2] << 8) | header[3];
    qdcount = ((__u16) header[4] << 8) | header[5];

    if ((flags & 0x8000) != 0 || qdcount == 0) {
        return -1;
    }

    return 0;
}

static __always_inline int parse_dns_response(const void *payload, __u64 len,
                                              __u16 *txid, __u8 *rcode)
{
    __u8 header[DNS_HEADER_SIZE];
    __u16 flags;

    if (len < DNS_HEADER_SIZE) {
        return -1;
    }

    if (bpf_probe_read_user(header, sizeof(header), payload) != 0) {
        return -1;
    }

    *txid = ((__u16) header[0] << 8) | header[1];
    flags = ((__u16) header[2] << 8) | header[3];

    if ((flags & 0x8000) == 0) {
        return -1;
    }

    *rcode = (__u8) (flags & 0x000f);

    return 0;
}

static __always_inline int is_dns_destination(const struct sockaddr *addr, __u32 addrlen)
{
    struct sockaddr_in dst;
    struct sockaddr_in6 dst6;

    if (!addr) {
        return 0;
    }

    if (addrlen >= sizeof(struct sockaddr_in)) {
        if (bpf_probe_read_user(&dst, sizeof(dst), addr) == 0) {
            if (dst.sin_family == AF_INET && bpf_ntohs(dst.sin_port) == DNS_PORT) {
                return 1;
            }
        }
    }

    if (addrlen < sizeof(struct sockaddr_in6)) {
        return 0;
    }

    if (bpf_probe_read_user(&dst6, sizeof(dst6), addr) != 0) {
        return 0;
    }

    if (dst6.sin6_family != AF_INET6 || bpf_ntohs(dst6.sin6_port) != DNS_PORT) {
        return 0;
    }

    return 1;
}

static __always_inline int is_dns_family_port(__u16 family, __u16 port)
{
    if ((family != AF_INET && family != AF_INET6) || port != DNS_PORT) {
        return 0;
    }

    return 1;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_dns_connect_enter(struct syscall_trace_enter *ctx)
{
    __u32 tid;
    __u64 pid_tgid;
    struct dns_connect_args args;
    __u16 family;
    __u16 port;
    struct sockaddr sa;
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;

    args.fd = (int) ctx->args[0];
    family = 0;
    port = 0;

    if (!ctx->args[1]) {
        return 0;
    }

    if (bpf_probe_read_user(&sa, sizeof(sa), (const void *) ctx->args[1]) != 0) {
        return 0;
    }

    family = sa.sa_family;
    if (family == AF_INET && (__u32) ctx->args[2] >= sizeof(struct sockaddr_in)) {
        if (bpf_probe_read_user(&sa4, sizeof(sa4), (const void *) ctx->args[1]) == 0) {
            port = bpf_ntohs(sa4.sin_port);
        }
    }
    else if (family == AF_INET6 && (__u32) ctx->args[2] >= sizeof(struct sockaddr_in6)) {
        if (bpf_probe_read_user(&sa6, sizeof(sa6), (const void *) ctx->args[1]) == 0) {
            port = bpf_ntohs(sa6.sin6_port);
        }
    }

    args.family = family;
    args.port = port;

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;

    bpf_map_update_elem(&dns_connect_pending, &tid, &args, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_dns_connect_exit(struct syscall_trace_exit *ctx)
{
    __u32 tid;
    __u32 pid;
    __u64 pid_tgid;
    __u64 mntns_id;
    __s64 ret;
    struct dns_connect_args *args;
    struct dns_socket_key key;

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;
    pid = (__u32) (pid_tgid >> 32);

    args = bpf_map_lookup_elem(&dns_connect_pending, &tid);
    if (!args) {
        return 0;
    }

    ret = ctx->ret;
    key.pid = pid;
    key.fd = args->fd;

    if (ret == 0 && is_dns_family_port(args->family, args->port)) {
        mntns_id = gadget_get_mntns_id();
        if (!gadget_should_discard_mntns_id(mntns_id)) {
            bpf_map_update_elem(&dns_sockets, &key, &mntns_id, BPF_ANY);
        }
    }
    else {
        bpf_map_delete_elem(&dns_sockets, &key);
    }

    bpf_map_delete_elem(&dns_connect_pending, &tid);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_dns_close_enter(struct syscall_trace_enter *ctx)
{
    __u64 pid_tgid;
    __u32 pid;
    struct dns_socket_key key;

    pid_tgid = bpf_get_current_pid_tgid();
    pid = (__u32) (pid_tgid >> 32);

    key.pid = pid;
    key.fd = (__s32) ((int) ctx->args[0]);

    bpf_map_delete_elem(&dns_sockets, &key);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_dns_sendto_enter(struct syscall_trace_enter *ctx)
{
    __u64 pid_tgid;
    __u32 pid;
    __u16 txid;
    __u16 raw_len;
    __u64 mntns_id;
    __u64 len;
    int fd;
    __u32 addrlen;
    const struct sockaddr *addr;
    const void *payload;
    struct dns_query_key key;
    struct dns_socket_key socket_key;
    __u64 *socket_mntns_id;
    struct dns_query_state state = {0};
    struct event *event;

    mntns_id = gadget_get_mntns_id();
    if (gadget_should_discard_mntns_id(mntns_id)) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    pid = (__u32) (pid_tgid >> 32);

    fd = (int) ctx->args[0];
    payload = (const void *) ctx->args[1];
    len = (__u64) ctx->args[2];
    addr = (const struct sockaddr *) ctx->args[4];
    addrlen = (__u32) ctx->args[5];

    if (!payload || len < DNS_HEADER_SIZE) {
        return 0;
    }

    socket_key.pid = pid;
    socket_key.fd = fd;
    socket_mntns_id = bpf_map_lookup_elem(&dns_sockets, &socket_key);

    if (!is_dns_destination(addr, addrlen) && !socket_mntns_id) {
        return 0;
    }

    if (parse_dns_query_header(payload, len, &txid) != 0) {
        return 0;
    }

    key.pid = pid;
    key.fd = fd;
    key.txid = txid;

    state.start_ns = bpf_ktime_get_ns();
    if (socket_mntns_id) {
        state.mntns_id = *socket_mntns_id;
    }
    else {
        state.mntns_id = mntns_id;
    }
    state.txid = txid;

    raw_len = (__u16) (len > DNS_QUERY_RAW_MAX ? DNS_QUERY_RAW_MAX : len);
    state.query_raw_len = raw_len;

    if (raw_len > 0) {
        if (bpf_probe_read_user(state.query_raw, raw_len, payload) != 0) {
            return 0;
        }
    }

    bpf_map_update_elem(&dns_queries, &key, &state, BPF_ANY);

    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return 0;
    }

    fill_common(event, state.mntns_id);
    event->type = EVENT_TYPE_DNS;
    event->details.dns.txid = txid;
    event->details.dns.query_type = 0;
    event->details.dns.rcode = 0;
    event->details.dns.response = 0;
    event->details.dns.latency_ns = 0;
    event->details.dns.error_raw = 0;
    event->details.dns.query_raw_len = state.query_raw_len;
    __builtin_memcpy(event->details.dns.query_raw,
                     state.query_raw,
                     sizeof(event->details.dns.query_raw));

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_dns_recvfrom_enter(struct syscall_trace_enter *ctx)
{
    __u32 tid;
    __u64 pid_tgid;
    struct dns_recv_args args;

    args.fd = (int) ctx->args[0];
    args.buf = (const void *) ctx->args[1];

    if (!args.buf) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;

    bpf_map_update_elem(&dns_recv, &tid, &args, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_dns_recvfrom_exit(struct syscall_trace_exit *ctx)
{
    __u32 tid;
    __u32 pid;
    __u64 now_ns;
    __u64 pid_tgid;
    __s64 ret;
    __u16 txid;
    __u8 rcode;
    struct dns_recv_args *args;
    struct dns_query_key key;
    struct dns_query_state *state;
    struct event *event;

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;
    pid = (__u32) (pid_tgid >> 32);

    args = bpf_map_lookup_elem(&dns_recv, &tid);
    if (!args) {
        return 0;
    }

    ret = ctx->ret;
    if (ret <= 0) {
        bpf_map_delete_elem(&dns_recv, &tid);
        return 0;
    }

    if (parse_dns_response(args->buf, (__u64) ret, &txid, &rcode) != 0) {
        bpf_map_delete_elem(&dns_recv, &tid);
        return 0;
    }

    key.pid = pid;
    key.fd = args->fd;
    key.txid = txid;

    state = bpf_map_lookup_elem(&dns_queries, &key);
    if (!state) {
        bpf_map_delete_elem(&dns_recv, &tid);
        return 0;
    }

    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        bpf_map_delete_elem(&dns_queries, &key);
        bpf_map_delete_elem(&dns_recv, &tid);
        return 0;
    }

    now_ns = bpf_ktime_get_ns();

    fill_common(event, state->mntns_id);
    event->type = EVENT_TYPE_DNS;
    event->details.dns.txid = txid;
    event->details.dns.query_type = 0;
    event->details.dns.rcode = rcode;
    event->details.dns.response = 1;
    event->details.dns.latency_ns = now_ns - state->start_ns;
    event->details.dns.error_raw = 0;
    event->details.dns.query_raw_len = state->query_raw_len;
    __builtin_memcpy(event->details.dns.query_raw,
                     state->query_raw,
                     sizeof(event->details.dns.query_raw));

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    bpf_map_delete_elem(&dns_queries, &key);
    bpf_map_delete_elem(&dns_recv, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
