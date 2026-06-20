// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>

#define _LINUX_TYPES_H
#define _LINUX_POSIX_TYPES_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#include "common/events.h"

#define MAX_ENTRIES 10240

struct vfs_open_args {
    gadget_mntns_id mntns_id;
    __u32 flags;
    __u32 mode;
    char path[VFS_PATH_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct vfs_open_args);
} values SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_vfs_openat_enter(struct syscall_trace_enter *ctx)
{
    __u32 tid;
    __u64 pid_tgid;
    __u64 mntns_id;
    const char *filename;
    struct vfs_open_args val = {};

    mntns_id = gadget_get_mntns_id();
    if (gadget_should_discard_mntns_id(mntns_id)) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;

    filename = (const char *) ctx->args[1];
    bpf_probe_read_user_str(val.path, sizeof(val.path), filename);

    val.flags = (__u32) ctx->args[2];
    val.mode = (__u32) ctx->args[3];
    val.mntns_id = mntns_id;

    bpf_map_update_elem(&values, &tid, &val, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_vfs_openat_exit(struct syscall_trace_exit *ctx)
{
    __u32 tid;
    __u64 pid_tgid;
    __u64 uid_gid;
    struct vfs_open_args *val;
    struct event *event;

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;

    val = bpf_map_lookup_elem(&values, &tid);
    if (!val) {
        return 0;
    }

    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        bpf_map_delete_elem(&values, &tid);
        return 0;
    }

    uid_gid = bpf_get_current_uid_gid();

    event->common.timestamp_raw = bpf_ktime_get_boot_ns();
    event->common.pid = pid_tgid >> 32;
    event->common.tid = tid;
    event->common.uid = (u32) uid_gid;
    event->common.gid = (u32) (uid_gid >> 32);
    event->common.mntns_id = val->mntns_id;
    bpf_get_current_comm(event->common.comm, sizeof(event->common.comm));

    event->type = EVENT_TYPE_VFS;
    event->details.vfs.operation = VFS_OP_OPENAT;
    event->details.vfs.flags = val->flags;
    event->details.vfs.mode = val->mode;
    event->details.vfs.fd = (int) ctx->ret;
    event->details.vfs.error_raw = ctx->ret < 0 ? -ctx->ret : 0;

    __builtin_memcpy(event->details.vfs.path, val->path, sizeof(event->details.vfs.path));

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    bpf_map_delete_elem(&values, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
