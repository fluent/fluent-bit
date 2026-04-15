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
#define ARGV_MAX_SCAN 20

struct execve_args {
    gadget_mntns_id mntns_id;
    char filename[PATH_MAX];
    char argv[EXECVE_ARG_MAX][EXECVE_ARG_LEN];
    char argv_last[EXECVE_ARG_LEN];
    __u32 argc;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct execve_args);
} values SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct execve_args);
} heap SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

static __always_inline __u32 get_ppid(void)
{
    struct task_struct *task;

    task = (struct task_struct *) bpf_get_current_task_btf();
    if (!task) {
        return 0;
    }

    return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline int submit_exec_event(void *ctx,
                                             struct execve_args *args,
                                             enum execve_stage stage,
                                             int error_raw)
{
    __u64 pid_tgid;
    __u64 uid_gid;
    struct event *event;

    event = gadget_reserve_buf(&events, sizeof(*event));
    if (!event) {
        return -1;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();

    event->common.timestamp_raw = bpf_ktime_get_boot_ns();
    event->common.pid = (__u32) (pid_tgid >> 32);
    event->common.tid = (__u32) pid_tgid;
    event->common.uid = (__u32) uid_gid;
    event->common.gid = (__u32) (uid_gid >> 32);
    event->common.mntns_id = args->mntns_id;
    bpf_get_current_comm(event->common.comm, sizeof(event->common.comm));

    event->type = EVENT_TYPE_EXECVE;
    event->details.execve.stage = stage;
    event->details.execve.ppid = get_ppid();
    event->details.execve.argc = args->argc;
    event->details.execve.error_raw = error_raw;

    bpf_probe_read_kernel_str(event->details.execve.filename,
                              sizeof(event->details.execve.filename),
                              args->filename);
    bpf_probe_read_kernel_str(event->details.execve.argv[0],
                              sizeof(event->details.execve.argv[0]),
                              args->argv[0]);
    bpf_probe_read_kernel_str(event->details.execve.argv[1],
                              sizeof(event->details.execve.argv[1]),
                              args->argv[1]);
    bpf_probe_read_kernel_str(event->details.execve.argv[2],
                              sizeof(event->details.execve.argv[2]),
                              args->argv[2]);
    bpf_probe_read_kernel_str(event->details.execve.argv_last,
                              sizeof(event->details.execve.argv_last),
                              args->argv_last);

    gadget_submit_buf(ctx, &events, event, sizeof(*event));

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct syscall_trace_enter *ctx)
{
    __u32 tid;
    __u32 i;
    __u64 pid_tgid;
    __u64 mntns_id;
    __u32 zero;
    const char *filename;
    const char *const *argv;
    const char *arg;
    struct execve_args *args;

    mntns_id = gadget_get_mntns_id();
    if (gadget_should_discard_mntns_id(mntns_id)) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32) pid_tgid;

    zero = 0;
    args = bpf_map_lookup_elem(&heap, &zero);
    if (!args) {
        return 0;
    }

    args->mntns_id = mntns_id;
    args->argc = 0;
    args->filename[0] = '\0';
    args->argv[0][0] = '\0';
    args->argv[1][0] = '\0';
    args->argv[2][0] = '\0';
    args->argv_last[0] = '\0';

    filename = (const char *) ctx->args[0];
    if (filename) {
        bpf_probe_read_user_str(args->filename, sizeof(args->filename), filename);
    }

    argv = (const char *const *) ctx->args[1];
    if (argv) {
#pragma unroll
        for (i = 0; i < ARGV_MAX_SCAN; i++) {
            arg = NULL;
            if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) != 0 || arg == NULL) {
                break;
            }
            args->argc++;
            bpf_probe_read_user_str(args->argv_last, sizeof(args->argv_last), arg);

            if (i == 0) {
                bpf_probe_read_user_str(args->argv[0], sizeof(args->argv[0]), arg);
            }
            else if (i == 1) {
                bpf_probe_read_user_str(args->argv[1], sizeof(args->argv[1]), arg);
            }
            else if (i == 2) {
                bpf_probe_read_user_str(args->argv[2], sizeof(args->argv[2]), arg);
            }
        }
    }

    bpf_map_update_elem(&values, &tid, args, BPF_ANY);
    submit_exec_event(ctx, args, EXECVE_STAGE_ENTER, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_execve_exit(struct syscall_trace_exit *ctx)
{
    __u32 tid;
    struct execve_args *args;
    int error_raw;

    tid = (__u32) bpf_get_current_pid_tgid();

    args = bpf_map_lookup_elem(&values, &tid);
    if (!args) {
        return 0;
    }

    error_raw = ctx->ret < 0 ? -ctx->ret : 0;
    submit_exec_event(ctx, args, EXECVE_STAGE_EXIT, error_raw);

    bpf_map_delete_elem(&values, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
