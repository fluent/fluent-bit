#define __TARGET_ARCH_x86


#include <vmlinux.h>

#define _LINUX_TYPES_H        // Prevent redefinition of linux/types.h
#define _LINUX_POSIX_TYPES_H  // Prevent redefinition of linux/posix_types.h

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#include "common/events.h"

#define MAX_ENTRIES 10240

/* Context struct for mapping memory sizes between entry and exit probes */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} sizes SEC(".maps");

/* Context struct for posix_memalign to keep track of pointers */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} memptrs SEC(".maps");

// Define the ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8192);
} events SEC(".maps");

/* Cleanup map entries when a thread terminates */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&sizes, &tid);
    bpf_map_delete_elem(&memptrs, &tid);
    return 0;
}

/* Helper functions */
static int gen_alloc_enter(size_t size) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);
    return 0;
}

static int gen_alloc_exit(struct pt_regs *ctx, enum memop op, u64 addr) {
    u64 mntns_id = gadget_get_mntns_id();
    if (gadget_should_discard_mntns_id(mntns_id))
        return 0;

    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *size_ptr = bpf_map_lookup_elem(&sizes, &tid);
    if (!size_ptr)
        return 0;

    struct event *eventp = gadget_reserve_buf(&events, sizeof(*eventp));
    if (!eventp)
        return 0;

    u64 uid_gid = bpf_get_current_uid_gid();

    eventp->common.timestamp_raw = bpf_ktime_get_ns();
    eventp->common.pid = tid >> 32;
    eventp->common.tid = tid;
    eventp->common.uid = uid_gid;
    eventp->common.gid = uid_gid >> 32;
    eventp->common.mntns_id = mntns_id;
    bpf_get_current_comm(eventp->common.comm, sizeof(eventp->common.comm));

    eventp->type = EVENT_TYPE_MEM;
    eventp->details.mem.operation = op;
    eventp->details.mem.addr = addr;
    eventp->details.mem.size = *size_ptr;

    gadget_submit_buf(ctx, &events, eventp, sizeof(*eventp));
    bpf_map_delete_elem(&sizes, &tid);

    return 0;
}

static int gen_free_enter(struct pt_regs *ctx, enum memop op, u64 addr) {
    u64 mntns_id = gadget_get_mntns_id();
    if (gadget_should_discard_mntns_id(mntns_id))
        return 0;

    struct event *eventp = gadget_reserve_buf(&events, sizeof(*eventp));
    if (!eventp)
        return 0;

    u32 tid = (u32)bpf_get_current_pid_tgid();

    eventp->common.timestamp_raw = bpf_ktime_get_ns();
    eventp->common.pid = tid >> 32;
    eventp->common.tid = tid;
    eventp->common.mntns_id = mntns_id;
    eventp->details.mem.operation = op;
    eventp->details.mem.addr = addr;
    eventp->details.mem.size = 0;

    gadget_submit_buf(ctx, &events, eventp, sizeof(*eventp));
    return 0;
}

/* Allocation tracking */
SEC("uprobe//lib64/libc.so.6:malloc")
int BPF_UPROBE(trace_uprobe_malloc, size_t size) {
    return gen_alloc_enter(size);
}

SEC("uretprobe//lib64/libc.so.6:malloc")
int trace_uretprobe_malloc(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx, MEMOP_MALLOC, PT_REGS_RC(ctx));
}

/* Free tracking */
SEC("uprobe//lib64/libc.so.6:free")
int BPF_UPROBE(trace_uprobe_free, void *address) {
    return gen_free_enter(ctx, MEMOP_FREE, (u64)address);
}

/* Calloc tracking */
SEC("uprobe//lib64/libc.so.6:calloc")
int BPF_UPROBE(trace_uprobe_calloc, size_t nmemb, size_t size) {
    return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe//lib64/libc.so.6:calloc")
int trace_uretprobe_calloc(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx, MEMOP_CALLOC, PT_REGS_RC(ctx));
}

/* Realloc tracking */
SEC("uprobe//lib64/libc.so.6:realloc")
int BPF_UPROBE(trace_uprobe_realloc, void *ptr, size_t size) {
    gen_free_enter(ctx, MEMOP_REALLOC_FREE, (u64)ptr);
    return gen_alloc_enter(size);
}

SEC("uretprobe//lib64/libc.so.6:realloc")
int trace_uretprobe_realloc(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx, MEMOP_REALLOC, PT_REGS_RC(ctx));
}

/* Mmap tracking */
SEC("uprobe//lib64/libc.so.6:mmap")
int BPF_UPROBE(trace_uprobe_mmap, void *address, size_t size) {
    return gen_alloc_enter(size);
}

SEC("uretprobe//lib64/libc.so.6:mmap")
int trace_uretprobe_mmap(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx, MEMOP_MMAP, PT_REGS_RC(ctx));
}

/* Munmap tracking */
SEC("uprobe//lib64/libc.so.6:munmap")
int BPF_UPROBE(trace_uprobe_munmap, void *address) {
    return gen_free_enter(ctx, MEMOP_MUNMAP, (u64)address);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
