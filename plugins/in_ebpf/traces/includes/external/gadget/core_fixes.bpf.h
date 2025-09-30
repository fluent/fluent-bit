/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */

#ifndef __CORE_FIXES_BPF_H
#define __CORE_FIXES_BPF_H

//#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

/**
 * kernel commit 9fdc4273b8da ("libbpf: Fix up verifier log for unguarded
 * failed CO-RE relos") explains the idea of BPF instruction "poisoning" for
 * failed relocations:
 *
 *     While failing CO-RE relocation is expected, it is expected to be
 *     property guarded in BPF code such that BPF verifier always eliminates
 *     BPF instructions corresponding to such failed CO-RE relos as dead code.
 *     In cases when user failed to take such precautions, BPF verifier
 *     provides the best log it can:
 *
 *       123: (85) call unknown#195896080
 *       invalid func unknown#195896080
 *
 *     Such incomprehensible log error is due to libbpf "poisoning" BPF
 *     instruction that corresponds to failed CO-RE relocation by replacing it
 *     with invalid `call 0xbad2310` instruction (195896080 == 0xbad2310 reads
 *     "bad relo" if you squint hard enough).
 *
 * cilium/ebpf uses the same stategy with the same value (0xbad2310).
 *
 *     const badRelo = asm.BuiltinFunc(0xbad2310)
 *
 * bpf_core_unreachable() provides a way to trigger the bpf verifier to reject
 * the program with the same error. This can be used in the following way:
 *
 *     typedef void (*btf_trace_block_rq_insert___new)(void *, struct request *);
 *
 *     if (bpf_core_type_matches(btf_trace_block_rq_issue___new)) {
 *         // After commit a54895fa (v5.11-rc1)
 *         return trace_rq_start((void *)ctx[0], true);
 *     } else {
 *         bpf_core_unreachable();
 *     }
 *
 * See:
 *     https://github.com/torvalds/linux/commit/9fdc4273b8da
 *     https://github.com/cilium/ebpf/commit/b2df9e8f0042
 *     https://github.com/cilium/ebpf/blob/v0.13.2/btf/core.go#L44
 */
static void (*bpf_core_unreachable)(void) = (void *) 0xbad2310;

/**
 * commit 2f064a59a1 ("sched: Change task_struct::state") changes
 * the name of task_struct::state to task_struct::__state
 * see:
 *     https://github.com/torvalds/linux/commit/2f064a59a1
 */
struct task_struct___o {
	volatile long int state;
} __attribute__((preserve_access_index));

struct task_struct___x {
	unsigned int __state;
} __attribute__((preserve_access_index));

static __always_inline __s64 get_task_state(void *task)
{
	struct task_struct___x *t = task;

	if (bpf_core_field_exists(t->__state))
		return BPF_CORE_READ(t, __state);
	return BPF_CORE_READ((struct task_struct___o *)task, state);
}

/**
 * commit 309dca309fc3 ("block: store a block_device pointer in struct bio")
 * adds a new member bi_bdev which is a pointer to struct block_device
 * see:
 *     https://github.com/torvalds/linux/commit/309dca309fc3
 */
struct bio___o {
	struct gendisk *bi_disk;
} __attribute__((preserve_access_index));

struct bio___x {
	struct block_device *bi_bdev;
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_gendisk(void *bio)
{
	struct bio___x *b = bio;

	if (bpf_core_field_exists(b->bi_bdev))
		return BPF_CORE_READ(b, bi_bdev, bd_disk);
	return BPF_CORE_READ((struct bio___o *)bio, bi_disk);
}

/**
 * commit d5869fdc189f ("block: introduce block_rq_error tracepoint")
 * adds a new tracepoint block_rq_error and it shares the same arguments
 * with tracepoint block_rq_complete. As a result, the kernel BTF now has
 * a `struct trace_event_raw_block_rq_completion` instead of
 * `struct trace_event_raw_block_rq_complete`.
 * see:
 *     https://github.com/torvalds/linux/commit/d5869fdc189f
 */
struct trace_event_raw_block_rq_complete___x {
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
} __attribute__((preserve_access_index));

struct trace_event_raw_block_rq_completion___x {
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
} __attribute__((preserve_access_index));

static __always_inline bool has_block_rq_completion()
{
	if (bpf_core_type_exists(
		    struct trace_event_raw_block_rq_completion___x))
		return true;
	return false;
}

/**
 * commit d152c682f03c ("block: add an explicit ->disk backpointer to the
 * request_queue") and commit f3fa33acca9f ("block: remove the ->rq_disk
 * field in struct request") make some changes to `struct request` and
 * `struct request_queue`. Now, to get the `struct gendisk *` field in a CO-RE
 * way, we need both `struct request` and `struct request_queue`.
 * see:
 *     https://github.com/torvalds/linux/commit/d152c682f03c
 *     https://github.com/torvalds/linux/commit/f3fa33acca9f
 */
struct request_queue___x {
	struct gendisk *disk;
} __attribute__((preserve_access_index));

struct request___x {
	struct request_queue___x *q;
	struct gendisk *rq_disk;
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_disk(void *request)
{
	struct request___x *r = request;

	if (bpf_core_field_exists(r->rq_disk))
		return BPF_CORE_READ(r, rq_disk);
	return BPF_CORE_READ(r, q, disk);
}

/**
 * commit 6521f8917082("namei: prepare for idmapped mounts") add `struct
 * user_namespace *mnt_userns` as vfs_create() and vfs_unlink() first argument.
 * At the same time, struct renamedata {} add `struct user_namespace
 * *old_mnt_userns` item. Now, to kprobe vfs_create()/vfs_unlink() in a CO-RE
 * way, determine whether there is a `old_mnt_userns` field for `struct
 * renamedata` to decide which input parameter of the vfs_create() to use as
 * `dentry`.
 * see:
 *     https://github.com/torvalds/linux/commit/6521f8917082
 */
struct renamedata___x {
	struct user_namespace *old_mnt_userns;
} __attribute__((preserve_access_index));

static __always_inline bool renamedata_has_old_mnt_userns_field(void)
{
	if (bpf_core_field_exists(struct renamedata___x, old_mnt_userns))
		return true;
	return false;
}

/**
 * commit 3544de8ee6e4("mm, tracing: record slab name for kmem_cache_free()")
 * replaces `trace_event_raw_kmem_free` with `trace_event_raw_kfree` and adds
 * `tracepoint_kmem_cache_free` to enhance the information recorded for
 * `kmem_cache_free`.
 * see:
 *     https://github.com/torvalds/linux/commit/3544de8ee6e4
 */

struct trace_event_raw_kmem_free___x {
	const void *ptr;
} __attribute__((preserve_access_index));

struct trace_event_raw_kfree___x {
	const void *ptr;
} __attribute__((preserve_access_index));

struct trace_event_raw_kmem_cache_free___x {
	const void *ptr;
} __attribute__((preserve_access_index));

static __always_inline bool has_kfree()
{
	if (bpf_core_type_exists(struct trace_event_raw_kfree___x))
		return true;
	return false;
}

static __always_inline bool has_kmem_cache_free()
{
	if (bpf_core_type_exists(struct trace_event_raw_kmem_cache_free___x))
		return true;
	return false;
}

#endif /* __CORE_FIXES_BPF_H */
