// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2024 The Inspektor Gadget authors

#ifndef __STACK_MAP_H
#define __STACK_MAP_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

#define KERNEL_STACK_MAP_MAX_ENTRIES	10000

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, KERNEL_STACK_MAP_MAX_ENTRIES);
} ig_kstack SEC(".maps");

/* Returns the kernel stack id, positive or zero on success, negative on failure */
static __always_inline long gadget_get_kernel_stack(void *ctx)
{
	return bpf_get_stackid(ctx, &ig_kstack, BPF_F_FAST_STACK_CMP);
}

#endif /* __STACK_MAP_H */
