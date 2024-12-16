/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef MNTNS_FILTER_H
#define MNTNS_FILTER_H

#include <gadget/mntns.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

const volatile bool gadget_filter_by_mntns = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, gadget_mntns_id);
	__type(value, __u32);
	__uint(max_entries, 1024);
} gadget_mntns_filter_map SEC(".maps");

// gadget_should_discard_mntns_id returns true if events generated from the given mntns_id should
// not be taken into consideration.
static __always_inline bool gadget_should_discard_mntns_id(gadget_mntns_id mntns_id)
{
	return gadget_filter_by_mntns &&
	       !bpf_map_lookup_elem(&gadget_mntns_filter_map, &mntns_id);
}

#endif
