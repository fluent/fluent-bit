#ifndef EBPF_EVENT_ID_H
#define EBPF_EVENT_ID_H

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} seq_counter SEC(".maps");

static __always_inline void generate_event_id(__u64 *event_id)
{
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&seq_counter, &key);
    if (counter) {
        /* ID is CPU shifted left by 48 bits, OR'd with per-CPU counter */
        *event_id = ((__u64)bpf_get_smp_processor_id() << 48) | (*counter);
        (*counter)++;
    }
    else {
        *event_id = 0;
    }
}

#endif /* EBPF_EVENT_ID_H */
