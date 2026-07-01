/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __TYPES_H
#define __TYPES_H

// Keep these types aligned with definitions in pkg/gadgets/run/tracer/tracer.go.

// union defining either an IPv4 or IPv6 address
union gadget_ip_addr_t {
	__u8 v6[16];
	__u32 v4;
};

// struct defining either an IPv4 or IPv6 L3 endpoint
struct gadget_l3endpoint_t {
	union gadget_ip_addr_t addr_raw;
	__u8 version; // 4 or 6
};

// struct defining an L4 endpoint
struct gadget_l4endpoint_t {
	union gadget_ip_addr_t addr_raw;
	__u16 port; // L4 port in host byte order
	__u16 proto; // IP protocol number
	__u8 version; // 4 or 6
};

// Inode id of a mount namespace. It's used to enrich the event in user space
typedef __u64 gadget_mntns_id;

// Inode id of a network namespace. It's used to enrich the event in user space
typedef __u32 gadget_netns_id;

// gadget_timestamp is a type that represents the nanoseconds since the system boot. Gadgets can use
// this type to provide a timestamp. The value contained must be the one returned by
// bpf_ktime_get_boot_ns() and it's automatically converted by Inspektor Gadget to a human friendly
// time.
typedef __u64 gadget_timestamp;

// gadget_signal is used to represent a unix signal. A field is automatically added that contains the name
// as string.
typedef __u32 gadget_signal;

// gadget_errno is used to represent a unix errno. A field is automatically added that contains the name
// as string.
typedef __u32 gadget_errno;

// gadget_uid is used to represent a uid. A field is automatically added that contains the corresponding user
// name on the host system
typedef __u32 gadget_uid;

// gadget_gid is used to represent a uid. A field is automatically added that contains the corresponding group
// name on the host system
typedef __u32 gadget_gid;

// gadget_syscall is used to represent a unix syscall. A field is automatically added that contains the name
// as string.
typedef __u64 gadget_syscall;

typedef __u32 gadget_kernel_stack;

// typedefs used for metrics
typedef __u32 gadget_counter__u32;
typedef __u64 gadget_counter__u64;
typedef __u32 gadget_gauge__u32;
typedef __u64 gadget_gauge__u64;
typedef __u32 gadget_histogram_slot__u32;
typedef __u64 gadget_histogram_slot__u64;

#endif /* __TYPES_H */
