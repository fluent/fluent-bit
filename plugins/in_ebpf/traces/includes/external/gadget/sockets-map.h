/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef SOCKETS_MAP_H
#define SOCKETS_MAP_H

// The include <bpf/bpf_helpers.h> below requires to include either
// <linux/types.h> or <vmlinux.h> before. We can't include both because they
// are incompatible. Let the gadget choose which one to include.
#if !defined(__VMLINUX_H__) && !defined(_LINUX_TYPES_H)
#error "Include <linux/types.h> or <vmlinux.h> before including this file."
#endif

// Necessary for the SEC() definition
#include <bpf/bpf_helpers.h>

// This file is shared between the networking and tracing programs.
// Therefore, avoid includes that are specific to one of these types of programs.
// For example, don't include <linux/ip.h> nor <vmlinux.h> here.
// Redefine the constants we need but namespaced (SE_) so we don't pollute gadgets.

#define SE_PACKET_HOST 0
#define SE_ETH_HLEN 14
#define SE_ETH_P_IP 0x0800 /* Internet Protocol packet     */
#define SE_ETH_P_IPV6 0x86DD /* IPv6 over bluebook           */
#define SE_AF_INET 2 /* Internet IP Protocol 	*/
#define SE_AF_INET6 10 /* IP version 6                 */

#define SE_IPV6_HLEN 40
#define SE_IPV6_NEXTHDR_OFFSET 6 // offsetof(struct ipv6hdr, nexthdr)

#define SE_TCPHDR_DEST_OFFSET 2 // offsetof(struct tcphdr, dest);
#define SE_TCPHDR_SOURCE_OFFSET 0 // offsetof(struct tcphdr, source);
#define SE_UDPHDR_DEST_OFFSET 2 // offsetof(struct udphdr, dest);
#define SE_UDPHDR_SOURCE_OFFSET 0 // offsetof(struct udphdr, source);

#define SE_NEXTHDR_HOP 0 /* Hop-by-hop option header. */
#define SE_NEXTHDR_TCP 6 /* TCP segment. */
#define SE_NEXTHDR_UDP 17 /* UDP message. */
#define SE_NEXTHDR_ROUTING 43 /* Routing header. */
#define SE_NEXTHDR_FRAGMENT 44 /* Fragmentation/reassembly header. */
#define SE_NEXTHDR_AUTH 51 /* Authentication header. */
#define SE_NEXTHDR_NONE 59 /* No next header */
#define SE_NEXTHDR_DEST 60 /* Destination options header. */

#define SE_TASK_COMM_LEN 16
#define SE_PATH_MAX 4096

struct sockets_key {
	__u32 netns;
	__u16 family;

	// proto is IPPROTO_TCP(6) or IPPROTO_UDP(17)
	__u8 proto;
	__u16 port;
};

struct sockets_value {
	__u64 mntns;
	__u64 pid_tgid;
	__u64 uid_gid;
	char task[SE_TASK_COMM_LEN];
	char ptask[SE_TASK_COMM_LEN];
	__u64 sock;
	__u64 deletion_timestamp;
	char cwd[SE_PATH_MAX];
	char exepath[SE_PATH_MAX];
	__u32 ppid;
	char ipv6only;
};

#define MAX_SOCKETS 16384
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SOCKETS);
	__type(key, struct sockets_key);
	__type(value, struct sockets_value);
} gadget_sockets SEC(".maps");

#ifdef GADGET_TYPE_NETWORKING
static __always_inline struct sockets_value *
gadget_socket_lookup(const struct __sk_buff *skb)
{
	struct sockets_value *ret;
	struct sockets_key key = {
		0,
	};
	int l4_off;
	__u16 h_proto;
	int i;
	long err;

	key.netns = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
	err = bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto),
				 &h_proto, sizeof(h_proto));
	if (err < 0)
		return 0;

	switch (h_proto) {
	case bpf_htons(SE_ETH_P_IP):
		key.family = SE_AF_INET;
		err = bpf_skb_load_bytes(
			skb, SE_ETH_HLEN + offsetof(struct iphdr, protocol),
			&key.proto, sizeof(key.proto));
		if (err < 0)
			return 0;

		// An IPv4 header doesn't have a fixed size. The IHL field of a packet
		// represents the size of the IP header in 32-bit words, so we need to
		// multiply this value by 4 to get the header size in bytes.
		__u8 ihl_byte;
		err = bpf_skb_load_bytes(skb, SE_ETH_HLEN, &ihl_byte,
					 sizeof(ihl_byte));
		if (err < 0)
			return 0;
		struct iphdr *iph = (struct iphdr *)&ihl_byte;
		__u8 ip_header_len = iph->ihl * 4;
		l4_off = SE_ETH_HLEN + ip_header_len;
		break;

	case bpf_htons(SE_ETH_P_IPV6):
		key.family = SE_AF_INET6;
		err = bpf_skb_load_bytes(
			skb, SE_ETH_HLEN + SE_IPV6_NEXTHDR_OFFSET,
			&key.proto, sizeof(key.proto));
		if (err < 0)
			return 0;
		l4_off = SE_ETH_HLEN + SE_IPV6_HLEN;

// Parse IPv6 extension headers
// Up to 6 extension headers can be chained. See ipv6_ext_hdr().
#pragma unroll
		for (i = 0; i < 6; i++) {
			__u8 nextproto;
			__u8 off;

			// TCP or UDP found
			if (key.proto == SE_NEXTHDR_TCP ||
			    key.proto == SE_NEXTHDR_UDP)
				break;

			err = bpf_skb_load_bytes(skb, l4_off, &nextproto,
						 sizeof(nextproto));
			if (err < 0)
				return 0;

			// Unfortunately, each extension header has a different way to calculate the header length.
			// Support the ones defined in ipv6_ext_hdr(). See ipv6_skip_exthdr().
			switch (key.proto) {
			case SE_NEXTHDR_FRAGMENT:
				// No hdrlen in the fragment header
				l4_off += 8;
				break;
			case SE_NEXTHDR_AUTH:
				// See ipv6_authlen()
				err = bpf_skb_load_bytes(skb, l4_off + 1, &off,
							 sizeof(off));
				if (err < 0)
					return 0;
				l4_off += 4 * (off + 2);
				break;
			case SE_NEXTHDR_HOP:
			case SE_NEXTHDR_ROUTING:
			case SE_NEXTHDR_DEST:
				// See ipv6_optlen()
				err = bpf_skb_load_bytes(skb, l4_off + 1, &off,
							 sizeof(off));
				if (err < 0)
					return 0;
				l4_off += 8 * (off + 1);
				break;
			case SE_NEXTHDR_NONE:
				// Nothing more in the packet. Not even TCP or UDP.
				return 0;
			default:
				// Unknown header
				return 0;
			}
			key.proto = nextproto;
		}
		break;

	default:
		return 0;
	}

	int off = l4_off;
	switch (key.proto) {
	case IPPROTO_TCP:
		if (skb->pkt_type == SE_PACKET_HOST)
			off += SE_TCPHDR_DEST_OFFSET;
		else
			off += SE_TCPHDR_SOURCE_OFFSET;
		break;
	case IPPROTO_UDP:
		if (skb->pkt_type == SE_PACKET_HOST)
			off += SE_UDPHDR_DEST_OFFSET;
		else
			off += SE_UDPHDR_SOURCE_OFFSET;
		break;
	default:
		return 0;
	}

	err = bpf_skb_load_bytes(skb, off, &key.port, sizeof(key.port));
	if (err < 0)
		return 0;
	key.port = bpf_ntohs(key.port);

	ret = bpf_map_lookup_elem(&gadget_sockets, &key);
	if (ret)
		return ret;

	// If a native socket was not found, try to find a dual-stack socket.
	if (key.family == SE_AF_INET) {
		key.family = SE_AF_INET6;
		ret = bpf_map_lookup_elem(&gadget_sockets, &key);
		if (ret && ret->ipv6only == 0)
			return ret;
	}

	return 0;
}
#endif

#ifdef GADGET_TYPE_TRACING
static __always_inline struct sockets_value *
gadget_socket_lookup(const struct sock *sk, __u32 netns)
{
	struct sockets_key key = {
		0,
	};
	key.netns = netns;
	key.family = BPF_CORE_READ(sk, __sk_common.skc_family);
	key.proto = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
	if (key.proto != IPPROTO_TCP && key.proto != IPPROTO_UDP)
		return 0;

	BPF_CORE_READ_INTO(&key.port, sk, __sk_common.skc_dport);
	struct inet_sock *sockp = (struct inet_sock *)sk;
	BPF_CORE_READ_INTO(&key.port, sockp, inet_sport);
	// inet_sock.inet_sport is in network byte order
	key.port = bpf_ntohs(key.port);

	return bpf_map_lookup_elem(&gadget_sockets, &key);
}
#endif

#endif
