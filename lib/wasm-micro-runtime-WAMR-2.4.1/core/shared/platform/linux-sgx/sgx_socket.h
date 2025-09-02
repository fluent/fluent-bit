/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _SGX_SOCKET_H
#define _SGX_SOCKET_H

#include "sgx_file.h"

#ifdef __cplusplus
extern "C" {
#endif

/* For setsockopt(2) */
#define SOL_SOCKET 1

#define SO_DEBUG 1
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_DONTROUTE 5
#define SO_BROADCAST 6
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_SNDBUFFORCE 32
#define SO_RCVBUFFORCE 33
#define SO_KEEPALIVE 9
#define SO_OOBINLINE 10
#define SO_NO_CHECK 11
#define SO_PRIORITY 12
#define SO_LINGER 13
#define SO_BSDCOMPAT 14
#define SO_REUSEPORT 15
#define SO_PASSCRED 16
#define SO_PEERCRED 17
#define SO_RCVLOWAT 18
#define SO_SNDLOWAT 19
#define SO_RCVTIMEO_OLD 20
#define SO_SNDTIMEO_OLD 21

/* User-settable options (used with setsockopt) */
#define TCP_NODELAY 1               /* Don't delay send to coalesce packets  */
#define TCP_MAXSEG 2                /* Set maximum segment size  */
#define TCP_CORK 3                  /* Control sending of partial frames  */
#define TCP_KEEPIDLE 4              /* Start keeplives after this period */
#define TCP_KEEPINTVL 5             /* Interval between keepalives */
#define TCP_KEEPCNT 6               /* Number of keepalives before death */
#define TCP_SYNCNT 7                /* Number of SYN retransmits */
#define TCP_LINGER2 8               /* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT 9          /* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP 10         /* Bound advertised window */
#define TCP_INFO 11                 /* Information about this connection. */
#define TCP_QUICKACK 12             /* Bock/re-enable quick ACKs.  */
#define TCP_CONGESTION 13           /* Congestion control algorithm.  */
#define TCP_MD5SIG 14               /* TCP MD5 Signature (RFC2385) */
#define TCP_COOKIE_TRANSACTIONS 15  /* TCP Cookie Transactions */
#define TCP_THIN_LINEAR_TIMEOUTS 16 /* Use linear timeouts for thin streams*/
#define TCP_THIN_DUPACK 17          /* Fast retrans. after 1 dupack */
#define TCP_USER_TIMEOUT 18         /* How long for loss retry before timeout */
#define TCP_REPAIR 19               /* TCP sock is under repair right now */
#define TCP_REPAIR_QUEUE 20         /* Set TCP queue to repair */
#define TCP_QUEUE_SEQ 21            /* Set sequence number of repaired queue. */
#define TCP_REPAIR_OPTIONS 22       /* Repair TCP connection options */
#define TCP_FASTOPEN 23             /* Enable FastOpen on listeners */
#define TCP_TIMESTAMP 24            /* TCP time stamp */
#define TCP_NOTSENT_LOWAT                                                    \
    25                       /* Limit number of unsent bytes in write queue. \
                              */
#define TCP_CC_INFO 26       /* Get Congestion Control (optional) info.  */
#define TCP_SAVE_SYN 27      /* Record SYN headers for new connections.  */
#define TCP_SAVED_SYN 28     /* Get SYN headers recorded for connection.  */
#define TCP_REPAIR_WINDOW 29 /* Get/set window parameters.  */
#define TCP_FASTOPEN_CONNECT 30   /* Attempt FastOpen with connect.  */
#define TCP_ULP 31                /* Attach a ULP to a TCP connection.  */
#define TCP_MD5SIG_EXT 32         /* TCP MD5 Signature with extensions.  */
#define TCP_FASTOPEN_KEY 33       /* Set the key for Fast Open (cookie).  */
#define TCP_FASTOPEN_NO_COOKIE 34 /* Enable TFO without a TFO cookie.  */
#define TCP_ZEROCOPY_RECEIVE 35
#define TCP_INQ 36 /* Notify bytes available to read as a cmsg on read.  */
#define TCP_CM_INQ TCP_INQ
#define TCP_TX_DELAY 37 /* Delay outgoing packets by XX usec.  */

/* Standard well-defined IP protocols.  */
#define IPPROTO_IP 0        /* Dummy protocol for TCP.  */
#define IPPROTO_ICMP 1      /* Internet Control Message Protocol.  */
#define IPPROTO_IGMP 2      /* Internet Group Management Protocol. */
#define IPPROTO_IPIP 4      /* IPIP tunnels (older KA9Q tunnels use 94).  */
#define IPPROTO_TCP 6       /* Transmission Control Protocol.  */
#define IPPROTO_EGP 8       /* Exterior Gateway Protocol.  */
#define IPPROTO_PUP 12      /* PUP protocol.  */
#define IPPROTO_UDP 17      /* User Datagram Protocol.  */
#define IPPROTO_IDP 22      /* XNS IDP protocol.  */
#define IPPROTO_TP 29       /* SO Transport Protocol Class 4.  */
#define IPPROTO_DCCP 33     /* Datagram Congestion Control Protocol.  */
#define IPPROTO_IPV6 41     /* IPv6 header.  */
#define IPPROTO_RSVP 46     /* Reservation Protocol.  */
#define IPPROTO_GRE 47      /* General Routing Encapsulation.  */
#define IPPROTO_ESP 50      /* encapsulating security payload.  */
#define IPPROTO_AH 51       /* authentication header.  */
#define IPPROTO_MTP 92      /* Multicast Transport Protocol.  */
#define IPPROTO_BEETPH 94   /* IP option pseudo header for BEET.  */
#define IPPROTO_ENCAP 98    /* Encapsulation Header.  */
#define IPPROTO_PIM 103     /* Protocol Independent Multicast.  */
#define IPPROTO_COMP 108    /* Compression Header Protocol.  */
#define IPPROTO_SCTP 132    /* Stream Control Transmission Protocol.  */
#define IPPROTO_UDPLITE 136 /* UDP-Lite protocol.  */
#define IPPROTO_MPLS 137    /* MPLS in IP.  */
#define IPPROTO_RAW 255     /* Raw IP packets.  */

#define IP_ROUTER_ALERT 5 /* bool */
#define IP_PKTINFO 8      /* bool */
#define IP_PKTOPTIONS 9
#define IP_PMTUDISC 10     /* obsolete name? */
#define IP_MTU_DISCOVER 10 /* int; see below */
#define IP_RECVERR 11      /* bool */
#define IP_RECVTTL 12      /* bool */
#define IP_RECVTOS 13      /* bool */
#define IP_MTU 14          /* int */
#define IP_FREEBIND 15
#define IP_IPSEC_POLICY 16
#define IP_XFRM_POLICY 17
#define IP_PASSSEC 18
#define IP_TRANSPARENT 19
#define IP_MULTICAST_ALL 49 /* bool */

/* TProxy original addresses */
#define IP_ORIGDSTADDR 20
#define IP_RECVORIGDSTADDR IP_ORIGDSTADDR
#define IP_MINTTL 21
#define IP_NODEFRAG 22
#define IP_CHECKSUM 23
#define IP_BIND_ADDRESS_NO_PORT 24
#define IP_RECVFRAGSIZE 25
#define IP_PMTUDISC_DONT 0
#define IP_PMTUDISC_WANT 1
#define IP_PMTUDISC_DO 2
#define IP_PMTUDISC_PROBE 3
#define IP_PMTUDISC_INTERFACE 4
#define IP_PMTUDISC_OMIT 5
#define IP_MULTICAST_IF 32
#define IP_MULTICAST_TTL 33
#define IP_MULTICAST_LOOP 34
#define IP_ADD_MEMBERSHIP 35
#define IP_DROP_MEMBERSHIP 36
#define IP_UNBLOCK_SOURCE 37
#define IP_BLOCK_SOURCE 38
#define IP_ADD_SOURCE_MEMBERSHIP 39
#define IP_DROP_SOURCE_MEMBERSHIP 40
#define IP_MSFILTER 41
#define IP_MULTICAST_ALL 49
#define IP_UNICAST_IF 50

#define IPV6_ADDRFORM 1
#define IPV6_2292PKTINFO 2
#define IPV6_2292HOPOPTS 3
#define IPV6_2292DSTOPTS 4
#define IPV6_2292RTHDR 5
#define IPV6_2292PKTOPTIONS 6
#define IPV6_CHECKSUM 7
#define IPV6_2292HOPLIMIT 8

#define SCM_SRCRT IPV6_RXSRCRT

#define IPV6_NEXTHOP 9
#define IPV6_AUTHHDR 10
#define IPV6_UNICAST_HOPS 16
#define IPV6_MULTICAST_IF 17
#define IPV6_MULTICAST_HOPS 18
#define IPV6_MULTICAST_LOOP 19
#define IPV6_JOIN_GROUP 20
#define IPV6_LEAVE_GROUP 21
#define IPV6_ROUTER_ALERT 22
#define IPV6_MTU_DISCOVER 23
#define IPV6_MTU 24
#define IPV6_RECVERR 25
#define IPV6_V6ONLY 26
#define IPV6_JOIN_ANYCAST 27
#define IPV6_LEAVE_ANYCAST 28
#define IPV6_MULTICAST_ALL 29
#define IPV6_ROUTER_ALERT_ISOLATE 30
#define IPV6_IPSEC_POLICY 34
#define IPV6_XFRM_POLICY 35
#define IPV6_HDRINCL 36

/* Advanced API (RFC3542) (1).  */
#define IPV6_RECVPKTINFO 49
#define IPV6_PKTINFO 50
#define IPV6_RECVHOPLIMIT 51
#define IPV6_HOPLIMIT 52
#define IPV6_RECVHOPOPTS 53
#define IPV6_HOPOPTS 54
#define IPV6_RTHDRDSTOPTS 55
#define IPV6_RECVRTHDR 56
#define IPV6_RTHDR 57
#define IPV6_RECVDSTOPTS 58
#define IPV6_DSTOPTS 59
#define IPV6_RECVPATHMTU 60
#define IPV6_PATHMTU 61
#define IPV6_DONTFRAG 62

/* Advanced API (RFC3542) (2).  */
#define IPV6_RECVTCLASS 66
#define IPV6_TCLASS 67

#define IPV6_AUTOFLOWLABEL 70

/* RFC5014.  */
#define IPV6_ADDR_PREFERENCES 72

/* RFC5082.  */
#define IPV6_MINHOPCOUNT 73

#define IPV6_ORIGDSTADDR 74
#define IPV6_RECVORIGDSTADDR IPV6_ORIGDSTADDR
#define IPV6_TRANSPARENT 75
#define IPV6_UNICAST_IF 76
#define IPV6_RECVFRAGSIZE 77
#define IPV6_FREEBIND 78

#define SOCK_STREAM 1
#define SOCK_DGRAM 2

#define MSG_OOB 0x0001
#define MSG_PEEK 0x0002
#define MSG_DONTROUTE 0x0004
#define MSG_CTRUNC 0x0008
#define MSG_PROXY 0x0010
#define MSG_TRUNC 0x0020
#define MSG_DONTWAIT 0x0040
#define MSG_EOR 0x0080
#define MSG_WAITALL 0x0100
#define MSG_FIN 0x0200
#define MSG_SYN 0x0400
#define MSG_CONFIRM 0x0800
#define MSG_RST 0x1000
#define MSG_ERRQUEUE 0x2000
#define MSG_NOSIGNAL 0x4000
#define MSG_MORE 0x8000
#define MSG_WAITFORONE 0x10000
#define MSG_BATCH 0x40000
#define MSG_FASTOPEN 0x20000000
#define MSG_CMSG_CLOEXEC 0x40000000

#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2

/* Address families.  */
#define AF_INET 2   /* IP protocol family.  */
#define AF_INET6 10 /* IP version 6.  */

/* Standard well-defined IP protocols.  */
#define IPPROTO_TCP 6 /* Transmission Control Protocol.  */

/* Types of sockets.  */
#define SOCK_DGRAM \
    2 /* Connectionless, unreliable datagrams of fixed maximum length.  */

struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    int msg_iovlen;
    void *msg_control;
    socklen_t msg_controllen;
    int msg_flags;
};

/* Internet address.  */
struct in_addr {
    uint32_t s_addr;
};
typedef struct in_addr in_addr_t;

/* Structure describing an Internet socket address.  */
#define __SOCK_SIZE__ 16 /* sizeof(struct sockaddr)	*/
struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;       /* Port number.  */
    struct in_addr sin_addr; /* Internet address.  */

    /* Pad to size of `struct sockaddr'. */
    unsigned char__pad[__SOCK_SIZE__ - sizeof(uint16_t) - sizeof(uint16_t)
                       - sizeof(struct in_addr)];
};

/* Structure used to manipulate the SO_LINGER option.  */
struct linger {
    int l_onoff;  /* Nonzero to linger on close.  */
    int l_linger; /* Time to linger.  */
};

/* Structure describing a generic socket address.  */
struct sockaddr {
    unsigned short int sa_family; /* Common data: address family and length.  */
    char sa_data[14];             /* Address data.  */
};

uint32_t
ntohl(uint32_t value);

uint32_t
htonl(uint32_t value);

uint16_t
htons(uint16_t value);

int
socket(int domain, int type, int protocol);

int
getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);

int
setsockopt(int sockfd, int level, int optname, const void *optval,
           socklen_t optlen);

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags);

ssize_t
recvmsg(int sockfd, struct msghdr *msg, int flags);

int
shutdown(int sockfd, int how);

#ifdef __cplusplus
}
#endif

#endif /* end of _SGX_SOCKET_H */
