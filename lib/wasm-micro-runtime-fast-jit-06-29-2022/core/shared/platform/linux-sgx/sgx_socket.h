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

#define SOL_SOCKET 1

#define SO_TYPE 3
#define SO_LINGER 13

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
#define AF_INET 2 /* IP protocol family.  */

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

int
socket(int domain, int type, int protocol);

int
getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);

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
