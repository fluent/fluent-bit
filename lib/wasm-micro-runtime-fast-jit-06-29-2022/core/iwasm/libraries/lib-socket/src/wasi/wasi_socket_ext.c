/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <wasi/api.h>
#include <wasi_socket_ext.h>

#define HANDLE_ERROR(error)              \
    if (error != __WASI_ERRNO_SUCCESS) { \
        errno = error;                   \
        return -1;                       \
    }

/* addr_num and port are in network order */
static void
ipv4_addr_to_wasi_addr(uint32_t addr_num, uint16_t port, __wasi_addr_t *out)
{
    out->kind = IPv4;
    out->addr.ip4.port = ntohs(port);
    out->addr.ip4.addr.n3 = (addr_num & 0xFF000000) >> 24;
    out->addr.ip4.addr.n2 = (addr_num & 0x00FF0000) >> 16;
    out->addr.ip4.addr.n1 = (addr_num & 0x0000FF00) >> 8;
    out->addr.ip4.addr.n0 = (addr_num & 0x000000FF);
}

static __wasi_errno_t
sockaddr_to_wasi_addr(const struct sockaddr *sock_addr, socklen_t addrlen,
                      __wasi_addr_t *wasi_addr)
{
    __wasi_errno_t ret = __WASI_ERRNO_SUCCESS;
    if (AF_INET == sock_addr->sa_family) {
        assert(sizeof(struct sockaddr_in) == addrlen);

        ipv4_addr_to_wasi_addr(
            ((struct sockaddr_in *)sock_addr)->sin_addr.s_addr,
            ((struct sockaddr_in *)sock_addr)->sin_port, wasi_addr);
    }
    else if (AF_INET6 == sock_addr->sa_family) {
        // TODO: IPV6
        ret = __WASI_ERRNO_AFNOSUPPORT;
    }
    else {
        ret = __WASI_ERRNO_AFNOSUPPORT;
    }

    return ret;
}

static __wasi_errno_t
sock_addr_remote(__wasi_fd_t fd, struct sockaddr *sock_addr, socklen_t *addrlen)
{
    __wasi_addr_t wasi_addr = { 0 };
    __wasi_errno_t error;

    error =
        __wasi_sock_addr_remote(fd, (uint8_t *)&wasi_addr, sizeof(wasi_addr));
    if (__WASI_ERRNO_SUCCESS != error) {
        return error;
    }

    if (IPv4 == wasi_addr.kind) {
        struct sockaddr_in sock_addr_in = { 0 };

        sock_addr_in.sin_family = AF_INET;
        sock_addr_in.sin_addr.s_addr = (wasi_addr.addr.ip4.addr.n3 << 24)
                                       | (wasi_addr.addr.ip4.addr.n2 << 16)
                                       | (wasi_addr.addr.ip4.addr.n1 << 8)
                                       | wasi_addr.addr.ip4.addr.n0;
        sock_addr_in.sin_port = htons(wasi_addr.addr.ip4.port);
        memcpy(sock_addr, &sock_addr_in, sizeof(sock_addr_in));

        *addrlen = sizeof(sock_addr_in);
    }
    else if (IPv6 == wasi_addr.kind) {
        // TODO: IPV6
        return __WASI_ERRNO_AFNOSUPPORT;
    }
    else {
        return __WASI_ERRNO_AFNOSUPPORT;
    }

    return __WASI_ERRNO_SUCCESS;
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    __wasi_addr_t wasi_addr = { 0 };
    __wasi_fd_t new_sockfd;
    __wasi_errno_t error;

    error = __wasi_sock_accept(sockfd, &new_sockfd);
    HANDLE_ERROR(error)

    // error = sock_addr_remote(new_sockfd, addr, addrlen);
    // HANDLE_ERROR(error)
    *addrlen = 0;

    return new_sockfd;
}

int
bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    __wasi_addr_t wasi_addr = { 0 };
    __wasi_errno_t error;

    error = sockaddr_to_wasi_addr(addr, addrlen, &wasi_addr);
    HANDLE_ERROR(error)

    error = __wasi_sock_bind(sockfd, &wasi_addr);
    HANDLE_ERROR(error)

    return __WASI_ERRNO_SUCCESS;
}

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    __wasi_addr_t wasi_addr = { 0 };
    __wasi_errno_t error;

    if (NULL == addr) {
        HANDLE_ERROR(__WASI_ERRNO_INVAL)
    }

    error = sockaddr_to_wasi_addr(addr, addrlen, &wasi_addr);
    HANDLE_ERROR(error)

    error = __wasi_sock_connect(sockfd, &wasi_addr);
    HANDLE_ERROR(error)

    return __WASI_ERRNO_SUCCESS;
}

int
listen(int sockfd, int backlog)
{
    __wasi_errno_t error = __wasi_sock_listen(sockfd, backlog);
    HANDLE_ERROR(error)
    return __WASI_ERRNO_SUCCESS;
}

ssize_t
recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    // Prepare input parameters.
    __wasi_iovec_t *ri_data = NULL;
    size_t i = 0;
    size_t ro_datalen = 0;
    __wasi_roflags_t ro_flags = 0;

    if (NULL == msg) {
        HANDLE_ERROR(__WASI_ERRNO_INVAL)
    }

    // Validate flags.
    if (flags != 0) {
        HANDLE_ERROR(__WASI_ERRNO_NOPROTOOPT)
    }

    // __wasi_ciovec_t -> struct iovec
    if (!(ri_data = malloc(sizeof(__wasi_iovec_t) * msg->msg_iovlen))) {
        HANDLE_ERROR(__WASI_ERRNO_NOMEM)
    }

    for (i = 0; i < msg->msg_iovlen; i++) {
        ri_data[i].buf = msg->msg_iov[i].iov_base;
        ri_data[i].buf_len = msg->msg_iov[i].iov_len;
    }

    // Perform system call.
    __wasi_errno_t error = __wasi_sock_recv(sockfd, ri_data, msg->msg_iovlen, 0,
                                            &ro_datalen, &ro_flags);
    free(ri_data);
    HANDLE_ERROR(error)

    return ro_datalen;
}

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    // Prepare input parameters.
    __wasi_ciovec_t *si_data = NULL;
    size_t so_datalen = 0;
    size_t i = 0;

    if (NULL == msg) {
        HANDLE_ERROR(__WASI_ERRNO_INVAL)
    }

    // This implementation does not support any flags.
    if (flags != 0) {
        HANDLE_ERROR(__WASI_ERRNO_NOPROTOOPT)
    }

    // struct iovec -> __wasi_ciovec_t
    if (!(si_data = malloc(sizeof(__wasi_ciovec_t) * msg->msg_iovlen))) {
        HANDLE_ERROR(__WASI_ERRNO_NOMEM)
    }

    for (i = 0; i < msg->msg_iovlen; i++) {
        si_data[i].buf = msg->msg_iov[i].iov_base;
        si_data[i].buf_len = msg->msg_iov[i].iov_len;
    }

    // Perform system call.
    __wasi_errno_t error =
        __wasi_sock_send(sockfd, si_data, msg->msg_iovlen, 0, &so_datalen);
    free(si_data);
    HANDLE_ERROR(error)

    return so_datalen;
}

int
socket(int domain, int type, int protocol)
{
    // the stub of address pool fd
    __wasi_fd_t poolfd = -1;
    __wasi_fd_t sockfd;
    __wasi_errno_t error;
    __wasi_address_family_t af;
    __wasi_sock_type_t socktype;

    if (AF_INET == domain) {
        af = INET4;
    }
    else if (AF_INET6 == domain) {
        af = INET6;
    }
    else {
        return __WASI_ERRNO_NOPROTOOPT;
    }

    if (SOCK_DGRAM == type) {
        socktype = SOCKET_DGRAM;
    }
    else if (SOCK_STREAM == type) {
        socktype = SOCKET_STREAM;
    }
    else {
        return __WASI_ERRNO_NOPROTOOPT;
    }

    error = __wasi_sock_open(poolfd, af, socktype, &sockfd);
    HANDLE_ERROR(error)

    return sockfd;
}
