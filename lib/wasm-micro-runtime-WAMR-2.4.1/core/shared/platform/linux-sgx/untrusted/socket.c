/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int
ocall_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

int
ocall_getsockopt(int sockfd, int level, int optname, void *val_buf,
                 unsigned int val_buf_size, void *len_buf)
{
    return getsockopt(sockfd, level, optname, val_buf, (socklen_t *)len_buf);
}

ssize_t
ocall_sendmsg(int sockfd, void *msg_buf, unsigned int msg_buf_size, int flags)
{
    struct msghdr *msg = (struct msghdr *)msg_buf;
    int i;
    ssize_t ret;

    if (msg->msg_name != NULL)
        msg->msg_name = msg_buf + (unsigned)(uintptr_t)msg->msg_name;

    if (msg->msg_control != NULL)
        msg->msg_control = msg_buf + (unsigned)(uintptr_t)msg->msg_control;

    if (msg->msg_iov != NULL) {
        msg->msg_iov = msg_buf + (unsigned)(uintptr_t)msg->msg_iov;
        for (i = 0; i < msg->msg_iovlen; i++) {
            msg->msg_iov[i].iov_base =
                msg_buf + (unsigned)(uintptr_t)msg->msg_iov[i].iov_base;
        }
    }

    return sendmsg(sockfd, msg, flags);
}

ssize_t
ocall_recvmsg(int sockfd, void *msg_buf, unsigned int msg_buf_size, int flags)
{
    struct msghdr *msg = (struct msghdr *)msg_buf;
    int i;
    ssize_t ret;

    if (msg->msg_name != NULL)
        msg->msg_name = msg_buf + (unsigned)(uintptr_t)msg->msg_name;

    if (msg->msg_control != NULL)
        msg->msg_control = msg_buf + (unsigned)(uintptr_t)msg->msg_control;

    if (msg->msg_iov != NULL) {
        msg->msg_iov = msg_buf + (unsigned)(uintptr_t)msg->msg_iov;
        for (i = 0; i < msg->msg_iovlen; i++) {
            msg->msg_iov[i].iov_base =
                msg_buf + (unsigned)(uintptr_t)msg->msg_iov[i].iov_base;
        }
    }

    return recvmsg(sockfd, msg, flags);
}

int
ocall_shutdown(int sockfd, int how)
{
    return shutdown(sockfd, how);
}

int
ocall_setsockopt(int sockfd, int level, int optname, void *optval,
                 unsigned int optlen)
{
    return setsockopt(sockfd, level, optname, optval, optlen);
}

int
ocall_bind(int sockfd, const void *addr, uint32_t addrlen)
{
    return bind(sockfd, (const struct sockaddr *)addr, addrlen);
}

int
ocall_getsockname(int sockfd, void *addr, uint32_t *addrlen, uint32_t addr_size)
{
    return getsockname(sockfd, (struct sockaddr *)addr, addrlen);
}

int
ocall_getpeername(int sockfd, void *addr, uint32_t *addrlen, uint32_t addr_size)
{
    return getpeername(sockfd, (struct sockaddr *)addr, addrlen);
}

int
ocall_listen(int sockfd, int backlog)
{
    return listen(sockfd, backlog);
}

int
ocall_accept(int sockfd, void *addr, uint32_t *addrlen, uint32_t addr_size)
{
    return accept(sockfd, (struct sockaddr *)addr, addrlen);
}

int
ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
    return recv(sockfd, buf, len, flags);
}

ssize_t
ocall_recvfrom(int sockfd, void *buf, size_t len, int flags, void *src_addr,
               uint32_t *addrlen, uint32_t addr_size)
{
    return recvfrom(sockfd, buf, len, flags, (struct sockaddr *)src_addr,
                    addrlen);
}

int
ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
    return send(sockfd, buf, len, flags);
}

ssize_t
ocall_sendto(int sockfd, const void *buf, size_t len, int flags,
             void *dest_addr, uint32_t addrlen)
{
    return sendto(sockfd, buf, len, flags, (struct sockaddr *)dest_addr,
                  addrlen);
}

int
ocall_connect(int sockfd, void *addr, uint32_t addrlen)
{
    return connect(sockfd, (const struct sockaddr *)addr, addrlen);
}