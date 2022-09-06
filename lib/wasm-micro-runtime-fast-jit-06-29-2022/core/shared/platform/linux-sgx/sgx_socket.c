/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"

#ifndef SGX_DISABLE_WASI

#define TRACE_OCALL_FAIL() os_printf("ocall %s failed!\n", __FUNCTION__)

/** OCALLs prototypes **/
int
ocall_accept(int *p_ret, int sockfd, void *addr, uint32_t *addrlen,
             uint32_t addr_size);

int
ocall_bind(int *p_ret, int sockfd, const void *addr, uint32_t addrlen);

int
ocall_close(int *p_ret, int fd);

int
ocall_connect(int *p_ret, int sockfd, void *addr, uint32_t addrlen);

int
ocall_fcntl_long(int *p_ret, int fd, int cmd, long arg);

int
ocall_getsockname(int *p_ret, int sockfd, void *addr, uint32_t *addrlen,
                  uint32_t addr_size);

int
ocall_getsockopt(int *p_ret, int sockfd, int level, int optname, void *val_buf,
                 unsigned int val_buf_size, void *len_buf);

int
ocall_listen(int *p_ret, int sockfd, int backlog);

int
ocall_recv(int *p_ret, int sockfd, void *buf, size_t len, int flags);

int
ocall_recvmsg(ssize_t *p_ret, int sockfd, void *msg_buf,
              unsigned int msg_buf_size, int flags);

int
ocall_send(int *p_ret, int sockfd, const void *buf, size_t len, int flags);

int
ocall_sendmsg(ssize_t *p_ret, int sockfd, void *msg_buf,
              unsigned int msg_buf_size, int flags);

int
ocall_setsockopt(int *p_ret, int sockfd, int level, int optname, void *optval,
                 unsigned int optlen);

int
ocall_shutdown(int *p_ret, int sockfd, int how);

int
ocall_socket(int *p_ret, int domain, int type, int protocol);
/** OCALLs prototypes end **/

/** In-enclave implementation of POSIX functions **/
static bool
is_little_endian()
{
    long i = 0x01020304;
    unsigned char *c = (unsigned char *)&i;
    return (*c == 0x04) ? true : false;
}

static void
swap32(uint8 *pData)
{
    uint8 value = *pData;
    *pData = *(pData + 3);
    *(pData + 3) = value;

    value = *(pData + 1);
    *(pData + 1) = *(pData + 2);
    *(pData + 2) = value;
}

static void
swap16(uint8 *pData)
{
    uint8 value = *pData;
    *(pData) = *(pData + 1);
    *(pData + 1) = value;
}

static uint32
htonl(uint32 value)
{
    uint32 ret;
    if (is_little_endian()) {
        ret = value;
        swap32((uint8 *)&ret);
        return ret;
    }

    return value;
}

static uint32
ntohl(uint32 value)
{
    return htonl(value);
}

static uint16
htons(uint16 value)
{
    uint16 ret;
    if (is_little_endian()) {
        ret = value;
        swap16((uint8 *)&ret);
        return ret;
    }

    return value;
}

static uint16
ntohs(uint16 value)
{
    return htons(value);
}

/* Coming from musl, under MIT license */
static int
__inet_aton(const char *s0, struct in_addr *dest)
{
    const char *s = s0;
    unsigned char *d = (void *)dest;
    unsigned long a[4] = { 0 };
    char *z;
    int i;

    for (i = 0; i < 4; i++) {
        a[i] = strtoul(s, &z, 0);
        if (z == s || (*z && *z != '.') || !isdigit(*s))
            return 0;
        if (!*z)
            break;
        s = z + 1;
    }
    if (i == 4)
        return 0;
    switch (i) {
        case 0:
            a[1] = a[0] & 0xffffff;
            a[0] >>= 24;
        case 1:
            a[2] = a[1] & 0xffff;
            a[1] >>= 16;
        case 2:
            a[3] = a[2] & 0xff;
            a[2] >>= 8;
    }
    for (i = 0; i < 4; i++) {
        if (a[i] > 255)
            return 0;
        d[i] = a[i];
    }
    return 1;
}

/* Coming from musl, under MIT license */
static int
inet_addr(const char *p)
{
    struct in_addr a;
    if (!__inet_aton(p, &a))
        return -1;
    return a.s_addr;
}

static int
inet_network(const char *p)
{
    return ntohl(inet_addr(p));
}
/** In-enclave implementation of POSIX functions end **/

static int
textual_addr_to_sockaddr(const char *textual, int port, struct sockaddr_in *out)
{
    assert(textual);

    out->sin_family = AF_INET;
    out->sin_port = htons(port);
    out->sin_addr.s_addr = inet_addr(textual);

    return BHT_OK;
}

int
socket(int domain, int type, int protocol)
{
    int ret;

    if (ocall_socket(&ret, domain, type, protocol) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    int ret;
    unsigned int val_buf_size = *optlen;

    if (ocall_getsockopt(&ret, sockfd, level, optname, optval, val_buf_size,
                         (void *)optlen)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

ssize_t
sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    ssize_t ret;
    int i;
    char *p;
    struct msghdr *msg1;

    uint64 total_size = sizeof(struct msghdr) + (uint64)msg->msg_namelen
                        + (uint64)msg->msg_controllen;

    total_size += sizeof(struct iovec) * (msg->msg_iovlen);

    for (i = 0; i < msg->msg_iovlen; i++) {
        total_size += msg->msg_iov[i].iov_len;
    }

    if (total_size >= UINT32_MAX)
        return -1;

    msg1 = BH_MALLOC((uint32)total_size);

    if (msg1 == NULL)
        return -1;

    p = (char *)(uintptr_t)sizeof(struct msghdr);

    if (msg->msg_name != NULL) {
        msg1->msg_name = p;
        memcpy((uintptr_t)p + (char *)msg1, msg->msg_name,
               (size_t)msg->msg_namelen);
        p += msg->msg_namelen;
    }

    if (msg->msg_control != NULL) {
        msg1->msg_control = p;
        memcpy((uintptr_t)p + (char *)msg1, msg->msg_control,
               (size_t)msg->msg_control);
        p += msg->msg_controllen;
    }

    if (msg->msg_iov != NULL) {
        msg1->msg_iov = (struct iovec *)p;
        p += (uintptr_t)(sizeof(struct iovec) * (msg->msg_iovlen));

        for (i = 0; i < msg->msg_iovlen; i++) {
            msg1->msg_iov[i].iov_base = p;
            msg1->msg_iov[i].iov_len = msg->msg_iov[i].iov_len;
            memcpy((uintptr_t)p + (char *)msg1, msg->msg_iov[i].iov_base,
                   (size_t)(msg->msg_iov[i].iov_len));
            p += msg->msg_iov[i].iov_len;
        }
    }

    if (ocall_sendmsg(&ret, sockfd, (void *)msg1, (uint32)total_size, flags)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

ssize_t
recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    ssize_t ret;
    int i;
    char *p;
    struct msghdr *msg1;

    uint64 total_size = sizeof(struct msghdr) + (uint64)msg->msg_namelen
                        + (uint64)msg->msg_controllen;

    total_size += sizeof(struct iovec) * (msg->msg_iovlen);

    for (i = 0; i < msg->msg_iovlen; i++) {
        total_size += msg->msg_iov[i].iov_len;
    }

    if (total_size >= UINT32_MAX)
        return -1;

    msg1 = BH_MALLOC((uint32)total_size);

    if (msg1 == NULL)
        return -1;

    memset(msg1, 0, total_size);

    p = (char *)(uintptr_t)sizeof(struct msghdr);

    if (msg->msg_name != NULL) {
        msg1->msg_name = p;
        p += msg->msg_namelen;
    }

    if (msg->msg_control != NULL) {
        msg1->msg_control = p;
        p += msg->msg_controllen;
    }

    if (msg->msg_iov != NULL) {
        msg1->msg_iov = (struct iovec *)p;
        p += (uintptr_t)(sizeof(struct iovec) * (msg->msg_iovlen));

        for (i = 0; i < msg->msg_iovlen; i++) {
            msg1->msg_iov[i].iov_base = p;
            msg1->msg_iov[i].iov_len = msg->msg_iov[i].iov_len;
            p += msg->msg_iov[i].iov_len;
        }
    }

    if (ocall_recvmsg(&ret, sockfd, (void *)msg1, (uint32)total_size, flags)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    p = (char *)(uintptr_t)(sizeof(struct msghdr));

    if (msg1->msg_name != NULL) {
        memcpy(msg->msg_name, (uintptr_t)p + (char *)msg1,
               (size_t)msg1->msg_namelen);
        p += msg1->msg_namelen;
    }

    if (msg1->msg_control != NULL) {
        memcpy(msg->msg_control, (uintptr_t)p + (char *)msg1,
               (size_t)msg1->msg_control);
        p += msg->msg_controllen;
    }

    if (msg1->msg_iov != NULL) {
        p += (uintptr_t)(sizeof(struct iovec) * (msg1->msg_iovlen));

        for (i = 0; i < msg1->msg_iovlen; i++) {
            memcpy(msg->msg_iov[i].iov_base, (uintptr_t)p + (char *)msg1,
                   (size_t)(msg1->msg_iov[i].iov_len));
            p += msg1->msg_iov[i].iov_len;
        }
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
shutdown(int sockfd, int how)
{
    int ret;

    if (ocall_shutdown(&ret, sockfd, how) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
os_socket_accept(bh_socket_t server_sock, bh_socket_t *sock, void *addr,
                 unsigned int *addrlen)

{
    struct sockaddr addr_tmp;
    unsigned int len = sizeof(struct sockaddr);

    if (ocall_accept(sock, server_sock, &addr_tmp, &len, len) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (*sock < 0) {
        errno = get_errno();
        return BHT_ERROR;
    }

    return BHT_OK;
}
int
os_socket_bind(bh_socket_t socket, const char *host, int *port)
{
    struct sockaddr_in addr;
    struct linger ling;
    unsigned int socklen;
    int ret;

    assert(host);
    assert(port);

    ling.l_onoff = 1;
    ling.l_linger = 0;

    if (ocall_fcntl_long(&ret, socket, F_SETFD, FD_CLOEXEC) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret < 0) {
        goto fail;
    }

    if (ocall_setsockopt(&ret, socket, SOL_SOCKET, SO_LINGER, &ling,
                         sizeof(ling))
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret < 0) {
        goto fail;
    }

    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(*port);
    addr.sin_family = AF_INET;

    if (ocall_bind(&ret, socket, &addr, sizeof(addr)) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret < 0) {
        goto fail;
    }

    socklen = sizeof(addr);

    if (ocall_getsockname(&ret, socket, (void *)&addr, &socklen, socklen)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1) {
        goto fail;
    }

    *port = ntohs(addr.sin_port);

    return BHT_OK;

fail:
    errno = get_errno();
    return BHT_ERROR;
}

int
os_socket_close(bh_socket_t socket)
{
    int ret;

    if (ocall_close(&ret, socket) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
os_socket_connect(bh_socket_t socket, const char *addr, int port)
{
    struct sockaddr_in addr_in = { 0 };
    socklen_t addr_len = sizeof(struct sockaddr_in);
    int ret = 0;

    if ((ret = textual_addr_to_sockaddr(addr, port, &addr_in)) < 0) {
        return ret;
    }

    if (ocall_connect(&ret, socket, &addr_in, addr_len) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
os_socket_create(bh_socket_t *sock, int tcp_or_udp)
{
    if (!sock) {
        return BHT_ERROR;
    }

    if (1 == tcp_or_udp) {
        if (ocall_socket(sock, AF_INET, SOCK_STREAM, IPPROTO_TCP)
            != SGX_SUCCESS) {
            TRACE_OCALL_FAIL();
            return -1;
        }
    }
    else if (0 == tcp_or_udp) {
        if (ocall_socket(sock, AF_INET, SOCK_DGRAM, 0) != SGX_SUCCESS) {
            TRACE_OCALL_FAIL();
            return -1;
        }
    }

    if (*sock == -1) {
        errno = get_errno();
        return BHT_ERROR;
    }

    return BHT_OK;
}

int
os_socket_inet_network(const char *cp, uint32 *out)
{
    if (!cp)
        return BHT_ERROR;

    *out = inet_network(cp);

    return BHT_OK;
}

int
os_socket_listen(bh_socket_t socket, int max_client)
{
    int ret;

    if (ocall_listen(&ret, socket, max_client) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
os_socket_recv(bh_socket_t socket, void *buf, unsigned int len)
{
    int ret;

    if (ocall_recv(&ret, socket, buf, len, 0) != SGX_SUCCESS) {
        errno = ENOSYS;
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
os_socket_send(bh_socket_t socket, const void *buf, unsigned int len)
{
    int ret;

    if (ocall_send(&ret, socket, buf, len, 0) != SGX_SUCCESS) {
        errno = ENOSYS;
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
os_socket_shutdown(bh_socket_t socket)
{
    return shutdown(socket, O_RDWR);
}

#endif
