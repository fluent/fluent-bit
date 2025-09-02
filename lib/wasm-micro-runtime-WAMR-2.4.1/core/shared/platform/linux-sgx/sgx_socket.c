/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

#ifndef SGX_DISABLE_WASI

#include "libc_errno.h"

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
ocall_getpeername(int *p_ret, int sockfd, void *addr, uint32_t *addrlen,
                  uint32_t addr_size);

int
ocall_getsockopt(int *p_ret, int sockfd, int level, int optname, void *val_buf,
                 unsigned int val_buf_size, void *len_buf);

int
ocall_listen(int *p_ret, int sockfd, int backlog);

int
ocall_recv(int *p_ret, int sockfd, void *buf, size_t len, int flags);

int
ocall_recvfrom(ssize_t *p_ret, int sockfd, void *buf, size_t len, int flags,
               void *src_addr, uint32_t *addrlen, uint32_t addr_size);

int
ocall_recvmsg(ssize_t *p_ret, int sockfd, void *msg_buf,
              unsigned int msg_buf_size, int flags);

int
ocall_send(int *p_ret, int sockfd, const void *buf, size_t len, int flags);

int
ocall_sendto(ssize_t *p_ret, int sockfd, const void *buf, size_t len, int flags,
             void *dest_addr, uint32_t addrlen);

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

uint32
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

uint32
ntohl(uint32 value)
{
    return htonl(value);
}

uint16
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
hexval(unsigned c)
{
    if (c - '0' < 10)
        return c - '0';
    c |= 32;
    if (c - 'a' < 6)
        return c - 'a' + 10;
    return -1;
}

/* Coming from musl, under MIT license */
static int
inet_pton(int af, const char *restrict s, void *restrict a0)
{
    uint16_t ip[8];
    unsigned char *a = a0;
    int i, j, v, d, brk = -1, need_v4 = 0;

    if (af == AF_INET) {
        for (i = 0; i < 4; i++) {
            for (v = j = 0; j < 3 && isdigit(s[j]); j++)
                v = 10 * v + s[j] - '0';
            if (j == 0 || (j > 1 && s[0] == '0') || v > 255)
                return 0;
            a[i] = v;
            if (s[j] == 0 && i == 3)
                return 1;
            if (s[j] != '.')
                return 0;
            s += j + 1;
        }
        return 0;
    }
    else if (af != AF_INET6) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (*s == ':' && *++s != ':')
        return 0;

    for (i = 0;; i++) {
        if (s[0] == ':' && brk < 0) {
            brk = i;
            ip[i & 7] = 0;
            if (!*++s)
                break;
            if (i == 7)
                return 0;
            continue;
        }
        for (v = j = 0; j < 4 && (d = hexval(s[j])) >= 0; j++)
            v = 16 * v + d;
        if (j == 0)
            return 0;
        ip[i & 7] = v;
        if (!s[j] && (brk >= 0 || i == 7))
            break;
        if (i == 7)
            return 0;
        if (s[j] != ':') {
            if (s[j] != '.' || (i < 6 && brk < 0))
                return 0;
            need_v4 = 1;
            i++;
            break;
        }
        s += j + 1;
    }
    if (brk >= 0) {
        memmove(ip + brk + 7 - i, ip + brk, 2 * (i + 1 - brk));
        for (j = 0; j < 7 - i; j++)
            ip[brk + j] = 0;
    }
    for (j = 0; j < 8; j++) {
        *a++ = ip[j] >> 8;
        *a++ = ip[j];
    }
    if (need_v4 && inet_pton(AF_INET, (void *)s, a - 4) <= 0)
        return 0;
    return 1;
}

static int
inet_addr(const char *p)
{
    struct in_addr a;
    if (!inet_pton(AF_INET, p, &a))
        return -1;
    return a.s_addr;
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

static int
sockaddr_to_bh_sockaddr(const struct sockaddr *sockaddr, socklen_t socklen,
                        bh_sockaddr_t *bh_sockaddr)
{
    switch (sockaddr->sa_family) {
        case AF_INET:
        {
            struct sockaddr_in *addr = (struct sockaddr_in *)sockaddr;

            assert(socklen >= sizeof(struct sockaddr_in));

            bh_sockaddr->port = ntohs(addr->sin_port);
            bh_sockaddr->addr_buffer.ipv4 = ntohl(addr->sin_addr.s_addr);
            bh_sockaddr->is_ipv4 = true;
            return BHT_OK;
        }
        default:
            errno = EAFNOSUPPORT;
            return BHT_ERROR;
    }
}

static int
bh_sockaddr_to_sockaddr(const bh_sockaddr_t *bh_sockaddr,
                        struct sockaddr *sockaddr, socklen_t *socklen)
{
    if (bh_sockaddr->is_ipv4) {
        struct sockaddr_in *addr = (struct sockaddr_in *)sockaddr;
        addr->sin_port = htons(bh_sockaddr->port);
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = htonl(bh_sockaddr->addr_buffer.ipv4);
        *socklen = sizeof(*addr);
        return BHT_OK;
    }
    else {
        errno = EAFNOSUPPORT;
        return BHT_ERROR;
    }
}

static int
os_socket_setbooloption(bh_socket_t socket, int level, int optname,
                        bool is_enabled)
{
    int option = (int)is_enabled;
    int ret;

    if (ocall_setsockopt(&ret, socket, level, optname, &option, sizeof(option))
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return BHT_ERROR;
    }

    if (ret != 0) {
        errno = get_errno();
        return BHT_ERROR;
    }

    return BHT_OK;
}

static int
os_socket_getbooloption(bh_socket_t socket, int level, int optname,
                        bool *is_enabled)
{
    assert(is_enabled);

    int optval;
    socklen_t optval_size = sizeof(optval);
    int ret;
    if (ocall_getsockopt(&ret, socket, level, optname, &optval, optval_size,
                         &optval_size)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return BHT_ERROR;
    }

    if (ret != 0) {
        errno = get_errno();
        return BHT_ERROR;
    }

    *is_enabled = (bool)optval;
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

int
setsockopt(int sockfd, int level, int optname, const void *optval,
           socklen_t optlen)
{
    int ret;

    if (ocall_setsockopt(&ret, sockfd, level, optname, (void *)optval, optlen)
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
os_socket_create(bh_socket_t *sock, bool is_ipv4, bool is_tcp)
{
    int af;

    if (!sock) {
        return BHT_ERROR;
    }

    if (is_ipv4) {
        af = AF_INET;
    }
    else {
        errno = ENOSYS;
        return BHT_ERROR;
    }

    if (is_tcp) {
        if (ocall_socket(sock, af, SOCK_STREAM, IPPROTO_TCP) != SGX_SUCCESS) {
            TRACE_OCALL_FAIL();
            return -1;
        }
    }
    else {
        if (ocall_socket(sock, af, SOCK_DGRAM, 0) != SGX_SUCCESS) {
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
os_socket_inet_network(bool is_ipv4, const char *cp, bh_ip_addr_buffer_t *out)
{
    if (!cp)
        return BHT_ERROR;

    if (is_ipv4) {
        if (inet_pton(AF_INET, cp, &out->ipv4) != 1) {
            return BHT_ERROR;
        }
        /* Note: ntohl(INADDR_NONE) == INADDR_NONE */
        out->ipv4 = ntohl(out->ipv4);
    }
    else {
        if (inet_pton(AF_INET6, cp, out->ipv6) != 1) {
            return BHT_ERROR;
        }
        for (int i = 0; i < 8; i++) {
            out->ipv6[i] = ntohs(out->ipv6[i]);
        }
    }

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
        TRACE_OCALL_FAIL();
        errno = ENOSYS;
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
os_socket_recv_from(bh_socket_t socket, void *buf, unsigned int len, int flags,
                    bh_sockaddr_t *src_addr)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    ssize_t ret;

    if (ocall_recvfrom(&ret, socket, buf, len, flags, &addr, &addr_len,
                       addr_len)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        errno = ENOSYS;
        return -1;
    }

    if (ret < 0) {
        errno = get_errno();
        return ret;
    }

    if (src_addr && addr_len > 0) {
        if (sockaddr_to_bh_sockaddr((struct sockaddr *)&addr, addr_len,
                                    src_addr)
            == BHT_ERROR) {
            return -1;
        }
    }

    return ret;
}

int
os_socket_send(bh_socket_t socket, const void *buf, unsigned int len)
{
    int ret;

    if (ocall_send(&ret, socket, buf, len, 0) != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        errno = ENOSYS;
        return -1;
    }

    if (ret == -1)
        errno = get_errno();

    return ret;
}

int
os_socket_send_to(bh_socket_t socket, const void *buf, unsigned int len,
                  int flags, const bh_sockaddr_t *dest_addr)
{
    struct sockaddr_in addr;
    socklen_t addr_len;
    ssize_t ret;

    if (bh_sockaddr_to_sockaddr(dest_addr, (struct sockaddr *)&addr, &addr_len)
        == BHT_ERROR) {
        return -1;
    }

    if (ocall_sendto(&ret, socket, buf, len, flags, (struct sockaddr *)&addr,
                     addr_len)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        errno = ENOSYS;
        return -1;
    }

    if (ret == -1) {
        errno = get_errno();
    }

    return ret;
}

__wasi_errno_t
os_socket_shutdown(bh_socket_t socket)
{
    if (shutdown(socket, O_RDWR) != 0) {
        return convert_errno(errno);
    }
    return __WASI_ESUCCESS;
}

int
os_socket_addr_resolve(const char *host, const char *service,
                       uint8_t *hint_is_tcp, uint8_t *hint_is_ipv4,
                       bh_addr_info_t *addr_info, size_t addr_info_size,
                       size_t *max_info_size)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_addr_local(bh_socket_t socket, bh_sockaddr_t *sockaddr)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int ret;

    if (ocall_getsockname(&ret, socket, (struct sockaddr *)&addr, &addr_len,
                          addr_len)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return BHT_ERROR;
    }

    if (ret != BHT_OK) {
        errno = get_errno();
        return BHT_ERROR;
    }

    return sockaddr_to_bh_sockaddr((struct sockaddr *)&addr, addr_len,
                                   sockaddr);
}

int
os_socket_addr_remote(bh_socket_t socket, bh_sockaddr_t *sockaddr)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int ret;

    if (ocall_getpeername(&ret, socket, (void *)&addr, &addr_len, addr_len)
        != SGX_SUCCESS) {
        TRACE_OCALL_FAIL();
        return -1;
    }

    if (ret != BHT_OK) {
        errno = get_errno();
        return BHT_ERROR;
    }

    return sockaddr_to_bh_sockaddr((struct sockaddr *)&addr, addr_len,
                                   sockaddr);
}

int
os_socket_set_send_timeout(bh_socket_t socket, uint64 timeout_us)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_send_timeout(bh_socket_t socket, uint64 *timeout_us)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_recv_timeout(bh_socket_t socket, uint64 timeout_us)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_recv_timeout(bh_socket_t socket, uint64 *timeout_us)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_send_buf_size(bh_socket_t socket, size_t bufsiz)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_send_buf_size(bh_socket_t socket, size_t *bufsiz)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_recv_buf_size(bh_socket_t socket, size_t bufsiz)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_recv_buf_size(bh_socket_t socket, size_t *bufsiz)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_keep_alive(bh_socket_t socket, bool is_enabled)
{
    return os_socket_setbooloption(socket, SOL_SOCKET, SO_KEEPALIVE,
                                   is_enabled);
}

int
os_socket_get_keep_alive(bh_socket_t socket, bool *is_enabled)
{
    return os_socket_getbooloption(socket, SOL_SOCKET, SO_KEEPALIVE,
                                   is_enabled);
}

int
os_socket_set_reuse_addr(bh_socket_t socket, bool is_enabled)
{
    return os_socket_setbooloption(socket, SOL_SOCKET, SO_REUSEADDR,
                                   is_enabled);
}

int
os_socket_get_reuse_addr(bh_socket_t socket, bool *is_enabled)
{
    return os_socket_getbooloption(socket, SOL_SOCKET, SO_REUSEADDR,
                                   is_enabled);
}

int
os_socket_set_reuse_port(bh_socket_t socket, bool is_enabled)
{
    return os_socket_setbooloption(socket, SOL_SOCKET, SO_REUSEPORT,
                                   is_enabled);
}

int
os_socket_get_reuse_port(bh_socket_t socket, bool *is_enabled)
{
    return os_socket_getbooloption(socket, SOL_SOCKET, SO_REUSEPORT,
                                   is_enabled);
}

int
os_socket_set_linger(bh_socket_t socket, bool is_enabled, int linger_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_linger(bh_socket_t socket, bool *is_enabled, int *linger_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_tcp_no_delay(bh_socket_t socket, bool is_enabled)
{
    return os_socket_setbooloption(socket, IPPROTO_TCP, TCP_NODELAY,
                                   is_enabled);
}

int
os_socket_get_tcp_no_delay(bh_socket_t socket, bool *is_enabled)
{
    return os_socket_getbooloption(socket, IPPROTO_TCP, TCP_NODELAY,
                                   is_enabled);
}

int
os_socket_set_tcp_quick_ack(bh_socket_t socket, bool is_enabled)
{
    return os_socket_setbooloption(socket, IPPROTO_TCP, TCP_QUICKACK,
                                   is_enabled);
}

int
os_socket_get_tcp_quick_ack(bh_socket_t socket, bool *is_enabled)
{
    return os_socket_getbooloption(socket, IPPROTO_TCP, TCP_QUICKACK,
                                   is_enabled);
}

int
os_socket_set_tcp_keep_idle(bh_socket_t socket, uint32 time_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_tcp_keep_idle(bh_socket_t socket, uint32 *time_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_tcp_keep_intvl(bh_socket_t socket, uint32 time_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_tcp_keep_intvl(bh_socket_t socket, uint32 *time_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_tcp_fastopen_connect(bh_socket_t socket, bool is_enabled)
{
    return os_socket_setbooloption(socket, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                                   is_enabled);
}

int
os_socket_get_tcp_fastopen_connect(bh_socket_t socket, bool *is_enabled)
{
    return os_socket_getbooloption(socket, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                                   is_enabled);
}

int
os_socket_set_ip_multicast_loop(bh_socket_t socket, bool ipv6, bool is_enabled)
{
    if (ipv6) {
        return os_socket_setbooloption(socket, IPPROTO_IPV6,
                                       IPV6_MULTICAST_LOOP, is_enabled);
    }
    else {
        return os_socket_setbooloption(socket, IPPROTO_IP, IP_MULTICAST_LOOP,
                                       is_enabled);
    }
}

int
os_socket_get_ip_multicast_loop(bh_socket_t socket, bool ipv6, bool *is_enabled)
{
    if (ipv6) {
        return os_socket_getbooloption(socket, IPPROTO_IPV6,
                                       IPV6_MULTICAST_LOOP, is_enabled);
    }
    else {
        return os_socket_getbooloption(socket, IPPROTO_IP, IP_MULTICAST_LOOP,
                                       is_enabled);
    }
}

int
os_socket_set_ip_add_membership(bh_socket_t socket,
                                bh_ip_addr_buffer_t *imr_multiaddr,
                                uint32_t imr_interface, bool is_ipv6)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_ip_drop_membership(bh_socket_t socket,
                                 bh_ip_addr_buffer_t *imr_multiaddr,
                                 uint32_t imr_interface, bool is_ipv6)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_ip_ttl(bh_socket_t socket, uint8_t ttl_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_ip_ttl(bh_socket_t socket, uint8_t *ttl_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_ip_multicast_ttl(bh_socket_t socket, uint8_t ttl_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_get_ip_multicast_ttl(bh_socket_t socket, uint8_t *ttl_s)
{
    errno = ENOSYS;

    return BHT_ERROR;
}

int
os_socket_set_ipv6_only(bh_socket_t socket, bool is_enabled)
{
    return os_socket_setbooloption(socket, IPPROTO_IPV6, IPV6_V6ONLY,
                                   is_enabled);
}

int
os_socket_get_ipv6_only(bh_socket_t socket, bool *is_enabled)
{
    return os_socket_getbooloption(socket, IPPROTO_IPV6, IPV6_V6ONLY,
                                   is_enabled);
}

int
os_socket_set_broadcast(bh_socket_t socket, bool is_enabled)
{
    return os_socket_setbooloption(socket, SOL_SOCKET, SO_BROADCAST,
                                   is_enabled);
}

int
os_socket_get_broadcast(bh_socket_t socket, bool *is_enabled)
{
    return os_socket_getbooloption(socket, SOL_SOCKET, SO_BROADCAST,
                                   is_enabled);
}

#endif
