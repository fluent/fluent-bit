/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <wasi/api.h>
#include <wasi_socket_ext.h>

/*
 * Avoid direct TLS access to allow a single library to be
 * linked to both of threaded and non-threaded applications.
 *
 * wasi-libc's errno is a TLS variable, exposed directly via
 * errno.h. if we use it here, LLVM may lower it differently,
 * depending on enabled features like atomcs and bulk-memory.
 * we tweak the way to access errno here in order to make us
 * compatible with both of threaded and non-threaded applications.
 * __errno_location() should be reasonably stable because
 * it was introduced as an alternative ABI for non-C software.
 * https://github.com/WebAssembly/wasi-libc/pull/347
 */
#if defined(errno)
#undef errno
#endif
int *
__errno_location(void);
#define errno (*__errno_location())

#define HANDLE_ERROR(error)              \
    if (error != __WASI_ERRNO_SUCCESS) { \
        errno = error;                   \
        return -1;                       \
    }

/* REVISIT: in many cases, EAI_SYSTEM may not be an ideal error code */
#define GAI_HANDLE_ERROR(error)          \
    if (error != __WASI_ERRNO_SUCCESS) { \
        errno = error;                   \
        return EAI_SYSTEM;               \
    }

static void
ipv4_addr_to_wasi_ip4_addr(uint32_t addr_num, __wasi_addr_ip4_t *out)
{
    addr_num = ntohl(addr_num);
    out->n0 = (addr_num & 0xFF000000) >> 24;
    out->n1 = (addr_num & 0x00FF0000) >> 16;
    out->n2 = (addr_num & 0x0000FF00) >> 8;
    out->n3 = (addr_num & 0x000000FF);
}

/* addr_num and port are in network order */
static void
ipv4_addr_to_wasi_addr(uint32_t addr_num, uint16_t port, __wasi_addr_t *out)
{
    out->kind = IPv4;
    out->addr.ip4.port = ntohs(port);
    ipv4_addr_to_wasi_ip4_addr(addr_num, &(out->addr.ip4.addr));
}

static void
ipv6_addr_to_wasi_ipv6_addr(uint16_t *addr, __wasi_addr_ip6_t *out)
{
    out->n0 = ntohs(addr[0]);
    out->n1 = ntohs(addr[1]);
    out->n2 = ntohs(addr[2]);
    out->n3 = ntohs(addr[3]);
    out->h0 = ntohs(addr[4]);
    out->h1 = ntohs(addr[5]);
    out->h2 = ntohs(addr[6]);
    out->h3 = ntohs(addr[7]);
}

static void
ipv6_addr_to_wasi_addr(uint16_t *addr, uint16_t port, __wasi_addr_t *out)
{
    out->kind = IPv6;
    out->addr.ip6.port = ntohs(port);
    ipv6_addr_to_wasi_ipv6_addr(addr, &(out->addr.ip6.addr));
}

static __wasi_errno_t
sockaddr_to_wasi_addr(const struct sockaddr *sock_addr, socklen_t addrlen,
                      __wasi_addr_t *wasi_addr)
{
    __wasi_errno_t ret = __WASI_ERRNO_SUCCESS;
    if (AF_INET == sock_addr->sa_family) {
        assert(sizeof(struct sockaddr_in) <= addrlen);

        ipv4_addr_to_wasi_addr(
            ((struct sockaddr_in *)sock_addr)->sin_addr.s_addr,
            ((struct sockaddr_in *)sock_addr)->sin_port, wasi_addr);
    }
    else if (AF_INET6 == sock_addr->sa_family) {
        assert(sizeof(struct sockaddr_in6) <= addrlen);
        ipv6_addr_to_wasi_addr(
            (uint16_t *)((struct sockaddr_in6 *)sock_addr)->sin6_addr.s6_addr,
            ((struct sockaddr_in6 *)sock_addr)->sin6_port, wasi_addr);
    }
    else {
        ret = __WASI_ERRNO_AFNOSUPPORT;
    }

    return ret;
}

static __wasi_errno_t
wasi_addr_to_sockaddr(const __wasi_addr_t *wasi_addr,
                      struct sockaddr *sock_addr, socklen_t *addrlen)
{
    switch (wasi_addr->kind) {
        case IPv4:
        {
            struct sockaddr_in sock_addr_in;
            uint32_t s_addr;

            memset(&sock_addr_in, 0, sizeof(sock_addr_in));

            s_addr = (wasi_addr->addr.ip4.addr.n0 << 24)
                     | (wasi_addr->addr.ip4.addr.n1 << 16)
                     | (wasi_addr->addr.ip4.addr.n2 << 8)
                     | wasi_addr->addr.ip4.addr.n3;

            sock_addr_in.sin_family = AF_INET;
            sock_addr_in.sin_addr.s_addr = htonl(s_addr);
            sock_addr_in.sin_port = htons(wasi_addr->addr.ip4.port);
            memcpy(sock_addr, &sock_addr_in, sizeof(sock_addr_in));

            *addrlen = sizeof(sock_addr_in);
            break;
        }
        case IPv6:
        {
            struct sockaddr_in6 sock_addr_in6;

            memset(&sock_addr_in6, 0, sizeof(sock_addr_in6));

            uint16_t *addr_buf = (uint16_t *)sock_addr_in6.sin6_addr.s6_addr;

            addr_buf[0] = htons(wasi_addr->addr.ip6.addr.n0);
            addr_buf[1] = htons(wasi_addr->addr.ip6.addr.n1);
            addr_buf[2] = htons(wasi_addr->addr.ip6.addr.n2);
            addr_buf[3] = htons(wasi_addr->addr.ip6.addr.n3);
            addr_buf[4] = htons(wasi_addr->addr.ip6.addr.h0);
            addr_buf[5] = htons(wasi_addr->addr.ip6.addr.h1);
            addr_buf[6] = htons(wasi_addr->addr.ip6.addr.h2);
            addr_buf[7] = htons(wasi_addr->addr.ip6.addr.h3);

            sock_addr_in6.sin6_family = AF_INET6;
            sock_addr_in6.sin6_port = htons(wasi_addr->addr.ip6.port);
            memcpy(sock_addr, &sock_addr_in6, sizeof(sock_addr_in6));

            *addrlen = sizeof(sock_addr_in6);
            break;
        }
        default:
            return __WASI_ERRNO_AFNOSUPPORT;
    }
    return __WASI_ERRNO_SUCCESS;
}

int
accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    __wasi_addr_t wasi_addr;
    __wasi_fd_t new_sockfd;
    __wasi_errno_t error;

    memset(&wasi_addr, 0, sizeof(wasi_addr));

    error = __wasi_sock_accept(sockfd, 0, &new_sockfd);
    HANDLE_ERROR(error)

    if (getpeername(new_sockfd, addr, addrlen) == -1) {
        return -1;
    }

    return new_sockfd;
}

int
bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    __wasi_addr_t wasi_addr;
    __wasi_errno_t error;

    memset(&wasi_addr, 0, sizeof(wasi_addr));

    error = sockaddr_to_wasi_addr(addr, addrlen, &wasi_addr);
    HANDLE_ERROR(error)

    error = __wasi_sock_bind(sockfd, &wasi_addr);
    HANDLE_ERROR(error)

    return 0;
}

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    __wasi_addr_t wasi_addr;
    __wasi_errno_t error;

    memset(&wasi_addr, 0, sizeof(wasi_addr));

    if (NULL == addr) {
        HANDLE_ERROR(__WASI_ERRNO_INVAL)
    }

    error = sockaddr_to_wasi_addr(addr, addrlen, &wasi_addr);
    HANDLE_ERROR(error)

    error = __wasi_sock_connect(sockfd, &wasi_addr);
    HANDLE_ERROR(error)

    return 0;
}

int
listen(int sockfd, int backlog)
{
    __wasi_errno_t error = __wasi_sock_listen(sockfd, backlog);
    HANDLE_ERROR(error)
    return 0;
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
    if (!(ri_data = (__wasi_iovec_t *)malloc(sizeof(__wasi_iovec_t)
                                             * msg->msg_iovlen))) {
        HANDLE_ERROR(__WASI_ERRNO_NOMEM)
    }

    for (i = 0; i < msg->msg_iovlen; i++) {
        ri_data[i].buf = (uint8_t *)msg->msg_iov[i].iov_base;
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
    if (!(si_data = (__wasi_ciovec_t *)malloc(sizeof(__wasi_ciovec_t)
                                              * msg->msg_iovlen))) {
        HANDLE_ERROR(__WASI_ERRNO_NOMEM)
    }

    for (i = 0; i < msg->msg_iovlen; i++) {
        si_data[i].buf = (uint8_t *)msg->msg_iov[i].iov_base;
        si_data[i].buf_len = msg->msg_iov[i].iov_len;
    }

    // Perform system call.
    __wasi_errno_t error =
        __wasi_sock_send(sockfd, si_data, msg->msg_iovlen, 0, &so_datalen);
    free(si_data);
    HANDLE_ERROR(error)

    return so_datalen;
}

ssize_t
sendto(int sockfd, const void *buf, size_t len, int flags,
       const struct sockaddr *dest_addr, socklen_t addrlen)
{
    // Prepare input parameters.
    __wasi_ciovec_t iov = { .buf = (uint8_t *)buf, .buf_len = len };
    uint32_t so_datalen = 0;
    __wasi_addr_t wasi_addr;
    __wasi_errno_t error;
    size_t si_data_len = 1;
    __wasi_siflags_t si_flags = 0;

    // This implementation does not support any flags.
    if (flags != 0) {
        HANDLE_ERROR(__WASI_ERRNO_NOPROTOOPT)
    }

    error = sockaddr_to_wasi_addr(dest_addr, addrlen, &wasi_addr);
    HANDLE_ERROR(error);

    // Perform system call.
    error = __wasi_sock_send_to(sockfd, &iov, si_data_len, si_flags, &wasi_addr,
                                &so_datalen);
    HANDLE_ERROR(error)

    return so_datalen;
}

ssize_t
recvfrom(int sockfd, void *buf, size_t len, int flags,
         struct sockaddr *src_addr, socklen_t *addrlen)
{
    // Prepare input parameters.
    __wasi_ciovec_t iov = { .buf = (uint8_t *)buf, .buf_len = len };
    uint32_t so_datalen = 0;
    __wasi_addr_t wasi_addr;
    __wasi_errno_t error;
    size_t si_data_len = 1;
    __wasi_siflags_t si_flags = 0;

    // This implementation does not support any flags.
    if (flags != 0) {
        HANDLE_ERROR(__WASI_ERRNO_NOPROTOOPT)
    }

    if (!src_addr) {
        return recv(sockfd, buf, len, flags);
    }

    // Perform system call.
    error = __wasi_sock_recv_from(sockfd, &iov, si_data_len, si_flags,
                                  &wasi_addr, &so_datalen);
    HANDLE_ERROR(error);

    error = wasi_addr_to_sockaddr(&wasi_addr, src_addr, addrlen);
    HANDLE_ERROR(error);

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
        HANDLE_ERROR(__WASI_ERRNO_NOPROTOOPT)
    }

    if (SOCK_DGRAM == type) {
        socktype = SOCKET_DGRAM;
    }
    else if (SOCK_STREAM == type) {
        socktype = SOCKET_STREAM;
    }
    else {
        HANDLE_ERROR(__WASI_ERRNO_NOPROTOOPT)
    }

    error = __wasi_sock_open(poolfd, af, socktype, &sockfd);
    HANDLE_ERROR(error)

    return sockfd;
}

int
getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    __wasi_addr_t wasi_addr;
    __wasi_errno_t error;

    memset(&wasi_addr, 0, sizeof(wasi_addr));

    error = __wasi_sock_addr_local(sockfd, &wasi_addr);
    HANDLE_ERROR(error)

    error = wasi_addr_to_sockaddr(&wasi_addr, addr, addrlen);
    HANDLE_ERROR(error)

    return 0;
}

int
getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    __wasi_addr_t wasi_addr;
    __wasi_errno_t error;

    memset(&wasi_addr, 0, sizeof(wasi_addr));

    error = __wasi_sock_addr_remote(sockfd, &wasi_addr);
    HANDLE_ERROR(error)

    error = wasi_addr_to_sockaddr(&wasi_addr, addr, addrlen);
    HANDLE_ERROR(error)

    return 0;
}

struct aibuf {
    struct addrinfo ai;
    union sa {
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } sa;
};

static __wasi_errno_t
addrinfo_hints_to_wasi_hints(const struct addrinfo *hints,
                             __wasi_addr_info_hints_t *wasi_hints)
{
    if (hints) {
        wasi_hints->hints_enabled = 1;

        switch (hints->ai_family) {
            case AF_INET:
                wasi_hints->family = INET4;
                break;
            case AF_INET6:
                wasi_hints->family = INET6;
                break;
            case AF_UNSPEC:
                wasi_hints->family = INET_UNSPEC;
                break;
            default:
                return __WASI_ERRNO_AFNOSUPPORT;
        }
        switch (hints->ai_socktype) {
            case SOCK_STREAM:
                wasi_hints->type = SOCKET_STREAM;
                break;
            case SOCK_DGRAM:
                wasi_hints->type = SOCKET_DGRAM;
                break;
            case 0:
                wasi_hints->type = SOCKET_ANY;
            default:
                return __WASI_ERRNO_NOTSUP;
        }

        if (hints->ai_protocol != 0) {
            return __WASI_ERRNO_NOTSUP;
        }

        if (hints->ai_flags != 0) {
            return __WASI_ERRNO_NOTSUP;
        }
    }
    else {
        wasi_hints->hints_enabled = 0;
    }

    return __WASI_ERRNO_SUCCESS;
}

static __wasi_errno_t
wasi_addr_info_to_addr_info(const __wasi_addr_info_t *addr_info,
                            struct addrinfo *ai)
{
    ai->ai_socktype =
        addr_info->type == SOCKET_DGRAM ? SOCK_DGRAM : SOCK_STREAM;
    ai->ai_protocol = 0;
    ai->ai_canonname = NULL;

    if (addr_info->addr.kind == IPv4) {
        ai->ai_family = AF_INET;
        ai->ai_addrlen = sizeof(struct sockaddr_in);
    }
    else {
        ai->ai_family = AF_INET6;
        ai->ai_addrlen = sizeof(struct sockaddr_in6);
    }

    return wasi_addr_to_sockaddr(&addr_info->addr, ai->ai_addr,
                                 &ai->ai_addrlen); // TODO err handling
}

int
getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
            struct addrinfo **res)
{
    __wasi_addr_info_hints_t wasi_hints;
    __wasi_addr_info_t *addr_info = NULL;
    __wasi_size_t addr_info_size, i;
    __wasi_size_t max_info_size = 16;
    __wasi_errno_t error;
    struct aibuf *aibuf_res;

    error = addrinfo_hints_to_wasi_hints(hints, &wasi_hints);
    GAI_HANDLE_ERROR(error)

    do {
        if (addr_info)
            free(addr_info);

        addr_info_size = max_info_size;
        addr_info = (__wasi_addr_info_t *)malloc(addr_info_size
                                                 * sizeof(__wasi_addr_info_t));

        if (!addr_info) {
            return EAI_MEMORY;
        }

        error = __wasi_sock_addr_resolve(node, service == NULL ? "" : service,
                                         &wasi_hints, addr_info, addr_info_size,
                                         &max_info_size);
        if (error != __WASI_ERRNO_SUCCESS) {
            free(addr_info);
            GAI_HANDLE_ERROR(error);
        }
    } while (max_info_size > addr_info_size);

    addr_info_size = max_info_size;
    if (addr_info_size == 0) {
        free(addr_info);
        return EAI_NONAME;
    }

    aibuf_res =
        (struct aibuf *)calloc(1, addr_info_size * sizeof(struct aibuf));
    if (!aibuf_res) {
        free(addr_info);
        return EAI_MEMORY;
    }

    *res = &aibuf_res[0].ai;

    for (i = 0; i < addr_info_size; i++) {
        struct addrinfo *ai = &aibuf_res[i].ai;
        ai->ai_addr = (struct sockaddr *)&aibuf_res[i].sa;

        error = wasi_addr_info_to_addr_info(&addr_info[i], ai);
        if (error != __WASI_ERRNO_SUCCESS) {
            free(addr_info);
            free(aibuf_res);
            GAI_HANDLE_ERROR(error)
        }
        ai->ai_next = i == addr_info_size - 1 ? NULL : &aibuf_res[i + 1].ai;
    }

    free(addr_info);

    return 0;
}

void
freeaddrinfo(struct addrinfo *res)
{
    /* res is a pointer to a first field in the first element
     * of aibuf array allocated in getaddrinfo, therefore this call
     * frees the memory of the entire array. */
    free(res);
}

static struct timeval
time_us_to_timeval(uint64_t time_us)
{
    struct timeval tv;
    tv.tv_sec = time_us / 1000000UL;
    tv.tv_usec = time_us % 1000000UL;
    return tv;
}

static uint64_t
timeval_to_time_us(struct timeval tv)
{
    return (tv.tv_sec * 1000000UL) + tv.tv_usec;
}

static int
get_sol_socket_option(int sockfd, int optname, void *__restrict optval,
                      socklen_t *__restrict optlen)
{
    __wasi_errno_t error;
    uint64_t timeout_us;
    bool is_linger_enabled;
    int linger_s;
    __wasi_fdstat_t sb;

    switch (optname) {
        case SO_RCVTIMEO:
            assert(*optlen == sizeof(struct timeval));
            error = __wasi_sock_get_recv_timeout(sockfd, &timeout_us);
            HANDLE_ERROR(error);
            *(struct timeval *)optval = time_us_to_timeval(timeout_us);
            return 0;
        case SO_SNDTIMEO:
            assert(*optlen == sizeof(struct timeval));
            error = __wasi_sock_get_send_timeout(sockfd, &timeout_us);
            HANDLE_ERROR(error);
            *(struct timeval *)optval = time_us_to_timeval(timeout_us);
            return 0;
        case SO_SNDBUF:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_send_buf_size(sockfd, (size_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        case SO_RCVBUF:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_recv_buf_size(sockfd, (size_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        case SO_KEEPALIVE:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_keep_alive(sockfd, (bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case SO_REUSEADDR:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_reuse_addr(sockfd, (bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case SO_REUSEPORT:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_reuse_port(sockfd, (bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case SO_LINGER:
            assert(*optlen == sizeof(struct linger));
            error =
                __wasi_sock_get_linger(sockfd, &is_linger_enabled, &linger_s);
            HANDLE_ERROR(error);
            ((struct linger *)optval)->l_onoff = (int)is_linger_enabled;
            ((struct linger *)optval)->l_linger = linger_s;
            return 0;
        case SO_BROADCAST:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_broadcast(sockfd, (bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case SO_TYPE:
            assert(*optlen == sizeof(int));
            error = __wasi_fd_fdstat_get(sockfd, &sb);
            HANDLE_ERROR(error);
            switch (sb.fs_filetype) {
                case __WASI_FILETYPE_SOCKET_DGRAM:
                    *(int *)optval = SOCK_DGRAM;
                    break;
                case __WASI_FILETYPE_SOCKET_STREAM:
                    *(int *)optval = SOCK_STREAM;
                    break;
                default:
                    errno = __WASI_ERRNO_NOTSOCK;
                    return -1;
            }
            return 0;
        default:
            error = __WASI_ERRNO_NOTSUP;
            HANDLE_ERROR(error);
            return 0;
    }
}

static int
get_ipproto_tcp_option(int sockfd, int optname, void *__restrict optval,
                       socklen_t *__restrict optlen)
{
    __wasi_errno_t error;
    switch (optname) {
        case TCP_KEEPIDLE:
            assert(*optlen == sizeof(uint32_t));
            error = __wasi_sock_get_tcp_keep_idle(sockfd, (uint32_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        case TCP_KEEPINTVL:
            assert(*optlen == sizeof(uint32_t));
            error = __wasi_sock_get_tcp_keep_intvl(sockfd, (uint32_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        case TCP_FASTOPEN_CONNECT:
            assert(*optlen == sizeof(int));
            error =
                __wasi_sock_get_tcp_fastopen_connect(sockfd, (bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case TCP_NODELAY:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_tcp_no_delay(sockfd, (bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case TCP_QUICKACK:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_tcp_quick_ack(sockfd, (bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        default:
            error = __WASI_ERRNO_NOTSUP;
            HANDLE_ERROR(error);
            return 0;
    }
}

static int
get_ipproto_ip_option(int sockfd, int optname, void *__restrict optval,
                      socklen_t *__restrict optlen)
{
    __wasi_errno_t error;

    switch (optname) {
        case IP_MULTICAST_LOOP:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_ip_multicast_loop(sockfd, false,
                                                      (bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case IP_TTL:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_ip_ttl(sockfd, (uint8_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        case IP_MULTICAST_TTL:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_ip_multicast_ttl(sockfd, (uint8_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        default:
            error = __WASI_ERRNO_NOTSUP;
            HANDLE_ERROR(error);
            return 0;
    }
}

static int
get_ipproto_ipv6_option(int sockfd, int optname, void *__restrict optval,
                        socklen_t *__restrict optlen)
{
    __wasi_errno_t error;

    switch (optname) {
        case IPV6_V6ONLY:
            assert(*optlen == sizeof(int));
            error = __wasi_sock_get_ipv6_only(sockfd, (bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case IPV6_MULTICAST_LOOP:
            assert(*optlen == sizeof(int));
            error =
                __wasi_sock_get_ip_multicast_loop(sockfd, true, (bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        default:
            error = __WASI_ERRNO_NOTSUP;
            HANDLE_ERROR(error);
            return 0;
    }
}

int
getsockopt(int sockfd, int level, int optname, void *__restrict optval,
           socklen_t *__restrict optlen)
{
    __wasi_errno_t error;

    switch (level) {
        case SOL_SOCKET:
            return get_sol_socket_option(sockfd, optname, optval, optlen);
        case IPPROTO_TCP:
            return get_ipproto_tcp_option(sockfd, optname, optval, optlen);
        case IPPROTO_IP:
            return get_ipproto_ip_option(sockfd, optname, optval, optlen);
        case IPPROTO_IPV6:
            return get_ipproto_ipv6_option(sockfd, optname, optval, optlen);
        default:
            error = __WASI_ERRNO_NOTSUP;
            HANDLE_ERROR(error);
            return 0;
    }
}

static int
set_sol_socket_option(int sockfd, int optname, const void *optval,
                      socklen_t optlen)
{
    __wasi_errno_t error;
    uint64_t timeout_us;

    switch (optname) {
        case SO_RCVTIMEO:
        {
            assert(optlen == sizeof(struct timeval));
            timeout_us = timeval_to_time_us(*(struct timeval *)optval);
            error = __wasi_sock_set_recv_timeout(sockfd, timeout_us);
            HANDLE_ERROR(error);
            return 0;
        }
        case SO_SNDTIMEO:
        {
            assert(optlen == sizeof(struct timeval));
            timeout_us = timeval_to_time_us(*(struct timeval *)optval);
            error = __wasi_sock_set_send_timeout(sockfd, timeout_us);
            HANDLE_ERROR(error);
            return 0;
        }
        case SO_SNDBUF:
        {
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_send_buf_size(sockfd, *(size_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        }
        case SO_RCVBUF:
        {
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_recv_buf_size(sockfd, *(size_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        }
        case SO_KEEPALIVE:
        {
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_keep_alive(sockfd, *(bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        }
        case SO_REUSEADDR:
        {
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_reuse_addr(sockfd, *(bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        }
        case SO_REUSEPORT:
        {
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_reuse_port(sockfd, *(bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        }
        case SO_LINGER:
        {
            assert(optlen == sizeof(struct linger));
            struct linger *linger_opt = ((struct linger *)optval);
            error = __wasi_sock_set_linger(sockfd, (bool)linger_opt->l_onoff,
                                           linger_opt->l_linger);
            HANDLE_ERROR(error);
            return 0;
        }
        case SO_BROADCAST:
        {
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_broadcast(sockfd, *(bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        }
        default:
        {
            error = __WASI_ERRNO_NOTSUP;
            HANDLE_ERROR(error);
            return 0;
        }
    }
}

static int
set_ipproto_tcp_option(int sockfd, int optname, const void *optval,
                       socklen_t optlen)
{
    __wasi_errno_t error;

    switch (optname) {
        case TCP_NODELAY:
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_tcp_no_delay(sockfd, *(bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case TCP_KEEPIDLE:
            assert(optlen == sizeof(uint32_t));
            error = __wasi_sock_set_tcp_keep_idle(sockfd, *(uint32_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        case TCP_KEEPINTVL:
            assert(optlen == sizeof(uint32_t));
            error = __wasi_sock_set_tcp_keep_intvl(sockfd, *(uint32_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        case TCP_FASTOPEN_CONNECT:
            assert(optlen == sizeof(int));
            error =
                __wasi_sock_set_tcp_fastopen_connect(sockfd, *(bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case TCP_QUICKACK:
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_tcp_quick_ack(sockfd, *(bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        default:
            error = __WASI_ERRNO_NOTSUP;
            HANDLE_ERROR(error);
            return 0;
    }
}

static int
set_ipproto_ip_option(int sockfd, int optname, const void *optval,
                      socklen_t optlen)
{
    __wasi_errno_t error;
    __wasi_addr_ip_t imr_multiaddr;
    struct ip_mreq *ip_mreq_opt;

    switch (optname) {
        case IP_MULTICAST_LOOP:
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_ip_multicast_loop(sockfd, false,
                                                      *(bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case IP_ADD_MEMBERSHIP:
            assert(optlen == sizeof(struct ip_mreq));
            ip_mreq_opt = (struct ip_mreq *)optval;
            imr_multiaddr.kind = IPv4;
            ipv4_addr_to_wasi_ip4_addr(ip_mreq_opt->imr_multiaddr.s_addr,
                                       &imr_multiaddr.addr.ip4);
            error = __wasi_sock_set_ip_add_membership(
                sockfd, &imr_multiaddr, ip_mreq_opt->imr_interface.s_addr);
            HANDLE_ERROR(error);
            return 0;
        case IP_DROP_MEMBERSHIP:
            assert(optlen == sizeof(struct ip_mreq));
            ip_mreq_opt = (struct ip_mreq *)optval;
            imr_multiaddr.kind = IPv4;
            ipv4_addr_to_wasi_ip4_addr(ip_mreq_opt->imr_multiaddr.s_addr,
                                       &imr_multiaddr.addr.ip4);
            error = __wasi_sock_set_ip_drop_membership(
                sockfd, &imr_multiaddr, ip_mreq_opt->imr_interface.s_addr);
            HANDLE_ERROR(error);
            return 0;
        case IP_TTL:
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_ip_ttl(sockfd, *(uint8_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        case IP_MULTICAST_TTL:
            assert(optlen == sizeof(int));
            error =
                __wasi_sock_set_ip_multicast_ttl(sockfd, *(uint8_t *)optval);
            HANDLE_ERROR(error);
            return 0;
        default:
            error = __WASI_ERRNO_NOTSUP;
            HANDLE_ERROR(error);
            return 0;
    }
}

static int
set_ipproto_ipv6_option(int sockfd, int optname, const void *optval,
                        socklen_t optlen)
{
    __wasi_errno_t error;
    struct ipv6_mreq *ipv6_mreq_opt;
    __wasi_addr_ip_t imr_multiaddr;

    switch (optname) {
        case IPV6_V6ONLY:
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_ipv6_only(sockfd, *(bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case IPV6_MULTICAST_LOOP:
            assert(optlen == sizeof(int));
            error = __wasi_sock_set_ip_multicast_loop(sockfd, true,
                                                      *(bool *)optval);
            HANDLE_ERROR(error);
            return 0;
        case IPV6_JOIN_GROUP:
            assert(optlen == sizeof(struct ipv6_mreq));
            ipv6_mreq_opt = (struct ipv6_mreq *)optval;
            imr_multiaddr.kind = IPv6;
            ipv6_addr_to_wasi_ipv6_addr(
                (uint16_t *)ipv6_mreq_opt->ipv6mr_multiaddr.s6_addr,
                &imr_multiaddr.addr.ip6);
            error = __wasi_sock_set_ip_add_membership(
                sockfd, &imr_multiaddr, ipv6_mreq_opt->ipv6mr_interface);
            HANDLE_ERROR(error);
            return 0;
        case IPV6_LEAVE_GROUP:
            assert(optlen == sizeof(struct ipv6_mreq));
            ipv6_mreq_opt = (struct ipv6_mreq *)optval;
            imr_multiaddr.kind = IPv6;
            ipv6_addr_to_wasi_ipv6_addr(
                (uint16_t *)ipv6_mreq_opt->ipv6mr_multiaddr.s6_addr,
                &imr_multiaddr.addr.ip6);
            error = __wasi_sock_set_ip_drop_membership(
                sockfd, &imr_multiaddr, ipv6_mreq_opt->ipv6mr_interface);
            HANDLE_ERROR(error);
            return 0;
        default:
            error = __WASI_ERRNO_NOTSUP;
            HANDLE_ERROR(error);
            return 0;
    }
}

int
setsockopt(int sockfd, int level, int optname, const void *optval,
           socklen_t optlen)
{
    __wasi_errno_t error;

    switch (level) {
        case SOL_SOCKET:
            return set_sol_socket_option(sockfd, optname, optval, optlen);
        case IPPROTO_TCP:
            return set_ipproto_tcp_option(sockfd, optname, optval, optlen);
        case IPPROTO_IP:
            return set_ipproto_ip_option(sockfd, optname, optval, optlen);
        case IPPROTO_IPV6:
            return set_ipproto_ipv6_option(sockfd, optname, optval, optlen);
        default:
            error = __WASI_ERRNO_NOTSUP;
            HANDLE_ERROR(error);
            return 0;
    }
}
