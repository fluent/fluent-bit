/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

#include <arpa/inet.h>

static void
textual_addr_to_sockaddr(const char *textual, int port, struct sockaddr_in *out)
{
    assert(textual);

    out->sin_family = AF_INET;
    out->sin_port = htons(port);
    out->sin_addr.s_addr = inet_addr(textual);
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
            bh_sockaddr->addr_bufer.ipv4 = ntohl(addr->sin_addr.s_addr);
            bh_sockaddr->is_ipv4 = true;
            return BHT_OK;
        }
        default:
            errno = EAFNOSUPPORT;
            return BHT_ERROR;
    }
}

int
os_socket_create(bh_socket_t *sock, bool is_ipv4, bool is_tcp)
{
    if (!sock) {
        return BHT_ERROR;
    }

    if (is_tcp) {
        *sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    else {
        *sock = socket(AF_INET, SOCK_DGRAM, 0);
    }

    return (*sock == -1) ? BHT_ERROR : BHT_OK;
}

int
os_socket_bind(bh_socket_t socket, const char *host, int *port)
{
    struct sockaddr_in addr;
    socklen_t socklen;
    int ret;

    assert(host);
    assert(port);

    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(*port);
    addr.sin_family = AF_INET;

    ret = bind(socket, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        goto fail;
    }

    socklen = sizeof(addr);
    if (getsockname(socket, (struct sockaddr *)&addr, &socklen) == -1) {
        goto fail;
    }

    *port = ntohs(addr.sin_port);

    return BHT_OK;

fail:
    return BHT_ERROR;
}

int
os_socket_settimeout(bh_socket_t socket, uint64 timeout_us)
{
    struct timeval tv;
    tv.tv_sec = timeout_us / 1000000UL;
    tv.tv_usec = timeout_us % 1000000UL;

    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv,
                   sizeof(tv))
        != 0) {
        return BHT_ERROR;
    }

    return BHT_OK;
}

int
os_socket_listen(bh_socket_t socket, int max_client)
{
    if (listen(socket, max_client) != 0) {
        return BHT_ERROR;
    }

    return BHT_OK;
}

int
os_socket_accept(bh_socket_t server_sock, bh_socket_t *sock, void *addr,
                 unsigned int *addrlen)
{
    struct sockaddr addr_tmp;
    socklen_t len = sizeof(struct sockaddr);

    *sock = accept(server_sock, (struct sockaddr *)&addr_tmp, &len);

    if (*sock < 0) {
        return BHT_ERROR;
    }

    return BHT_OK;
}

int
os_socket_connect(bh_socket_t socket, const char *addr, int port)
{
    struct sockaddr_in addr_in = { 0 };
    socklen_t addr_len = sizeof(struct sockaddr_in);
    int ret = 0;

    textual_addr_to_sockaddr(addr, port, &addr_in);

    ret = connect(socket, (struct sockaddr *)&addr_in, addr_len);
    if (ret == -1) {
        return BHT_ERROR;
    }

    return BHT_OK;
}

int
os_socket_recv(bh_socket_t socket, void *buf, unsigned int len)
{
    return recv(socket, buf, len, 0);
}

int
os_socket_send(bh_socket_t socket, const void *buf, unsigned int len)
{
    return send(socket, buf, len, 0);
}

int
os_socket_close(bh_socket_t socket)
{
    close(socket);
    return BHT_OK;
}

int
os_socket_shutdown(bh_socket_t socket)
{
    shutdown(socket, O_RDWR);
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
os_socket_addr_remote(bh_socket_t socket, bh_sockaddr_t *sockaddr)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if (getpeername(socket, (struct sockaddr *)&addr, &addr_len) == -1) {
        return BHT_ERROR;
    }

    return sockaddr_to_bh_sockaddr((struct sockaddr *)&addr, addr_len,
                                   sockaddr);
}

int
os_socket_addr_local(bh_socket_t socket, bh_sockaddr_t *sockaddr)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if (getsockname(socket, (struct sockaddr *)&addr, &addr_len) == -1) {
        return BHT_ERROR;
    }

    return sockaddr_to_bh_sockaddr((struct sockaddr *)&addr, addr_len,
                                   sockaddr);
}
