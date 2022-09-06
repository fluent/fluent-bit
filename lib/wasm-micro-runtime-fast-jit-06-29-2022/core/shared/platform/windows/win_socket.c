/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "platform_api_extension.h"

/* link with Ws2_32.lib */
#pragma comment(lib, "ws2_32.lib")

static bool is_winsock_inited = false;

int
init_winsock()
{
    WSADATA wsaData;

    if (!is_winsock_inited) {
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            os_printf("winsock init failed");
            return BHT_ERROR;
        }

        is_winsock_inited = true;
    }

    return BHT_OK;
}

void
deinit_winsock()
{
    if (is_winsock_inited) {
        WSACleanup();
    }
}

int
os_socket_create(bh_socket_t *sock, int tcp_or_udp)
{
    if (!sock) {
        return BHT_ERROR;
    }

    if (1 == tcp_or_udp) {
        *sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    else if (0 == tcp_or_udp) {
        *sock = socket(AF_INET, SOCK_DGRAM, 0);
    }

    return (*sock == -1) ? BHT_ERROR : BHT_OK;
}

int
os_socket_bind(bh_socket_t socket, const char *host, int *port)
{
    struct sockaddr_in addr;
    int socklen, ret;

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
    if (getsockname(socket, (void *)&addr, &socklen) == -1) {
        os_printf("getsockname failed with error %d\n", WSAGetLastError());
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
    DWORD tv = (DWORD)(timeout_us / 1000UL);

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
        os_printf("socket listen failed with error %d\n", WSAGetLastError());
        return BHT_ERROR;
    }

    return BHT_OK;
}

int
os_socket_accept(bh_socket_t server_sock, bh_socket_t *sock, void *addr,
                 unsigned int *addrlen)
{
    struct sockaddr addr_tmp;
    unsigned int len = sizeof(struct sockaddr);

    *sock = accept(server_sock, (struct sockaddr *)&addr_tmp, &len);

    if (*sock < 0) {
        os_printf("socket accept failed with error %d\n", WSAGetLastError());
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
    closesocket(socket);
    return BHT_OK;
}

int
os_socket_shutdown(bh_socket_t socket)
{
    shutdown(socket, SD_BOTH);
    return BHT_OK;
}

int
os_socket_inet_network(const char *cp, uint32 *out)
{
    if (!cp)
        return BHT_ERROR;

    *out = inet_addr(cp);
    return BHT_OK;
}