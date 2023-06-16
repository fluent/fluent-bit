/*
 * Copyright (C) 2022 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef TCP_UTILS_H
#define TCP_UTILS_H

#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>

int
sockaddr_to_string(struct sockaddr *addr, char *str, size_t len)
{
    uint16_t port;
    char ip_string[64];
    void *addr_buf;
    int ret;

    switch (addr->sa_family) {
        case AF_INET:
        {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            port = addr_in->sin_port;
            addr_buf = &addr_in->sin_addr;
            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
            port = addr_in6->sin6_port;
            addr_buf = &addr_in6->sin6_addr;
            break;
        }
        default:
            return -1;
    }

    inet_ntop(addr->sa_family, addr_buf, ip_string,
              sizeof(ip_string) / sizeof(ip_string[0]));

    ret = snprintf(str, len, "%s:%d", ip_string, ntohs(port));

    return ret > 0 && (size_t)ret < len ? 0 : -1;
}

#endif /* TCP_UTILS_H */