/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "conn_udp.h"

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

int
udp_open(uint16 port)
{
    int sock, ret;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
        close(sock);
        return -1;
    }

    /* Put the socket in non-blocking mode */
    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

int
udp_send(int sock, struct sockaddr *dest, const char *data, int size)
{
    return sendto(sock, data, size, MSG_CONFIRM, dest, sizeof(*dest));
}

int
udp_recv(int sock, char *buffer, int buf_size)
{
    struct sockaddr_in remaddr;
    socklen_t addrlen = sizeof(remaddr);

    return recvfrom(sock, buffer, buf_size, 0, (struct sockaddr *)&remaddr,
                    &addrlen);
}
