/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "conn_tcp.h"

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

int
tcp_open(char *address, uint16 port)
{
    int sock, ret;
    struct sockaddr_in servaddr;

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(address);
    servaddr.sin_port = htons(port);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1)
        return -1;

    ret = connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr));
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
tcp_send(int sock, const char *data, int size)
{
    return send(sock, data, size, 0);
}

int
tcp_recv(int sock, char *buffer, int buf_size)
{
    return recv(sock, buffer, buf_size, 0);
}
