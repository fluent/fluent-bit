/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include "socket_utils.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef __wasi__
#include <wasi_socket_ext.h>
#endif

static void
init_sockaddr_inet(struct sockaddr_in *addr)
{
    /* 127.0.0.1:1234 */
    addr->sin_family = AF_INET;
    addr->sin_port = htons(1234);
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
}

static void
init_sockaddr_inet6(struct sockaddr_in6 *addr)
{
    /* [::1]:1234 */
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(1234);
    addr->sin6_addr = in6addr_loopback;
}

int
main(int argc, char *argv[])
{
    int socket_fd, ret, total_size = 0, af;
    char buffer[1024] = { 0 };
    char ip_string[64] = { 0 };
    socklen_t len;
    struct sockaddr_storage server_address = { 0 };
    struct sockaddr_storage local_address = { 0 };

    if (argc > 1 && strcmp(argv[1], "inet6") == 0) {
        af = AF_INET6;
        len = sizeof(struct sockaddr_in6);
        init_sockaddr_inet6((struct sockaddr_in6 *)&server_address);
    }
    else {
        af = AF_INET;
        len = sizeof(struct sockaddr_in);
        init_sockaddr_inet((struct sockaddr_in *)&server_address);
    }

    printf("[Client] Create socket\n");
    socket_fd = socket(af, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        perror("Create socket failed");
        return EXIT_FAILURE;
    }

    printf("[Client] Connect socket\n");
    if (connect(socket_fd, (struct sockaddr *)&server_address, len) == -1) {
        perror("Connect failed");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    len = sizeof(local_address);
    ret = getsockname(socket_fd, (struct sockaddr *)&local_address, &len);
    if (ret == -1) {
        perror("Failed to retrieve socket address");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    if (sockaddr_to_string((struct sockaddr *)&local_address, ip_string,
                           sizeof(ip_string) / sizeof(ip_string[0]))
        != 0) {
        printf("[Client] failed to parse local address\n");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    printf("[Client] Local address is: %s\n", ip_string);

    printf("[Client] Client receive\n");
    while (1) {
        ret = recv(socket_fd, buffer + total_size, sizeof(buffer) - total_size,
                   0);
        if (ret <= 0)
            break;
        total_size += ret;
    }

    printf("[Client] %d bytes received:\n", total_size);
    if (total_size > 0) {
        printf("Buffer received:\n%s\n", buffer);
    }

    close(socket_fd);
    printf("[Client] BYE \n");
    return EXIT_SUCCESS;
}
