/*
 * Copyright (C) 2022 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "socket_utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef __wasi__
#include <wasi_socket_ext.h>
#endif

#define MAX_CONNECTIONS_COUNT 5

static void
init_sockaddr_inet(struct sockaddr_in *addr)
{
    /* 0.0.0.0:1234 */
    addr->sin_family = AF_INET;
    addr->sin_port = htons(1234);
    addr->sin_addr.s_addr = htonl(INADDR_ANY);
}

static void
init_sockaddr_inet6(struct sockaddr_in6 *addr)
{
    /* [::]:1234 */
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(1234);
    addr->sin6_addr = in6addr_any;
}

int
main(int argc, char *argv[])
{
    int socket_fd = -1, af;
    socklen_t addrlen = 0;
    struct sockaddr_storage addr = { 0 };
    char *reply_message = "Hello from server";
    unsigned connections = 0;
    char ip_string[64] = { 0 };
    char buffer[1024] = { 0 };

    if (argc > 1 && strcmp(argv[1], "inet6") == 0) {
        af = AF_INET6;
        addrlen = sizeof(struct sockaddr_in6);
        init_sockaddr_inet6((struct sockaddr_in6 *)&addr);
    }
    else {
        af = AF_INET;
        addrlen = sizeof(struct sockaddr_in);
        init_sockaddr_inet((struct sockaddr_in *)&addr);
    }

    printf("[Server] Create socket\n");
    socket_fd = socket(af, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("Create socket failed");
        goto fail;
    }

    printf("[Server] Bind socket\n");
    if (bind(socket_fd, (struct sockaddr *)&addr, addrlen) < 0) {
        perror("Bind failed");
        goto fail;
    }

    printf("[Server] Wait for clients to connect ..\n");
    while (connections < MAX_CONNECTIONS_COUNT) {
        addrlen = sizeof(addr);
        /* make sure there is space for the string terminator */
        int ret = recvfrom(socket_fd, buffer, sizeof(buffer) - 1, 0,
                           (struct sockaddr *)&addr, &addrlen);
        if (ret < 0) {
            perror("Read failed");
            goto fail;
        }
        buffer[ret] = '\0';

        if (sockaddr_to_string((struct sockaddr *)&addr, ip_string,
                               sizeof(ip_string) / sizeof(ip_string[0]))
            != 0) {
            printf("[Server] failed to parse client address\n");
            goto fail;
        }

        printf("[Server] received %d bytes from %s: %s\n", ret, ip_string,
               buffer);

        if (sendto(socket_fd, reply_message, strlen(reply_message), 0,
                   (struct sockaddr *)&addr, addrlen)
            < 0) {
            perror("Send failed");
            break;
        }

        connections++;
    }

    if (connections == MAX_CONNECTIONS_COUNT) {
        printf("[Server] Achieve maximum amount of connections\n");
    }

    printf("[Server] Shuting down ..\n");
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    sleep(3);
    printf("[Server] BYE \n");
    return EXIT_SUCCESS;

fail:
    printf("[Server] Shuting down ..\n");
    if (socket_fd >= 0)
        close(socket_fd);
    sleep(3);
    return EXIT_FAILURE;
}
