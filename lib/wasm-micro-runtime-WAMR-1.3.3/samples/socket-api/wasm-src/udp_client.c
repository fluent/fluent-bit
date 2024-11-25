/*
 * Copyright (C) 2022 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <arpa/inet.h>
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
    int socket_fd, ret, af;
    char buffer[1024] = { 0 };
    socklen_t serverlen;
    struct sockaddr_storage server_address = { 0 };
    const char *message = "Hello from client";

    if (argc > 1 && strcmp(argv[1], "inet6") == 0) {
        af = AF_INET6;
        init_sockaddr_inet6((struct sockaddr_in6 *)&server_address);
        serverlen = sizeof(struct sockaddr_in6);
    }
    else {
        af = AF_INET;
        init_sockaddr_inet((struct sockaddr_in *)&server_address);
        serverlen = sizeof(struct sockaddr_in);
    }

    printf("[Client] Create socket\n");
    socket_fd = socket(af, SOCK_DGRAM, 0);
    if (socket_fd == -1) {
        perror("Create socket failed");
        return EXIT_FAILURE;
    }

    printf("[Client] Client send\n");
    ret = sendto(socket_fd, message, strlen(message), 0,
                 (struct sockaddr *)&server_address, serverlen);
    if (ret < 0) {
        close(socket_fd);
        perror("Send failed");
        return EXIT_FAILURE;
    }

    printf("[Client] Client receive\n");
    serverlen = sizeof(server_address);
    /* make sure there is space for the string terminator */
    ret = recvfrom(socket_fd, buffer, sizeof(buffer) - 1, 0,
                   (struct sockaddr *)&server_address, &serverlen);

    if (ret > 0) {
        buffer[ret] = '\0';
        printf("[Client] Buffer recieved: %s\n", buffer);
    }

    close(socket_fd);
    printf("[Client] BYE \n");
    return EXIT_SUCCESS;
}
