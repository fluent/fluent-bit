/*
 * Copyright (C) 2022 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef __wasi__
#include <wasi_socket_ext.h>
#endif

int
main(int argc, char *argv[])
{
    int socket_fd;
    int client_socket_fd;
    struct sockaddr_in addr = { 0 };
    int addrlen = sizeof(addr);
    int bool_opt = 1;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Create socket failed");
        return EXIT_FAILURE;
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &bool_opt,
                   sizeof(bool_opt))
        == -1) {
        perror("Failed setting SO_REUSEADDR");
        goto fail;
    }

    if (bind(socket_fd, (struct sockaddr *)&addr, addrlen) == -1) {
        perror("Bind socket failed");
        goto fail;
    }

    if (listen(socket_fd, 1) == -1) {
        perror("Listen failed");
        goto fail;
    }

    if ((client_socket_fd =
             accept(socket_fd, (struct sockaddr *)&addr, (socklen_t *)&addrlen))
        == -1) {
        perror("Accept failed");
        goto fail;
    }

    printf("Client connected, sleeping for 10s\n");
    sleep(10);

    printf("Shutting down\n");
    shutdown(client_socket_fd, SHUT_RDWR);
    close(client_socket_fd);
    shutdown(socket_fd, SHUT_RDWR);
    close(socket_fd);
    return EXIT_SUCCESS;

fail:
    close(socket_fd);
    return EXIT_FAILURE;
}
