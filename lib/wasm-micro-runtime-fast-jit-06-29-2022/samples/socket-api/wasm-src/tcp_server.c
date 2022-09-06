/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef __wasi__
#include <wasi_socket_ext.h>
#endif

#define WORKER_NUM 5

void *
run(void *arg)
{
    const char *message = "Say Hi from the Server\n";
    int new_socket = *(int *)arg;
    int i;

    printf("[Server] Communicate with the new connection #%u @ %p ..\n",
           new_socket, (void *)(uintptr_t)pthread_self());

    for (i = 0; i < 5; i++) {
        if (send(new_socket, message, strlen(message), 0) < 0) {
            perror("Send failed");
            break;
        }
    }

    printf("[Server] Shuting down the new connection #%u ..\n", new_socket);
    shutdown(new_socket, SHUT_RDWR);

    return NULL;
}

int
main(int argc, char *argv[])
{
    int socket_fd = -1, addrlen = 0;
    struct sockaddr_in addr = { 0 };
    unsigned connections = 0;
    pthread_t workers[WORKER_NUM] = { 0 };
    int client_sock_fds[WORKER_NUM] = { 0 };

    printf("[Server] Create socket\n");
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("Create socket failed");
        goto fail;
    }

    /* 0.0.0.0:1234 */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    printf("[Server] Bind socket\n");
    addrlen = sizeof(addr);
    if (bind(socket_fd, (struct sockaddr *)&addr, addrlen) < 0) {
        perror("Bind failed");
        goto fail;
    }

    printf("[Server] Listening on socket\n");
    if (listen(socket_fd, 3) < 0) {
        perror("Listen failed");
        goto fail;
    }

    printf("[Server] Wait for clients to connect ..\n");
    while (connections < WORKER_NUM) {
        client_sock_fds[connections] =
            accept(socket_fd, (struct sockaddr *)&addr, (socklen_t *)&addrlen);
        if (client_sock_fds[connections] < 0) {
            perror("Accept failed");
            break;
        }

        printf("[Server] Client connected\n");
        if (pthread_create(&workers[connections], NULL, run,
                           &client_sock_fds[connections])) {
            perror("Create a worker thread failed");
            shutdown(client_sock_fds[connections], SHUT_RDWR);
            break;
        }

        connections++;
    }

    if (connections == WORKER_NUM) {
        printf("[Server] Achieve maximum amount of connections\n");
    }

    for (int i = 0; i < WORKER_NUM; i++) {
        pthread_join(workers[i], NULL);
    }

    printf("[Server] Shuting down ..\n");
    shutdown(socket_fd, SHUT_RDWR);
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
