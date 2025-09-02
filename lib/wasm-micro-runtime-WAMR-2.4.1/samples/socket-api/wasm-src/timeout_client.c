/*
 * Copyright (C) 2022 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef __wasi__
#include <wasi_socket_ext.h>
#endif

int
main(int argc, char *argv[])
{
    int socket_fd;
    struct sockaddr_in addr;
    struct timeval tv = { 0, 1 };
    const int snd_buf_len = 8;
    const int data_buf_len = 1000000;
    char *buffer = (char *)malloc(sizeof(char) * data_buf_len);
    int result;
    socklen_t opt_len = sizeof(snd_buf_len);
    struct timeval snd_start_time, snd_end_time;
    int bool_opt = 1;

    if (buffer == NULL) {
        perror("Allocation failed, please re-run with larger heap size");
        return EXIT_FAILURE;
    }

    /* 127.0.0.1:1234 */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Create socket failed");
        goto fail1;
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &bool_opt,
                   sizeof(bool_opt))
        == -1) {
        perror("Failed setting SO_REUSEADDR");
        goto fail2;
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        perror("Failed setting SO_RCVTIMEO");
        goto fail2;
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
        perror("Failed setting SO_SNDTIMEO");
        goto fail2;
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &data_buf_len,
                   sizeof(data_buf_len))
        == -1) {
        perror("Failed setting SO_SNDBUF");
        goto fail2;
    }

    if (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("Connect failed");
        goto fail2;
    }

    if (getsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, (void *)&data_buf_len,
                   &opt_len)
        == -1) {
        perror("Failed getting SO_SNDBUF");
        goto fail2;
    }

    printf("Waiting on recv, which should timeout\n");
    result = recv(socket_fd, buffer, 1, 0);

    if (result != -1 || errno != EAGAIN) {
        perror("Recv did not timeout as expected");
        goto fail2;
    }

    printf("Waiting on send, which should timeout\n");
    gettimeofday(&snd_start_time, NULL);
    result = send(socket_fd, buffer, data_buf_len, 0);
    gettimeofday(&snd_end_time, NULL);

    if (result >= data_buf_len
        || snd_start_time.tv_sec != snd_end_time.tv_sec) {
        perror("Send did not timeout as expected");
        goto fail2;
    }

    printf("Success. Closing socket \n");
    close(socket_fd);
    free(buffer);
    return EXIT_SUCCESS;

fail2:
    close(socket_fd);
fail1:
    free(buffer);
    return EXIT_FAILURE;
}
