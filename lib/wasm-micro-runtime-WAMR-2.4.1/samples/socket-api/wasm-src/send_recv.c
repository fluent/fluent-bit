/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <arpa/inet.h>
#include <assert.h>
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

static pthread_mutex_t lock = { 0 };
static pthread_cond_t cond = { 0 };
static bool server_create_failed = false;
static bool server_is_ready = false;

void *
run_as_server(void *arg)
{
    (void)arg;
    int sock = -1, on = 1;
    struct sockaddr_in addr = { 0 };
    int addrlen = 0;
    int new_sock = -1;
    char *buf[] = {
        "The stars shine down", "It brings us light", "Light comes down",
        "To make us paths",     "It watches us",      "And mourns for us",
    };
    struct iovec iov[] = {
        { .iov_base = buf[0], .iov_len = strlen(buf[0]) + 1 },
        { .iov_base = buf[1], .iov_len = strlen(buf[1]) + 1 },
        { .iov_base = buf[2], .iov_len = strlen(buf[2]) + 1 },
        { .iov_base = buf[3], .iov_len = strlen(buf[3]) + 1 },
        { .iov_base = buf[4], .iov_len = strlen(buf[4]) + 1 },
        { .iov_base = buf[5], .iov_len = strlen(buf[5]) + 1 },
    };
    struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 6 };
    ssize_t send_len = 0;

    pthread_mutex_lock(&lock);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        server_create_failed = true;
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&lock);
        perror("Create a socket failed");
        return NULL;
    }

#ifndef __wasi__
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on))) {
        server_create_failed = true;
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&lock);
        perror("Setsockopt failed");
        goto fail1;
    }
#endif

    /* 0.0.0.0:1234 */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    addrlen = sizeof(addr);
    if (bind(sock, (struct sockaddr *)&addr, addrlen) < 0) {
        server_create_failed = true;
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&lock);
        perror("Bind failed");
        goto fail1;
    }

    if (listen(sock, 0) < 0) {
        server_create_failed = true;
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&lock);
        perror("Listen failed");
        goto fail1;
    }

    server_is_ready = true;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);

    printf("Server is online ... \n");

    new_sock = accept(sock, (struct sockaddr *)&addr, (socklen_t *)&addrlen);
    if (new_sock < 0) {
        perror("Accept failed");
        goto fail1;
    }

    printf("Start sending. \n");
    send_len = sendmsg(new_sock, &msg, 0);
    if (send_len < 0) {
        perror("Sendmsg failed");
        goto fail2;
    }
    printf("Send %ld bytes successfully!\n", send_len);

fail2:
    close(new_sock);
fail1:
    shutdown(sock, SHUT_RDWR);
    close(sock);
    return NULL;
}

void *
run_as_client(void *arg)
{
    (void)arg;
    int sock = -1;
    struct sockaddr_in addr = { 0 };
    /* buf of server is 106 bytes */
    char buf[110] = { 0 };
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
    ssize_t recv_len = 0;

    pthread_mutex_lock(&lock);
    while (!server_create_failed && !server_is_ready) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

    if (server_create_failed) {
        return NULL;
    }

    printf("Client is running...\n");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Create a socket failed");
        return NULL;
    }

    /* 127.0.0.1:1234 */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Connect failed");
        goto fail;
    }

    printf("Start receiving. \n");
    recv_len = recvmsg(sock, &msg, 0);
    if (recv_len < 0) {
        perror("Recvmsg failed");
        goto fail;
    }

    printf("Receive %ld bytes successfully!\n", recv_len);
    assert(recv_len == 106);

    printf("Data:\n");
    char *s = msg.msg_iov->iov_base;
    while (strlen(s) > 0) {
        printf("  %s\n", s);
        s += strlen(s) + 1;
    }

fail:
    shutdown(sock, SHUT_RDWR);
    close(sock);
    return NULL;
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    pthread_t cs[2] = { 0 };
    uint8_t i = 0;
    int ret = EXIT_SUCCESS;

    if (pthread_mutex_init(&lock, NULL)) {
        perror("Initialize mutex failed");
        ret = EXIT_FAILURE;
        goto RETURN;
    }

    if (pthread_cond_init(&cond, NULL)) {
        perror("Initialize condition failed");
        ret = EXIT_FAILURE;
        goto DESTROY_MUTEX;
    }

    if (pthread_create(&cs[0], NULL, run_as_server, NULL)) {
        perror("Create a server thread failed");
        ret = EXIT_FAILURE;
        goto DESTROY_COND;
    }

    if (pthread_create(&cs[1], NULL, run_as_client, NULL)) {
        perror("Create a client thread failed");
        ret = EXIT_FAILURE;
        goto DESTROY_COND;
    }

    for (i = 0; i < 2; i++) {
        pthread_join(cs[i], NULL);
    }

DESTROY_COND:
    pthread_cond_destroy(&cond);
DESTROY_MUTEX:
    pthread_mutex_destroy(&lock);
RETURN:
    return ret;
}
