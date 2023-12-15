/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <unistd.h>
#include <string.h>
#include <assert.h>
#ifdef __wasi__
#include <wasi/api.h>
#include <sys/socket.h>
#include <wasi_socket_ext.h>
#endif
#include <arpa/inet.h>
#include <pthread.h>
#define SERVER_MSG "Message from server."
#define PORT 8989
pthread_mutex_t mut;
pthread_cond_t cond;
int server_init_complete = 0;
char buffer[sizeof(SERVER_MSG) + 1];

struct socket_info {
    union {
        struct sockaddr_in addr_ipv4;
        struct sockaddr_in6 addr_ipv6;
    } addr;
    int sock;
};

struct thread_args {
    int family;
    int protocol;
};

struct socket_info
init_socket_addr(int family, int protocol)
{
    int sock = socket(family, protocol, 0);
    assert(sock != -1);

    struct socket_info info;
    if (family == AF_INET) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        info.addr.addr_ipv4 = addr;
    }
    else if (family == AF_INET6) {
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(PORT);
        addr.sin6_addr = in6addr_loopback;
        info.addr.addr_ipv6 = addr;
    }
    info.sock = sock;
    return info;
}

void
assert_thread_args(struct thread_args *args)
{
    assert(args->family == AF_INET || args->family == AF_INET6);
    assert(args->protocol == SOCK_STREAM || args->protocol == SOCK_DGRAM);
}

void *
server(void *arg)
{
    server_init_complete = 0;
    struct thread_args *args = (struct thread_args *)arg;
    assert_thread_args(args);

    struct socket_info init_server_sock =
        init_socket_addr(args->family, args->protocol);

    int server_sock = init_server_sock.sock;
    socklen_t addr_size;
    struct sockaddr_storage client_addr;
    strcpy(buffer, SERVER_MSG);

    struct sockaddr *server_addr = (struct sockaddr *)&init_server_sock.addr;
    int ret = bind(server_sock, server_addr,
                   args->family == AF_INET ? sizeof(struct sockaddr_in)
                                           : sizeof(struct sockaddr_in6));
    assert(ret == 0);

    (args->protocol == SOCK_STREAM) && listen(server_sock, 1);
    pthread_mutex_lock(&mut);
    server_init_complete = 1;
    pthread_mutex_unlock(&mut);
    pthread_cond_signal(&cond);

    addr_size = sizeof(client_addr);
    if (args->protocol == SOCK_STREAM) {
        int client_sock =
            accept(server_sock, (struct sockaddr *)&client_addr, &addr_size);
        assert(client_sock >= 0);
        sendto(client_sock, buffer, strlen(buffer), 0,
               (struct sockaddr *)&client_addr, addr_size);

        assert(close(client_sock) == 0);
    }
    else {
        recvfrom(server_sock, buffer, sizeof(buffer), 0,
                 (struct sockaddr *)&client_addr, &addr_size);
        sendto(server_sock, buffer, strlen(buffer), 0,
               (struct sockaddr *)&client_addr, addr_size);

        assert(close(server_sock) == 0);
    }

    return NULL;
}

void *
client(void *arg)
{
    struct thread_args *args = (struct thread_args *)arg;
    assert_thread_args(args);

    pthread_mutex_lock(&mut);

    while (server_init_complete == 0) {
        pthread_cond_wait(&cond, &mut);
    }

    struct socket_info init_client_sock =
        init_socket_addr(args->family, args->protocol);
    int sock = init_client_sock.sock;
    pthread_mutex_unlock(&mut);

    if (args->family == AF_INET) {
        struct sockaddr_in addr = init_client_sock.addr.addr_ipv4;
        if (args->protocol == SOCK_STREAM) {
            assert(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != -1);
        }
        else {
            assert(sendto(sock, buffer, strlen(buffer), 0,
                          (struct sockaddr *)&addr, sizeof(addr))
                   != -1);
        }
    }
    else {
        struct sockaddr_in6 addr = init_client_sock.addr.addr_ipv6;
        if (args->protocol == SOCK_STREAM) {
            assert(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != -1);
        }
        else {
            assert(sendto(sock, buffer, strlen(buffer), 0,
                          (struct sockaddr *)&addr, sizeof(addr))
                   != -1);
        }
    }

    recv(sock, buffer, sizeof(buffer), 0);
    assert(strcmp(buffer, SERVER_MSG) == 0);
    assert(close(sock) == 0);
    return NULL;
}

void
test_protocol(int family, int protocol)
{
    pthread_t server_thread, client_thread;
    assert(pthread_cond_init(&cond, NULL) == 0);
    assert(pthread_mutex_init(&mut, NULL) == 0);

    struct thread_args args = { family, protocol };
    assert(pthread_create(&server_thread, NULL, server, (void *)&args) == 0);
    assert(pthread_create(&client_thread, NULL, client, (void *)&args) == 0);
    assert(pthread_join(server_thread, NULL) == 0);
    assert(pthread_join(client_thread, NULL) == 0);

    assert(pthread_mutex_destroy(&mut) == 0);
    assert(pthread_cond_destroy(&cond) == 0);
}

int
main(int argc, char **argv)
{
    /* test tcp with ipv4 and ipv6 */
    test_protocol(AF_INET, SOCK_STREAM);
    test_protocol(AF_INET6, SOCK_STREAM);

    /* test udp with ipv4 and ipv6 */
    test_protocol(AF_INET, SOCK_DGRAM);
    test_protocol(AF_INET6, SOCK_DGRAM);

    return 0;
}