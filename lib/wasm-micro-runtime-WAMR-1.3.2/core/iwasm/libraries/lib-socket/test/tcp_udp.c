/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#ifdef __wasi__
#include <wasi/api.h>
#include <sys/socket.h>
#include <wasi_socket_ext.h>
#endif
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>

#define SERVER_MSG "Message from server."
#define PORT 8989

pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

int server_init_complete = 0;

typedef struct {
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int sock;
    int protocol;
} socket_info_t;

void
wait_for_server(int wait_time_seconds)
{
    int res = 0;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += wait_time_seconds;

    pthread_mutex_lock(&mut);
    while (server_init_complete == 0) {
        res = pthread_cond_timedwait(&cond, &mut, &ts);
        if (res == ETIMEDOUT)
            break;
    }
    pthread_mutex_unlock(&mut);

    assert(res == 0);
}

void
notify_server_started()
{
    pthread_mutex_lock(&mut);
    server_init_complete = 1;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mut);
}

socket_info_t
init_socket_addr(int family, int protocol)
{
    socket_info_t info;

    info.sock = socket(family, protocol, 0);
    assert(info.sock != -1);
    info.protocol = protocol;

    memset(&info.addr, 0, sizeof(info.addr));

    if (family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)&info.addr;
        addr->sin_family = AF_INET;
        addr->sin_port = htons(PORT);
        addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        info.addr_len = sizeof(struct sockaddr_in);
    }
    else if (family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&info.addr;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(PORT);
        addr->sin6_addr = in6addr_loopback;
        info.addr_len = sizeof(struct sockaddr_in6);
    }

    return info;
}

void *
server(void *arg)
{
    char buffer[sizeof(SERVER_MSG) + 1] = { 0 };
    struct sockaddr_storage client_addr;
    socket_info_t *info = (socket_info_t *)arg;
    struct sockaddr *server_addr = (struct sockaddr *)&info->addr;
    int server_sock = info->sock;

    int optval = 1;
    assert(setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval,
                      sizeof(optval))
           == 0);

    assert(bind(server_sock, server_addr, info->addr_len) == 0);

    if (info->protocol == SOCK_STREAM)
        listen(server_sock, 1);
    notify_server_started();

    socklen_t addr_size = info->addr_len;
    if (info->protocol == SOCK_STREAM) {
        int client_sock =
            accept(server_sock, (struct sockaddr *)&client_addr, &addr_size);
        assert(client_sock >= 0);
        assert(recv(client_sock, buffer, sizeof(buffer), 0) > 0);
        strcpy(buffer, SERVER_MSG);
        assert(send(client_sock, buffer, sizeof(buffer), 0) > 0);
        assert(recv(client_sock, buffer, sizeof(buffer), 0) > 0);
    }
    else {
        assert(recvfrom(server_sock, buffer, sizeof(buffer), 0,
                        (struct sockaddr *)&client_addr, &addr_size)
               > 0);
        strcpy(buffer, SERVER_MSG);
        assert(sendto(server_sock, buffer, strlen(buffer), 0,
                      (struct sockaddr *)&client_addr, addr_size)
               > 0);
        assert(recvfrom(server_sock, buffer, sizeof(buffer), 0,
                        (struct sockaddr *)&client_addr, &addr_size)
               > 0);
    }
    assert(close(server_sock) == 0);

    return NULL;
}

void *
client(void *arg)
{
    char buffer[sizeof(SERVER_MSG) + 1];
    socket_info_t *info = (socket_info_t *)arg;
    int sock = info->sock;
    struct sockaddr *addr = (struct sockaddr *)&info->addr;

    wait_for_server(1);

    if (info->protocol == SOCK_STREAM) {
        assert(connect(sock, addr, info->addr_len) != -1);
    }

    assert(sendto(sock, "open", strlen("open"), 0, addr, info->addr_len) > 0);
    assert(recv(sock, buffer, sizeof(buffer), 0) > 0);
    assert(strncmp(buffer, SERVER_MSG, strlen(SERVER_MSG)) == 0);
    assert(sendto(sock, "close", sizeof("close"), 0, addr, info->addr_len) > 0);
    assert(close(sock) == 0);

    return NULL;
}

void
test_protocol(int family, int protocol)
{
    pthread_t server_thread, client_thread;
    socket_info_t server_info = init_socket_addr(family, protocol);
    socket_info_t client_info = init_socket_addr(family, protocol);

    printf("Testing address family: %d protocol: %d\n", family, protocol);

    server_init_complete = 0;

    assert(pthread_create(&server_thread, NULL, server, (void *)&server_info)
           == 0);
    assert(pthread_create(&client_thread, NULL, client, (void *)&client_info)
           == 0);
    assert(pthread_join(server_thread, NULL) == 0);
    assert(pthread_join(client_thread, NULL) == 0);
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
