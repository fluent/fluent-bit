/*
 * Copyright (C) 2022 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef __wasi__
#include <wasi_socket_ext.h>
#endif

#define MULTICAST_ADDR 16777440
#define OPTION_ASSERT(A, B, OPTION)           \
    if (A == B) {                             \
        printf("%s is expected\n", OPTION);   \
    }                                         \
    else {                                    \
        printf("%s is unexpected\n", OPTION); \
        perror("assertion failed");           \
        return EXIT_FAILURE;                  \
    }

static struct timeval
to_timeval(time_t tv_sec, suseconds_t tv_usec)
{
    struct timeval tv = { tv_sec, tv_usec };
    return tv;
}

static int
set_and_get_bool_opt(int socket_fd, int level, int optname, int val)
{
    int bool_opt = val;
    int ret = -1;
    socklen_t opt_len = sizeof(bool_opt);

    ret = setsockopt(socket_fd, level, optname, &bool_opt, sizeof(bool_opt));
    if (ret != 0)
        return !val;

    bool_opt = !bool_opt;
    ret = getsockopt(socket_fd, level, optname, &bool_opt, &opt_len);
    if (ret != 0)
        return !val;

    return bool_opt;
}

int
main(int argc, char *argv[])
{
    int tcp_socket_fd = 0;
    int udp_socket_fd = 0;
    int udp_ipv6_socket_fd = 0;
    struct timeval tv;
    socklen_t opt_len;
    int buf_len;
    int result;
    struct linger linger_opt;
    uint32_t time_s;
    int ttl;

    printf("[Client] Create TCP socket\n");
    tcp_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_socket_fd == -1) {
        perror("Create socket failed");
        return EXIT_FAILURE;
    }

    printf("[Client] Create UDP socket\n");
    udp_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket_fd == -1) {
        perror("Create socket failed");
        return EXIT_FAILURE;
    }

    printf("[Client] Create UDP IPv6 socket\n");
    udp_ipv6_socket_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (udp_ipv6_socket_fd == -1) {
        perror("Create socket failed");
        return EXIT_FAILURE;
    }

    // SO_RCVTIMEO
    tv = to_timeval(123, 1000);
    result =
        setsockopt(tcp_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    OPTION_ASSERT(result, 0, "setsockopt SO_RCVTIMEO result")

    tv = to_timeval(0, 0);
    opt_len = sizeof(tv);
    result = getsockopt(tcp_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &opt_len);
    OPTION_ASSERT(result, 0, "getsockopt SO_RCVTIMEO result")
    OPTION_ASSERT(tv.tv_sec, 123, "SO_RCVTIMEO tv_sec");
    // OPTION_ASSERT(tv.tv_usec, 1000, "SO_RCVTIMEO tv_usec");

    // SO_SNDTIMEO
    tv = to_timeval(456, 2000);
    result =
        setsockopt(tcp_socket_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    OPTION_ASSERT(result, 0, "setsockopt SO_SNDTIMEO result")

    tv = to_timeval(0, 0);
    opt_len = sizeof(tv);
    result = getsockopt(tcp_socket_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, &opt_len);
    OPTION_ASSERT(result, 0, "getsockopt SO_SNDTIMEO result")
    OPTION_ASSERT(tv.tv_sec, 456, "SO_SNDTIMEO tv_sec");
    // OPTION_ASSERT(tv.tv_usec, 2000, "SO_SNDTIMEO tv_usec");

    // SO_SNDBUF
    buf_len = 8192;
    result = setsockopt(tcp_socket_fd, SOL_SOCKET, SO_SNDBUF, &buf_len,
                        sizeof(buf_len));
    OPTION_ASSERT(result, 0, "setsockopt SO_SNDBUF result")

    buf_len = 0;
    opt_len = sizeof(buf_len);
    result =
        getsockopt(tcp_socket_fd, SOL_SOCKET, SO_SNDBUF, &buf_len, &opt_len);
    OPTION_ASSERT(result, 0, "getsockopt SO_SNDBUF result")
    OPTION_ASSERT((buf_len == 16384 || buf_len == 8192), 1,
                  "SO_SNDBUF buf_len");

    // SO_RCVBUF
    buf_len = 4096;
    result = setsockopt(tcp_socket_fd, SOL_SOCKET, SO_RCVBUF, &buf_len,
                        sizeof(buf_len));
    OPTION_ASSERT(result, 0, "setsockopt SO_RCVBUF result")

    buf_len = 0;
    opt_len = sizeof(buf_len);
    result =
        getsockopt(tcp_socket_fd, SOL_SOCKET, SO_RCVBUF, &buf_len, &opt_len);
    OPTION_ASSERT(result, 0, "getsockopt SO_RCVBUF result")
    OPTION_ASSERT((buf_len == 8192 || buf_len == 4096), 1, "SO_SNDBUF buf_len");

    // SO_KEEPALIVE
    OPTION_ASSERT(
        set_and_get_bool_opt(tcp_socket_fd, SOL_SOCKET, SO_KEEPALIVE, 1), 1,
        "SO_KEEPALIVE enabled");
    OPTION_ASSERT(
        set_and_get_bool_opt(tcp_socket_fd, SOL_SOCKET, SO_KEEPALIVE, 0), 0,
        "SO_KEEPALIVE disabled");

    // SO_REUSEADDR
    OPTION_ASSERT(
        set_and_get_bool_opt(tcp_socket_fd, SOL_SOCKET, SO_REUSEADDR, 1), 1,
        "SO_REUSEADDR enabled");
    OPTION_ASSERT(
        set_and_get_bool_opt(tcp_socket_fd, SOL_SOCKET, SO_REUSEADDR, 0), 0,
        "SO_REUSEADDR disabled");

    // SO_REUSEPORT
    OPTION_ASSERT(
        set_and_get_bool_opt(tcp_socket_fd, SOL_SOCKET, SO_REUSEPORT, 1), 1,
        "SO_REUSEPORT enabled");
    OPTION_ASSERT(
        set_and_get_bool_opt(tcp_socket_fd, SOL_SOCKET, SO_REUSEPORT, 0), 0,
        "SO_REUSEPORT disabled");

    // SO_LINGER
    linger_opt.l_onoff = 1;
    linger_opt.l_linger = 10;
    result = setsockopt(tcp_socket_fd, SOL_SOCKET, SO_LINGER, &linger_opt,
                        sizeof(linger_opt));
    OPTION_ASSERT(result, 0, "setsockopt SO_LINGER result")

    linger_opt.l_onoff = 0;
    linger_opt.l_linger = 0;
    opt_len = sizeof(linger_opt);
    result =
        getsockopt(tcp_socket_fd, SOL_SOCKET, SO_LINGER, &linger_opt, &opt_len);
    OPTION_ASSERT(result, 0, "getsockopt SO_LINGER result")
    OPTION_ASSERT(linger_opt.l_onoff, 1, "SO_LINGER l_onoff");
    OPTION_ASSERT(linger_opt.l_linger, 10, "SO_LINGER l_linger");

    // SO_BROADCAST
    OPTION_ASSERT(
        set_and_get_bool_opt(udp_socket_fd, SOL_SOCKET, SO_BROADCAST, 1), 1,
        "SO_BROADCAST enabled");
    OPTION_ASSERT(
        set_and_get_bool_opt(udp_socket_fd, SOL_SOCKET, SO_BROADCAST, 0), 0,
        "SO_BROADCAST disabled");

    // TCP_KEEPIDLE
#ifdef TCP_KEEPIDLE
    time_s = 16;
    result = setsockopt(tcp_socket_fd, IPPROTO_TCP, TCP_KEEPIDLE, &time_s,
                        sizeof(time_s));
    OPTION_ASSERT(result, 0, "setsockopt TCP_KEEPIDLE result")

    time_s = 0;
    opt_len = sizeof(time_s);
    result =
        getsockopt(tcp_socket_fd, IPPROTO_TCP, TCP_KEEPIDLE, &time_s, &opt_len);
    OPTION_ASSERT(result, 0, "getsockopt TCP_KEEPIDLE result")
    OPTION_ASSERT(time_s, 16, "TCP_KEEPIDLE");
#endif

    // TCP_KEEPINTVL
    time_s = 8;
    result = setsockopt(tcp_socket_fd, IPPROTO_TCP, TCP_KEEPINTVL, &time_s,
                        sizeof(time_s));
    OPTION_ASSERT(result, 0, "setsockopt TCP_KEEPINTVL result")

    time_s = 0;
    opt_len = sizeof(time_s);
    result = getsockopt(tcp_socket_fd, IPPROTO_TCP, TCP_KEEPINTVL, &time_s,
                        &opt_len);
    OPTION_ASSERT(result, 0, "getsockopt TCP_KEEPINTVL result")
    OPTION_ASSERT(time_s, 8, "TCP_KEEPINTVL");

    // TCP_FASTOPEN_CONNECT
#ifdef TCP_FASTOPEN_CONNECT
    OPTION_ASSERT(set_and_get_bool_opt(tcp_socket_fd, IPPROTO_TCP,
                                       TCP_FASTOPEN_CONNECT, 1),
                  1, "TCP_FASTOPEN_CONNECT enabled");
    OPTION_ASSERT(set_and_get_bool_opt(tcp_socket_fd, IPPROTO_TCP,
                                       TCP_FASTOPEN_CONNECT, 0),
                  0, "TCP_FASTOPEN_CONNECT disabled");
#endif

    // TCP_NODELAY
    OPTION_ASSERT(
        set_and_get_bool_opt(tcp_socket_fd, IPPROTO_TCP, TCP_NODELAY, 1), 1,
        "TCP_NODELAY enabled");
    OPTION_ASSERT(
        set_and_get_bool_opt(tcp_socket_fd, IPPROTO_TCP, TCP_NODELAY, 0), 0,
        "TCP_NODELAY disabled");

    // TCP_QUICKACK
#ifdef TCP_QUICKACK
    OPTION_ASSERT(
        set_and_get_bool_opt(tcp_socket_fd, IPPROTO_TCP, TCP_QUICKACK, 1), 1,
        "TCP_QUICKACK enabled");
    OPTION_ASSERT(
        set_and_get_bool_opt(tcp_socket_fd, IPPROTO_TCP, TCP_QUICKACK, 0), 0,
        "TCP_QUICKACK disabled");
#endif

    // IP_TTL
    ttl = 8;
    result = setsockopt(tcp_socket_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    OPTION_ASSERT(result, 0, "IP_TIL");
    ttl = 0;
    opt_len = sizeof(ttl);
    result = getsockopt(tcp_socket_fd, IPPROTO_IP, IP_TTL, &ttl, &opt_len);
    OPTION_ASSERT(ttl, 8, "IP_TTL");
    OPTION_ASSERT(result, 0, "IP_TIL");

    // IPV6_V6ONLY
    OPTION_ASSERT(
        set_and_get_bool_opt(udp_ipv6_socket_fd, IPPROTO_IPV6, IPV6_V6ONLY, 1),
        1, "IPV6_V6ONLY enabled");
    OPTION_ASSERT(
        set_and_get_bool_opt(udp_ipv6_socket_fd, IPPROTO_IPV6, IPV6_V6ONLY, 0),
        0, "IPV6_V6ONLY disabled");

    // IP_MULTICAST_LOOP
    OPTION_ASSERT(
        set_and_get_bool_opt(udp_socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, 1),
        1, "IP_MULTICAST_LOOP enabled");
    OPTION_ASSERT(
        set_and_get_bool_opt(udp_socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, 0),
        0, "IP_MULTICAST_LOOP disabled");

    // IP_MULTICAST_TTL
    ttl = 8;
    result = setsockopt(udp_socket_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
                        sizeof(ttl));
    OPTION_ASSERT(result, 0, "IP_MULTICAST_TTL");
    ttl = 0;
    opt_len = sizeof(ttl);
    result =
        getsockopt(udp_socket_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, &opt_len);
    OPTION_ASSERT(ttl, 8, "IP_MULTICAST_TTL");
    OPTION_ASSERT(result, 0, "IP_MULTICAST_TTL");

    // IPV6_MULTICAST_LOOP
    OPTION_ASSERT(set_and_get_bool_opt(udp_ipv6_socket_fd, IPPROTO_IPV6,
                                       IPV6_MULTICAST_LOOP, 1),
                  1, "IPV6_MULTICAST_LOOP enabled");
    OPTION_ASSERT(set_and_get_bool_opt(udp_ipv6_socket_fd, IPPROTO_IPV6,
                                       IPV6_MULTICAST_LOOP, 0),
                  0, "IPV6_MULTICAST_LOOP disabled");

    printf("[Client] Close sockets\n");
    close(tcp_socket_fd);
    close(udp_socket_fd);
    close(udp_ipv6_socket_fd);
    return EXIT_SUCCESS;
}
