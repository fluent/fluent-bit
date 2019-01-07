/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_macros.h>

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

/* Copy a sub-string in a new memory buffer */
static char *copy_substr(char *str, int s)
{
    char *buf;

    buf = flb_malloc(s + 1);
    strncpy(buf, str, s);
    buf[s] = '\0';

    return buf;
}

int flb_net_host_set(char *plugin_name, struct flb_net_host *host, char *address)
{
    int len;
    int olen;
    char *s, *e, *u;

    memset(host, '\0', sizeof(struct flb_net_host));

    olen = strlen(address);
    if (olen == strlen(plugin_name)) {
        return 0;
    }

    len = strlen(plugin_name) + 3;
    if (olen < len) {
        return -1;
    }

    s = address + len;
    if (*s == '[') {
        /* IPv6 address (RFC 3986) */
        e = strchr(++s, ']');
        if (!e) {
            return -1;
        }
        host->name = copy_substr(s, e - s);
        host->ipv6 = FLB_TRUE;
        s = e + 1;
    } else {
        e = s;
        while (!(*e == '\0' || *e == ':' || *e == '/')) {
            ++e;
        }
        if (e == s) {
            return -1;
        }
        host->name = copy_substr(s, e - s);
        s = e;
    }
    if (*s == ':') {
        host->port = atoi(++s);
    }

    u = strchr(s, '/');
    if (u) {
        host->uri = flb_uri_create(u);
    }
    host->address = flb_strdup(address);

    if (host->name) {
        host->listen = host->name;
    }

    return 0;
}

int flb_net_socket_reset(flb_sockfd_t fd)
{
    int status = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &status, sizeof(int)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int flb_net_socket_tcp_nodelay(flb_sockfd_t fd)
{
    int on = 1;
    int ret;

    ret = setsockopt(fd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
    if (ret == -1) {
        perror("setsockopt");
        return -1;
    }

    return 0;
}

int flb_net_socket_nonblocking(flb_sockfd_t fd)
{
#ifdef _WIN32
    unsigned long on = 1;
    if (ioctlsocket(fd, FIONBIO, &on) != 0) {
#else
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1) {
#endif
        perror("fcntl");
        return -1;
    }

    return 0;
}

/*
 * Enable the TCP_FASTOPEN feature for server side implemented in Linux Kernel >= 3.7,
 * for more details read here:
 *
 *  TCP Fast Open: expediting web services: http://lwn.net/Articles/508865/
 */
int flb_net_socket_tcp_fastopen(flb_sockfd_t fd)
{
    int qlen = 5;
    return setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
}

flb_sockfd_t flb_net_socket_create(int family, int nonblock)
{
    flb_sockfd_t fd;

    /* create the socket and set the nonblocking flag status */
    fd = socket(family, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    if (nonblock) {
        flb_net_socket_nonblocking(fd);
    }

    return fd;
}

flb_sockfd_t flb_net_socket_create_udp(int family, int nonblock)
{
    flb_sockfd_t fd;

    /* create the socket and set the nonblocking flag status */
    fd = socket(family, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    if (nonblock) {
        flb_net_socket_nonblocking(fd);
    }

    return fd;
}

/* Connect to a TCP socket server and returns the file descriptor */
flb_sockfd_t flb_net_tcp_connect(char *host, unsigned long port)
{
    flb_sockfd_t fd = -1;
    int ret;
    struct addrinfo hints;
    struct addrinfo *res, *rp;
    char _port[6];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(_port, sizeof(_port), "%lu", port);
    ret = getaddrinfo(host, _port, &hints, &res);
    if (ret != 0) {
        flb_warn("net_tcp_connect: getaddrinfo(host='%s'): %s",
                 host, gai_strerror(ret));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = flb_net_socket_create(rp->ai_family, 0);
        if (fd == -1) {
            flb_error("Error creating client socket, retrying");
            continue;
        }

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
            flb_error("Cannot connect to %s port %s", host, _port);
            flb_socket_close(fd);
            continue;
        }
        break;
    }

    freeaddrinfo(res);

    if (rp == NULL) {
        return -1;
    }

    return fd;
}

/* "Connect" to a UDP socket server and returns the file descriptor */
flb_sockfd_t flb_net_udp_connect(char *host, unsigned long port)
{
    flb_sockfd_t fd = -1;
    int ret;
    struct addrinfo hints;
    struct addrinfo *res, *rp;
    char _port[6];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    snprintf(_port, sizeof(_port), "%lu", port);
    ret = getaddrinfo(host, _port, &hints, &res);
    if (ret != 0) {
        flb_warn("net_udp_connect: getaddrinfo(host='%s'): %s",
                 host, gai_strerror(ret));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = flb_net_socket_create_udp(rp->ai_family, 0);
        if (fd == -1) {
            flb_error("Error creating client socket, retrying");
            continue;
        }

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
            flb_error("Cannot connect to %s port %s", host, _port);
            flb_socket_close(fd);
            continue;
        }
        break;
    }

    freeaddrinfo(res);

    if (rp == NULL) {
        return -1;
    }

    return fd;
}

/* Connect to a TCP socket server and returns the file descriptor */
int flb_net_tcp_fd_connect(flb_sockfd_t fd, char *host, unsigned long port)
{
    int ret;
    struct addrinfo hints;
    struct addrinfo *res;
    char _port[6];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(_port, sizeof(_port), "%lu", port);
    ret = getaddrinfo(host, _port, &hints, &res);
    if (ret != 0) {
        flb_warn("net_tcp_fd_connect: getaddrinfo(host='%s'): %s",
                 host, gai_strerror(ret));
        return -1;
    }

    ret = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    return ret;
}

flb_sockfd_t flb_net_server(char *port, char *listen_addr)
{
    flb_sockfd_t fd = -1;
    int ret;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    ret = getaddrinfo(listen_addr, port, &hints, &res);
    if (ret != 0) {
        flb_warn("net_server: getaddrinfo(listen='%s:%s'): %s",
                 listen_addr, port, gai_strerror(ret));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = flb_net_socket_create(rp->ai_family, 1);
        if (fd == -1) {
            flb_error("Error creating server socket, retrying");
            continue;
        }

        flb_net_socket_tcp_nodelay(fd);
        flb_net_socket_reset(fd);

        ret = flb_net_bind(fd, rp->ai_addr, rp->ai_addrlen, 128);
        if(ret == -1) {
            flb_warn("Cannot listen on %s port %s", listen_addr, port);
            flb_socket_close(fd);
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (rp == NULL) {
        return -1;
    }

    return fd;
}

flb_sockfd_t flb_net_server_udp(char *port, char *listen_addr)
{
    flb_sockfd_t fd = -1;
    int ret;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    ret = getaddrinfo(listen_addr, port, &hints, &res);
    if (ret != 0) {
        flb_warn("net_server_udp: getaddrinfo(listen='%s:%s'): %s",
                 listen_addr, port, gai_strerror(ret));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = flb_net_socket_create_udp(rp->ai_family, 0);
        if (fd == -1) {
            flb_error("Error creating server socket, retrying");
            continue;
        }

        ret = flb_net_bind_udp(fd, rp->ai_addr, rp->ai_addrlen);
        if(ret == -1) {
            flb_warn("Cannot listen on %s port %s", listen_addr, port);
            flb_socket_close(fd);
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (rp == NULL) {
        return -1;
    }

    return fd;
}

int flb_net_bind(flb_sockfd_t fd, const struct sockaddr *addr,
                 socklen_t addrlen, int backlog)
{
    int ret;

    ret = bind(fd, addr, addrlen);
    if( ret == -1 ) {
        flb_error("Error binding socket");
        return ret;
    }

    ret = listen(fd, backlog);
    if(ret == -1 ) {
        flb_error("Error setting up the listener");
        return -1;
    }

    return ret;
}

int flb_net_bind_udp(flb_sockfd_t fd, const struct sockaddr *addr,
                 socklen_t addrlen)
{
    int ret;

    ret = bind(fd, addr, addrlen);
    if( ret == -1 ) {
        flb_error("Error binding socket");
        return ret;
    }

    return ret;
}

flb_sockfd_t flb_net_accept(flb_sockfd_t server_fd)
{
    flb_sockfd_t remote_fd;
    struct sockaddr sock_addr;
    socklen_t socket_size = sizeof(struct sockaddr);

#ifdef FLB_HAVE_ACCEPT4
    remote_fd = accept4(server_fd, &sock_addr, &socket_size,
                        SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    remote_fd = accept(server_fd, &sock_addr, &socket_size);
    flb_net_socket_nonblocking(remote_fd);
#endif

    if (remote_fd == -1) {
        perror("accept4");
    }

    return remote_fd;
}

int flb_net_socket_ip_str(flb_sockfd_t fd, char **buf, int size, unsigned long *len)
{
    int ret;
    struct sockaddr_storage addr;
    socklen_t s_len = sizeof(addr);

    ret = getpeername(fd, (struct sockaddr *) &addr, &s_len);
    if (ret == -1) {
        return -1;
    }

    errno = 0;

    if (addr.ss_family == AF_INET) {
        if ((inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr,
                      *buf, size)) == NULL) {
            flb_error("socket_ip_str: Can't get the IP text form (%i)",
                      errno);
            return -1;
        }
    }
    else if (addr.ss_family == AF_INET6) {
        if ((inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr,
                       *buf, size)) == NULL) {
            flb_error("socket_ip_str: Can't get the IP text form (%i)",
                      errno);
            return -1;
        }
    }

    *len = strlen(*buf);
    return 0;
}
