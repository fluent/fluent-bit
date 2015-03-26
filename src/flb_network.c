/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/types.h>          /* See NOTES */
#include <arpa/inet.h>

#include <fluent-bit/flb_network.h>

int flb_net_socket_reset(int sockfd)
{
    int status = 1;

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &status, sizeof(int)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int flb_net_socket_tcp_nodelay(int sockfd)
{
    int on = 1;
    return setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
}

int flb_net_socket_nonblocking(int sockfd)
{
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        return -1;
    }
    fcntl(sockfd, F_SETFD, FD_CLOEXEC);

    return 0;
}

/*
 * Enable the TCP_FASTOPEN feature for server side implemented in Linux Kernel >= 3.7,
 * for more details read here:
 *
 *  TCP Fast Open: expediting web services: http://lwn.net/Articles/508865/
 */
int flb_net_socket_tcp_fastopen(int sockfd)
{
    int qlen = 5;
    return setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
}

int flb_net_socket_create()
{
    int fd;

    /* create the socket and set the nonblocking flag status */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd <= 0) {
        perror("socket");
        return -1;
    }
    flb_net_socket_tcp_nodelay(fd);

    return fd;
}

/* Connect to a TCP socket server and returns the file descriptor */
int flb_net_tcp_connect(char *host, unsigned long port)
{
    int sock_fd;
    struct sockaddr_in *remote;
    struct hostent *hostp;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd <= 0) {
        printf("Error: could not create socket\n");
        return -1;
    }

    remote = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
    remote->sin_family = AF_INET;

    hostp = gethostbyname(host);
    if (hostp == NULL) {
        close(sock_fd);
        return -1;
    }
    memcpy(&remote->sin_addr, hostp->h_addr, sizeof(remote->sin_addr));
    remote->sin_port = htons(port);
    if (connect(sock_fd,
                (struct sockaddr *) remote, sizeof(struct sockaddr)) == -1) {
        close(sock_fd);
        free(remote);
        return -1;
    }

    free(remote);
    return sock_fd;
}

int flb_net_server(char *port, char *listen_addr)
{
    int socket_fd = -1;
    int ret;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    ret = getaddrinfo(listen_addr, port, &hints, &res);
    if(ret != 0) {
        fprintf(stderr, "Can't get addr info: %s", gai_strerror(ret));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        socket_fd = flb_net_socket_create();
        if (socket_fd == -1) {
            fprintf(stderr, "Error creating server socket, retrying");
            continue;
        }

        flb_net_socket_tcp_nodelay(socket_fd);
        flb_net_socket_reset(socket_fd);

        ret = flb_net_bind(socket_fd, rp->ai_addr, rp->ai_addrlen, 128);
        if(ret == -1) {
            fprintf(stderr, "Cannot listen on %s:%s\n", listen_addr, port);
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (rp == NULL) {
        return -1;
    }

    return socket_fd;
}

int flb_net_bind(int socket_fd, const struct sockaddr *addr,
                 socklen_t addrlen, int backlog)
{
    int ret;

    ret = bind(socket_fd, addr, addrlen);
    if( ret == -1 ) {
        fprintf(stderr, "Error binding socket");
        return ret;
    }

    ret = listen(socket_fd, backlog);
    if(ret == -1 ) {
        fprintf(stderr, "Error setting up the listener");
        return -1;
    }

    return ret;
}

int flb_net_accept(int server_fd)
{
    int remote_fd;
    struct sockaddr sock_addr;
    socklen_t socket_size = sizeof(struct sockaddr);

    remote_fd = accept4(server_fd, &sock_addr, &socket_size,
                        SOCK_NONBLOCK | SOCK_CLOEXEC);

    if (remote_fd == -1) {
        perror("accept4");
    }

    return remote_fd;
}

int flb_net_socket_ip_str(int socket_fd, char **buf, int size, unsigned long *len)
{
    int ret;
    struct sockaddr_storage addr;
    socklen_t s_len = sizeof(addr);

    ret = getpeername(socket_fd, (struct sockaddr *) &addr, &s_len);
    if (ret == -1) {
        return -1;
    }

    errno = 0;

    if(addr.ss_family == AF_INET) {
        if((inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr,
                      *buf, size)) == NULL) {
            fprintf(stderr, "socket_ip_str: Can't get the IP text form (%i)", errno);
            return -1;
        }
    }
    else if(addr.ss_family == AF_INET6) {
        if((inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr,
                      *buf, size)) == NULL) {
            fprintf(stderr, "socket_ip_str: Can't get the IP text form (%i)", errno);
            return -1;
        }
    }

    *len = strlen(*buf);
    return 0;
}
