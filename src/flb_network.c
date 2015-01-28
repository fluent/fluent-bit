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
        printf("Error connecting to %s:%lu\n", host, port);
        free(remote);
        return -1;
    }

    free(remote);
    return sock_fd;
}
