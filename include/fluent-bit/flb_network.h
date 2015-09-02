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

#ifndef FLB_NETWORK_H
#define FLB_NETWORK_H

#include <netinet/tcp.h>
#include <sys/socket.h>

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN  23
#endif

/* TCP options */
int flb_net_socket_reset(int sockfd);
int flb_net_socket_tcp_nodelay(int sockfd);
int flb_net_socket_nonblocking(int sockfd);
int flb_net_socket_tcp_fastopen(int sockfd);

/* Socket handling */
int flb_net_socket_create(int family, int nonblock);
int flb_net_tcp_connect(char *host, unsigned long port);
int flb_net_tcp_fd_connect(int fd, char *host, unsigned long port);
int flb_net_server(char *port, char *listen_addr);
int flb_net_bind(int socket_fd, const struct sockaddr *addr,
                 socklen_t addrlen, int backlog);
int flb_net_accept(int server_fd);
int flb_net_socket_ip_str(int socket_fd, char **buf, int size, unsigned long *len);

#endif
