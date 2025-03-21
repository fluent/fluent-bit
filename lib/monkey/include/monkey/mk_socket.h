/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#ifndef MK_SOCKET_H
#define MK_SOCKET_H

#include <fcntl.h>

#ifdef _WIN32
#include <winsock2.h>
#include <afunix.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#endif

#include <monkey/mk_core.h>
#include <monkey/mk_config.h>
#include <monkey/mk_info.h>

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 04000
#endif

#ifndef SO_REUSEPORT
#define SO_REUSEPORT  15
#endif

/*
 * TCP_FASTOPEN: as this is a very new option in the Linux Kernel, the value is
 * not yet exported and can be missing, lets make sure is available for all
 * cases:
 *
 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commitdiff;h=1046716368979dee857a2b8a91c4a8833f21b9cb
 */
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN  23
#endif

#define TCP_CORK_ON 1
#define TCP_CORK_OFF 0

#define TCP_CORKING_PATH  "/proc/sys/net/ipv4/tcp_autocorking"

int mk_socket_set_cork_flag(int fd, int state);
int mk_socket_set_tcp_fastopen(int sockfd);
int mk_socket_set_tcp_nodelay(int sockfd);
int mk_socket_set_tcp_defer_accept(int sockfd);
int mk_socket_set_tcp_reuseport(int sockfd);
int mk_socket_set_nonblocking(int sockfd);

int mk_socket_create(int domain, int type, int protocol);
int mk_socket_connect(char *host, int port, int async);
int mk_socket_open(char *path, int async);
int mk_socket_reset(int socket);
int mk_socket_bind(int socket_fd, const struct sockaddr *addr,
                   socklen_t addrlen, int backlog, struct mk_server *server);
int mk_socket_server(char *port, char *listen_addr,
                     int reuse_port, struct mk_server *server);
int mk_socket_ip_str(int socket_fd, char **buf, int size, unsigned long *len);
int mk_socket_accept(int server_fd);


#endif
