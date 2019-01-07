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

#ifndef FLB_NETWORK_H
#define FLB_NETWORK_H

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_uri.h>

/* Defines a host service and it properties */
struct flb_net_host {
    int  ipv6;             /* IPv6 required ?      */
    char *address;         /* Original address     */
    int   port;            /* TCP port             */
    char *name;            /* Hostname             */
    char *listen;          /* Listen interface     */
    struct flb_uri *uri;   /* Extra URI parameters */
};

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN  23
#endif

/* Generic functions */
int flb_net_host_set(char *plugin_name, struct flb_net_host *host, char *address);

/* TCP options */
int flb_net_socket_reset(flb_sockfd_t fd);
int flb_net_socket_tcp_nodelay(flb_sockfd_t fd);
int flb_net_socket_nonblocking(flb_sockfd_t fd);
int flb_net_socket_tcp_fastopen(flb_sockfd_t sockfd);

/* Socket handling */
flb_sockfd_t flb_net_socket_create(int family, int nonblock);
flb_sockfd_t flb_net_socket_create_udp(int family, int nonblock);
flb_sockfd_t flb_net_tcp_connect(char *host, unsigned long port);
flb_sockfd_t flb_net_udp_connect(char *host, unsigned long port);
int flb_net_tcp_fd_connect(flb_sockfd_t fd, char *host, unsigned long port);
flb_sockfd_t flb_net_server(char *port, char *listen_addr);
flb_sockfd_t flb_net_server_udp(char *port, char *listen_addr);
int flb_net_bind(flb_sockfd_t fd, const struct sockaddr *addr,
                 socklen_t addrlen, int backlog);
int flb_net_bind_udp(flb_sockfd_t fd, const struct sockaddr *addr,
                 socklen_t addrlen);
flb_sockfd_t flb_net_accept(flb_sockfd_t server_fd);
int flb_net_socket_ip_str(flb_sockfd_t fd, char **buf, int size, unsigned long *len);

#endif
