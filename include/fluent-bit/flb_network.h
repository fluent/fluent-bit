/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_uri.h>

/* Network connection setup */
struct flb_net_setup {
    /* enable/disable keepalive support */
    int keepalive;

    /* max time in seconds that a keepalive connection can be idle */
    int keepalive_idle_timeout;

    /* max time in seconds to wait for a established connection */
    int connect_timeout;

    /* network interface to bind and use to send data */
    flb_sds_t source_address;
};

/* Defines a host service and it properties */
struct flb_net_host {
    int  ipv6;             /* IPv6 required ?      */
    flb_sds_t address;     /* Original address     */
    int   port;            /* TCP port             */
    flb_sds_t name;        /* Hostname             */
    flb_sds_t listen;      /* Listen interface     */
    struct flb_uri *uri;   /* Extra URI parameters */
};

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN  23
#endif

/* Generic functions */
void flb_net_setup_init(struct flb_net_setup *net);
int flb_net_host_set(const char *plugin_name, struct flb_net_host *host, const char *address);

/* TCP options */
int flb_net_socket_reset(flb_sockfd_t fd);
int flb_net_socket_tcp_nodelay(flb_sockfd_t fd);
int flb_net_socket_blocking(flb_sockfd_t fd);
int flb_net_socket_nonblocking(flb_sockfd_t fd);
int flb_net_socket_tcp_fastopen(flb_sockfd_t sockfd);

/* Socket handling */
flb_sockfd_t flb_net_socket_create(int family, int nonblock);
flb_sockfd_t flb_net_socket_create_udp(int family, int nonblock);
flb_sockfd_t flb_net_tcp_connect(const char *host, unsigned long port);
flb_sockfd_t flb_net_udp_connect(const char *host, unsigned long port);
int flb_net_tcp_fd_connect(flb_sockfd_t fd, const char *host, unsigned long port);
flb_sockfd_t flb_net_server(const char *port, const char *listen_addr);
flb_sockfd_t flb_net_server_udp(const char *port, const char *listen_addr);
int flb_net_bind(flb_sockfd_t fd, const struct sockaddr *addr,
                 socklen_t addrlen, int backlog);
int flb_net_bind_udp(flb_sockfd_t fd, const struct sockaddr *addr,
                 socklen_t addrlen);
flb_sockfd_t flb_net_accept(flb_sockfd_t server_fd);
int flb_net_socket_ip_str(flb_sockfd_t fd, char **buf, int size, unsigned long *len);

#endif
