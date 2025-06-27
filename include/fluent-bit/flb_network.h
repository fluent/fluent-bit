/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_upstream_conn.h>
#include <fluent-bit/flb_net_dns.h>

#define FLB_NETWORK_DEFAULT_BACKLOG_SIZE              128
#define FLB_NETWORK_UNIX_SOCKET_PEER_ADDRESS_TEMPLATE "pid_%s"
#define FLB_NETWORK_ADDRESS_UNAVAILABLE               "unavailable"

/* FLB_NETWORK_MAX_UNIX_ADDRESS_LENGTH should be enough for the
 * string "PID " plus the string form of a signed 32 bit integer
 * and a NULL character.
 */

/* Network connection setup */
struct flb_net_setup {
    /* enable/disable keepalive support */
    int keepalive;

    /* max time in seconds that a keepalive connection can be idle */
    int keepalive_idle_timeout;

    /* max time in seconds to wait for a established connection */
    int connect_timeout;

    /* max time in seconds an incoming connection can take including the
     * TLS handshake
     */
    int accept_timeout;

    /* accept timeout log error (default: true) */
    int accept_timeout_log_error;

    /* max time in seconds to wait for blocking io calls */
    int io_timeout;

    /* connect timeout log error (default: true) */
    int connect_timeout_log_error;

    /* network interface to bind and use to send data */
    flb_sds_t source_address;

    /* maximum of times a keepalive connection can be used */
    int keepalive_max_recycle;

    /* enable/disable tcp keepalive */
    int tcp_keepalive;

    /* interval between the last data packet sent and the first TCP keepalive probe */
    int tcp_keepalive_time;

    /* the interval between TCP keepalive probes */
    int tcp_keepalive_interval;

    /* number of unacknowledged probes to consider a connection dead */
    int tcp_keepalive_probes;

    /* dns mode : TCP or UDP */
    char *dns_mode;

    /* dns resolver : LEGACY or ASYNC */
    char *dns_resolver;

    /* prioritize ipv4 results when trying to establish a connection */
    int   dns_prefer_ipv4;

    /* prioritize ipv6 results when trying to establish a connection */
    int   dns_prefer_ipv6;

    /* allow this port to be shared */
    int   share_port;

    /* maximum number of allowed active TCP connections */
    int max_worker_connections;
};

/* Defines a host service and it properties */
struct flb_net_host {
    int ipv6;              /* IPv6 required ?        */
    flb_sds_t address;     /* Original address       */
    int port;              /* TCP port               */
    flb_sds_t name;        /* Hostname               */
    flb_sds_t listen;      /* Listen interface       */
    struct flb_uri *uri;   /* Extra URI parameters   */
};

#define FLB_DNS_LEGACY  'L'
#define FLB_DNS_ASYNC   'A'

#define FLB_DNS_USE_TCP 'T'
#define FLB_DNS_USE_UDP 'U'

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN  23
#endif

/* General initialization of the networking layer */
void flb_net_lib_init();
void flb_net_ctx_init(struct flb_net_dns *dns_ctx);

void flb_net_dns_ctx_init();
struct flb_net_dns *flb_net_dns_ctx_get();
void flb_net_dns_ctx_set(struct flb_net_dns *dns_ctx);

/* Generic functions */
void flb_net_setup_init(struct flb_net_setup *net);
int flb_net_host_set(const char *plugin_name, struct flb_net_host *host, const char *address);

/* DNS handling */
void flb_net_dns_lookup_context_cleanup(struct flb_net_dns *dns_ctx);

/* TCP options */
int flb_net_socket_reset(flb_sockfd_t fd);
int flb_net_socket_tcp_nodelay(flb_sockfd_t fd);
int flb_net_socket_blocking(flb_sockfd_t fd);
int flb_net_socket_nonblocking(flb_sockfd_t fd);
int flb_net_socket_rcv_buffer(flb_sockfd_t fd, int rcvbuf);
int flb_net_socket_tcp_fastopen(flb_sockfd_t sockfd);
int flb_net_socket_tcp_keepalive(flb_sockfd_t fd, struct flb_net_setup *net);

/* Socket handling */
flb_sockfd_t flb_net_socket_create(int family, int nonblock);
flb_sockfd_t flb_net_socket_create_udp(int family, int nonblock);
flb_sockfd_t flb_net_tcp_connect(const char *host, unsigned long port,
                                 char *source_addr, int connect_timeout,
                                 int is_async,
                                 void *async_ctx,
                                 struct flb_connection *u_conn);

flb_sockfd_t flb_net_udp_connect(const char *host, unsigned long port,
                                 char *source_addr);

int flb_net_tcp_fd_connect(flb_sockfd_t fd, const char *host, unsigned long port);
flb_sockfd_t flb_net_server(const char *port, const char *listen_addr, int share_port);
flb_sockfd_t flb_net_server_udp(const char *port, const char *listen_addr, int share_port);
flb_sockfd_t flb_net_server_unix(const char *listen_path, int stream_mode,
                                 int backlog, int share_port);
int flb_net_bind(flb_sockfd_t fd, const struct sockaddr *addr,
                 socklen_t addrlen, int backlog);
int flb_net_bind_udp(flb_sockfd_t fd, const struct sockaddr *addr,
                 socklen_t addrlen);
flb_sockfd_t flb_net_accept(flb_sockfd_t server_fd);

int flb_net_address_to_str(int family, const struct sockaddr *addr,
                           char *output_buffer, size_t output_buffer_size);

int flb_net_socket_peer_address(flb_sockfd_t fd,
                                struct sockaddr_storage *output_buffer);

int flb_net_socket_address_info(flb_sockfd_t fd,
                                struct sockaddr_storage *address,
                                unsigned short int *port_output_buffer,
                                char *str_output_buffer,
                                int str_output_buffer_size,
                                size_t *str_output_data_size);

int flb_net_socket_peer_ip_str(flb_sockfd_t fd,
                               char *output_buffer,
                               int output_buffer_size,
                               size_t *output_data_size,
                               int *output_address_family);

int flb_net_socket_peer_ip_raw(flb_sockfd_t fd,
                               char *output_buffer,
                               int output_buffer_size,
                               size_t *output_data_size,
                               int *output_address_family);

int flb_net_socket_peer_port(flb_sockfd_t fd,
                             unsigned short int *output_buffer);

int flb_net_socket_peer_info(flb_sockfd_t fd,
                             unsigned short int *port_output_buffer,
                             struct sockaddr_storage *raw_output_buffer,
                             char *str_output_buffer,
                             int str_output_buffer_size,
                             size_t *str_output_data_size);

size_t flb_network_address_size(struct sockaddr_storage *address);

uint64_t flb_net_htonll(uint64_t value);

#endif
