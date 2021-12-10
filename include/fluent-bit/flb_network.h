/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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
#include <fluent-bit/flb_upstream_conn.h>
#include <fluent-bit/flb_net_dns.h>
#include <ares.h>

/* Network connection setup */
struct flb_net_setup {
    /* enable/disable keepalive support */
    char keepalive;

    /* max time in seconds that a keepalive connection can be idle */
    int keepalive_idle_timeout;

    /* max time in seconds to wait for a established connection */
    int connect_timeout;

    /* network interface to bind and use to send data */
    flb_sds_t source_address;

    /* maximum of times a keepalive connection can be used */
    int keepalive_max_recycle;

    /* dns mode : TCP or UDP */
    char *dns_mode;

    /* dns reolver : LEGACY or ASYNC */
    char *dns_resolver;
};

/* Defines a host service and it properties */
struct flb_net_host {
    int ipv6;              /* IPv6 required ?      */
    flb_sds_t address;     /* Original address     */
    int port;              /* TCP port             */
    flb_sds_t name;        /* Hostname             */
    flb_sds_t listen;      /* Listen interface     */
    struct flb_uri *uri;   /* Extra URI parameters */
};

/* Defines an async DNS lookup context */
struct flb_dns_lookup_context {
    struct mk_event              response_event;                  /* c-ares socket event */
    int                          ares_socket_registered;
    struct ares_socket_functions ares_socket_functions;
    int                         *udp_timeout_detected;
    int                          ares_socket_created;
    int                          ares_socket_type;
    void                        *ares_channel;
    int                         *result_code;
    struct mk_event_loop        *event_loop;
    struct flb_coro             *coroutine;
    struct flb_sched_timer      *udp_timer;
    int                          finished;
    int                          dropped;
    struct flb_net_dns          *dns_ctx;
    struct addrinfo            **result;
    /* result is a synthetized result, don't call freeaddrinfo on it */
    struct mk_list               _head;
};

#define FLB_DNS_LOOKUP_CONTEXT_FOR_EVENT(event) \
    ((struct flb_dns_lookup_context *) \
        &((uint8_t *) event)[-offsetof(struct flb_dns_lookup_context, response_event)])

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
int flb_net_socket_tcp_fastopen(flb_sockfd_t sockfd);

/* Socket handling */
flb_sockfd_t flb_net_socket_create(int family, int nonblock);
flb_sockfd_t flb_net_socket_create_udp(int family, int nonblock);
flb_sockfd_t flb_net_tcp_connect(const char *host, unsigned long port,
                                 char *source_addr, int connect_timeout,
                                 int is_async,
                                 void *async_ctx,
                                 struct flb_upstream_conn *u_conn);

flb_sockfd_t flb_net_udp_connect(const char *host, unsigned long port,
                                 char *source_addr);

int flb_net_tcp_fd_connect(flb_sockfd_t fd, const char *host, unsigned long port);
flb_sockfd_t flb_net_server(const char *port, const char *listen_addr);
flb_sockfd_t flb_net_server_udp(const char *port, const char *listen_addr);
int flb_net_bind(flb_sockfd_t fd, const struct sockaddr *addr,
                 socklen_t addrlen, int backlog);
int flb_net_bind_udp(flb_sockfd_t fd, const struct sockaddr *addr,
                 socklen_t addrlen);
flb_sockfd_t flb_net_accept(flb_sockfd_t server_fd);
int flb_net_address_to_str(int family, const struct sockaddr *addr,
                           char *output_buffer, size_t output_buffer_size);
int flb_net_socket_ip_str(flb_sockfd_t fd, char **buf, int size, unsigned long *len);

#endif
