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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#ifdef FLB_SYSTEM_WINDOWS
#define poll WSAPoll
#else
#include <sys/poll.h>
#endif

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_upstream.h>

#include <monkey/mk_core.h>

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

void flb_net_setup_init(struct flb_net_setup *net)
{
    net->keepalive = FLB_TRUE;
    net->keepalive_idle_timeout = 30;
    net->keepalive_max_recycle = 0;
    net->connect_timeout = 10;
    net->source_address = NULL;
}

int flb_net_host_set(const char *plugin_name, struct flb_net_host *host, const char *address)
{
    int len;
    int olen;
    const char *s, *e, *u;

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
        host->name = flb_sds_create_len(s, e - s);
        host->ipv6 = FLB_TRUE;
        s = e + 1;
    }
    else {
        e = s;
        while (!(*e == '\0' || *e == ':' || *e == '/')) {
            ++e;
        }
        if (e == s) {
            return -1;
        }
        host->name = flb_sds_create_len(s, e - s);
        s = e;
    }

    if (*s == ':') {
        host->port = atoi(++s);
    }

    u = strchr(s, '/');
    if (u) {
        host->uri = flb_uri_create(u);
    }
    host->address = flb_sds_create(address);

    if (host->name) {
        host->listen = flb_sds_create(host->name);
    }

    return 0;
}

int flb_net_socket_reset(flb_sockfd_t fd)
{
    int status = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &status, sizeof(int)) == -1) {
        flb_errno();
        return -1;
    }

    return 0;
}

int flb_net_socket_tcp_nodelay(flb_sockfd_t fd)
{
    int on = 1;
    int ret;

    ret = setsockopt(fd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
    if (ret == -1) {
        flb_errno();
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
        flb_errno();
        return -1;
    }

    return 0;
}

int flb_net_socket_blocking(flb_sockfd_t fd)
{
#ifdef _WIN32
    unsigned long off = 0;
    if (ioctlsocket(fd, FIONBIO, &off) != 0) {
#else
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK) == -1) {
#endif
        flb_errno();
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
        flb_errno();
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
        flb_errno();
        return -1;
    }

    if (nonblock) {
        flb_net_socket_nonblocking(fd);
    }

    return fd;
}

/*
 * Perform TCP connection for a blocking socket. This interface set's the socket
 * to non-blocking mode temporary in order to add a timeout to the connection,
 * the blocking mode is restored at the end.
 */
static int net_connect_sync(int fd, const struct sockaddr *addr, socklen_t addrlen,
                            char *host, int port, int connect_timeout)
{
    int ret;
    int err;
    int socket_errno;
    struct pollfd pfd_read;

    /* Set socket to non-blocking mode */
    flb_net_socket_nonblocking(fd);

    /* connect(2) */
    ret = connect(fd, addr, addrlen);
    if (ret == -1) {
        /*
         * An asynchronous connect can return -1, but what is important is the
         * socket status, getting a EINPROGRESS is expected, but any other case
         * means a failure.
         */
#ifdef FLB_SYSTEM_WINDOWS
        socket_errno = flb_socket_error(fd);
        err = -1;
#else
        socket_errno = errno;
        err = flb_socket_error(fd);
#endif
        if (!FLB_EINPROGRESS(socket_errno) && err != 0) {
            flb_error("[net] connection #%i failed to: %s:%i",
                      fd, host, port);
            goto exit_error;
        }

        /* The connection is still in progress, implement a socket timeout */
        flb_trace("[net] connection #%i in process to %s:%i",
                  fd, host, port);

        /*
         * Prepare a timeout using poll(2): we could use our own
         * event loop mechanism for this, but it will require an
         * extra file descriptor, the poll(2) call is straightforward
         * for this use case.
         */

        pfd_read.fd = fd;
        pfd_read.events = POLLOUT;
        ret = poll(&pfd_read, 1, connect_timeout * 1000);
        if (ret == 0) {
            /* Timeout */
            flb_error("[net] connection #%i timeout after %i seconds to: "
                      "%s:%i",
                      fd, connect_timeout, host, port);
            goto exit_error;
        }
        else if (ret < 0) {
            /* Generic error */
            flb_errno();
            flb_error("[net] connection #%i failed to: %s:%i",
                      fd, host, port);
            goto exit_error;
        }
    }

    /*
     * No exception, the connection succeeded, return the normal
     * non-blocking mode to the socket.
     */
    flb_net_socket_blocking(fd);
    return 0;

 exit_error:
    flb_net_socket_blocking(fd);
    return -1;
}


/*
 * Asynchronous socket connection: this interface might be called from a co-routine,
 * so in order to perform a real async connection and get notified back, it needs
 * access to the event loop context and the connection context 'upstream connection.
 */
static int net_connect_async(int fd,
                             const struct sockaddr *addr, socklen_t addrlen,
                             char *host, int port, int connect_timeout,
                             void *async_ctx, struct flb_upstream_conn *u_conn)
{
    int ret;
    int err;
    int error = 0;
    int socket_errno;
    uint32_t mask;
    char so_error_buf[256];
    char *str;
    struct flb_upstream *u = u_conn->u;

    /* connect(2) */
    ret = connect(fd, addr, addrlen);
    if (ret == 0) {
        return 0;
    }

    /*
     * An asynchronous connect can return -1, but what is important is the
     * socket status, getting a EINPROGRESS is expected, but any other case
     * means a failure.
     */
#ifdef FLB_SYSTEM_WINDOWS
    socket_errno = flb_socket_error(fd);
    err = -1;
#else
    socket_errno = errno;
    err = flb_socket_error(fd);
#endif
    if (!FLB_EINPROGRESS(socket_errno) && err != 0) {
        flb_error("[net] connection #%i failed to: %s:%i",
                  fd, host, port);
        return -1;
    }

    /* The connection is still in progress, implement a socket timeout */
    flb_trace("[net] connection #%i in process to %s:%i",
              fd, host, port);

    /* Register the connection socket into the main event loop */
    MK_EVENT_ZERO(&u_conn->event);
    u_conn->coro = async_ctx;
    ret = mk_event_add(u_conn->evl,
                       fd,
                       FLB_ENGINE_EV_THREAD,
                       MK_EVENT_WRITE, &u_conn->event);
    if (ret == -1) {
        /*
         * If we failed here there no much that we can do, just
         * let the caller know that we failed.
         */
        return -1;
    }

    /*
     * Return the control to the parent caller, we need to wait for
     * the event loop to get back to us.
     */
    flb_coro_yield(async_ctx, FLB_FALSE);

    /* Save the mask before the event handler do a reset */
    mask = u_conn->event.mask;

    /* We got a notification, remove the event registered */
    ret = mk_event_del(u_conn->evl, &u_conn->event);
    if (ret == -1) {
        flb_error("[io] connect event handler error");
        return -1;
    }

    /* Check the connection status */
    if (mask & MK_EVENT_WRITE) {
        error = flb_socket_error(u_conn->fd);

        /* Check the exception */
        if (error != 0) {
            /*
             * The upstream connection might want to override the
             * exception (mostly used for local timeouts: ETIMEDOUT.
             */
            if (u_conn->net_error > 0) {
                error = u_conn->net_error;
            }

            /* Connection is broken, not much to do here */
            str = strerror_r(error, so_error_buf, sizeof(so_error_buf));
            flb_error("[net] TCP connection failed: %s:%i (%s)",
                      u->tcp_host, u->tcp_port, str);
            return -1;
        }
    }
    else {
        flb_error("[net] TCP connection, unexpected error: %s:%i",
                  u->tcp_host, u->tcp_port);
        return -1;
    }

    return 0;
}

int flb_net_bind_address(int fd, char *source_addr)
{
    int ret;
    struct addrinfo hint;
    struct addrinfo *res = NULL;
    struct sockaddr_storage addr;

    memset(&hint, '\0', sizeof hint);

    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

    ret = getaddrinfo(source_addr, NULL, &hint, &res);
    if (ret == -1) {
        flb_errno();
        flb_error("[net] cannot read source_address=%s", source_addr);
        return -1;
    }

    /* Bind the address */
    memcpy(&addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    ret = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
    if (ret == -1) {
        flb_errno();
        flb_error("[net] could not bind source_address=%s", source_addr);
        return -1;
    }

    return 0;
}

static void set_ip_family(const char *host, struct addrinfo *hints)
{

    int ret;
    struct in6_addr serveraddr;

    /* check if the given 'host' is a network address, adjust ai_flags */
    ret = inet_pton(AF_INET, host, &serveraddr);
    if (ret == 1) {    /* valid IPv4 text address ? */
        hints->ai_family = AF_INET;
        hints->ai_flags |= AI_NUMERICHOST;
    }
    else {
        ret = inet_pton(AF_INET6, host, &serveraddr);
        if (ret == 1) { /* valid IPv6 text address ? */
            hints->ai_family = AF_INET6;
            hints->ai_flags |= AI_NUMERICHOST;
        }
    }
}

/* Connect to a TCP socket server and returns the file descriptor */
flb_sockfd_t flb_net_tcp_connect(const char *host, unsigned long port,
                                 char *source_addr, int connect_timeout,
                                 int is_async,
                                 void *async_ctx,
                                 struct flb_upstream_conn *u_conn)
{
    int ret;
    flb_sockfd_t fd = -1;
    char _port[6];
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    if (is_async == FLB_TRUE && !u_conn) {
        flb_error("[net] invalid async mode with not set upstream connection");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* Set hints */
    set_ip_family(host, &hints);

    /* fomart the TCP port */
    snprintf(_port, sizeof(_port), "%lu", port);

    /* retrieve DNS info */
    ret = getaddrinfo(host, _port, &hints, &res);
    if (ret != 0) {
        flb_warn("[net] getaddrinfo(host='%s'): %s", host, gai_strerror(ret));
        return -1;
    }

    /*
     * Try to connect: on this iteration we try to connect to the first
     * available address.
     */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        /* create socket */
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd == -1) {
            flb_error("[net] coult not create client socket, retrying");
            continue;
        }

        /* asynchronous socket ? */
        if (is_async == FLB_TRUE) {
            flb_net_socket_nonblocking(fd);
        }

        /* Bind a specific network interface ? */
        if (source_addr != NULL) {
            ret = flb_net_bind_address(fd, source_addr);
            if (ret == -1) {
                flb_warn("[net] falling back to random interface");
            }
            else {
                flb_trace("[net] client connect bind address: %s", source_addr);
            }
        }

        /* Disable Nagle's algorithm */
        flb_net_socket_tcp_nodelay(fd);

        if (u_conn) {
            u_conn->fd = fd;
            u_conn->event.fd = fd;
        }

        /* Perform TCP connection */
        if (is_async == FLB_TRUE) {
            ret = net_connect_async(fd, rp->ai_addr, rp->ai_addrlen,
                                    (char *) host, port, connect_timeout,
                                    async_ctx, u_conn);

        }
        else {
            ret = net_connect_sync(fd, rp->ai_addr, rp->ai_addrlen,
                                   (char *) host, port, connect_timeout);
        }

        if (ret == -1) {
            /* If the connection failed, just abort and report the problem */
            flb_error("[net] socket #%i could not connect to %s:%s",
                      fd, host, _port);
            if (u_conn) {
                u_conn->fd = -1;
                u_conn->event.fd = -1;
            }
            flb_socket_close(fd);
            fd = -1;
            break;
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
flb_sockfd_t flb_net_udp_connect(const char *host, unsigned long port,
                                 char *source_addr)
{
    int ret;
    flb_sockfd_t fd = -1;
    char _port[6];
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    /* Set hints */
    set_ip_family(host, &hints);

    /* Format UDP port */
    snprintf(_port, sizeof(_port), "%lu", port);

    /* retrieve DNS info */
    ret = getaddrinfo(host, _port, &hints, &res);
    if (ret != 0) {
        flb_warn("net]: getaddrinfo(host='%s'): %s",
                 host, gai_strerror(ret));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        /* create socket */
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd == -1) {
            flb_error("[net] coult not create client socket, retrying");
            continue;
        }

        /* Bind a specific network interface ? */
        if (source_addr != NULL) {
            ret = flb_net_bind_address(fd, source_addr);
            if (ret == -1) {
                flb_warn("[net] falling back to random interface");
            }
            else {
                flb_trace("[net] client connect bind address: %s", source_addr);
            }
        }

        /*
         * Why do we connect(2) an UDP socket ?, is this useful ?: Yes. Despite
         * an UDP socket it's not in a connection state, connecting through the
         * API it helps the Kernel to configure the destination address and
         * is totally valid, so then you don't need to use sendto(2).
         *
         * For our use case this is quite helpful, since the caller keeps using
         * the same Fluent Bit I/O API to deliver a message.
         */
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
            flb_error("[net] UDP socket %i could connect to %s:%s",
                      fd, host, _port);
            flb_socket_close(fd);
            fd = -1;
            break;
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
int flb_net_tcp_fd_connect(flb_sockfd_t fd, const char *host, unsigned long port)
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

flb_sockfd_t flb_net_server(const char *port, const char *listen_addr)
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

flb_sockfd_t flb_net_server_udp(const char *port, const char *listen_addr)
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
