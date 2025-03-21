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

#define _GNU_SOURCE

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#include <monkey/monkey.h>
#include <monkey/mk_info.h>
#include <monkey/mk_socket.h>
#include <monkey/mk_kernel.h>
#include <monkey/mk_net.h>
#include <monkey/mk_core.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_plugin.h>

#include <time.h>

/*
 * Example from:
 * http://www.baus.net/on-tcp_cork
 */
int mk_socket_set_cork_flag(int fd, int state)
{
    MK_TRACE("Socket, set Cork Flag FD %i to %s", fd, (state ? "ON" : "OFF"));

#if defined (TCP_CORK)
    return setsockopt(fd, SOL_TCP, TCP_CORK, &state, sizeof(state));
#elif defined (TCP_NOPUSH)
    return setsockopt(fd, SOL_SOCKET, TCP_NOPUSH, &state, sizeof(state));
#endif

    return 0;
}

int mk_socket_set_nonblocking(int sockfd)
{

    MK_TRACE("Socket, set FD %i to non-blocking", sockfd);

#ifdef _WIN32
    u_long flags;

    flags = 0;
    if (SOCKET_ERROR == ioctlsocket(sockfd, FIONBIO, &flags)) {
        mk_err("Can't set to non-blocking mode socket %i", sockfd);
        return -1;
    }
#else
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        mk_err("Can't set to non-blocking mode socket %i", sockfd);
        return -1;
    }
    fcntl(sockfd, F_SETFD, FD_CLOEXEC);
#endif

    return 0;
}

/*
 * Enable the TCP_FASTOPEN feature for server side implemented in
 * Linux Kernel >= 3.7, for more details read here:
 *
 *  TCP Fast Open: expediting web services: http://lwn.net/Articles/508865/
 */
int mk_socket_set_tcp_fastopen(int sockfd)
{
#if defined (__linux__)
    int qlen = 5;
    return setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
#endif

    (void) sockfd;
    return -1;
}

int mk_socket_set_tcp_nodelay(int sockfd)
{
    int on = 1;

    return setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));
}

int mk_socket_set_tcp_defer_accept(int sockfd)
{
#if defined (__linux__)
    int timeout = 0;

    return setsockopt(sockfd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof(int));
#else
    (void) sockfd;
    return -1;
#endif
}

int mk_socket_set_tcp_reuseport(int sockfd)
{
    int on = 1;
    return setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
}

int mk_socket_create(int domain, int type, int protocol)
{
    int fd;

#ifdef SOCK_CLOEXEC
    fd = socket(domain, type | SOCK_CLOEXEC, protocol);
#else
    fd = socket(domain, type, protocol);

#ifndef _WIN32
    fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
#endif

    if (fd == -1) {
        mk_libc_error("socket");
        return -1;
    }

    return fd;
}

int mk_socket_open(char *path, int async)
{
    int ret;
    int socket_fd;
    struct sockaddr_un address;

    socket_fd = mk_socket_create(PF_UNIX, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        return -1;
    }

    memset(&address, '\0', sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);

    if (async == MK_TRUE) {
        mk_socket_set_nonblocking(socket_fd);
    }

    ret = connect(socket_fd, (struct sockaddr *) &address,
                  sizeof(struct sockaddr_un));
    if (ret == -1) {
        if (errno == EINPROGRESS) {
            return socket_fd;
        }
        else {
#ifdef MK_HAVE_TRACE
            mk_libc_error("connect");
#endif
            close(socket_fd);
            return -1;
        }
    }

    return socket_fd;
}


int mk_socket_connect(char *host, int port, int async)
{
    int ret;
    int socket_fd = -1;
    char *port_str = 0;
    unsigned long len;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    mk_string_build(&port_str, &len, "%d", port);

    ret = getaddrinfo(host, port_str, &hints, &res);
    mk_mem_free(port_str);
    if(ret != 0) {
        mk_err("Can't get addr info: %s", gai_strerror(ret));
        return -1;
    }
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        socket_fd = mk_socket_create(rp->ai_family,
                                     rp->ai_socktype, rp->ai_protocol);

        if (socket_fd == -1) {
            mk_warn("Error creating client socket, retrying");
            continue;
        }

        if (async == MK_TRUE) {
            mk_socket_set_nonblocking(socket_fd);
        }

        ret = connect(socket_fd,
                      (struct sockaddr *) rp->ai_addr, rp->ai_addrlen);
        if (ret == -1) {
            if (errno == EINPROGRESS) {
                break;
            }
            else {
                printf("%s", strerror(errno));
                perror("connect");
                exit(1);
                close(socket_fd);
                continue;
            }
        }
        break;
    }
    freeaddrinfo(res);

    if (rp == NULL)
        return -1;

    return socket_fd;
}

int mk_socket_reset(int socket)
{
    int status = 1;

    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &status, sizeof(int)) == -1) {
        mk_libc_error("socket");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int mk_socket_bind(int socket_fd, const struct sockaddr *addr,
                   socklen_t addrlen, int backlog, struct mk_server *server)
{
    int ret;

    ret = bind(socket_fd, addr, addrlen);
    if( ret == -1 ) {
        mk_warn("Error binding socket");
        return ret;
    }

    /*
     * Enable TCP_FASTOPEN by default: if for some reason this call fail,
     * it will not affect the behavior of the server, in order to succeed,
     * Monkey must be running in a Linux system with Kernel >= 3.7 and the
     * tcp_fastopen flag enabled here:
     *
     *     # cat /proc/sys/net/ipv4/tcp_fastopen
     *
     * To enable this feature just do:
     *
     *     # echo 1 > /proc/sys/net/ipv4/tcp_fastopen
     */
    if (server->kernel_features & MK_KERNEL_TCP_FASTOPEN) {
        ret = mk_socket_set_tcp_fastopen(socket_fd);
        if (ret == -1) {
            mk_warn("Could not set TCP_FASTOPEN");
        }
    }

    ret = listen(socket_fd, backlog);
    if(ret == -1 ) {
        return -1;
    }

    return ret;
}

/* Just IPv4 for now... */
int mk_socket_server(char *port, char *listen_addr,
                     int reuse_port, struct mk_server *server)
{
    int ret;
    int socket_fd = -1;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    mk_net_init();

    ret = getaddrinfo(listen_addr, port, &hints, &res);
    if(ret != 0) {
        mk_err("Can't get addr info: %s", gai_strerror(ret));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        socket_fd = mk_socket_create(rp->ai_family,
                                     rp->ai_socktype, rp->ai_protocol);
        if (socket_fd == -1) {
            mk_warn("Error creating server socket, retrying");
            continue;
        }

        ret = mk_socket_set_tcp_nodelay(socket_fd);
        if (ret == -1) {
            mk_warn("Could not set TCP_NODELAY");
        }

        mk_socket_reset(socket_fd);

        /* Check if reuse port can be enabled on this socket */
        if (reuse_port == MK_TRUE &&
            (server->kernel_features & MK_KERNEL_SO_REUSEPORT)) {
            ret = mk_socket_set_tcp_reuseport(socket_fd);
            if (ret == -1) {
                mk_warn("Could not use SO_REUSEPORT, using fair balancing mode");
                server->scheduler_mode = MK_SCHEDULER_FAIR_BALANCING;
            }
        }

        ret = mk_socket_bind(socket_fd, rp->ai_addr, rp->ai_addrlen,
                             MK_SOMAXCONN, server);
        if(ret == -1) {
            mk_err("Cannot listen on %s:%s", listen_addr, port);
            freeaddrinfo(res);
            return -1;
        }
        break;
    }
    freeaddrinfo(res);

    if (rp == NULL)
        return -1;

    return socket_fd;
}

int mk_socket_ip_str(int socket_fd, char **buf, int size, unsigned long *len)
{
    int ret;
    struct sockaddr_storage addr;
    socklen_t s_len = sizeof(addr);

    ret = getpeername(socket_fd, (struct sockaddr *) &addr, &s_len);

    if (mk_unlikely(ret == -1)) {
        MK_TRACE("[FD %i] Can't get addr for this socket", socket_fd);
        return -1;
    }

    errno = 0;

    if(addr.ss_family == AF_INET) {
        if((inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr,
                      *buf, size)) == NULL) {
            mk_warn("mk_socket_ip_str: Can't get the IP text form (%i)", errno);
            return -1;
        }
    }
    else if(addr.ss_family == AF_INET6) {
        if((inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr,
                      *buf, size)) == NULL) {
            mk_warn("mk_socket_ip_str: Can't get the IP text form (%i)", errno);
            return -1;
        }
    }

    *len = strlen(*buf);
    return 0;
}

int mk_socket_accept(int server_fd)
{
    int remote_fd;

    struct sockaddr sock_addr;
    socklen_t socket_size = sizeof(struct sockaddr);

#ifdef MK_HAVE_ACCEPT4
    remote_fd = accept4(server_fd, &sock_addr, &socket_size,
                        SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    remote_fd = accept(server_fd, &sock_addr, &socket_size);
    mk_socket_set_nonblocking(remote_fd);
#endif

    return remote_fd;
}
