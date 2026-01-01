/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <ctype.h>

#ifdef FLB_SYSTEM_WINDOWS
#define poll WSAPoll
#include <winsock2.h>
#include <ws2tcpip.h>
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
#include <fluent-bit/flb_scheduler.h>

#include <monkey/mk_core.h>
#include <ares.h>

#ifdef FLB_SYSTEM_MACOS
#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif
/* Use POSIX version of strerror_r forcibly on macOS. */
#include <string.h>
#endif

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

static pthread_once_t local_thread_net_dns_ctx_init = PTHREAD_ONCE_INIT;
FLB_TLS_DEFINE(struct flb_net_dns, flb_net_dns_ctx);

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


/*
 * Initialize thread-local-storage, every worker thread has it owns
 * dns context with relevant info populated inside the thread.
 */

static void flb_net_dns_ctx_init_private()
{
    FLB_TLS_INIT(flb_net_dns_ctx);
}

void flb_net_dns_ctx_init()
{
    pthread_once(&local_thread_net_dns_ctx_init, flb_net_dns_ctx_init_private);
}

struct flb_net_dns *flb_net_dns_ctx_get()
{
    return FLB_TLS_GET(flb_net_dns_ctx);
}

void flb_net_dns_ctx_set(struct flb_net_dns *dns_ctx)
{
    FLB_TLS_SET(flb_net_dns_ctx, dns_ctx);
}

void flb_net_lib_init()
{
    int result;

    result = ares_library_init_mem(ARES_LIB_INIT_ALL, flb_malloc, flb_free, flb_realloc);

    if(0 != result) {
        flb_error("[network] c-ares memory settings initialization error : %s",
                  ares_strerror(result));
    }
}

void flb_net_ctx_init(struct flb_net_dns *dns_ctx)
{
    mk_list_init(&dns_ctx->lookups);
    mk_list_init(&dns_ctx->lookups_drop);
}

void flb_net_setup_init(struct flb_net_setup *net)
{
    net->dns_mode = NULL;
    net->dns_resolver = NULL;
    net->dns_prefer_ipv4 = FLB_FALSE;
    net->dns_prefer_ipv6 = FLB_FALSE;
    net->keepalive = FLB_TRUE;
    net->keepalive_idle_timeout = 30;
    net->keepalive_max_recycle = 0;
    net->tcp_keepalive = FLB_FALSE;
    net->tcp_keepalive_time = -1;
    net->tcp_keepalive_interval = -1;
    net->tcp_keepalive_probes = -1;
    net->accept_timeout = 10;
    net->connect_timeout = 10;
    net->io_timeout = 0; /* Infinite time */
    net->source_address = NULL;
    net->backlog = FLB_NETWORK_DEFAULT_BACKLOG_SIZE;
    net->proxy_env_ignore = FLB_FALSE;
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

int flb_net_socket_share_port(flb_sockfd_t fd)
{
    int on = 1;
    int ret;

#ifdef SO_REUSEPORT
    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#else
    ret = -1;
#endif

    if (ret == -1) {
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

int flb_net_socket_rcv_buffer(flb_sockfd_t fd, int rcvbuf)
{
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) != 0) {
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

int flb_net_socket_set_rcvtimeout(flb_sockfd_t fd, int timeout_in_seconds)
{
#ifdef FLB_SYSTEM_WINDOWS
    /* WINDOWS */
    DWORD timeout = timeout_in_seconds * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout)
        == -1) {
#else
    /* LINUX and MAC OS X */
    struct timeval tv;
    tv.tv_sec = timeout_in_seconds;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) == -1) {
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


/*
 * Enable TCP keepalive
 */
int flb_net_socket_tcp_keepalive(flb_sockfd_t fd, struct flb_net_setup *net)
{
    int interval;
    int enabled;
    int probes;
    int time;
    int ret;

    enabled = 1;

    time = net->tcp_keepalive_time;
    probes = net->tcp_keepalive_probes;
    interval = net->tcp_keepalive_interval;

    ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                     (const void *) &enabled, sizeof(enabled));

    if (ret == 0 && time >= 0) {
#ifdef __APPLE__
        ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE,
#else
                ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
#endif
                (const void *) &time, sizeof(time));    }

    if (ret == 0 && interval >= 0) {
        ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
                         (const void *) &interval, sizeof(interval));
    }

    if (ret == 0 && probes >= 0) {
        ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
                         (const void *) &probes, sizeof(probes));
    }

    if (ret != 0) {
        flb_error("[net] failed to configure TCP keepalive for connection #%i", fd);

        ret = -1;
    }

    return ret;
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
        err = 0;
#else
        socket_errno = errno;
        err = flb_socket_error(fd);
#endif

        if (!FLB_EINPROGRESS(socket_errno) || err != 0) {
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

        /* check the connection status */
        socket_errno = flb_socket_error(fd);
        if (socket_errno != 0) {
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
                             void *async_ctx, struct flb_connection *u_conn)
{
    int ret;
    int err;
    int error = 0;
    int socket_errno;
    uint32_t mask;
    char so_error_buf[256];
    char *str;
    struct flb_upstream *u;

    u = u_conn->upstream;

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
    err = 0;
#else
    socket_errno = errno;
    err = flb_socket_error(fd);
#endif
    /* The logic behind this check is that when establishing a connection
     * errno should be EINPROGRESS with no additional information in order
     * for it to be a healthy attempt. However, when errno is EINPROGRESS
     * and an error occurs it could be saved in the so_error socket field
     * which has to be accessed through getsockopt(... SO_ERROR ...) so
     * in order to preserve that behavior while also properly detecting
     * other errno values as error conditions the comparison was changed.
     *
     * Windows note : flb_socket_error returns either the value returned
     * by WSAGetLastError or the value returned by getsockopt(... SO_ERROR ...)
     * if WSAGetLastError returns WSAEWOULDBLOCK as per libevents code.
     *
     * General note : according to the connect syscall man page (not libc)
     * there could be a timing issue with checking SO_ERROR here because
     * the suggested use involves checking it after a select or poll call
     * returns the socket as writable which is not the case here.
     */

    if (!FLB_EINPROGRESS(socket_errno) || err != 0) {
        return -1;
    }

    /* The connection is still in progress, implement a socket timeout */
    flb_trace("[net] connection #%i in process to %s:%i",
              fd, host, port);

    /* Register the connection socket into the main event loop */
    MK_EVENT_ZERO(&u_conn->event);

    ret = mk_event_add(u_conn->evl,
                       fd,
                       FLB_ENGINE_EV_THREAD,
                       MK_EVENT_WRITE,
                       &u_conn->event);

    u_conn->event.priority = FLB_ENGINE_PRIORITY_CONNECT;

    if (ret == -1) {
        /*
         * If we failed here there no much that we can do, just
         * let the caller know that we failed.
         */
        return -1;
    }

    u_conn->coroutine = async_ctx;

    /*
     * Return the control to the parent caller, we need to wait for
     * the event loop to get back to us.
     */
    flb_coro_yield(async_ctx, FLB_FALSE);

    /* We want this field to hold NULL at all times unless we are explicitly
     * waiting to be resumed.
     */
    u_conn->coroutine = NULL;

    /* Save the mask before the event handler do a reset */
    mask = u_conn->event.mask;

    /*
     * If the socket has been invalidated (e.g: timeout or shutdown), just
     * print a debug message and return.
     */
    if (u_conn->fd == -1) {
        flb_debug("[net] TCP connection not longer available: %s:%i",
                  u->tcp_host, u->tcp_port);
        return -1;
    }

    /* We got a notification, remove the event registered */
    ret = mk_event_del(u_conn->evl, &u_conn->event);
    if (ret == -1) {
        flb_error("[io] connect event handler error");
        return -1;
    }

    if (u_conn->net_error == ETIMEDOUT) {
        flb_debug("[net] TCP connection timed out: %s:%i",
                  u->tcp_host, u->tcp_port);
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
#ifdef __GLIBC__
            str = strerror_r(error, so_error_buf, sizeof(so_error_buf));
#else
            ret = strerror_r(error, so_error_buf, sizeof(so_error_buf));
            if (ret == 0) {
                str = so_error_buf;
            }
            else {
                flb_errno();
                return -1;
            }
#endif
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

static void flb_net_dns_lookup_context_destroy(struct flb_dns_lookup_context *lookup_context)
{
    mk_list_del(&lookup_context->_head);
    ares_destroy(lookup_context->ares_channel);
    flb_free(lookup_context);
}

static void flb_net_dns_lookup_context_drop(struct flb_dns_lookup_context *lookup_context)
{
    if (!lookup_context->dropped) {
        lookup_context->dropped = FLB_TRUE;

        if (lookup_context->ares_socket_registered) {
            mk_event_del(lookup_context->event_loop,
                         &lookup_context->response_event);
            lookup_context->ares_socket_registered = FLB_FALSE;
        }

        mk_list_del(&lookup_context->_head);
        mk_list_add(&lookup_context->_head, &lookup_context->dns_ctx->lookups_drop);

        if (lookup_context->udp_timer != NULL &&
            lookup_context->udp_timer->active) {
            flb_sched_timer_invalidate(lookup_context->udp_timer);

            lookup_context->udp_timer = NULL;
        }
    }
}

void flb_net_dns_lookup_context_cleanup(struct flb_net_dns *dns_ctx)
{
    struct flb_dns_lookup_context *lookup_context;
    struct flb_coro               *coroutine;
    struct mk_list                *head;
    struct mk_list                *tmp;

    mk_list_foreach_safe(head, tmp, &dns_ctx->lookups_drop) {
        lookup_context = mk_list_entry(head, struct flb_dns_lookup_context, _head);

        coroutine = lookup_context->coroutine;

        flb_net_dns_lookup_context_destroy(lookup_context);

        if (coroutine != NULL) {
            flb_coro_resume(coroutine);
        }
    }
}

static void flb_net_free_translated_addrinfo(struct addrinfo *input)
{
    struct addrinfo *current_record;
    struct addrinfo *next_record;

    if (input != NULL) {
        next_record = NULL;

        for (current_record = input ;
             current_record != NULL ;
             current_record = next_record) {

            if (current_record->ai_addr != NULL) {
                flb_free(current_record->ai_addr);
            }

            next_record = current_record->ai_next;

            flb_free(current_record);
        }
    }
}

static void flb_net_append_addrinfo_entry(struct addrinfo **head,
                                          struct addrinfo **tail,
                                          struct addrinfo  *entry)
{
    if (*head == NULL) {
        *head = entry;
    }
    else {
        (*tail)->ai_next = entry;
    }

    *tail = entry;
}

static struct addrinfo *flb_net_sort_addrinfo_list(struct addrinfo *input,
                                                   int preferred_family)
{
    struct addrinfo *preferred_results_head;
    struct addrinfo *remainder_results_head;
    struct addrinfo *preferred_results_tail;
    struct addrinfo *remainder_results_tail;
    struct addrinfo *current_record;
    struct addrinfo *next_record;

    remainder_results_head = NULL;
    preferred_results_head = NULL;
    remainder_results_tail = NULL;
    preferred_results_tail = NULL;
    current_record = NULL;
    next_record = NULL;

    for (current_record = input ;
         current_record != NULL ;
         current_record = next_record) {
        next_record = current_record->ai_next;
        current_record->ai_next = NULL;

        if (preferred_family == current_record->ai_family) {
            flb_net_append_addrinfo_entry(&preferred_results_head,
                                          &preferred_results_tail,
                                          current_record);
        }
        else
        {
            flb_net_append_addrinfo_entry(&remainder_results_head,
                                          &remainder_results_tail,
                                          current_record);
        }
    }

    if (preferred_results_tail != NULL) {
        preferred_results_tail->ai_next = remainder_results_head;
    }

    if (preferred_results_head == NULL) {
        return remainder_results_head;
    }

    return preferred_results_head;
}

static struct addrinfo *flb_net_translate_ares_addrinfo(struct ares_addrinfo *input)
{
    struct addrinfo           *previous_output_record;
    struct addrinfo           *current_output_record;
    struct ares_addrinfo_node *current_ares_record;
    int                        failure_detected;
    struct addrinfo           *output;

    output = NULL;
    failure_detected = 0;
    current_output_record = NULL;
    previous_output_record = NULL;

    if (input != NULL) {
        for (current_ares_record = input->nodes ;
             current_ares_record != NULL ;
             current_ares_record = current_ares_record->ai_next) {

            current_output_record = flb_calloc(1, sizeof(struct addrinfo));

            if (current_output_record == NULL) {
                flb_errno();
                failure_detected = 1;
                break;
            }

            if (output == NULL) {
                output = current_output_record;
            }

            current_output_record->ai_flags = current_ares_record->ai_flags;
            current_output_record->ai_family = current_ares_record->ai_family;
            current_output_record->ai_socktype = current_ares_record->ai_socktype;
            current_output_record->ai_protocol = current_ares_record->ai_protocol;
            current_output_record->ai_addrlen = current_ares_record->ai_addrlen;

            current_output_record->ai_addr = flb_malloc(current_output_record->ai_addrlen);

            if (current_output_record->ai_addr == NULL) {
                flb_errno();
                failure_detected = 1;
                break;
            }

            memcpy(current_output_record->ai_addr,
                   current_ares_record->ai_addr,
                   current_output_record->ai_addrlen);

            if (previous_output_record != NULL) {
                previous_output_record->ai_next = current_output_record;
            }

            previous_output_record = current_output_record;
        }
    }

    if (failure_detected) {
        if (output != NULL) {
            flb_net_free_translated_addrinfo(output);

            output = NULL;
        }
    }

    return output;
}


static void flb_net_getaddrinfo_callback(void *arg, int status, int timeouts,
                                         struct ares_addrinfo *res)
{
    struct flb_dns_lookup_context *lookup_context;

    lookup_context = (struct flb_dns_lookup_context *) arg;

    if (lookup_context->finished ||
        lookup_context->dropped) {
        return;
    }

    if (ARES_SUCCESS == status) {
        *(lookup_context->result) = flb_net_translate_ares_addrinfo(res);

        if (*(lookup_context->result) == NULL) {
            /* Translation fails only when calloc fails. */

            *(lookup_context->result_code) = ARES_ENOMEM;
        }
        else {
            *(lookup_context->result_code) = ARES_SUCCESS;
        }

        ares_freeaddrinfo(res);
    }
    else {
        *(lookup_context->result_code) = status;
    }

    lookup_context->finished = 1;
}

static int flb_net_getaddrinfo_event_handler(void *arg)
{
    struct flb_dns_lookup_context *lookup_context;

    lookup_context = FLB_DNS_LOOKUP_CONTEXT_FOR_EVENT(arg);

    if (lookup_context->finished ||
        lookup_context->dropped) {
        return 0;
    }

    ares_process_fd(lookup_context->ares_channel,
                    lookup_context->response_event.fd,
                    lookup_context->response_event.fd);

    if (lookup_context->finished) {
        flb_net_dns_lookup_context_drop(lookup_context);
    }

    return 0;
}

static void flb_net_getaddrinfo_timeout_handler(struct flb_config *config, void *data)
{
    struct flb_dns_lookup_context *lookup_context;

    (void) config;

    lookup_context = (struct flb_dns_lookup_context *) data;

    if (lookup_context->finished ||
        lookup_context->dropped) {
        return;
    }

    *(lookup_context->udp_timeout_detected) = FLB_TRUE;
    lookup_context->finished = FLB_TRUE;
    lookup_context->udp_timer = NULL;

    /* We deliverately set udp_timer because we don't want flb_net_dns_lookup_context_drop
     * to call flb_sched_timer_invalidate on the timer which was already disabled and
     * is about to be destroyed after this this callback returns.
     */

    ares_cancel(lookup_context->ares_channel);

    *(lookup_context->result_code) = ARES_ETIMEOUT;

    flb_net_dns_lookup_context_drop(lookup_context);
}

static ares_socket_t flb_dns_ares_socket(int af, int type, int protocol, void *userdata)
{
    struct flb_dns_lookup_context *lookup_context;
    int                            event_mask;
    ares_socket_t                  sockfd;
    int                            result;

    lookup_context = (struct flb_dns_lookup_context *) userdata;

    if (lookup_context->ares_socket_created) {
        /* This context already had a connection established and the code is not ready
         * to handle multiple connections so we abort the process.
         */
        errno = EACCES;

        return -1;
    }

    sockfd = socket(af, type, protocol);

    if (sockfd == -1) {
        return -1;
    }

    /* According to configure_socket in ares_process.c:970 if we provide our own socket
     * functions we need to set the socket up ourselves but the only specific thing we
     * need is for the socket to be set to non blocking mode so that's all we do here.
     */

    result = flb_net_socket_nonblocking(sockfd);

    if (result) {
        flb_socket_close(sockfd);

        return -1;
    }

    lookup_context->ares_socket_type       = type;
    lookup_context->ares_socket_created    = FLB_TRUE;

    lookup_context->response_event.mask    = MK_EVENT_EMPTY;
    lookup_context->response_event.status  = MK_EVENT_NONE;
    lookup_context->response_event.data    = &lookup_context->response_event;
    lookup_context->response_event.handler = flb_net_getaddrinfo_event_handler;
    lookup_context->response_event.fd      = sockfd;

    event_mask = MK_EVENT_READ;

    if (SOCK_STREAM == type) {
        event_mask |= MK_EVENT_WRITE;
    }

    result = mk_event_add(lookup_context->event_loop, sockfd, FLB_ENGINE_EV_CUSTOM,
                          event_mask, &lookup_context->response_event);
    lookup_context->response_event.priority = FLB_ENGINE_PRIORITY_DNS;
    if (result) {
        flb_socket_close(sockfd);

        return -1;
    }

    lookup_context->response_event.type = FLB_ENGINE_EV_CUSTOM;
    lookup_context->ares_socket_registered = FLB_TRUE;

    return sockfd;
}

static int flb_dns_ares_close(ares_socket_t sockfd, void *userdata)
{
    struct flb_dns_lookup_context *lookup_context;
    int                            result;

    lookup_context = (struct flb_dns_lookup_context *) userdata;

    if (lookup_context->ares_socket_registered) {
        lookup_context->ares_socket_registered = FLB_FALSE;

        mk_event_del(lookup_context->event_loop, &lookup_context->response_event);
    }

    result = flb_socket_close(sockfd);

    return result;
}

static int flb_dns_ares_connect(ares_socket_t sockfd, const struct sockaddr *addr,
                                ares_socklen_t addrlen, void *userdata)
{
    return connect(sockfd, addr, addrlen);
}

static ares_ssize_t flb_dns_ares_recvfrom(ares_socket_t sockfd, void *data,
                                          size_t data_len, int flags,
                                          struct sockaddr *from, ares_socklen_t *from_len,
                                          void *userdata)
{
    return recvfrom(sockfd, data, data_len, flags, from, from_len);
}

static ares_ssize_t flb_dns_ares_send(ares_socket_t sockfd, const struct iovec *vec,
                                      int len, void *userdata)
{
    return writev(sockfd, vec, len);
}

static struct flb_dns_lookup_context *flb_net_dns_lookup_context_create(
                                                            struct flb_net_dns *dns_ctx,
                                                            struct mk_event_loop *evl,
                                                            struct flb_coro *coroutine,
                                                            char dns_mode,
                                                            int *result)
{
    struct flb_dns_lookup_context *lookup_context;
    int                            local_result;
    int                            optmask;
    struct ares_options            opts = {0};

    local_result = 0;
    optmask = 0;

    if (result == NULL) {
        result = &local_result;
    }

    /* The initialization order here is important since it makes it easier to handle
     * failures
    */
    lookup_context = flb_calloc(1, sizeof(struct flb_dns_lookup_context));

    if (!lookup_context) {
        flb_errno();

        *result = ARES_ENOMEM;

        return NULL;
    }

    /* c-ares options: Set the transport layer to the desired protocol */

    optmask = ARES_OPT_FLAGS;

    opts.flags = ARES_FLAG_EDNS;
    if (dns_mode == FLB_DNS_USE_TCP) {
        opts.flags |= ARES_FLAG_USEVC;
    }

    *result = ares_init_options((ares_channel *) &lookup_context->ares_channel,
                                &opts, optmask);

    if (*result != ARES_SUCCESS) {
        flb_free(lookup_context);

        return NULL;
    }

    lookup_context->ares_socket_functions.asocket = flb_dns_ares_socket;
    lookup_context->ares_socket_functions.aclose = flb_dns_ares_close;
    lookup_context->ares_socket_functions.aconnect = flb_dns_ares_connect;
    lookup_context->ares_socket_functions.arecvfrom = flb_dns_ares_recvfrom;
    lookup_context->ares_socket_functions.asendv = flb_dns_ares_send;
    lookup_context->ares_socket_created = 0;
    lookup_context->event_loop = evl;
    lookup_context->udp_timer = NULL;
    lookup_context->coroutine = coroutine;
    lookup_context->finished = 0;
    lookup_context->dropped = 0;
    lookup_context->dns_ctx = dns_ctx;

    ares_set_socket_functions(lookup_context->ares_channel,
                              &lookup_context->ares_socket_functions,
                              lookup_context);

    *result = ARES_SUCCESS;

    mk_list_add(&lookup_context->_head, &dns_ctx->lookups);

    return lookup_context;
}

int flb_net_getaddrinfo(const char *node, const char *service, struct addrinfo *hints,
                        struct addrinfo **res, char *dns_mode_textual, int timeout)
{
    int                            udp_timeout_detected;
    struct flb_dns_lookup_context *lookup_context;
    int                            errno_backup;
    int                            result_code;
    struct addrinfo               *result_data;
    struct ares_addrinfo_hints     ares_hints;
    struct mk_event_loop          *event_loop;
    struct flb_coro               *coroutine;
    char                           dns_mode;
    struct flb_net_dns            *dns_ctx;
    int                            result;
    struct flb_sched              *sched;

    errno_backup = errno;

    dns_mode = FLB_DNS_USE_UDP;

    if (dns_mode_textual != NULL) {
        dns_mode = toupper(dns_mode_textual[0]);
    }

    event_loop = flb_engine_evl_get();
    assert(event_loop != NULL);

    coroutine = flb_coro_get();
    assert(coroutine != NULL);

    dns_ctx = flb_net_dns_ctx_get();
    assert(dns_ctx != NULL);

    lookup_context = flb_net_dns_lookup_context_create(dns_ctx, event_loop, coroutine,
                                                       dns_mode, &result);

    if (result != ARES_SUCCESS) {
        errno = errno_backup;
        return result;
    }

    lookup_context->udp_timeout_detected = &udp_timeout_detected;
    lookup_context->result_code = &result_code;
    lookup_context->result = &result_data;

    /* We think that either the callback or the timeout handler should be executed always
     * but just in case that there is a corner case we initialize result_code with an
     * error code so in case none of those is invoked (which shouldn't happen) the code
     * is not ARES_SUCCESS and thus cause a NULL pointer to be returned.
     */
    result_code = ARES_ESERVFAIL;
    result_data = NULL;
    udp_timeout_detected = 0;

    /* The timeout we get is expressed in seconds so we need to convert it to
     * milliseconds
     */
    timeout *= 1000;

    /* We need to ensure that our timer won't overlap with the upstream timeout handler.
     */
    if (timeout > 3000) {
        timeout -= 1000;
    }
    else {
        timeout -= (timeout / 3);
    }

    ares_hints.ai_flags = hints->ai_flags;
    ares_hints.ai_family = hints->ai_family;
    ares_hints.ai_socktype = hints->ai_socktype;
    ares_hints.ai_protocol = hints->ai_protocol;

    ares_getaddrinfo(lookup_context->ares_channel, node, service, &ares_hints,
                     flb_net_getaddrinfo_callback, lookup_context);

    if (!lookup_context->finished) {
        if (lookup_context->ares_socket_created) {
            if (lookup_context->ares_socket_type == SOCK_DGRAM) {
                /* If the socket type created by c-ares is UDP then we need to create our
                 * own timeout mechanism before yielding and cancel it if things go as
                 * expected.
                 */

                sched = flb_sched_ctx_get();
                assert(sched != NULL);

                result = flb_sched_timer_cb_create(sched, FLB_SCHED_TIMER_CB_ONESHOT,
                                                   timeout,
                                                   flb_net_getaddrinfo_timeout_handler,
                                                   lookup_context,
                                                   &lookup_context->udp_timer);
                if (result == -1) {
                    /* Timer creation failed, it happen because of file descriptor or memory
                     * exhaustion (ulimits usually)
                     */

                    result_code = ARES_ENOMEM;

                    ares_cancel(lookup_context->ares_channel);

                    lookup_context->coroutine = NULL;

                    flb_net_dns_lookup_context_drop(lookup_context);
                }
                else {
                    flb_coro_yield(coroutine, FLB_FALSE);
                }
            }
            else {
                flb_coro_yield(coroutine, FLB_FALSE);
            }
        }
        else {
            /* Do we want to do anything special for this condition? */
        }
    }
    else {
        lookup_context->coroutine = NULL;

        flb_net_dns_lookup_context_drop(lookup_context);
    }

    if (!result_code) {
        *res = result_data;
    }

    result = result_code;
    errno = errno_backup;

    return result;
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
                                 struct flb_connection *u_conn)
{
    int ret;
    int use_async_dns;
    char resolver_initial;
    flb_sockfd_t fd = -1;
    char _port[6];
    char address[41];
    struct addrinfo hints;
    struct addrinfo *sorted_res, *res, *rp;

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

    use_async_dns = is_async;

    if (u_conn->net->dns_resolver != NULL) {
        resolver_initial = toupper(u_conn->net->dns_resolver[0]);

        if (resolver_initial == FLB_DNS_LEGACY) {
            use_async_dns = FLB_FALSE;
        }
    }

    /* retrieve DNS info */
    if (use_async_dns) {
        ret = flb_net_getaddrinfo(host, _port, &hints, &res,
                                  u_conn->net->dns_mode,
                                  connect_timeout);
    }
    else {
        ret = getaddrinfo(host, _port, &hints, &res);
    }

    if (ret) {
        if (use_async_dns) {
            flb_warn("[net] getaddrinfo(host='%s', err=%d): %s", host, ret, ares_strerror(ret));
        }
        else {
            flb_warn("[net] getaddrinfo(host='%s', err=%d): %s", host, ret, gai_strerror(ret));
        }

        return -1;
    }

    if (u_conn->net_error > 0) {
        if (u_conn->net_error == ETIMEDOUT) {
            flb_warn("[net] timeout detected between DNS lookup and connection attempt");
        }

        if (use_async_dns) {
            flb_net_free_translated_addrinfo(res);
        }
        else {
            freeaddrinfo(res);
        }

        return -1;
    }

    sorted_res = res;

    if (u_conn->net->dns_prefer_ipv4) {
        sorted_res = flb_net_sort_addrinfo_list(res, AF_INET);

        if (sorted_res == NULL) {
            flb_debug("[net] error sorting ipv4 getaddrinfo results");

            if (use_async_dns) {
                flb_net_free_translated_addrinfo(res);
            }
            else {
                freeaddrinfo(res);
            }

            return -1;
        }
    }
    else if (u_conn->net->dns_prefer_ipv6) {
        sorted_res = flb_net_sort_addrinfo_list(res, AF_INET6);

        if (sorted_res == NULL) {
            flb_debug("[net] error sorting ipv6 getaddrinfo results");

            if (use_async_dns) {
                flb_net_free_translated_addrinfo(res);
            }
            else {
                freeaddrinfo(res);
            }

            return -1;
        }
    }

    /*
     * Try to connect: on this iteration we try to connect to the first
     * available address.
     */
    for (rp = sorted_res; rp != NULL; rp = rp->ai_next) {
        if (u_conn->net_error > 0) {
            if (u_conn->net_error == ETIMEDOUT) {
                flb_warn("[net] timeout detected between connection attempts");
            }
        }

        /* create socket */
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
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

        /* Set receive timeout */
        flb_net_socket_set_rcvtimeout(fd, u_conn->net->io_timeout);

        if (u_conn) {
            u_conn->fd = fd;
            u_conn->event.fd = fd;
        }

        flb_connection_set_remote_host(u_conn, rp->ai_addr);

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

        if (u_conn->net_error == ETIMEDOUT) {
            /* flb_upstream_conn_timeouts called prepare_destroy_conn which
             * closed the file descriptor and removed it from the event so
             * we can safely ignore it.
             */

            fd = -1;

            break;
        }

        if (ret == -1) {
            address[0] = '\0';

            ret = flb_net_address_to_str(rp->ai_family, rp->ai_addr,
                                         address, sizeof(address));

            /* If the connection failed, just abort and report the problem */
            flb_debug("[net] socket #%i could not connect to %s:%s",
                      fd, address, _port);

            if (u_conn) {
                u_conn->fd = -1;
                u_conn->event.fd = -1;
            }

            flb_socket_close(fd);
            fd = -1;

            continue;
        }

        break;
    }

    if (fd == -1) {
        flb_debug("[net] could not connect to %s:%s",
                  host, _port);
    }

    if (use_async_dns) {
        flb_net_free_translated_addrinfo(res);
    }
    else {
        freeaddrinfo(res);
    }

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

flb_sockfd_t flb_net_server(const char *port, const char *listen_addr,
                            int backlog, int share_port)
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

        if (share_port) {
            flb_net_socket_share_port(fd);
        }

        flb_net_socket_tcp_nodelay(fd);
        flb_net_socket_reset(fd);

        ret = flb_net_bind(fd, rp->ai_addr, rp->ai_addrlen, backlog);
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

flb_sockfd_t flb_net_server_udp(const char *port, const char *listen_addr, int share_port)
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

        if (share_port) {
            flb_net_socket_share_port(fd);
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

#ifdef FLB_HAVE_UNIX_SOCKET
flb_sockfd_t flb_net_server_unix(const char *listen_path,
                                 int stream_mode,
                                 int backlog,
                                 int share_port)
{
    size_t             address_length;
    size_t             path_length;
    struct sockaddr_un address;
    int                ret;
    flb_sockfd_t       fd;

    if (stream_mode) {
        fd = flb_net_socket_create(AF_UNIX, FLB_TRUE);
    }
    else {
        fd = flb_net_socket_create_udp(AF_UNIX, FLB_TRUE);
    }

    if (fd != -1) {
        memset(&address, 0, sizeof(struct sockaddr_un));

        path_length = strlen(listen_path);

        address_length = offsetof(struct sockaddr_un, sun_path) +
                         path_length +
                         1;

        address.sun_family = AF_UNIX;

        strncpy(address.sun_path, listen_path, sizeof(address.sun_path));

        if (share_port) {
            flb_net_socket_share_port(fd);
        }

        if (stream_mode) {
            ret = flb_net_bind(fd,
                               (const struct sockaddr *) &address,
                               address_length,
                               backlog);
        }
        else {
            ret = flb_net_bind_udp(fd,
                                   (const struct sockaddr *) &address,
                                   address_length);
        }

        if(ret == -1) {
            flb_warn("Cannot bind to or listen on %s", listen_path);

            flb_socket_close(fd);
        }
    }
    else {
        flb_error("Error creating server socket");
    }

    return fd;
}
#else
flb_sockfd_t flb_net_server_unix(const char *listen_path,
                                 int stream_mode,
                                 int backlog)
{
    flb_error("Unix sockets are not available in this platform");

    return -1;
}
#endif

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
    struct sockaddr_storage sock_addr = { 0 };
    socklen_t socket_size = sizeof(sock_addr);

    /*
     * sock_addr used to be a sockaddr struct, but this was too
     * small of a structure to handle IPV6 addresses (#9053).
     * This would cause accept() to not accept the connection (with no error),
     * and a loop would occur continually trying to accept the connection.
     * The sockaddr_storage can handle both IPV4 and IPV6.
     */

#ifdef FLB_HAVE_ACCEPT4
    remote_fd = accept4(server_fd, (struct sockaddr*)&sock_addr, &socket_size,
                        SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    remote_fd = accept(server_fd, (struct sockaddr*)&sock_addr, &socket_size);
    flb_net_socket_nonblocking(remote_fd);
#endif

    if (remote_fd == -1) {
        perror("accept4");
    }

    return remote_fd;
}

int flb_net_address_to_str(int family, const struct sockaddr *addr,
                           char *output_buffer, size_t output_buffer_size)
{
    struct sockaddr *proper_addr;
    const char      *result;

    if (family == AF_INET) {
        proper_addr = (struct sockaddr *) &((struct sockaddr_in *) addr)->sin_addr;
    }
    else if (family == AF_INET6) {
        proper_addr = (struct sockaddr *) &((struct sockaddr_in6 *) addr)->sin6_addr;
    }
    else {
        strncpy(output_buffer,
                "CONVERSION ERROR 1",
                output_buffer_size);

        return -1;
    }

    result = inet_ntop(family, proper_addr, output_buffer, output_buffer_size);

    if (result == NULL) {
        strncpy(output_buffer,
                "CONVERSION ERROR 2",
                output_buffer_size);

        return -2;
    }

    return 0;
}

#ifdef FLB_COMPILE_UNUSED_FUNCTIONS
static int net_socket_get_local_address(flb_sockfd_t fd,
                                        struct sockaddr_storage *address)
{
    socklen_t buffer_size;
    int       result;

    buffer_size = sizeof(struct sockaddr_storage);

    result = getsockname(fd, (struct sockaddr *) &address, &buffer_size);

    if (result == -1) {
        return -1;
    }

    return 0;
}
#endif

static int net_socket_get_peer_address(flb_sockfd_t fd,
                                       struct sockaddr_storage *address)
{
    socklen_t buffer_size;
    int       result;

    buffer_size = sizeof(struct sockaddr_storage);

    result = getpeername(fd, (struct sockaddr *) address, &buffer_size);

    if (result == -1) {
        return -1;
    }

    return 0;
}

static unsigned short int net_address_port(struct sockaddr_storage *address)
{
    unsigned short int port;

    if (address->ss_family == AF_INET) {
        port = ((struct sockaddr_in *) address)->sin_port;
    }
    else if (address->ss_family == AF_INET6) {
        port = ((struct sockaddr_in6 *) address)->sin6_port;
    }
    else {
        port = 0;
    }

    return ntohs(port);
}

#ifdef FLB_HAVE_UNIX_SOCKET
static int net_address_unix_socket_peer_pid_raw(flb_sockfd_t fd,
                                                struct sockaddr_storage *address,
                                                char *output_buffer,
                                                int output_buffer_size,
                                                size_t *output_data_size)
{
#if !defined(FLB_SYSTEM_MACOS) && !defined(FLB_SYSTEM_FREEBSD)
    unsigned int peer_credentials_size;
    struct ucred peer_credentials;
#endif
    size_t       required_buffer_size;
    int          result = 0;

    if (address->ss_family != AF_UNIX) {
        return -1;
    }

    required_buffer_size  = 11; /* maximum 32 bit signed integer */
    required_buffer_size += 1; /* string terminator */

    if (required_buffer_size > output_buffer_size) {
        return -1;
    }

#if !defined(FLB_SYSTEM_MACOS) && !defined(FLB_SYSTEM_FREEBSD)
    peer_credentials_size = sizeof(struct ucred);

    result = getsockopt(fd,
                        SOL_SOCKET,
                        SO_PEERCRED,
                        &peer_credentials,
                        &peer_credentials_size);

    if (result != -1) {
        *output_data_size = snprintf(output_buffer,
                                     output_buffer_size,
                                     "%ld",
                                     (long) peer_credentials.pid);
    }
#else
    *output_data_size = snprintf(output_buffer,
                                 output_buffer_size,
                                 FLB_NETWORK_ADDRESS_UNAVAILABLE);
#endif

    return result;
}

static int net_address_unix_socket_peer_pid_str(flb_sockfd_t fd,
                                                struct sockaddr_storage *address,
                                                char *output_buffer,
                                                int output_buffer_size,
                                                size_t *output_data_size)
{
    size_t  required_buffer_size;
    size_t  peer_pid_length;
    char    peer_pid[12];
    int     result;

    if (address->ss_family != AF_UNIX) {
        return -1;
    }

    result = net_address_unix_socket_peer_pid_raw(fd,
                                                  address,
                                                  peer_pid,
                                                  sizeof(peer_pid),
                                                  &peer_pid_length);

    if (result != 0) {
        return -1;
    }

    required_buffer_size  = strlen(FLB_NETWORK_UNIX_SOCKET_PEER_ADDRESS_TEMPLATE);
    required_buffer_size += peer_pid_length;
    required_buffer_size -= 2; /* format string specifiers */
    required_buffer_size += 1; /* string terminator */

    if (required_buffer_size > output_buffer_size) {
        *output_data_size = required_buffer_size;

        return -1;
    }

    *output_data_size = snprintf(output_buffer,
                                 output_buffer_size,
                                 FLB_NETWORK_UNIX_SOCKET_PEER_ADDRESS_TEMPLATE,
                                 peer_pid);

    return 0;
}
#endif

size_t flb_network_address_size(struct sockaddr_storage *address)
{
    if (address->ss_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    }
    else if (address->ss_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
#ifdef FLB_HAVE_UNIX_SOCKET
    else if (address->ss_family == AF_UNIX) {
        return sizeof(struct sockaddr_un);
    }
#endif

    return 0;
}

static int net_address_ip_raw(flb_sockfd_t fd,
                              struct sockaddr_storage *address,
                              char *output_buffer,
                              int output_buffer_size,
                              size_t *output_data_size)
{
    char    peer_pid[12];
    char   *address_data;
    size_t  address_size;
    int     result;

    errno = 0;

    if (address->ss_family == AF_UNSPEC) {
        flb_debug("socket_ip_raw: uninitialized address");

        return -1;
    }
    if (address->ss_family == AF_INET) {
        address_data = ((char *) &((struct sockaddr_in *) address)->sin_addr);
        address_size = sizeof(struct in_addr);
    }
    else if (address->ss_family == AF_INET6) {
        address_data = ((char *) &((struct sockaddr_in6 *) address)->sin6_addr);
        address_size = sizeof(struct in6_addr);
    }
#ifdef FLB_HAVE_UNIX_SOCKET
    else if (address->ss_family == AF_UNIX) {
        result = net_address_unix_socket_peer_pid_raw(fd,
                                                      address,
                                                      peer_pid,
                                                      sizeof(peer_pid),
                                                      &address_size);

        if (result != 0) {
            flb_debug("socket_ip_raw: error getting client process pid");

            return -1;
        }

        address_data = peer_pid;
    }
#endif
    else {
        flb_debug("socket_ip_raw: unsupported address type (%i)",
                  address->ss_family);

        return -1;
    }

    if (output_buffer_size < address_size) {
        flb_debug("socket_ip_raw: insufficient buffer size (%i < %zu)",
                  output_buffer_size, address_size);

        return -1;
    }

    memcpy(output_buffer, address_data, address_size);

    if (output_data_size != NULL) {
        *output_data_size = address_size;
    }

    return 0;
}

static int net_address_ip_str(flb_sockfd_t fd,
                              struct sockaddr_storage *address,
                              char *output_buffer,
                              int output_buffer_size,
                              size_t *output_data_size)
{
    void *address_data;
    int   result;

    errno = 0;

    if (address->ss_family == AF_UNSPEC) {
        *output_data_size = snprintf(output_buffer,
                                     output_buffer_size,
                                     FLB_NETWORK_ADDRESS_UNAVAILABLE);

        return 0;
    }
    else if (address->ss_family == AF_INET) {
        address_data = (void *) &((struct sockaddr_in *) address)->sin_addr;
    }
    else if (address->ss_family == AF_INET6) {
        address_data = (void *) &((struct sockaddr_in6 *) address)->sin6_addr;
    }
#ifdef FLB_HAVE_UNIX_SOCKET
    else if (address->ss_family == AF_UNIX) {
        result = net_address_unix_socket_peer_pid_str(fd,
                                                      address,
                                                      output_buffer,
                                                      output_buffer_size,
                                                      output_data_size);

        if (result != 0) {
            flb_debug("socket_ip_str: error getting client process pid");
        }

        return result;
    }
#endif
    else {
        flb_debug("socket_ip_str: unsupported address type (%i)",
                  address->ss_family);

        return -1;
    }

    if ((inet_ntop(address->ss_family,
                   address_data,
                   output_buffer,
                   output_buffer_size)) == NULL) {
        flb_debug("socket_ip_str: Can't get the IP text form (%i)", errno);

        return -1;
    }

    *output_data_size = strlen(output_buffer);

    return 0;
}

int flb_net_socket_peer_address(flb_sockfd_t fd,
                                struct sockaddr_storage *output_buffer)
{
    return net_socket_get_peer_address(fd, output_buffer);
}

int flb_net_socket_address_info(flb_sockfd_t fd,
                                struct sockaddr_storage *address,
                                unsigned short int *port_output_buffer,
                                char *str_output_buffer,
                                int str_output_buffer_size,
                                size_t *str_output_data_size)
{
    int result;

    result = net_address_ip_str(fd, address,
                                str_output_buffer,
                                str_output_buffer_size,
                                str_output_data_size);

    if (result == 0) {
        if (port_output_buffer != NULL) {
            *port_output_buffer = net_address_port(address);
        }
    }

    return result;
}

int flb_net_socket_ip_peer_str(flb_sockfd_t fd,
                               char *output_buffer,
                               int output_buffer_size,
                               size_t *output_data_size,
                               int *output_address_family)
{
    struct sockaddr_storage address;
    int                     result;

    result = net_socket_get_peer_address(fd, &address);

    if (result != 0) {
        return -1;
    }

    if (address.ss_family == AF_UNIX) {

    }

    result = net_address_ip_str(fd, &address,
                                output_buffer,
                                output_buffer_size,
                                output_data_size);

    if (result == 0) {
        if (output_address_family != NULL) {
            *output_address_family = address.ss_family;
        }
    }

    return result;
}

int flb_net_socket_peer_ip_raw(flb_sockfd_t fd,
                               char *output_buffer,
                               int output_buffer_size,
                               size_t *output_data_size,
                               int *output_address_family)
{
    struct sockaddr_storage address;
    int                     result;

    result = net_socket_get_peer_address(fd, &address);

    if (result != 0) {
        return -1;
    }

    result = net_address_ip_raw(fd, &address,
                                output_buffer,
                                output_buffer_size,
                                output_data_size);

    if (result == 0) {
        if (output_address_family != NULL) {
            *output_address_family = address.ss_family;
        }
    }

    return result;
}

int flb_net_socket_peer_port(flb_sockfd_t fd,
                             unsigned short int *output_buffer)
{
    struct sockaddr_storage address;
    int                     result;

    result = net_socket_get_peer_address(fd, &address);

    if (result != 0) {
        return -1;
    }

    *output_buffer = net_address_port(&address);

    return 0;
}

int flb_net_socket_peer_info(flb_sockfd_t fd,
                             unsigned short int *port_output_buffer,
                             struct sockaddr_storage *raw_output_buffer,
                             char *str_output_buffer,
                             int str_output_buffer_size,
                             size_t *str_output_data_size)
{
    struct sockaddr_storage address;
    int                     result;

    result = net_socket_get_peer_address(fd, &address);

    if (result != 0) {
        return -1;
    }

    memcpy(raw_output_buffer,
           &address,
           sizeof(struct sockaddr_storage));

    return flb_net_socket_address_info(fd,
                                       &address,
                                       port_output_buffer,
                                       str_output_buffer,
                                       str_output_buffer_size,
                                       str_output_data_size);
}

uint64_t flb_net_htonll(uint64_t value)
{
#if defined(_WIN32)
    /* use windows system provided htonll */
    return htonll(value);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return ((uint64_t) htonl(value & 0xFFFFFFFF) << 32) | htonl(value >> 32);
#else
    return value;
#endif
}