/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2016 Monkey Software LLC <eduardo@monkey.io>
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

#include <monkey/mk_core.h>
#include <monkey/mk_net.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_thread.h>
#include <monkey/mk_tls.h>
#include <monkey/mk_socket.h>

#ifdef _WIN32
#include <winsock2.h>
#include <afunix.h>
#else
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#if defined (__linux__)
#include <sys/sendfile.h>
#endif

static int net_plain_read(struct mk_plugin *plugin, int socket_fd,
                          void *buf, int count)
{
    (void) plugin;

    return recv(socket_fd, buf, count, 0);
}

static int net_plain_write(struct mk_plugin *plugin, int socket_fd,
                           const void *buf, size_t count)
{
    (void) plugin;

    return send(socket_fd, buf, count, 0);
}

static int net_plain_writev(struct mk_plugin *plugin, int socket_fd,
                            struct mk_iov *mk_io)
{
    (void) plugin;

    return mk_iov_send(socket_fd, mk_io);
}

static int net_plain_close(struct mk_plugin *plugin, int socket_fd)
{
    (void) plugin;

#ifdef _WIN32
    return closesocket(socket_fd);
#else
    return close(socket_fd);
#endif
}

static int net_plain_send_file(struct mk_plugin *plugin, int socket_fd,
                               int file_fd, off_t *file_offset,
                               size_t file_count)
{
    ssize_t ret = -1;

    (void) plugin;

#if defined (__linux__)
    ret = sendfile(socket_fd, file_fd, file_offset, file_count);
    if (ret == -1 && errno != EAGAIN) {
        MK_TRACE("[net] sendfile(%i) failed: %s", socket_fd, strerror(errno));
    }
    return ret;
#elif defined (__APPLE__)
    off_t offset = *file_offset;
    off_t len = (off_t) file_count;

    ret = sendfile(file_fd, socket_fd, offset, &len, NULL, 0);
    if (ret == -1 && errno != EAGAIN) {
        MK_TRACE("[net] sendfile(%i) failed: %s", socket_fd, strerror(errno));
    }
    else if (len > 0) {
        *file_offset += len;
        return len;
    }
    return ret;
#elif defined (__FreeBSD__)
    off_t offset = *file_offset;
    off_t len = (off_t) file_count;

    ret = sendfile(file_fd, socket_fd, offset, len, NULL, 0, 0);
    if (ret == -1 && errno != EAGAIN) {
        MK_TRACE("[net] sendfile(%i) failed: %s", socket_fd, strerror(errno));
    }
    else if (len > 0) {
        *file_offset += len;
        return len;
    }
    return ret;
#else
    ssize_t bytes_written = 0;
    ssize_t send_ret;
    ssize_t to_be_sent;
    uint8_t temporary_buffer[1024];

    if (file_offset != NULL) {
        lseek(file_fd, *file_offset, SEEK_SET);
    }

    while (1) {
        ret = read(file_fd, temporary_buffer, sizeof(temporary_buffer));
        if (ret == 0) {
            return bytes_written;
        }
        else if (ret < 0) {
            return -1;
        }

        to_be_sent = ret;
        while (to_be_sent > 0) {
            send_ret = send(socket_fd,
                            &temporary_buffer[ret - to_be_sent],
                            to_be_sent, 0);
            if (send_ret == -1) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    return -1;
                }
            }
            else {
                bytes_written += send_ret;
                to_be_sent -= send_ret;
            }
        }
    }
#endif
}

static struct mk_plugin_network mk_net_io_plain = {
    .read        = net_plain_read,
    .write       = net_plain_write,
    .writev      = net_plain_writev,
    .close       = net_plain_close,
    .send_file   = net_plain_send_file,
    .event_interest = NULL,
    .buffer_size = MK_REQUEST_CHUNK,
    .plugin      = NULL
};

/* Initialize the network stack*/
int mk_net_init()
{
#ifdef _WIN32
    int result;
    WSADATA wsa_data;
    static int initialized = 0;

    if(0 != initialized) {
        return 0;
    }

    result = WSAStartup(MAKEWORD(2, 2), &wsa_data);

    if(0 != result) {
        if(WSAEINPROGRESS == result)
        {
            Sleep(100); /* Let the other thread finish initializing the stack */

            return 0;
        }

        return -1;
    }

    initialized = 1;    
#endif

    return 0;
}

struct mk_plugin_network *mk_net_transport_default()
{
    return &mk_net_io_plain;
}

int mk_net_transport_event_interest(struct mk_plugin_network *transport,
                                    int fd, int fallback)
{
    if (transport != NULL && transport->event_interest != NULL) {
        return transport->event_interest(transport->plugin, fd, fallback);
    }

    return fallback;
}

/* Connect to a TCP socket server */
static int mk_net_fd_connect(int fd, char *host, unsigned long port)
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
        return -1;
    }

    ret = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    return ret;
}

struct mk_net_connection *mk_net_conn_create(char *addr, int port)
{
    int fd;
    int ret;
    int error = 0;
    socklen_t len = sizeof(error);
    struct mk_sched_worker *sched;
    struct mk_net_connection *conn;

    /* Allocate connection context */
    conn = mk_mem_alloc(sizeof(struct mk_net_connection));
    if (!conn) {
        return NULL;
    }

    /* Create socket */
    fd = mk_socket_create(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        mk_mem_free(conn);
        return NULL;
    }

    /* Make socket async */
    mk_socket_set_nonblocking(fd);
    conn->fd = fd;

    ret = mk_net_fd_connect(conn->fd, addr, port);
    if (ret == -1) {
        if (errno != EINPROGRESS) {
            close(fd);
            mk_mem_free(conn);
            return NULL;
        }

        MK_EVENT_NEW(&conn->event);

        sched = mk_sched_get_thread_conf();
        // FIXME: not including the thread
        //conn->thread = mk_thread_get();
        ret = mk_event_add(sched->loop, conn->fd, MK_EVENT_THREAD,
                           MK_EVENT_WRITE, &conn->event);
        if (ret == -1) {
            close(fd);
            mk_mem_free(conn);
            return NULL;
        }

        /*
         * Return the control to the parent caller, we need to wait for
         * the event loop to get back to us.
         */
        mk_thread_yield(conn->thread);

        /* We got a notification, remove the event registered */
        ret = mk_event_del(sched->loop, &conn->event);

        /* Check the connection status */
        if (conn->event.mask & MK_EVENT_WRITE) {
            ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
            if (ret == -1) {
                close(fd);
                mk_mem_free(conn);
                return NULL;
            }

            if (error != 0) {
                /* Connection is broken, not much to do here */
                fprintf(stderr, "Async connection failed %s:%i\n",
                        conn->host, conn->port);
                close(fd);
                mk_mem_free(conn);
                return NULL;
            }
            MK_EVENT_NEW(&conn->event);
            return conn;
        }
        else {
            close(fd);
            mk_mem_free(conn);
            return NULL;
        }
    }

    return NULL;
}

int mk_net_conn_write(struct mk_channel *channel,
                      void *data, size_t len)
{
    int ret = 0;
    int error;
    ssize_t bytes;
    size_t total = 0;
    size_t send;
    socklen_t slen = sizeof(error);
    struct mk_thread *th = MK_TLS_GET(mk_thread);
    struct mk_sched_worker *sched;

    sched = mk_sched_get_thread_conf();
    if (!sched) {
        return -1;
    }

 retry:
    error = 0;

    if (len - total > 524288) {
        send = 524288;
    }
    else {
        send = (len - total);
    }

    send = len - total;
    bytes = channel->io->write(channel->io->plugin, channel->fd, (uint8_t *)data + total, send);
    if (bytes == -1) {
        if (errno == EAGAIN) {
            MK_EVENT_NEW(channel->event);
            channel->thread = th;
            ret = mk_event_add(sched->loop,
                               channel->fd,
                               MK_EVENT_THREAD,
                               mk_net_transport_event_interest(channel->io,
                                                               channel->fd,
                                                               MK_EVENT_WRITE),
                               channel->event);
            if (ret == -1) {
                /*
                 * If we failed here there no much that we can do, just
                 * let the caller we failed
                 */
                return -1;
            }

            /*
             * Return the control to the parent caller, we need to wait for
             * the event loop to get back to us.
             */
            mk_thread_yield(th);

            /* We got a notification, remove the event registered */
            ret = mk_event_del(sched->loop, channel->event);
            if (ret == -1) {
                return -1;
            }

            /* Check the connection status */
            if (channel->event->mask & MK_EVENT_WRITE) {
                ret = getsockopt(channel->fd, SOL_SOCKET, SO_ERROR, &error, &slen);
                if (ret == -1) {
                    fprintf(stderr, "[io] could not validate socket status");
                    return -1;
                }

                if (error != 0) {
                    return -1;
                }

                MK_EVENT_NEW(channel->event);
                goto retry;
            }
            else {
                return -1;
            }

        }
        else {
            return -1;
        }
    }

    /* Update counters */
    total += bytes;
    if (total < len) {
        channel->thread = th;
        ret = mk_event_add(sched->loop,
                           channel->fd,
                           MK_EVENT_THREAD,
                           mk_net_transport_event_interest(channel->io,
                                                           channel->fd,
                                                           MK_EVENT_WRITE),
                           channel->event);
        if (ret == -1) {
            /*
             * If we failed here there no much that we can do, just
             * let the caller we failed
             */
            return -1;
        }

        mk_thread_yield(th);
        goto retry;
    }

    if (channel->event->status & MK_EVENT_REGISTERED) {
        /* We got a notification, remove the event registered */
        ret = mk_event_del(sched->loop, channel->event);
    }

    return total;
}
