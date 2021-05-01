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

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#if defined (__linux__)
#include <sys/sendfile.h>
#endif

#include <monkey/mk_api.h>

int mk_liana_plugin_init(struct plugin_api **api, char *confdir)
{
    (void) confdir;
    mk_api = *api;
    return 0;
}

int mk_liana_plugin_exit()
{
    return 0;
}

int mk_liana_read(int socket_fd, void *buf, int count)
{
    return recv(socket_fd, (void*)buf, count, 0);
}

int mk_liana_write(int socket_fd, const void *buf, size_t count )
{
    ssize_t bytes_sent = -1;

    bytes_sent = send(socket_fd, buf, count, 0);

    return bytes_sent;
}

int mk_liana_writev(int socket_fd, struct mk_iov *mk_io)
{
    ssize_t bytes_sent = -1;

    bytes_sent = mk_api->iov_send(socket_fd, mk_io);

    return bytes_sent;
}

int mk_liana_close(int socket_fd)
{
#ifdef _WIN32
    return closesocket(socket_fd);
#else
    return close(socket_fd);
#endif
}

int mk_liana_send_file(int socket_fd, int file_fd, off_t *file_offset,
                       size_t file_count)
{
    ssize_t bytes_written = 0;
    ssize_t to_be_sent = -1;
    ssize_t send_ret = -1;
    ssize_t ret = -1;

#if defined (__linux__)
    ret = sendfile(socket_fd, file_fd, file_offset, file_count);
    if (ret == -1 && errno != EAGAIN) {
        PLUGIN_TRACE("[FD %i] error from sendfile(): %s",
                     socket_fd, strerror(errno));
    }
    return ret;
#elif defined (__APPLE__)
    off_t offset = *file_offset;
    off_t len = (off_t) file_count;

    ret = sendfile(file_fd, socket_fd, offset, &len, NULL, 0);
    if (ret == -1 && errno != EAGAIN) {
        PLUGIN_TRACE("[FD %i] error from sendfile(): %s",
                     socket_fd, strerror(errno));
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
        PLUGIN_TRACE("[FD %i] error from sendfile(): %s",
                     socket_fd, strerror(errno));
    }
    else if (len > 0) {
        *file_offset += len;
        return len;
    }
    return ret;
#else
    #pragma message ("This is a terrible sendfile \"implementation\" and just a crutch")

    uint8_t temporary_buffer[1024];

    if (NULL != file_offset) {
        lseek(file_fd, *file_offset, SEEK_SET);
    }

    while (1) {
        memset(temporary_buffer, 0, sizeof(temporary_buffer));

        ret = read(file_fd, temporary_buffer, sizeof(temporary_buffer));

        if (0 == ret)
        {
            return bytes_written;
        }
        else if (0 > ret)
        {
            return -1;
        }
        else if (0 < ret)
        {
            to_be_sent = ret;

            while (to_be_sent > 0)
            {
                send_ret = send(file_fd, &temporary_buffer[ret - to_be_sent], to_be_sent, 0);

                if (-1 == send_ret)
                {
                    if (EAGAIN != errno &&
                        EWOULDBLOCK != errno)
                    {
                        return -1;
                    }
                }
                else
                {
                    bytes_written += send_ret;
                    to_be_sent -= send_ret;
                }
            }
        }
    }
#endif
}

/* Network Layer plugin Callbacks */
struct mk_plugin_network mk_plugin_network_liana = {
    .read          = mk_liana_read,
    .write         = mk_liana_write,
    .writev        = mk_liana_writev,
    .close         = mk_liana_close,
    .send_file     = mk_liana_send_file,
    .buffer_size   = MK_REQUEST_CHUNK
};

struct mk_plugin mk_plugin_liana = {
    /* Identification */
    .shortname     = "liana",
    .name          = "Liana Network Layer",
    .version       = MK_VERSION_STR,
    .hooks         = MK_PLUGIN_NETWORK_LAYER,

    /* Init / Exit */
    .init_plugin   = mk_liana_plugin_init,
    .exit_plugin   = mk_liana_plugin_exit,

    /* Init Levels */
    .master_init   = NULL,
    .worker_init   = NULL,

    /* Type */
    .network       = &mk_plugin_network_liana,

    /* Capabilities */
    .capabilities  = MK_CAP_SOCK_PLAIN
};
