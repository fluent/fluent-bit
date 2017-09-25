/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

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
    return read(socket_fd, (void *) buf, count);
}

int mk_liana_write(int socket_fd, const void *buf, size_t count )
{
    ssize_t bytes_sent = -1;

    bytes_sent = write(socket_fd, buf, count);
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
    return close(socket_fd);
}

int mk_liana_send_file(int socket_fd, int file_fd, off_t *file_offset,
                       size_t file_count)
{
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
#error Sendfile not supported on platform
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
