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

/*
 * Fluent Bit core uses unnamed Unix pipes for signaling and general
 * communication across components. When building on Windows this is
 * problematic because Windows pipes are not selectable and only
 * sockets are.
 *
 * This file aims to wrap around the required backend calls depending
 * of the operating system.
 *
 * This file provides 4 interfaces:
 *
 * - flb_pipe_create          : create a pair of connected file descriptors or sockets.
 * - flb_pipe_destroy         : destroy a pair of connected fds or sockets.
 * - flb_pipe_close           : close individual end of a pipe.
 * - flb_pipe_set_nonblocking : make a socket nonblocking
 *
 * we need to have a 'closer' handler because for Windows a file descriptor
 * is not a socket.
 */

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_pipe.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>

#ifdef _WIN32

/*
 * Building on Windows means that Monkey library (lib/monkey) and it
 * core runtime have been build with 'libevent' backend support, that
 * library provide an abstraction to create a socketpairs.
 *
 * Creating a pipe on Fluent Bit @Windows, means create a socket pair.
 */

int flb_pipe_create(flb_pipefd_t pipefd[2])
{
    struct linger sl = {1, 0}; /* l_onoff = 1, l_linger = 0 */

    if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, pipefd) == -1) {
        perror("socketpair");
        return -1;
    }

    if (setsockopt(pipefd[0], SOL_SOCKET, SO_LINGER, (const char*)&sl, sizeof(sl)) == -1) {
        perror("setsockopt linger failed on pipefd[0]");
        flb_pipe_destroy(pipefd);
        return -1;
    }

    if (setsockopt(pipefd[1], SOL_SOCKET, SO_LINGER, (const char*)&sl, sizeof(sl)) == -1) {
        perror("setsockopt linger failed on pipefd[1]");
        flb_pipe_destroy(pipefd);
        return -1;
    }

    return 0;
}

void flb_pipe_destroy(flb_pipefd_t pipefd[2])
{
    evutil_closesocket(pipefd[0]);
    evutil_closesocket(pipefd[1]);
}

int flb_pipe_close(flb_pipefd_t fd)
{
    return evutil_closesocket(fd);
}

int flb_pipe_set_nonblocking(flb_pipefd_t fd)
{
    return evutil_make_socket_nonblocking(fd);
}
#else
/* All other flavors of Unix/BSD are OK */

#include <stdint.h>
#include <fcntl.h>

int flb_pipe_create(flb_pipefd_t pipefd[2])
{
    return pipe(pipefd);
}

void flb_pipe_destroy(flb_pipefd_t pipefd[2])
{
    close(pipefd[0]);
    close(pipefd[1]);
}

int flb_pipe_close(flb_pipefd_t fd)
{
    /*
     *  when chunk file is destroyed, the fd for file will be -1, we should avoid
     *  deleting chunk file with fd -1
     */
    if (fd == -1) {
        return -1;
    }

    return close(fd);
}

int flb_pipe_set_nonblocking(flb_pipefd_t fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        return -1;
    if (flags & O_NONBLOCK)
        return 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
#endif

/* Blocking read until receive 'count' bytes */
ssize_t flb_pipe_read_all(int fd, void *buf, size_t count)
{
    ssize_t bytes;
    size_t total = 0;

    do {
        bytes = flb_pipe_r(fd, (char *) buf + total, count - total);
        if (bytes == -1) {
            if (FLB_PIPE_WOULDBLOCK()) {
                /*
                 * This could happen, since this function goal is not to
                 * return until all data have been read, just sleep a little
                 * bit (0.05 seconds)
                 */
                flb_time_msleep(50);
                continue;
            }
            return -1;
        }
        else if (bytes == 0) {
            /* Broken pipe ? */
            flb_pipe_error();
            return -1;
        }
        total += bytes;

    } while (total < count);

    return total;
}

/* Blocking write until send 'count bytes */
ssize_t flb_pipe_write_all(int fd, const void *buf, size_t count)
{
    ssize_t bytes;
    size_t total = 0;

    do {
        bytes = flb_pipe_w(fd, (const char *) buf + total, count - total);
        if (bytes == -1) {
            if (FLB_PIPE_WOULDBLOCK()) {
                /*
                 * This could happen, since this function goal is not to
                 * return until all data have been read, just sleep a little
                 * bit (0.05 seconds)
                 */
                flb_time_msleep(50);
                continue;
            }
            return -1;
        }
        else if (bytes == 0) {
            /* Broken pipe ? */
            flb_pipe_error();
            return -1;
        }
        total += bytes;

    } while (total < count);

    return total;
}