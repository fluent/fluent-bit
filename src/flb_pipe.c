/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
 * This file provides 3 interfaces:
 *
 * - flb_pipe_create : create a pair of connected file descriptors or sockets.
 * - flb_pipe_destroy: destroy a pair of connected fds or sockets.
 * - flb_pipe_close  : close individual end of a pipe.
 *
 * we need to handle a 'closer' handler because for Windows a file descriptor
 * is not a socket.
 */

#include <fluent-bit/flb_pipe.h>

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
    if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, pipefd) == -1) {
        perror("socketpair");
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

#else
/* All other flavors of Unix/BSD are OK */

#include <unistd.h>
#include <stdint.h>

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
    return close(fd);
}

#endif
