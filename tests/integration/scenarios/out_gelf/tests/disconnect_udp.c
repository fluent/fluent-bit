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

/* Test-only Linux send interposer: disconnect a real connected UDP socket. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

static int disconnected_once;

int connect(int fd, const struct sockaddr *address, socklen_t address_size)
{
    static int (*real_connect)(int, const struct sockaddr *, socklen_t);
    static int failed_reconnect;
    const struct sockaddr_in *peer = (const struct sockaddr_in *) address;
    const char *port;
    const char *fail_reconnect;

    if (real_connect == NULL) {
        real_connect = dlsym(RTLD_NEXT, "connect");
    }

    port = getenv("GELF_TEST_PORT");
    fail_reconnect = getenv("GELF_TEST_FAIL_RECONNECT");
    if (disconnected_once && !failed_reconnect && port != NULL &&
        fail_reconnect != NULL && atoi(fail_reconnect) != 0 &&
        address->sa_family == AF_INET && ntohs(peer->sin_port) == atoi(port)) {
        failed_reconnect = 1;
        fprintf(stderr, "GELF test: failed reconnect\n");
        errno = EHOSTUNREACH;
        return -1;
    }

    return real_connect(fd, address, address_size);
}

ssize_t send(int fd, const void *buffer, size_t length, int flags)
{
    static ssize_t (*real_send)(int, const void *, size_t, int);
    static int sends;
    struct sockaddr_in peer;
    struct sockaddr disconnected = {0};
    socklen_t peer_size = sizeof(peer);
    const char *port;
    const char *fail_at;

    if (real_send == NULL) {
        real_send = dlsym(RTLD_NEXT, "send");
    }

    port = getenv("GELF_TEST_PORT");
    fail_at = getenv("GELF_TEST_FAIL_AT");
    if (port != NULL && fail_at != NULL &&
        getpeername(fd, (struct sockaddr *) &peer, &peer_size) == 0 &&
        peer.sin_family == AF_INET && ntohs(peer.sin_port) == atoi(port)) {
        sends++;
        if (sends == atoi(fail_at)) {
            disconnected.sa_family = AF_UNSPEC;
            if (connect(fd, &disconnected, sizeof(disconnected)) != 0) {
                abort();
            }
            disconnected_once = 1;
            fprintf(stderr, "GELF test: disconnected UDP socket\n");
        }
    }

    return real_send(fd, buffer, length, flags);
}
