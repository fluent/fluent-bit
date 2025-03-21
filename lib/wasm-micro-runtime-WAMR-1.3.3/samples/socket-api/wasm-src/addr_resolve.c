/*
 * Copyright (C) 2022 Amazon.com, Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __wasi__
#include <wasi_socket_ext.h>
#else
#include <netdb.h>
#endif

int
lookup_host(const char *host)
{
    struct addrinfo hints, *res, *result;
    int errcode;
    char addrstr[100];
    void *ptr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    errcode = getaddrinfo(host, NULL, &hints, &result);
    if (errcode != 0) {
        perror("getaddrinfo");
        return -1;
    }

    res = result;

    printf("Host: %s\n", host);
    while (res) {
        switch (res->ai_family) {
            case AF_INET:
                ptr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
                break;
            case AF_INET6:
                ptr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
                break;
            default:
                printf("Unsupported address family: %d\n", res->ai_family);
                continue;
        }
        inet_ntop(res->ai_family, ptr, addrstr, 100);
        printf("IPv%d address: %s (%s)\n", res->ai_family == AF_INET6 ? 6 : 4,
               addrstr, res->ai_socktype == SOCK_STREAM ? "TCP" : "UDP");
        res = res->ai_next;
    }

    freeaddrinfo(result);

    return EXIT_SUCCESS;
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s DOMAIN\n", argv[0]);
        return EXIT_FAILURE;
    }

    return lookup_host(argv[1]);
}
