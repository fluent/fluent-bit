/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <assert.h>
#include <string.h>
#ifdef __wasi__
#include <wasi/api.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <wasi_socket_ext.h>
#else
#include <netdb.h>
#endif

void
test_nslookup(int af)
{
    struct addrinfo *res;
    int count = 0;
    struct addrinfo hints;
    char *url = "google-public-dns-a.google.com";

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    int ret = getaddrinfo(url, 0, &hints, &res);
    assert(ret == 0);
    struct addrinfo *address = res;
    while (address) {
        assert(address->ai_family == af);
        assert(address->ai_socktype == SOCK_STREAM);
        count++;
        address = address->ai_next;
    }

    assert(count > 0);
    freeaddrinfo(res);
}

int
main()
{
    test_nslookup(AF_INET);  /* for ipv4 */
    test_nslookup(AF_INET6); /* for ipv6 */

    return 0;
}
