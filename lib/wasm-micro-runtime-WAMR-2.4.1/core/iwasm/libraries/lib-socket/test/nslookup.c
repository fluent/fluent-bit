/*
 * Copyright (C) 2023 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
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

void *
test_nslookup_mt(void *params)
{
    int *af = (int *)params;
    test_nslookup(*af);
    return NULL;
}

int
main()
{
    int afs[] = { AF_INET, AF_INET6 };

    for (int i = 0; i < sizeof(afs) / sizeof(afs[0]); i++) {
        pthread_t th;

        printf("Testing %d in main thread...\n", afs[i]);
        test_nslookup(afs[i]);
        printf("Testing %d in a new thread...\n", afs[i]);
        pthread_create(&th, NULL, test_nslookup_mt, &afs[i]);
        pthread_join(th, NULL);
    }

    return 0;
}
