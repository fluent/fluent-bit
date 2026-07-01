/*
 * Copyright (C) 2022 Amazon.com Inc. or its affiliates. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef __wasi__
#include <wasi_socket_ext.h>
#endif

static void
init_sockaddr_inet(struct sockaddr_in *addr)
{
    addr->sin_family = AF_INET;
    addr->sin_port = htons(1234);
}

static void
init_sockaddr_inet6(struct sockaddr_in6 *addr)
{
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(1234);
}

static int
get_ip_addr_type(char *addr, char *buf)
{
    if (inet_pton(AF_INET6, addr, buf)) {
        return AF_INET6;
    }
    if (inet_pton(AF_INET, addr, buf)) {
        return AF_INET;
    }
    return -1;
}

static int
is_valid_addr_type(int addr_type)
{
    return !(addr_type == -1
             || (addr_type != AF_INET && addr_type != AF_INET6));
}

int
main(int argc, char *argv[])
{
    struct ipv6_mreq ipv6_group;
    struct ip_mreq ipv4_group;
    int sd;
    int datalen;
    char databuf[1024] = { 0 };
    char multicast_addr_buffer[16];
    struct sockaddr_storage local_address = { 0 };
    int addr_type = -1;
    int read_result;
    int bool_opt = 1;

    if (argc < 2) {
        printf("Usage is <Multicast IP>\n");
        return EXIT_FAILURE;
    }

    addr_type = get_ip_addr_type(argv[1], multicast_addr_buffer);

    if (!is_valid_addr_type(addr_type)) {
        printf("Not a valid ipv4 or ipv6 address\n");
        return EXIT_FAILURE;
    }

    if ((sd = socket(addr_type, SOCK_DGRAM, 0)) == -1) {
        perror("Failed opening socket");
        return EXIT_FAILURE;
    }

    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &bool_opt, sizeof(bool_opt))
        == -1) {
        perror("Failed setting SO_REUSEADDR");
        goto fail;
    }

    if (addr_type == AF_INET) {
        init_sockaddr_inet((struct sockaddr_in *)&local_address);
        memcpy(&(ipv4_group.imr_multiaddr), multicast_addr_buffer, 4);
        ipv4_group.imr_interface.s_addr = htonl(INADDR_ANY);

        if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &ipv4_group,
                       sizeof(ipv4_group))
            == -1) {
            perror("Failed joining IPv4 multicast group");
            goto fail;
        }
    }
    else {
        init_sockaddr_inet6((struct sockaddr_in6 *)&local_address);
        memcpy(&(ipv6_group.ipv6mr_multiaddr), multicast_addr_buffer, 16);
        ipv6_group.ipv6mr_interface = 0;

        if (setsockopt(sd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &ipv6_group,
                       sizeof(ipv6_group))
            == -1) {
            perror("Failed joining IPv6 multicast group");
            goto fail;
        }
    }

    if (bind(sd, (struct sockaddr *)&local_address, sizeof(local_address))
        == -1) {
        perror("Failed binding socket");
        goto fail;
    }

    printf("Joined multicast group. Waiting for datagram...\n");

    datalen = sizeof(databuf) - 1;
    read_result = read(sd, databuf, datalen);

    if (read_result < 0) {
        perror("Failed binding socket");
        goto fail;
    }

    printf("Reading datagram message...OK.\n");
    printf("The message from multicast server is: \"%s\"\n", databuf);
    close(sd);
    return EXIT_SUCCESS;

fail:
    close(sd);
    return EXIT_FAILURE;
}
