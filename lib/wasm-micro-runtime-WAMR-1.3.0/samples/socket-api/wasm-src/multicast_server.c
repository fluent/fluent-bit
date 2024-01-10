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

static void
init_sockaddr_inet(struct sockaddr_in *addr, char *addr_buffer)
{
    addr->sin_family = AF_INET;
    addr->sin_port = htons(1234);
    memcpy(&(addr->sin_addr), addr_buffer, 4);
}

static void
init_sockaddr_inet6(struct sockaddr_in6 *addr, char *addr_buffer)
{
    addr->sin6_family = AF_INET6;
    addr->sin6_port = htons(1234);
    memcpy(&(addr->sin6_addr), addr_buffer, 16);
}

int
main(int argc, char *argv[])
{
    struct sockaddr_storage addr = { 0 };
    int sd;
    char *databuf = "Test message";
    int datalen = strlen(databuf) + 1;
    char multicast_addr_buffer[16];
    int addr_type = -1;
    int multicast_interface;
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
        return EXIT_FAILURE;
    }

    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &bool_opt, sizeof(bool_opt))
        == -1) {
        perror("Failed setting SO_REUSEADDR");
        goto fail;
    }

    if (addr_type == AF_INET) {
        multicast_interface = htonl(INADDR_ANY);
        if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF,
                       (char *)&multicast_interface,
                       sizeof(multicast_interface))) {
            perror("Failed setting local interface");
            goto fail;
        }
        init_sockaddr_inet((struct sockaddr_in *)&addr, multicast_addr_buffer);
    }
    else {
        multicast_interface = 0;
        if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                       (char *)&multicast_interface,
                       sizeof(multicast_interface))) {
            perror("Failed setting local interface");
            goto fail;
        }
        init_sockaddr_inet6((struct sockaddr_in6 *)&addr,
                            multicast_addr_buffer);
    }

    if (sendto(sd, databuf, datalen, 0, (struct sockaddr *)&addr, sizeof(addr))
        == -1) {
        perror("Failed sending datagram");
        goto fail;
    }

    printf("Datagram sent\n");
    close(sd);
    return EXIT_SUCCESS;

fail:
    close(sd);
    return EXIT_FAILURE;
}