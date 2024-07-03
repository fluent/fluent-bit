//
// Created by alisrasic on 10/26/22.
//

#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <string.h>

#ifndef FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_IP_UTILS_H_
#define FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_IP_UTILS_H_


const bool is_ipv6_private_address(struct in6_addr net);
bool is_ipv4_private_address(struct in_addr net);
bool is_ip_address_private(char *input);
#endif //FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_IP_UTILS_H_
