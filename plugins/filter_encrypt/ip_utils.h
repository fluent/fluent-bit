#ifndef FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_IP_UTILS_H_
#define FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_IP_UTILS_H_

#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
extern void initialize_winsock();
extern void cleanup_winsock();
#else
#include <arpa/inet.h>
#endif

bool is_ipv6_private_address(struct in6_addr net);
bool is_ipv4_private_address(struct in_addr net);
bool is_ip_address_private(const char *input);

#endif // FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_UTILS_IP_UTILS_H_
