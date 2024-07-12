#include "ip_utils.h"
#include "winsock_utils.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#define CBUF_SZ 128

static char buffer[CBUF_SZ];

bool prefix(const char *pre, const char *str)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}

bool is_ipv6_private_address(struct in6_addr net)
{
    if (!inet_ntop(AF_INET6, &net, buffer, CBUF_SZ)) {
        perror("Error: can't print new address");
        return false;
    }

    bool is_private = false;
    if (prefix("fc", buffer) || prefix("fd", buffer) || prefix("fe", buffer) ||
        prefix("ff", buffer) || prefix("::1", buffer)) {
        is_private = true;
    }

    return is_private;
}

bool is_ipv4_private_address(struct in_addr net)
{
    unsigned byte1 = (ntohl(net.s_addr) >> 24) & 0xff;
    unsigned byte2 = (ntohl(net.s_addr) >> 16) & 0xff;

    if (byte1 == 10 || byte1 == 127) return true;
    if ((byte1 == 172) && (byte2 >= 16) && (byte2 <= 31)) return true;
    if ((byte1 == 192) && (byte2 == 168)) return true;
    if (byte1 >= 224 && byte1 <= 239) return true; // Multicast
    if (byte1 == 169 && byte2 == 254) return true; // Link-local

    return false;
}

bool is_ip_address_private(const char *input)
{
    struct in_addr ip4_input;
    struct in6_addr ip6_input;

    if (inet_pton(AF_INET, input, &ip4_input.s_addr) > 0) {
        return is_ipv4_private_address(ip4_input);
    }
    if (inet_pton(AF_INET6, input, &ip6_input) > 0) {
        return is_ipv6_private_address(ip6_input);
    }

    fprintf(stderr, "Invalid IP address: %s\n", input);
    return false;
}

#ifdef _WIN32
void initialize_winsock()
{
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        exit(EXIT_FAILURE);
    }
}

void cleanup_winsock()
{
    WSACleanup();
}
#endif
