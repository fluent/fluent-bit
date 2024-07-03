//
// Created by alisrasic on 10/26/22.
//


#include "ip_utils.h"

#define DO_DEBUG 0

#define CBUF_SZ 128
char buffer[CBUF_SZ];

struct in_addr ip4_input;
struct in6_addr ip6_input;

bool prefix(const char *pre, const char *str)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}

const bool is_ipv6_private_address(struct in6_addr net)
{
    int af;
    af = AF_INET6;
    if (buffer != inet_ntop(af, &net, buffer, CBUF_SZ)) {
        if (DO_DEBUG) perror("Error: can't print new address");
        char *invalid_input = "::"; // or 0000:0000:0000:0000:0000:0000:0000:0000
        return invalid_input;
    }

    if (DO_DEBUG) printf("IPv6: %s\n", buffer);

    bool is_private = 0;
    // Private internets, ULA address => fc00::/7 range, Link-Local addresses => fe80::/10,
    // Multicast addresses are in the ff00::/8
    // Localhost => ::1
    if( prefix("fc", buffer) ||
        prefix("fe", buffer) ||
        prefix("fd", buffer) ||
        prefix("ff", buffer) ||
        prefix("::1", buffer)){
        is_private = 1;
    }
    if (DO_DEBUG) printf("in_ip6 = %s (isPrivate: %d)\n", buffer, is_private);

    return is_private;
}


bool is_ipv4_private_address(struct in_addr net)
{
    unsigned byte1 = (ntohl(net.s_addr) >> 24) & 0xff;
    unsigned byte2 = (ntohl(net.s_addr) >> 16) & 0xff;
    unsigned byte3 = (ntohl(net.s_addr) >> 8) & 0xff;
    unsigned byte4 = (ntohl(net.s_addr)) & 0xff;

    // 10.x.y.z
    if (byte1 == 10 || byte1 == 127)
        return true;

    // 172.16.0.0 - 172.31.255.255
    if ((byte1 == 172) && (byte2 >= 16) && (byte2 <= 31))
        return true;

    // 192.168.0.0 - 192.168.255.255
    if ((byte1 == 192) && (byte2 == 168))
        return true;

    // Multicast
    if (byte1 >= 224 && byte1 <= 239) {
        return true;
    }

    // Link-local
    if(byte1 == 169 && byte2 == 254) {
        return true;
    }

    return false;
}


bool is_ip_address_private(char *input) {

    char ipv6_to_str[128];
    int af;
    // trying IPv4
    af = AF_INET;
    if(inet_pton(af, input, &ip4_input.s_addr) <= 0) {
        //trying IPv6
        af = AF_INET6;
        if (inet_pton(af, input, &ip6_input) <= 0) {
            // invalid IP address
            if (DO_DEBUG) printf("Invalid IP address: %s", input);
            return -1;
        }
        return is_ipv6_private_address(ip6_input);
    }
    return is_ipv4_private_address(ip4_input);
}