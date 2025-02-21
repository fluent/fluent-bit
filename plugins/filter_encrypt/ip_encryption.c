#include "ip_encryption.h"
#include "winsock_utils.h"
#include "cryptopANT.h"
#include <fluent-bit/flb_utils.h>
#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#include <openssl/blowfish.h>
#include <openssl/aes.h>

static int pass_bits4 = 0;
static int pass_bits6 = 0;
typedef unsigned char uchar;

struct in_addr ip4, ip4s;
struct in6_addr ip6, ip6s;

#define IP4MAXLEN       15      // strlen("xxx.xxx.xxx.xxx")
#define IP6MAXLEN       39      // strlen("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx")
#define CBUF_SZ         (IP6MAXLEN*2)

void set_encryption_key(const char *encryption_key) {
    flb_debug("setting encryption_key: %s\n", encryption_key);
    set_encrypt_key(encryption_key);
}

char *encrypt_ip(const char* input) {
    int af;
    if (flb_log_check(FLB_LOG_TRACE)) flb_debug("input value: %s\n", input);
    static char cbuf[CBUF_SZ];
    char ipv6_to_str[128];

    // invalid inputs will return 0.0.0.0
    char *invalid_input = "0.0.0.0";

    // trying IPv4
    af = AF_INET;
    if (inet_pton(af, input, &ip4) <= 0) {
        // trying IPv6
        af = AF_INET6;
        if (inet_pton(af, input, &ip6) <= 0) {
            if (flb_log_check(FLB_LOG_DEBUG)) fprintf(stderr, "don't understand address (%s)\n", cbuf);
            return invalid_input;
        }
        ip6s = scramble_ip6(&ip6, pass_bits6);
        ipv6_to_str_unexpanded(ipv6_to_str, &ip6s);
        if (cbuf != inet_ntop(af, &ip6s, cbuf, CBUF_SZ)) {
            if (flb_log_check(FLB_LOG_DEBUG)) perror("Error: can't print new address");
            invalid_input = "::"; // or 0000:0000:0000:0000:0000:0000:0000:0000
            return invalid_input;
        }
        if (flb_log_check(FLB_LOG_TRACE)) flb_debug("encrypted value(IPv6): %s\n", cbuf);
    } else {
        ip4s.s_addr = scramble_ip4(ip4.s_addr, pass_bits4);
        inet_ntop(AF_INET, &ip4s.s_addr, cbuf, CBUF_SZ);
        if (flb_log_check(FLB_LOG_TRACE)) flb_debug("encrypted value(IPv4): %s\n", cbuf);
    }
    return cbuf;
}

void init_winsock_if_needed() {
#ifdef _WIN32
    initialize_winsock();
#endif
}
