/* -*-  Mode:C; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (C) 2004-2018 by the University of Southern California
 * $Id: 35e089a7da2122012654b19832826c3224f1f2dc $
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 */

// #ifndef lint
// static const char rcsid[] =
//     "@(#) $Id: 35e089a7da2122012654b19832826c3224f1f2dc $";
// #endif

#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/md5.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#include <fluent-bit/flb_log.h>

#include "utils.h"
#include "cryptopANT.h"

#define IPV6_PADDING      40

#define MAX_BLK_LENGTH        32
#define CACHE_BITS        24    /* How many bits of IPv4 we cache, cannot be zero */
#define BF_KEYLEN        16    /* bytes */

#define TEST_CACHE        0

#define RESET_ETHER_MCAST(p)    (*(char*)(p) &= 0xfe)

#ifndef MAX
#define MAX(a, b)        ((a) > (b) ? (a) : (b))
#endif

#ifdef HAVE__U6_ADDR32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

//determined by autoconf
#ifdef WORDS_BIGENDIAN
//sigh, older version of the code was not byte-order safe; this is needed
//to ensure backward compatibility AND compatibility with BE-systems.
#include <byteswap.h>
#define cryptopant_swap32(x) bswap_32(x)
#else
#define cryptopant_swap32(x) (x)
#endif

#define DO_DEBUG 0

typedef struct ipv4_hash_blk_ {
    uint32_t ip4;
    uint8_t pad[MAX_BLK_LENGTH - sizeof(uint32_t)];
} ipv4_hash_blk_t;

typedef struct ipv6_hash_blk_ {
    struct in6_addr ip6;
    uint8_t pad[MAX_BLK_LENGTH - sizeof(struct in6_addr)];
} ipv6_hash_blk_t;


uint8_t scramble_ether_addr[ETHER_ADDR_LEN];
uint16_t scramble_ether_vlan;
int scramble_mac;

static int readhexstring(FILE *, u_char *, int *);

static uint32_t ip4cache[1 << CACHE_BITS];
static uint32_t ip4pad;            /* first 4 bytes of pad */
static uint32_t ip6pad[4];
static u_char scramble_mac_buf[MAX_BLK_LENGTH];

typedef unsigned char uchar;
static uchar ckey[128] = {0x00};

static struct {
    AES_KEY aeskey;
    BF_KEY bfkey;
} scramble_key;
static uint8_t ivec[64];

/* statistics */
static long ipv4_cache_hits = 0;
static long ipv4_anon_calls = 0;
static long ipv6_anon_calls = 0;

char ipv6_to_str[128];


static ipv4_hash_blk_t b4_in, b4_out;
static ipv6_hash_blk_t b6_in, b6_out;

static scramble_crypt_t scramble_crypto4 = SCRAMBLE_BLOWFISH;
static scramble_crypt_t scramble_crypto6 = SCRAMBLE_BLOWFISH;

static struct {
    char *name;
    scramble_crypt_t type;
} scramble_names[] = {
        {"md5",      SCRAMBLE_MD5},
        {"blowfish", SCRAMBLE_BLOWFISH},
        {"aes",      SCRAMBLE_AES},
        {"sha",      SCRAMBLE_SHA1},
};

const char *
scramble_type2name(scramble_crypt_t t) {
    int i;
    for (i = 0; i < sizeof(scramble_names) / sizeof(scramble_names[0]); ++i)
        if (scramble_names[i].type == t)
            return scramble_names[i].name;
    return NULL;
}

scramble_crypt_t
scramble_name2type(const char *name) {
    int i;
    for (i = 0; i < sizeof(scramble_names) / sizeof(scramble_names[0]); ++i)
        if (strcasecmp(name, scramble_names[i].name) == 0)
            return scramble_names[i].type;
    return SCRAMBLE_NONE;
}

scramble_crypt_t
scramble_crypto_ip4(void) {
    return scramble_crypto4;
}

scramble_crypt_t
scramble_crypto_ip6(void) {
    return scramble_crypto6;
}

int
scramble_newkey(u_char *key, int klen) {
    FILE *rnd = fopen(SCRAMBLE_RANDOM_DEV, "r");
    if (rnd == NULL) {
        perror("scramble_newkey(): fopen");
        return -1;
    }
    if (fread(key, 1, klen, rnd) != klen) {
        perror("scramble_newkey(): fread");
        fclose(rnd);
        return -1;
    }
    fclose(rnd);
    return 0;
}

int
scramble_newpad(u_char *pad, int plen) {
    FILE *rnd = fopen(SCRAMBLE_RANDOM_DEV, "r");
    if (rnd == NULL) {
        perror("scramble_newpad(): fopen");
        return -1;
    }
    if (fread(pad, 1, plen, rnd) != plen) {
        perror("scramble_newpad(): fread");
        fclose(rnd);
        return -1;
    }
    fclose(rnd);
    return 0;
}

int
scramble_newmac(u_char *mac, int mlen) {
    FILE *rnd = fopen(SCRAMBLE_RANDOM_DEV, "r");
    if (rnd == NULL) {
        perror("scramble_newkey(): fopen");
        return -1;
    }
    if (fread(mac, 1, mlen, rnd) != mlen) {
        perror("scramble_newkey(): fread");
        fclose(rnd);
        return -1;
    }
    fclose(rnd);
    return 0;
}

int
scramble_newiv(u_char *iv, int ivlen) {
    FILE *rnd = fopen(SCRAMBLE_RANDOM_DEV, "r");
    if (rnd == NULL) {
        perror("scramble_newiv(): fopen");
        return -1;
    }
    if (fread(iv, 1, ivlen, rnd) != ivlen) {
        perror("scramble_newiv(): fread");
        fclose(rnd);
        return -1;
    }
    fclose(rnd);
    return 0;
}

/* read a hex string from fd at current position and store it in s */
static int
readhexstring(FILE *f, u_char *s, int *len) {
    char c = 0;
    int i;
    for (i = 0; i < *len + 1; ++i) {
        switch (fread(&c, 1, 1, f)) {
            case 0:
                *len = i;
                return 0;
            case 1:
                break;
            default:
                return -1;
        }
        if (!isxdigit(c)) {
            *len = i;
            return 0;
        }
        s[i] = ((isdigit(c)) ? c - '0' : tolower(c) - 'a' + 10) << 4;
        if (fread(&c, 1, 1, f) != 1) {
            *len = i;
            return -1; /* error: a byte has 2 digits */
        }
        if (!isxdigit(c)) {
            *len = i;
            return -1;
        }
        s[i] |= (isdigit(c)) ? c - '0' : tolower(c) - 'a' + 10;
    }
    if (i == *len + 1)
        return -1; /* means buffer is too short */
    return 0;
}

int
scramble_readstate(const char *fn, scramble_state_t *s) {
    u_char c4, c6;
    int l4 = 1, l6 = 1;
    FILE *f = fopen(fn, "r");
    if (f == NULL) {
        perror("scramble_readstate(): fopen");
        return -1;
    }
    if (readhexstring(f, (u_char *) &c4, &l4) != 0) {
        fprintf(stderr, "scramble_readstate(): error reading c4");
        fclose(f);
        return -1;
    }
    assert(l4 == 1);
    s->c4 = (scramble_crypt_t) c4;
    if (readhexstring(f, (u_char *) &c6, &l6) != 0) {
        fprintf(stderr, "scramble_readstate(): error reading c6");
        fclose(f);
        return -1;
    }
    assert(l6 == 1);
    s->c6 = (scramble_crypt_t) c6;
    if (readhexstring(f, s->key, &s->klen) != 0) {
        fprintf(stderr, "scramble_readstate(): error reading key");
        fclose(f);
        return -1;
    }
    if (readhexstring(f, s->pad, &s->plen) != 0) {
        fprintf(stderr, "scramble_readstate(): error reading pad");
        fclose(f);
        return -1;
    }
    if (readhexstring(f, s->mac, &s->mlen) != 0) {
        fprintf(stderr, "scramble_readstate(): error reading mac");
        fclose(f);
        return -1;
    }
    if (readhexstring(f, s->iv, &s->ivlen) != 0) {
        fprintf(stderr, "scramble_readstate(): error reading iv");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

int
scramble_savestate(const char *fn, const scramble_state_t *s) {
    int i;
    /* set restrictive mode */
    int fd = creat(fn, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("scramble_savestate(): open");
        return -1;
    }
    FILE *f = fdopen(fd, "w");
    if (f == NULL) {
        perror("scramble_savestate(): fopen");
        return -1;
    }
    if (fprintf(f, "%02x:%02x:", (unsigned) s->c4, (unsigned) s->c6) < 0) {
        perror("scramble_savestate(): error saving cryptos");
        fclose(f);
        return -1;
    }
    for (i = 0; i < s->klen; ++i) {
        if (fprintf(f, "%02x", s->key[i]) < 0) {
            perror("scramble_savestate(): error saving key");
            fclose(f);
            return -1;
        }
    }
    fprintf(f, ":");
    for (i = 0; i < s->plen; ++i) {
        if (fprintf(f, "%02x", s->pad[i]) < 0) {
            perror("scramble_savestate(): error saving pad");
            fclose(f);
            return -1;
        }
    }
    fprintf(f, ":");
    for (i = 0; i < s->mlen; ++i) {
        if (fprintf(f, "%02x", s->mac[i]) < 0) {
            perror("scramble_savestate(): error saving mac");
            fclose(f);
            return -1;
        }
    }

    fprintf(f, ":");
    for (i = 0; i < s->ivlen; ++i) {
        if (fprintf(f, "%02x", s->iv[i]) < 0) {
            perror("scramble_savestate(): error saving lv");
            fclose(f);
            return -1;
        }
    }
    fprintf(f, "\n");
    fclose(f);
    return 0;
}

void ipv6_to_str_unexpanded(char *str, const struct in6_addr *addr) {
    sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            (int)addr->s6_addr[0], (int)addr->s6_addr[1],
            (int)addr->s6_addr[2], (int)addr->s6_addr[3],
            (int)addr->s6_addr[4], (int)addr->s6_addr[5],
            (int)addr->s6_addr[6], (int)addr->s6_addr[7],
            (int)addr->s6_addr[8], (int)addr->s6_addr[9],
            (int)addr->s6_addr[10], (int)addr->s6_addr[11],
            (int)addr->s6_addr[12], (int)addr->s6_addr[13],
            (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}


char *
extract_ipv6pad(const char *ckey, char * ipv6pad){
    char *startPad = strchr(ckey, ':') + 1;
    int len = startPad - ckey;

    strncpy(ipv6pad, startPad, MAX_BLK_LENGTH);
    ipv6pad[len] = '\0';
    //printf("dst = %s\n", ipv6pad);
    return ipv6pad;
}

char *
convert_to_ipv6_format(const char *ipv6_pad, char *new_pad) {
    int i = 0;
    int head = 0;
    int length;

    length = strlen(ipv6_pad);
    int appended_chars = 0;
    int group_of = 4;
    for (i = 0; i < length; i++) {
        new_pad[i+appended_chars] = ipv6_pad[head];
        if(i % (group_of) == (group_of-1)) {
            appended_chars++;
            if(i+appended_chars < IPV6_PADDING-1) {
                new_pad[i + appended_chars] = ':';
            }
        }
        head++;
    }
    new_pad[i+appended_chars-1] = '\0';
    return new_pad;
}

void set_encrypt_key(const char *enckey) {
    char ipv6_pad[MAX_BLK_LENGTH] = {0};
    char new_pad_formatted[IPV6_PADDING] = {0};

    //extract_ipv6pad(enckey, ipv6_pad);
    //convert_to_ipv6_format(ipv6_pad, new_pad_formatted);

    scramble_crypto4 = SCRAMBLE_HMAC_SHA256;
    scramble_crypto6 = SCRAMBLE_HMAC_SHA256;

    ipv6_to_str_unexpanded(ipv6_to_str, &b6_in.ip6);

    if (inet_pton(AF_INET6, new_pad_formatted, &b6_in.ip6) >0) {
        ipv6_to_str_unexpanded(ipv6_to_str, &b6_in.ip6);
        ip6pad[0] = b6_in.ip6.s6_addr32[0];
        ip6pad[1] = b6_in.ip6.s6_addr32[1];
        ip6pad[2] = b6_in.ip6.s6_addr32[2];
        ip6pad[3] = b6_in.ip6.s6_addr32[3];
    }

    //printf("set_encrypt_key key: %s\n", ckey);

    snprintf(ckey, 16+1, "%s", enckey);
    AES_set_encrypt_key(ckey, 256, &scramble_key.aeskey);
}

int
scramble_init(const scramble_state_t *s) {

    int plen;
    if (s->plen > MAX_BLK_LENGTH)
        plen = MAX_BLK_LENGTH;
    else
        plen = s->plen;

    scramble_crypto4 = s->c4;
    scramble_crypto6 = s->c6;

    memcpy(&b6_in, s->pad, s->plen);
    ip6pad[0] = b6_in.ip6.s6_addr32[0];
    ip6pad[1] = b6_in.ip6.s6_addr32[1];
    ip6pad[2] = b6_in.ip6.s6_addr32[2];
    ip6pad[3] = b6_in.ip6.s6_addr32[3];

    if (s->c4 == SCRAMBLE_BLOWFISH || s->c6 == SCRAMBLE_BLOWFISH) {
        BF_set_key(&scramble_key.bfkey, s->klen, s->key);
    }
    if (s->c4 == SCRAMBLE_AES || s->c6 == SCRAMBLE_AES) {
        if (flb_log_check(FLB_LOG_TRACE)) printf("setting key: %s\n", ckey);
        AES_set_encrypt_key(ckey, 256, &scramble_key.aeskey);
    }

    scramble_mac = 0;

    //memcpy(scramble_mac_buf, s->mac, s->mlen);

    if (s->mlen > 0) {
        scramble_mac = 1;
        if (s->mlen < ETHER_ADDR_LEN + ETHER_VLAN_LEN) {
            fprintf(stderr,
                    "scramble_init(): mac string is too short (%d)\n",
                    s->mlen);
            return -1;
        }
    }
    memcpy(scramble_ether_addr, scramble_mac_buf, ETHER_ADDR_LEN);

    /* we don't want to map ether unicast to multicast and visa versa */
    RESET_ETHER_MCAST(scramble_ether_addr);

    memcpy(&scramble_ether_vlan, scramble_mac_buf + ETHER_ADDR_LEN, ETHER_VLAN_LEN);
    return 0;
}

/* init everything from file, if it doesn't exist, create it */
int
scramble_init_from_file(const char *fn, scramble_crypt_t c4, scramble_crypt_t c6, int *do_mac) {
    u_char pad[MAX_BLK_LENGTH];
    u_char key[MAX_BLK_LENGTH];
    u_char mac[MAX_BLK_LENGTH];
    u_char iv[MAX_BLK_LENGTH];

    scramble_state_t s;
    FILE *f;

    s.pad = pad;
    s.key = key;
    s.mac = mac;
    s.iv = iv;
    if ((f = fopen(fn, "r")) == NULL) {
        if (errno != ENOENT) {
            perror("scamble_init_file(): fopen");
            return -1;
        }
        if (c4 == SCRAMBLE_NONE || c6 == SCRAMBLE_NONE)
            return -1;

        /* file doesn't exist, create it */
        s.c4 = c4;
        s.c6 = c6;
        s.plen = MAX_BLK_LENGTH;
        s.klen = 16; /* XXX */
        s.ivlen = 16;

        if (scramble_newpad(pad, s.plen) < 0)
            return -1;
        if (scramble_newkey(key, s.klen) < 0)
            return -1;
        if (scramble_newiv(iv, s.ivlen) < 0)
            return -1;
        if (do_mac && *do_mac) {
            s.mlen = ETHER_ADDR_LEN + ETHER_VLAN_LEN;
            if (scramble_newmac(mac, s.mlen) < 0)
                return -1;
        } else
            s.mlen = 0;
        if (scramble_savestate(fn, &s) < 0)
            return -1;
    } else {
        fclose(f);
        s.plen = MAX_BLK_LENGTH;
        s.klen = MAX_BLK_LENGTH;
        s.mlen = MAX_BLK_LENGTH;
        s.ivlen = MAX_BLK_LENGTH;
        if (scramble_readstate(fn, &s) < 0)
            return -1;
        if (do_mac)
            *do_mac = (s.mlen > 0);
    }

    if (scramble_init(&s) < 0)
        return -1;
    return 0;
}

/* scramble IPv4 addresses, input and output are in network byte order */
uint32_t
scramble_ip4(uint32_t input, int pass_bits) {
    uint32_t output = 0;
    uint32_t m = 0xffffffff << 1;
    int i = 31;
    int class_bits = 0;
    int pbits = 0;
#define MAX_CLASS_BITS        4
    static int _class_bits[1 << MAX_CLASS_BITS] = {
            1, 1, 1, 1, 1, 1, 1, 1, /* class A: preserve 1 bit  */
            2, 2, 2, 2,     /* class B: preserve 2 bits */
            3, 3,         /* class C: preserve 3 bits */
            4,         /* class D: preserve 4 bits */
            32         /* class bad, preserve all  */
    };
    uint32_t *cp;

    if (DO_DEBUG > 0) printf("pass_bits:%d\n", pass_bits);

    static char cbuf[128];
    struct in_addr ip4, ip4s;

    input = ntohl(input);
    cp = ip4cache + (input >> (32 - CACHE_BITS));

    assert(pass_bits >= 0 && pass_bits < 33);

    ++ipv4_anon_calls;

    b4_in.ip4 = input;

    class_bits = _class_bits[input >> (32 - MAX_CLASS_BITS)];

    // check cache first
    output = *cp;
    if (output != 0) {
        output <<= (32 - CACHE_BITS);
        if (class_bits < CACHE_BITS)
            class_bits = CACHE_BITS;
        ++ipv4_cache_hits;
    }

    pbits = MAX(pass_bits, class_bits);
    if (flb_log_check(FLB_LOG_TRACE)) printf("pbits: %d\n", pbits);
    for (i = 31; i > pbits - 1; --i) {
        if (flb_log_check(FLB_LOG_TRACE)) printf("\nround #%d\n", i);
        /* pass through 'i' highest bits of ip4 */
        b4_in.ip4 &= m;

        if (DO_DEBUG > 1 && flb_log_check(FLB_LOG_TRACE)) printf("after &=m %" PRIu32 "\n",b4_in.ip4);

        inet_ntop(AF_INET, &b4_in.ip4, cbuf, 128);
        if (DO_DEBUG > 1 && flb_log_check(FLB_LOG_TRACE))  printf("after &=m %s\n", cbuf);
        if (DO_DEBUG > 1 && flb_log_check(FLB_LOG_TRACE))  printf("ip4pad %" PRIu32 "\n",ip4pad);

        /* the following could be:
         *   b4_in.ip4 |= (ip4pad & ~m); */
        b4_in.ip4 |= (ip4pad >> i);
        if (DO_DEBUG > 1 && flb_log_check(FLB_LOG_TRACE)) printf("after  |= (ip4pad >> i) %" PRIu32 "\n",b4_in.ip4);

        b4_in.ip4 = cryptopant_swap32(b4_in.ip4);

        if (DO_DEBUG > 1 && flb_log_check(FLB_LOG_TRACE)) printf("ip_numeric after swap %" PRIu32 "\n",b4_in.ip4);
        if (DO_DEBUG > 1 && flb_log_check(FLB_LOG_TRACE)) printf("ip as hex after swap 0x%08x\n",b4_in.ip4);

        switch (scramble_crypto4) {
            case SCRAMBLE_MD5:
                MD5((u_char *) &b4_in, MD5_DIGEST_LENGTH, (u_char *) &b4_out);
                break;
            case SCRAMBLE_BLOWFISH:
                BF_ecb_encrypt((u_char *) &b4_in, (u_char *) &b4_out, &scramble_key.bfkey, BF_ENCRYPT);
                break;
            case SCRAMBLE_AES:
                AES_ecb_encrypt((u_char *) &b4_in, (u_char *) &b4_out, &scramble_key.aeskey, AES_ENCRYPT);
                break;
            case SCRAMBLE_SHA1:
                SHA1((u_char *) &b4_in, SHA_DIGEST_LENGTH, (u_char *) &b4_out);
                break;
            case SCRAMBLE_HMAC_SHA256:
                if (DO_DEBUG > 0) printf("SCRAMBLE_HMAC_SHA256\n");
                unsigned char *result = NULL;
                unsigned int resultlen = -1;

                ipv4_hash_blk_t *pb4_in = &b4_in;
                unsigned int anotherInteger = b4_in.ip4;

                unsigned char bytes[4];
                bytes[3] = (b4_in.ip4 >> 24) & 0xFF;
                bytes[2] = (b4_in.ip4 >> 16) & 0xFF;
                bytes[1] = (b4_in.ip4 >> 8) & 0xFF;
                bytes[0] = b4_in.ip4 & 0xFF;
                if (DO_DEBUG > 1 && flb_log_check(FLB_LOG_TRACE)) printf("%x %x %x %x\n", bytes[0], bytes[1], bytes[2], bytes[3]);

                if (DO_DEBUG > 0) printf("ckey:\n");
                if (DO_DEBUG > 0) print_bytes(ckey,strlen(ckey));
                result = HMAC(EVP_sha256(), ckey, strlen(ckey), bytes, sizeof(bytes),
                                     result, &resultlen);

                char *resultBuf = malloc(resultlen*2);

                for (unsigned int i = 0; i < 4; i++){
                    sprintf(resultBuf + i*2, "%02hhX", result[i]);
                }

                unsigned char outputs[5] = {0x00};
                outputs[3] = result[0];
                outputs[2] = result[1];
                outputs[1] = result[2];
                outputs[0] = result[3];

                unsigned int i = (outputs[3] << 24) | (outputs[2] << 16) | (outputs[1] << 8) | (outputs[0]);
                if (DO_DEBUG > 1 && flb_log_check(FLB_LOG_TRACE)) printf("i = %d\n", i);

                b4_out.ip4 = ntohl(i);
                free(resultBuf);
                break;
            default:
                abort();
        }
        //if (flb_log_check(FLB_LOG_TRACE)) printf("b4_in.ip4 = %d\n", b4_in.ip4);
        //if (flb_log_check(FLB_LOG_TRACE)) printf("b4_out.ip4 = %d\n", b4_out.ip4);
//        output |= ((*((u_char *) &b4_out.ip4) & 1) << (31 - i));
//        b4_in.ip4 = cryptopant_swap32(b4_in.ip4);
//        m <<= 1;




        if (DO_DEBUG > 1) printf("after encrypt b4_out in u32: %" PRIu32 "\n",b4_out.ip4);
        if (DO_DEBUG > 0) printf("after encrypt b4_out in hex: 0x%08x\n",b4_out.ip4);
        int CBUF_SZ = 128;
        inet_ntop(AF_INET, &b4_out.ip4, cbuf, CBUF_SZ);
        if (DO_DEBUG > 0) printf("after encrypt b4_out.ip4 = %s\n", cbuf);

        //abort();

        int lowByte = b4_out.ip4 & 0xff;
        int midLeftByte = (b4_out.ip4>>8) & 0xff;
        int midRightByte = (b4_out.ip4>>16) & 0xff;
        int highByte = (b4_out.ip4>>24) & 0xff;

        output |= ( (lowByte & 1) << (31 - i));

        inet_ntop(AF_INET, &ip4s.s_addr, cbuf, CBUF_SZ);
        if (DO_DEBUG > 0) printf("ip4s.s_addr = %s\n", cbuf);

        if (DO_DEBUG > 1) printf("output = %d\n",output);
        b4_in.ip4 = cryptopant_swap32(b4_in.ip4);
        m <<= 1;

//        printf("m <<= 1: % " PRIu32 "\n",m);
//        printf(" output(% " PRIu32 ") ^ input(%" PRIu32 ")\n",output, input);
        ip4s.s_addr = htonl(output ^ input);
//        printf("ip4s.s_addr htonl(output^input) %" PRIu32 "\n",ip4s.s_addr);
        inet_ntop(AF_INET, &ip4s.s_addr, cbuf, CBUF_SZ);
//        printf("ip4s.s_addr = %s\n", cbuf);

    }

    /* output == 0 is OK, means pass address unchanged */

    *cp = (output >> (32 - CACHE_BITS));

    return htonl(output ^ input);
}


/* scramble ipv6 address in place, in network byte order */
struct in6_addr scramble_ip6(struct in6_addr *input, int pass_bits) {
    struct in6_addr output;
    int i, w;
    int pbits = pass_bits;

    char ipv6_to_str[128];
    ipv6_to_str_unexpanded(ipv6_to_str, input);  // Corrected to pass a single pointer
    if (flb_log_check(FLB_LOG_TRACE)) printf("ipv6_to_str = %s\n", ipv6_to_str);

    b6_in.ip6.s6_addr32[0] = ip6pad[0]; /* XXX this one not needed */
    b6_in.ip6.s6_addr32[1] = ip6pad[1];
    b6_in.ip6.s6_addr32[2] = ip6pad[2];
    b6_in.ip6.s6_addr32[3] = ip6pad[3];

    ++ipv6_anon_calls;
    for (w = 0; w < 4; ++w) {
        uint32_t m = 0xffffffff << 1;
        uint32_t x = ntohl(input->s6_addr32[w]);
        uint32_t hpad = ntohl(ip6pad[w]);
        output.s6_addr32[w] = 0;
        /* anonymize x, using hpad */
        for (i = 31; i > pbits - 1; --i) {
            /* pass through 'i' highest bits of the word */
            x &= m;
            /* the following could be:
             *   x |= (hpad & ~m); */
            x |= (hpad >> i);
            b6_in.ip6.s6_addr32[w] = htonl(x);

            if (DO_DEBUG > 0) printf("b6in[%d]:%d\n", w, b6_in.ip6.s6_addr32[w]);

            if (DO_DEBUG > 0) printf("before encryption b6_in[0]=%d, [1]=%d, [2]=%d, [3]=%d\n",
                   b6_in.ip6.s6_addr32[0],
                   b6_in.ip6.s6_addr32[1],
                   b6_in.ip6.s6_addr32[2],
                   b6_in.ip6.s6_addr32[3]);

            if (DO_DEBUG > 0) printf("before encryption b6out[0]=%d, [1]=%d, [2]=%d, [3]=%d\n",
                   b6_out.ip6.s6_addr32[0],
                   b6_out.ip6.s6_addr32[1],
                   b6_out.ip6.s6_addr32[2],
                   b6_out.ip6.s6_addr32[3]);

            /* hashing proper */
            unsigned char *result = NULL;
            unsigned int resultlen = -1;

            switch (scramble_crypto6) {
                case SCRAMBLE_MD5:
                    MD5((u_char *) &b6_in, MD5_DIGEST_LENGTH, (u_char *) &b6_out);
                    break;
                case SCRAMBLE_BLOWFISH:
                    /* use BF in chain mode */
                    memset(ivec, 0, sizeof(ivec));
                    BF_cbc_encrypt((u_char *) &b6_in, (u_char *) &b6_out,
                                   sizeof(struct in6_addr),
                                   &scramble_key.bfkey,
                                   ivec, BF_ENCRYPT);
                    break;
                case SCRAMBLE_AES:
                    AES_ecb_encrypt((u_char *) &b6_in, (u_char *) &b6_out,
                                    &scramble_key.aeskey, AES_ENCRYPT);
                    break;
                case SCRAMBLE_SHA1:
                    SHA1((u_char *) &b6_in, SHA_DIGEST_LENGTH, (u_char *) &b6_out);
                    break;
                case SCRAMBLE_HMAC_SHA256:
                    if (DO_DEBUG > 0) printf("ckey:\n");
                    if (DO_DEBUG > 0) print_bytes(ckey, strlen(ckey));
                    unsigned char *result = NULL;
                    unsigned int resultlen = -1;

                    result = HMAC(EVP_sha256(), ckey, strlen(ckey), (const unsigned char *)&b6_in.ip6, sizeof(struct in6_addr),
                                  (unsigned char *)&b6_out.ip6, &resultlen);
                    break;
                default:
                    abort();
            }
            ipv6_to_str_unexpanded(ipv6_to_str, &b6_out.ip6);
            if (DO_DEBUG > 0) printf("output:%s\n", ipv6_to_str);

            output.s6_addr32[w] |= ((ntohl(b6_out.ip6.s6_addr32[3]) & 1)
                    << (31 - i));

            if (DO_DEBUG > 0) printf(" after encryption b6out[0]=%d, [1]=%d, [2]=%d, [3]=%d\n",
                   b6_out.ip6.s6_addr32[0],
                   b6_out.ip6.s6_addr32[1],
                   b6_out.ip6.s6_addr32[2],
                   b6_out.ip6.s6_addr32[3]);

            if (DO_DEBUG > 0) printf("output[w] |= ..:%d\n", output.s6_addr32[w]);

            ipv6_to_str_unexpanded(ipv6_to_str, &b6_in.ip6);
            if (DO_DEBUG > 0) printf("output:%s\n", ipv6_to_str);

            m <<= 1;
        }
        pbits = (pbits >= 32) ? pbits - 32 : 0;
        /* pbits >= 32 this means the above for-loop wasn't executed */

        output.s6_addr32[w] = htonl(output.s6_addr32[w]) ^ input->s6_addr32[w];

        /* restore the word */
        b6_in.ip6.s6_addr32[w] = input->s6_addr32[w];
    }
    return output;
}

/* reverse map scrambled IP addresses, all network byte order */
uint32_t
unscramble_ip4(uint32_t input, int pass_bits) {
    int i;
    uint32_t guess, res;

    guess = input; /* Starting with the input seems
		        * a good idea because some bits
			* may be passed through
			* unchanged */
    for (i = 32; i > 0; --i) {
        res = scramble_ip4(guess, pass_bits);
        /* we're only interested in flipping the
         * higher bit, don't care about the rest */
        res ^= input;
        if (res == 0)
            return guess;
        guess ^= res;
    }
    //unreachable, since there should be always a match
    //(since we're zeroing out at least one bit per iteration)
    assert(0);
    return (0xffffffff); /* cannot find the match */
}

/* unscramble ipv6 address in place, in network byte order */
struct in6_addr
unscramble_ip6(struct in6_addr *input, int pass_bits) {
    struct in6_addr guess;
    struct in6_addr res;
    uint32_t r = 0;

    int i;

    guess = *input;
    for (i = 0; i < 4; ++i) {
        for (;;) {
            res = guess;
            res = scramble_ip6(&res, pass_bits);
            r = res.s6_addr32[i] ^ input->s6_addr32[i];

            if (r == 0) break;

            guess.s6_addr32[i] ^= r;
        }
    }
    *input = guess;
    return guess;  // Return the unscrambled address
}
