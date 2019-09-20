/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sha512.h>

#include "flb_tests_internal.h"

#define SHA512_ABCDEF "e32ef19623e8ed9d267f657a81944b3d07adbb768518068e88435745564e8d4150a0a703be2a7d88b61e3d390c2bb97e2d4c311fdc69d6b1267f05f59aa920e7"
#define SHA512_OFFBYONE "ca8b236e13383f1f2293c9e286376444e99b7f180ba85713f140b55795fd2f8625d8b84201154d7956b74e2a1e0d5fbff1b61c7288c3f45834ad409e7bdfe536"

static void hexlify(uint8_t *hash, char *out)
{
    int i;
    static const char hex[] = "0123456789abcdef";
    char *buf = out;

    for (i = 0; i < 64; i++) {
        *buf++ = hex[hash[i] >> 4];
        *buf++ = hex[hash[i] & 0xf];
    }
}

static void test_sha512_abcdef()
{
    struct flb_sha512 sha512;
    uint8_t buf[64];
    char dhex[128];

    flb_sha512_init(&sha512);
    flb_sha512_update(&sha512, "abc", 3);
    flb_sha512_update(&sha512, "def", 3);
    flb_sha512_sum(&sha512, buf);

    hexlify(buf, dhex);

    TEST_CHECK(memcmp(dhex, SHA512_ABCDEF, 128) == 0);
}

static void test_sha512_offbyone()
{
    struct flb_sha512 sha512;
    uint8_t buf[64];
    char dhex[128];

    flb_sha512_init(&sha512);
    flb_sha512_update(&sha512, "0123456789abcdef0123456789abcdef", 32);
    flb_sha512_update(&sha512, "0123456789abcdef0123456789abcdef", 32);
    flb_sha512_update(&sha512, "0123456789abcdef0123456789abcdef", 32);
    flb_sha512_update(&sha512, "0123456789abcdef0123456789abcde",  31);
    flb_sha512_sum(&sha512, buf);

    hexlify(buf, dhex);

    TEST_CHECK(memcmp(dhex, SHA512_OFFBYONE, 128) == 0);
}

TEST_LIST = {
    { "test_sha512_abcdef", test_sha512_abcdef },
    { "test_sha512_offbyone", test_sha512_offbyone },
    { 0 }
};
