/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_hash.h>

#include "flb_tests_internal.h"

#define SHA512_ABCDEF "e32ef19623e8ed9d267f657a81944b3d07adbb768518068e88435745564e8d4150a0a703be2a7d88b61e3d390c2bb97e2d4c311fdc69d6b1267f05f59aa920e7"
#define SHA512_OFFBYONE "ca8b236e13383f1f2293c9e286376444e99b7f180ba85713f140b55795fd2f8625d8b84201154d7956b74e2a1e0d5fbff1b61c7288c3f45834ad409e7bdfe536"

static size_t get_sample_digest_data(unsigned char ***buffer_list,
                                     size_t **length_list,
                                     char **precomputed_digest,
                                     int *precomputed_digest_type)
{
    static const int    digest_type = FLB_HASH_SHA512;
    static size_t       lengths[] = {0, 0, 0, 0};
    static const char  *buffers[] = {
                                        "This is one ",
                                        "of the four ",
                                        "buffers that will be passed ",
                                        "to the simple batched digest processor function"
                                    };
    static const char  *digest = "65cdb3e49288e227eeacc939010f3e98ef5d4f619dfc629c9cd6d2d6c357e534" \
                                 "8f69a87a05ad336d7849e8c2ebd6ba68deeed433aa7b876bbaf1bb173366bf88";
    size_t              index;

    if (lengths[0] == 0) {
        for (index = 0 ; index < 4 ; index++) {
            lengths[index] = strlen(buffers[index]);
        }
    }

    *buffer_list = (unsigned char **) buffers;
    *length_list = lengths;
    *precomputed_digest = (char *) digest;
    *precomputed_digest_type = digest_type;

    return 4;
}

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

static void test_digest_abcdef()
{
    struct  flb_hash digest;
    char    dhex[128];
    uint8_t buf[64];

    flb_hash_init(&digest, FLB_HASH_SHA512);
    flb_hash_update(&digest, (unsigned char *) "abc", 3);
    flb_hash_update(&digest, (unsigned char *) "def", 3);
    flb_hash_finalize(&digest, buf, sizeof(buf));
    flb_hash_cleanup(&digest);

    hexlify(buf, dhex);

    TEST_CHECK(memcmp(dhex, SHA512_ABCDEF, 128) == 0);
}

static void test_digest_offbyone()
{
    struct flb_hash digest;
    uint8_t buf[64];
    char dhex[128];

    flb_hash_init(&digest, FLB_HASH_SHA512);
    flb_hash_update(&digest, (unsigned char *) "0123456789abcdef0123456789abcdef", 32);
    flb_hash_update(&digest, (unsigned char *) "0123456789abcdef0123456789abcdef", 32);
    flb_hash_update(&digest, (unsigned char *) "0123456789abcdef0123456789abcdef", 32);
    flb_hash_update(&digest, (unsigned char *) "0123456789abcdef0123456789abcde",  31);
    flb_hash_finalize(&digest, buf, sizeof(buf));
    flb_hash_cleanup(&digest);

    hexlify(buf, dhex);

    TEST_CHECK(memcmp(dhex, SHA512_OFFBYONE, 128) == 0);

}

static void test_digest_standard()
{
    char              hex_digest[128];
    int               ref_digest_type;
    char             *ref_hex_digest;
    uint8_t           raw_digest[64];
    size_t            buffer_count;
    unsigned char   **buffer_list;
    size_t           *length_list;
    struct flb_hash   digest;
    int               result;
    size_t            index;

    buffer_count = get_sample_digest_data(&buffer_list, &length_list,
                                          &ref_hex_digest, &ref_digest_type);

    TEST_CHECK(buffer_count > 0);
    TEST_CHECK(ref_digest_type == FLB_HASH_SHA512);

    result = flb_hash_init(&digest, ref_digest_type);
    TEST_CHECK(result == FLB_CRYPTO_SUCCESS);

    for (index = 0 ; index < buffer_count ; index++) {
        result = flb_hash_update(&digest, buffer_list[index], length_list[index]);
        TEST_CHECK(result == FLB_CRYPTO_SUCCESS);
    }

    result = flb_hash_finalize(&digest, raw_digest, sizeof(raw_digest));
    TEST_CHECK(result == FLB_CRYPTO_SUCCESS);

    hexlify(raw_digest, hex_digest);

    TEST_CHECK(memcmp(hex_digest, ref_hex_digest, 128) == 0);

    flb_hash_cleanup(&digest);
}

static void test_digest_simple_batch()
{
    char            hex_digest[128];
    int             ref_digest_type;
    char           *ref_hex_digest;
    uint8_t         raw_digest[64];
    size_t          buffer_count;
    unsigned char **buffer_list;
    size_t         *length_list;
    int             result;

    buffer_count = get_sample_digest_data(&buffer_list, &length_list,
                                          &ref_hex_digest, &ref_digest_type);

    TEST_CHECK(buffer_count > 0);
    TEST_CHECK(ref_digest_type == FLB_HASH_SHA512);

    result = flb_hash_simple_batch(ref_digest_type,
                                   buffer_count,
                                   buffer_list,
                                   length_list,
                                   raw_digest,
                                   sizeof(raw_digest));

    TEST_CHECK(result == FLB_CRYPTO_SUCCESS);

    hexlify(raw_digest, hex_digest);

    TEST_CHECK(memcmp(hex_digest, ref_hex_digest, 128) == 0);
}

TEST_LIST = {
    { "test_digest_simple_batch", test_digest_simple_batch },
    { "test_digest_standard",     test_digest_standard },
    { "test_digest_abcdef",       test_digest_abcdef },
    { "test_digest_offbyone",     test_digest_offbyone },
    { 0 }
};
