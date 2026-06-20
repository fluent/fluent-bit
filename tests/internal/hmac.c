/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_hmac.h>

#include "flb_tests_internal.h"

static size_t get_sample_data(unsigned char ***buffer_list,
                              size_t **length_list,
                              char **precomputed_key,
                              char **precomputed_mac,
                              int *precomputed_mac_type)
{
    static size_t       lengths[] = {0, 0, 0, 0};
    static const char  *buffers[] = {
                                        "This is one ",
                                        "of the four ",
                                        "buffers that will be passed ",
                                        "to the simple batched digest processor function"
                                    };
    static const char  *signature = "a68b8b3e480e00e0e61b4c097a29e64a261dc2548c608677c2827ea1e5b65d77";
    static const int    mac_type = FLB_HASH_SHA256;
    size_t              index;
    static const char  *key = "Long live the bird thing!";

    if (lengths[0] == 0) {
        for (index = 0 ; index < 4 ; index++) {
            lengths[index] = strlen(buffers[index]);
        }
    }

    *buffer_list = (unsigned char **) buffers;
    *length_list = lengths;
    *precomputed_key = (char *) key;
    *precomputed_mac = (char *) signature;
    *precomputed_mac_type = mac_type;

    return 4;
}

static void hexlify(uint8_t *hash, char *out)
{
    int i;
    static const char hex[] = "0123456789abcdef";
    char *buf = out;

    for (i = 0; i < 32; i++) {
        *buf++ = hex[hash[i] >> 4];
        *buf++ = hex[hash[i] & 0xf];
    }
}

static void test_hmac_standard()
{
    int               ref_signature_type;
    char              hex_signature[64];
    char             *ref_hex_signature;
    uint8_t           raw_signature[32];
    size_t            buffer_count;
    unsigned char   **buffer_list;
    size_t           *length_list;
    char             *ref_key;
    int               result;
    size_t            index;
    struct flb_hmac   hmac;

    buffer_count = get_sample_data(&buffer_list, &length_list,
                                   &ref_key,
                                   &ref_hex_signature,
                                   &ref_signature_type);

    TEST_CHECK(buffer_count > 0);
    TEST_CHECK(ref_signature_type == FLB_HASH_SHA256);

    result = flb_hmac_init(&hmac,
                           ref_signature_type,
                           (unsigned char *) ref_key,
                           strlen(ref_key));
    TEST_CHECK(result == FLB_CRYPTO_SUCCESS);

    for (index = 0 ; index < buffer_count ; index++) {
        result = flb_hmac_update(&hmac, buffer_list[index], length_list[index]);
        TEST_CHECK(result == FLB_CRYPTO_SUCCESS);
    }

    result = flb_hmac_finalize(&hmac, raw_signature, sizeof(raw_signature));
    TEST_CHECK(result == FLB_CRYPTO_SUCCESS);

    hexlify(raw_signature, hex_signature);

    TEST_CHECK(memcmp(hex_signature, ref_hex_signature, 64) == 0);

    flb_hmac_cleanup(&hmac);
}


static void test_hmac_simple_batch()
{
    int               ref_signature_type;
    char              hex_signature[64];
    char             *ref_hex_signature;
    uint8_t           raw_signature[32];
    size_t            buffer_count;
    unsigned char   **buffer_list;
    size_t           *length_list;
    char             *ref_key;
    int               result;

    buffer_count = get_sample_data(&buffer_list, &length_list,
                                   &ref_key,
                                   &ref_hex_signature,
                                   &ref_signature_type);

    TEST_CHECK(buffer_count > 0);
    TEST_CHECK(ref_signature_type == FLB_HASH_SHA256);

    result = flb_hmac_simple_batch(ref_signature_type,
                                   (unsigned char *) ref_key,
                                   strlen(ref_key),
                                   buffer_count,
                                   buffer_list,
                                   length_list,
                                   raw_signature,
                                   sizeof(raw_signature));
    TEST_CHECK(result == FLB_CRYPTO_SUCCESS);

    hexlify(raw_signature, hex_signature);

    TEST_CHECK(memcmp(hex_signature, ref_hex_signature, 64) == 0);
}

TEST_LIST = {
    { "test_hmac_simple_batch", test_hmac_simple_batch },
    { "test_hmac_standard",     test_hmac_standard },
    { 0 }
};
