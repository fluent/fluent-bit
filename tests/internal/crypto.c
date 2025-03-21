/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_crypto.h>

#include "flb_tests_internal.h"

#define PRIVATE_KEY             (unsigned char *) \
                                "-----BEGIN RSA PRIVATE KEY-----\n"                                  \
                                "MIICXgIBAAKBgQDUkO22PyhYHJlXYQomNXEeX7ChfdqyY1ukUMsPQPbmjgsDZ/tG\n" \
                                "rvNtJVtwuOjGi+DGTG+fSFdgoGDbypOXOC5sX2Luwen+Ixvqay1V3pm16cOVOHf8\n" \
                                "XYAMLqTh1Aq3CykQeuTLKQPGG5rL6utFsgzQEgVpSZdLi2W3RfcJGS22EQIDAQAB\n" \
                                "AoGAPMuWsWEu8MR9NviSJotyZvWHVyjfu9WfCEfzS9GQzDAkBj1fKMAw7y6YEI1S\n" \
                                "RjcLequx4SSXmRNFoJc3zzBKVj77vf60vahoaq11My9pMLDSENK/JKW+VpueKYrT\n" \
                                "5Z9C6y9dB7NKXd8YANDApYNc4+a4l01WFNxjBXJveDo6+IECQQD0iT1ne96LIPFO\n" \
                                "j82SGlDkc1w7ZOZKl5kvRwM1VfXmDzdpFhEDndDnFa7Dth3t0QOQVVkbOUnNvQ+Z\n" \
                                "XEVr6l2FAkEA3ogBoIns72p8sRqE2Uavum53M7SxRJTN/Fn5mBN6aNX2if4M2k6r\n" \
                                "Uwhyld6k0PwAB1zVNUlTi0pyR7BcnrAGHQJBAO81NTD+1hLJVeQg/do3Dfx78LRV\n" \
                                "HoXHSF0cHUJWZWX4ap7MrDYachkrd7sRcrOJq+/L3Y+o+c5dbF38ChjnuTUCQQCg\n" \
                                "3ZDPjOVK7Z/WJ2WB7Cd8jf590lGTUj7V/fUAipQi1Qm0F4MTDWusSp8K2DgtGv6q\n" \
                                "U+GM88UBHIAgcs2BqZ3BAkEAjKEOgXNjeYabdkVrQMvJMAJF52vBpSksrV1jqV1F\n" \
                                "AH/sGR3C9faYNzFltPnQcE0USluDQRS/7UHNtn1VEBb34A==\n"                 \
                                "-----END RSA PRIVATE KEY-----\n"

#define PRIVATE_KEY_LENGTH      (strlen((char *) PRIVATE_KEY))

#define PUBLIC_KEY              (unsigned char *) \
                                "-----BEGIN PUBLIC KEY-----\n"                                       \
                                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUkO22PyhYHJlXYQomNXEeX7Ch\n" \
                                "fdqyY1ukUMsPQPbmjgsDZ/tGrvNtJVtwuOjGi+DGTG+fSFdgoGDbypOXOC5sX2Lu\n" \
                                "wen+Ixvqay1V3pm16cOVOHf8XYAMLqTh1Aq3CykQeuTLKQPGG5rL6utFsgzQEgVp\n" \
                                "SZdLi2W3RfcJGS22EQIDAQAB\n"                                         \
                                "-----END PUBLIC KEY-----\n"

#define PUBLIC_KEY_LENGTH       (strlen((char *) PUBLIC_KEY))

#define INPUT_DATA              (unsigned char *) "This was encrypted by fluent-bits RSA wrapper!"

#define INPUT_DATA_LENGTH       (strlen((char *) INPUT_DATA))

#define SIGNATURE_INPUT         INPUT_DATA
#define SIGNATURE_INPUT_LENGTH  INPUT_DATA_LENGTH

#define SIGNATURE_DIGEST_TYPE   FLB_HASH_SHA256
#define SIGNATURE_PADDING_TYPE  FLB_CRYPTO_PADDING_PKCS1
#define SIGNATURE_OUTPUT        ((unsigned char []) {                                                     \
                                  0x73, 0x03, 0x78, 0x0b, 0x61, 0x2a, 0x3b, 0x94, 0x5e, 0x26, 0x77, 0x65, \
                                  0x96, 0x74, 0x96, 0xbb, 0x6b, 0x1b, 0xdf, 0x8b, 0xfa, 0xa2, 0x57, 0x77, \
                                  0xc3, 0x39, 0xaf, 0x21, 0x56, 0x43, 0x87, 0xfe, 0xfb, 0x90, 0xa1, 0x19, \
                                  0xf4, 0xc3, 0xe1, 0x74, 0xdb, 0x6b, 0x6a, 0x89, 0xeb, 0x01, 0x4e, 0xbc, \
                                  0xf7, 0xe6, 0x0b, 0x7c, 0x1b, 0xa1, 0x6a, 0x7b, 0x55, 0x24, 0x1f, 0xbc, \
                                  0x78, 0x20, 0x11, 0x76, 0xf5, 0x02, 0x16, 0x29, 0xb4, 0x17, 0xff, 0x29, \
                                  0x43, 0x89, 0x4a, 0x7d, 0x23, 0x0d, 0x63, 0x59, 0x76, 0x75, 0xd2, 0x9d, \
                                  0x2c, 0x9f, 0x56, 0x6d, 0x27, 0x53, 0xeb, 0xa3, 0xa7, 0x90, 0x56, 0x4d, \
                                  0x88, 0xe5, 0x4e, 0x55, 0xca, 0x36, 0x58, 0x6f, 0x16, 0x1a, 0xb9, 0x1c, \
                                  0x4a, 0x8b, 0x0c, 0x30, 0x41, 0x19, 0x93, 0x23, 0x47, 0xcc, 0x41, 0x6c, \
                                  0x9a, 0x15, 0x9e, 0xec, 0x22, 0xac, 0x4a, 0xb9                          \
                                })

#define SIGNATURE_OUTPUT_LENGTH (sizeof(ENCRYPTED_DATA))

#define ENCRYPTION_PADDING_TYPE FLB_CRYPTO_PADDING_PKCS1
#define ENCRYPTION_INPUT        INPUT_DATA
#define ENCRYPTED_DATA          ((unsigned char []) {                                                      \
                                  0x0b, 0xd3, 0x91, 0x15, 0xb4, 0xed, 0xcd, 0x6c, 0xf1, 0x5c, 0x88, 0x15,  \
                                  0xde, 0x9d, 0x02, 0x7a, 0x0c, 0x13, 0x93, 0xdc, 0x98, 0x7c, 0x7c, 0xa0,  \
                                  0x70, 0x80, 0xff, 0x88, 0x68, 0xb6, 0x17, 0x10, 0xfd, 0x02, 0xaa, 0x96,  \
                                  0x54, 0x75, 0x83, 0x51, 0x9e, 0xe3, 0x72, 0x58, 0xd3, 0x01, 0x79, 0x61,  \
                                  0xfa, 0x17, 0x18, 0x48, 0xa8, 0xcb, 0xe9, 0x54, 0x5d, 0x87, 0x83, 0x86,  \
                                  0x5f, 0x1b, 0xf2, 0x01, 0x7f, 0x98, 0x93, 0xa1, 0x6e, 0x2d, 0x23, 0x2c,  \
                                  0x8b, 0xc9, 0x36, 0xad, 0xfc, 0xdb, 0x9d, 0xa0, 0xd2, 0x17, 0xa1, 0x9d,  \
                                  0x2e, 0x25, 0xee, 0x54, 0xf5, 0xe3, 0xa6, 0xdb, 0x98, 0x7a, 0x09, 0xef,  \
                                  0x43, 0xcc, 0x7e, 0x44, 0x53, 0x7e, 0x4a, 0x8b, 0x14, 0x9b, 0x42, 0x67,  \
                                  0xa2, 0x9a, 0x51, 0xdb, 0xf4, 0xfc, 0x93, 0xe7, 0xe1, 0xda, 0x28, 0xad,  \
                                  0x97, 0x7e, 0xd4, 0xc0, 0xe2, 0x4e, 0xfa, 0xeb                           \
                                })

#define ENCRYPTED_DATA_LENGTH (sizeof(ENCRYPTED_DATA))


/* This test encrypts and decrypts a buffer with a pre-generated 1024 bit RSA
 * key and then ensures the results match.
 */

static void test_rsa_simple_encrypt()
{
    unsigned char decrypted_data_buffer[1024 * 10];
    size_t        decrypted_data_buffer_size;
    unsigned char encrypted_data_buffer[1024 * 10];
    size_t        encrypted_data_buffer_size;
    int           result;

    encrypted_data_buffer_size = sizeof(encrypted_data_buffer);
    decrypted_data_buffer_size = sizeof(decrypted_data_buffer);

    result = flb_crypto_encrypt_simple(ENCRYPTION_PADDING_TYPE,
                                       PUBLIC_KEY, PUBLIC_KEY_LENGTH,
                                       INPUT_DATA, INPUT_DATA_LENGTH,
                                       encrypted_data_buffer,
                                       &encrypted_data_buffer_size);

    TEST_CHECK(result == FLB_CRYPTO_SUCCESS);

    if (result == FLB_CRYPTO_SUCCESS) {
        result = flb_crypto_decrypt_simple(ENCRYPTION_PADDING_TYPE,
                                           PRIVATE_KEY,
                                           PRIVATE_KEY_LENGTH,
                                           encrypted_data_buffer,
                                           encrypted_data_buffer_size,
                                           decrypted_data_buffer,
                                           &decrypted_data_buffer_size);

        TEST_CHECK(result == FLB_CRYPTO_SUCCESS);
        TEST_CHECK(decrypted_data_buffer_size == INPUT_DATA_LENGTH);

        if (result == FLB_CRYPTO_SUCCESS) {
            TEST_CHECK(memcmp(decrypted_data_buffer, INPUT_DATA, INPUT_DATA_LENGTH) == 0);
        }
    }
}

/* This test decrypts a buffer that was encrpyted using openssls rsa utility
 * with a pre-generated 1024 bit RSA key and then ensures the results match.
 */

static void test_rsa_simple_decrypt()
{
    unsigned char decrypted_data_buffer[1024 * 10];
    size_t        decrypted_data_buffer_size;
    int           result;

    decrypted_data_buffer_size = sizeof(decrypted_data_buffer);

    result = flb_crypto_decrypt_simple(ENCRYPTION_PADDING_TYPE,
                                       PRIVATE_KEY,
                                       PRIVATE_KEY_LENGTH,
                                       ENCRYPTED_DATA,
                                       ENCRYPTED_DATA_LENGTH,
                                       decrypted_data_buffer,
                                       &decrypted_data_buffer_size);

    TEST_CHECK(result == FLB_CRYPTO_SUCCESS);
    TEST_CHECK(decrypted_data_buffer_size == INPUT_DATA_LENGTH);

    if (result == FLB_CRYPTO_SUCCESS) {
        TEST_CHECK(memcmp(decrypted_data_buffer, INPUT_DATA, INPUT_DATA_LENGTH) == 0);
    }
}


/* This test signs a message using a pre-generated 1024 bit RSA key and
 * compares the signature with one that has been pre-generated using
 * openssls pkeyutil.
 */

static void test_rsa_simple_sign()
{
    unsigned char signature_buffer[1024];
    size_t        signature_buffer_size;
    unsigned char digest_buffer[32];
    int           result;

    result = flb_hash_simple(SIGNATURE_DIGEST_TYPE,
                             SIGNATURE_INPUT,
                             SIGNATURE_INPUT_LENGTH,
                             digest_buffer,
                             sizeof(digest_buffer));

    TEST_CHECK(result == FLB_CRYPTO_SUCCESS);

    if (result == FLB_CRYPTO_SUCCESS) {
        signature_buffer_size = sizeof(signature_buffer);

        result = flb_crypto_sign_simple(FLB_CRYPTO_PRIVATE_KEY,
                                        SIGNATURE_PADDING_TYPE,
                                        SIGNATURE_DIGEST_TYPE,
                                        PRIVATE_KEY,
                                        PRIVATE_KEY_LENGTH,
                                        digest_buffer,
                                        sizeof(digest_buffer),
                                        signature_buffer,
                                        &signature_buffer_size);

        TEST_CHECK(result == FLB_CRYPTO_SUCCESS);
        TEST_CHECK(signature_buffer_size == SIGNATURE_OUTPUT_LENGTH);

        if (result == FLB_CRYPTO_SUCCESS) {
            TEST_CHECK(memcmp(signature_buffer,
                              SIGNATURE_OUTPUT,
                              SIGNATURE_OUTPUT_LENGTH) == 0);
        }
    }
}

TEST_LIST = {
    { "test_rsa_simple_encrypt", test_rsa_simple_encrypt },
    { "test_rsa_simple_decrypt", test_rsa_simple_decrypt },
    { "test_rsa_simple_sign",    test_rsa_simple_sign },

    { 0 }
};
