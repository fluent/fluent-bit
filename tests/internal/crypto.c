/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_digest.h>
#include <fluent-bit/flb_crypto.h>

#include "flb_tests_internal.h"

#define PRIVATE_KEY             (unsigned char *) \
                                "-----BEGIN RSA PRIVATE KEY-----\n" \
                                "MIICXgIBAAKBgQCjbIvtEbniHexHZPoiCzH3s4JZm3E8k5XBa+YQbVD3wxZBM5Q2\n" \
                                "yH/E6XersHw4eDHXXppJAFZAWSl81rdV8INpzF9mfkJB8RjsW82WXokh4fGAyo1s\n" \
                                "gCmp8duXdpfkNnDIAFfck39E/48Wm3ZobWPvWKxzRAkBT0b9WoklQ8BJJwIDAQAB\n" \
                                "AoGBAIciStJNxhdkBu1CYlOkTj01AqR2FLyyjTLTtfn/auR1PQHNVNG4GW8KXxpp\n" \
                                "ZU6MlSox4AJddPTgxZ2lLxSxPPf8be0gq4BoAvfn0Xp8YubuWWys6P6DASRGZDmB\n" \
                                "W7zvQ9W+LFaSD5N35skQL+G45N25JqJi4Okj8qQGbC37lNYBAkEA2Cg13HeepMIp\n" \
                                "sLoRH4XgYlVacDPMp8u09GOEd+muI2hYqnCdLx33LjovHXxBuhjdBa5LaZeQgFxH\n" \
                                "f9XiqhCvMQJBAMGMBk/k74uCrLK9zGFDoxIDRMhyqf4CUN0UThMQLM0dbGDaYEdA\n" \
                                "ZjIa7W4jVb9Ho5qzWXdp5rHpsKv9KN2L19cCQQCzwfTQzHWU5JdRDduRkH8Cp6KX\n" \
                                "LqyiWii5GE2gfye+8FbUHuTIuy3FNsPZzGzIe0bLI6A5Rr730EXxjIh8D3XxAkEA\n" \
                                "qCqxBVQmqrIkub1dypkJJEqAxiWS/GgouJ6+46NnOeU52MGFbANRiHGLIOpEw8lM\n" \
                                "Jst0jeQPFUC2SAnUKwMpywJAV9D3r5XWmsCooAo+X8U4cnBRmmvY6fa239EFhE+E\n" \
                                "anHof0Uog92rAjpJZ5tmWzTJGe/oC73yUHQuA64K6SHKqQ==\n" \
                                "-----END RSA PRIVATE KEY-----"

#define PRIVATE_KEY_LENGTH      (strlen((char *) PRIVATE_KEY))

#define PUBLIC_KEY              (unsigned char *) \
                                "-----BEGIN RSA PUBLIC KEY-----\n" \
                                "MIGJAoGBAKNsi+0RueId7Edk+iILMfezglmbcTyTlcFr5hBtUPfDFkEzlDbIf8Tp\n" \
                                "d6uwfDh4MddemkkAVkBZKXzWt1Xwg2nMX2Z+QkHxGOxbzZZeiSHh8YDKjWyAKanx\n" \
                                "25d2l+Q2cMgAV9yTf0T/jxabdmhtY+9YrHNECQFPRv1aiSVDwEknAgMBAAE=\n" \
                                "-----END RSA PUBLIC KEY-----"

#define PUBLIC_KEY_LENGTH       (strlen((char *) PUBLIC_KEY))

#define INPUT_DATA              (unsigned char *) "This was encrypted by fluent-bits RSA wrapper!"

#define INPUT_DATA_LENGTH       (strlen((char *) INPUT_DATA))

#define SIGNATURE_INPUT         INPUT_DATA
#define SIGNATURE_INPUT_LENGTH  INPUT_DATA_LENGTH

#define SIGNATURE_DIGEST_TYPE   FLB_DIGEST_SHA256
#define SIGNATURE_PADDING_TYPE  FLB_CRYPTO_PADDING_PKCS1
#define SIGNATURE_OUTPUT        ((unsigned char []) {                                                      \
                                   0x76, 0x29, 0xe6, 0x74, 0x92, 0x83, 0x2d, 0x73, 0x16, 0x82, 0x3b, 0x50, \
                                   0x9b, 0x0f, 0x9d, 0xa6, 0x5d, 0x36, 0x24, 0xc6, 0xc1, 0x61, 0x78, 0x1b, \
                                   0x25, 0x3e, 0x74, 0xe6, 0x95, 0x0e, 0x98, 0x88, 0xab, 0x56, 0x6e, 0xdf, \
                                   0xeb, 0xe0, 0x34, 0x75, 0xb1, 0xfe, 0x51, 0x20, 0x71, 0x00, 0x1f, 0xb5, \
                                   0x51, 0x85, 0xb2, 0x34, 0x93, 0x7b, 0x84, 0x73, 0xba, 0xf9, 0x7b, 0xce, \
                                   0x5b, 0x34, 0xbb, 0x25, 0x57, 0x78, 0x81, 0x69, 0xd4, 0x01, 0x9e, 0x06, \
                                   0xac, 0xbc, 0x79, 0x6b, 0x07, 0x40, 0xd2, 0x85, 0xc6, 0x6a, 0x44, 0xe5, \
                                   0x96, 0xc7, 0xf2, 0x12, 0xc1, 0x45, 0x77, 0x27, 0x62, 0x00, 0xa4, 0x61, \
                                   0x8d, 0xd2, 0x23, 0xe6, 0x45, 0x10, 0x13, 0x5d, 0x16, 0x0d, 0xc5, 0xa2, \
                                   0x34, 0x2c, 0x06, 0xe7, 0xfd, 0xfc, 0xb7, 0xcf, 0x37, 0x8f, 0xec, 0x5a, \
                                   0x01, 0x17, 0x20, 0x6e, 0x89, 0x04, 0x23, 0x54                          \
                                })

#define SIGNATURE_OUTPUT_LENGTH (sizeof(ENCRYPTED_DATA))

#define ENCRYPTION_PADDING_TYPE FLB_CRYPTO_PADDING_PKCS1
#define ENCRYPTION_INPUT        INPUT_DATA
#define ENCRYPTED_DATA          ((unsigned char []) {                                                      \
                                   0x72, 0x17, 0xf9, 0x96, 0xf9, 0x71, 0x33, 0xea, 0xb2, 0xc8, 0x8f, 0x97, \
                                   0xbe, 0x03, 0x7c, 0xef, 0xa8, 0x38, 0x51, 0xd1, 0x13, 0xf6, 0xe3, 0x42, \
                                   0xcf, 0xc7, 0xe6, 0x6a, 0xe2, 0xa7, 0xe0, 0xf0, 0x19, 0x43, 0x6f, 0xbc, \
                                   0x0c, 0x01, 0x84, 0x9d, 0x73, 0x8e, 0xd5, 0xeb, 0x7c, 0xbf, 0x07, 0x89, \
                                   0x1c, 0xca, 0x10, 0xa9, 0x35, 0x5d, 0x7a, 0x6f, 0x3f, 0x02, 0xc9, 0xaa, \
                                   0xa4, 0x7e, 0xdf, 0x04, 0x2b, 0xe9, 0x86, 0xb3, 0xe1, 0x0a, 0x25, 0xa5, \
                                   0x7f, 0x8b, 0x82, 0xf8, 0x05, 0x2d, 0x10, 0x03, 0x96, 0xf0, 0xe1, 0x41, \
                                   0x15, 0x61, 0xde, 0x47, 0xe4, 0x97, 0x26, 0x2d, 0x58, 0x84, 0x7b, 0x78, \
                                   0x4a, 0x86, 0x07, 0x7b, 0xf7, 0xa6, 0xac, 0x39, 0xe1, 0x0f, 0xa7, 0x9c, \
                                   0x59, 0xfc, 0x17, 0x77, 0xb6, 0x7c, 0x98, 0x21, 0x7e, 0x4f, 0x23, 0xb8, \
                                   0x5f, 0xc9, 0x45, 0x14, 0x52, 0x20, 0x46, 0x49                          \
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

    result = flb_digest_simple(SIGNATURE_DIGEST_TYPE,
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
