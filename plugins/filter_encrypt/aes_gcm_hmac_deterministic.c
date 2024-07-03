#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hmac.h"
#include "utils.h"
#include "aes_gcm_hmac_deterministic.h"

#define DO_DEBUG 0
#define BILLION  1000000000L
#define TO_HEX(i) (i <= 9 ? '0' + i : 'A' - 10 + i)

void handleErrorsAesGcmHmac(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

char* aes_128_gcm_encrypt_deterministic(unsigned char *plaintext,
                                        int plaintext_len,
                                        unsigned char *key)
{
    /* A 128 bit IV */
    const int IV_LEN = 16;
    unsigned char iv[IV_LEN];

    unsigned char *result_len = NULL;
    unsigned char *hash_result = NULL;
    unsigned char *result = NULL;
    unsigned int resultlen = -1;

    if (DO_DEBUG > 0) printf("key:%s(%d)\n", key, strlen((char *)key));
    if (DO_DEBUG > 0) printf("plaintext:%s(%d)\n", plaintext, strlen((char *)plaintext));
    hash_result = mx_hmac_sha256((const void *)key, strlen((char *)key), plaintext, strlen((char *)plaintext), result, &resultlen);
    int i;
    for (i = 0; i < IV_LEN; i++) {
        iv[i] = hash_result[i];
    }

    size_t iv_len = IV_LEN;

    /* Additional data */
    unsigned char *additional = (unsigned char *)"";

    /* Needs to be large enough - reserved double the size of plaintext */
    const int ciphertext_size = strlen((char *)plaintext) * 2;
    unsigned char ciphertext[ciphertext_size];
    memset(ciphertext, 0, sizeof(ciphertext));

    /* Buffer for the tag */
    unsigned char tag[17] = {0};

    /* A 128 bit TAG */
    const int TAG_LEN = 16;

    int ciphertext_len;

    ciphertext_len = aes_gcm_encrypt_deterministic(plaintext, strlen((char *)plaintext),
                                                   additional, strlen((char *)additional),
                                                   key,
                                                   iv, IV_LEN,
                                                   ciphertext, tag);

    char *ciphertext_tag = concaten(ciphertext, ciphertext_len, tag, TAG_LEN);

    char *iv_ciphertext_tag = concaten(iv, IV_LEN, ciphertext_tag, ciphertext_len + TAG_LEN);

    int iv_ciphertext_tag_len = IV_LEN + ciphertext_len + TAG_LEN;

    if (DO_DEBUG > 0) printf("inputs:\n");
    if (DO_DEBUG > 0) print_bytes(iv_ciphertext_tag, strlen(iv_ciphertext_tag));

    char *iv_ciphertext_tag_b64 = base64encode(iv_ciphertext_tag, iv_ciphertext_tag_len);

    free(ciphertext_tag);
    free(iv_ciphertext_tag);

    return iv_ciphertext_tag_b64;
}

int aes_gcm_encrypt_deterministic(unsigned char *plaintext, int plaintext_len,
                                  unsigned char *aad, int aad_len,
                                  unsigned char *key,
                                  unsigned char *iv, int iv_len,
                                  unsigned char *ciphertext,
                                  unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* A 128 bit TAG */
    const int TAG_LEN = 16;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsAesGcmHmac();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrorsAesGcmHmac();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrorsAesGcmHmac();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrorsAesGcmHmac();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrorsAesGcmHmac();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrorsAesGcmHmac();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrorsAesGcmHmac();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
        handleErrorsAesGcmHmac();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_gcm_decrypt_deterministic(unsigned char *ciphertext, int ciphertext_len,
                                  unsigned char *aad, int aad_len,
                                  unsigned char *tag,
                                  unsigned char *key,
                                  unsigned char *iv, int iv_len,
                                  unsigned char *plaintext)
{
    /* A 128 bit TAG */
    const int TAG_LEN = 16;

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsAesGcmHmac();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrorsAesGcmHmac();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrorsAesGcmHmac();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrorsAesGcmHmac();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrorsAesGcmHmac();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrorsAesGcmHmac();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
        handleErrorsAesGcmHmac();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}
