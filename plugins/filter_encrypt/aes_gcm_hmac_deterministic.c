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
    const int IV_LEN = 16;
    unsigned char *iv = (unsigned char *)malloc(IV_LEN * sizeof(unsigned char));
    if (!iv) {
        perror("Failed to allocate memory for IV");
        return NULL;
    }

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

    unsigned char *additional = (unsigned char *)"";

    const int ciphertext_size = strlen((char *)plaintext) * 2;
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_size * sizeof(unsigned char));
    if (!ciphertext) {
        perror("Failed to allocate memory for ciphertext");
        free(iv);
        free(hash_result);
        return NULL;
    }
    memset(ciphertext, 0, ciphertext_size);

    unsigned char tag[17] = {0};

    const int TAG_LEN = 16;

    int ciphertext_len;

    ciphertext_len = aes_gcm_encrypt_deterministic(plaintext, strlen((char *)plaintext),
                                                   additional, strlen((char *)additional),
                                                   key,
                                                   iv, IV_LEN,
                                                   ciphertext, tag);

    char *ciphertext_tag = concaten(ciphertext, ciphertext_len, tag, TAG_LEN);
    free(ciphertext);

    if (ciphertext_tag == NULL) {
        free(iv);
        free(hash_result);
        return NULL;
    }

    char *iv_ciphertext_tag = concaten(iv, IV_LEN, ciphertext_tag, ciphertext_len + TAG_LEN);
    free(ciphertext_tag);
    free(iv);

    if (iv_ciphertext_tag == NULL) {
        free(hash_result);
        return NULL;
    }

    int iv_ciphertext_tag_len = IV_LEN + ciphertext_len + TAG_LEN;

    if (DO_DEBUG > 0) {
        printf("inputs:\n");
        print_bytes(iv_ciphertext_tag, strlen(iv_ciphertext_tag));
    }

    char *iv_ciphertext_tag_b64 = base64encode(iv_ciphertext_tag, iv_ciphertext_tag_len);
    free(iv_ciphertext_tag);
    free(hash_result);

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
    const int TAG_LEN = 16;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrorsAesGcmHmac();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }

    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }

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
    const int TAG_LEN = 16;
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrorsAesGcmHmac();
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }

    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;
    }
}
