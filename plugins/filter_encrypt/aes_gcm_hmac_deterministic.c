#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fluent-bit/flb_log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hmac.h"
#include "utils.h"
#include "aes_gcm_hmac_deterministic.h"

#define DO_DEBUG 1
#define BILLION  1000000000L
#define TO_HEX(i) (i <= 9 ? '0' + i : 'A' - 10 + i)
#define AES_GCM_TAG_LEN 16
#define AES_GCM_IV_LEN 16

void handleErrorsAesGcmHmac(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

char* aes_128_gcm_encrypt_deterministic(unsigned char *plaintext,
                                        int plaintext_len,
                                        unsigned char *key)
{
    flb_debug("Entering aes_128_gcm_encrypt_deterministic.\n");

    // Allocate IV
    unsigned char *iv = (unsigned char *)malloc(AES_GCM_IV_LEN * sizeof(unsigned char));
    if (!iv) {
        flb_debug("Failed to allocate memory for IV.\n");
        perror("Failed to allocate memory for IV");
        return NULL;
    }
    flb_debug("IV allocated successfully at %p.\n", (void*)iv);

    // Allocate buffer for HMAC result
    unsigned int resultlen = 0;
    unsigned char result_buffer[EVP_MAX_MD_SIZE]; // Typically 32 bytes for SHA-256
    unsigned char *hash_result = mx_hmac_sha256((const void *)key, strlen((char *)key),
                                                plaintext, plaintext_len, result_buffer, &resultlen);
    if (!hash_result) {
        flb_debug("HMAC-SHA256 hashing failed.\n");
        free(iv);
        return NULL;
    }
    flb_debug("HMAC-SHA256 hashing succeeded. Result length: %u\n", resultlen);

    // Ensure that the hash result is at least IV_LEN bytes
    if (resultlen < AES_GCM_IV_LEN) {
        flb_debug("Hash result length (%u) is less than IV length (%d).\n", resultlen, AES_GCM_IV_LEN);
        free(iv);
        return NULL;
    }

    // Use the first AES_GCM_IV_LEN bytes of the hash result as the IV
    memcpy(iv, hash_result, AES_GCM_IV_LEN);
    flb_debug("IV derived from hash result.\n");

    unsigned char additional[] = ""; // Empty Additional Authenticated Data (AAD)
    int aad_len = 0; // Explicitly set to 0 since AAD is empty

    // Allocate ciphertext buffer: plaintext_len + TAG_LEN (16 bytes)
    int ciphertext_size = plaintext_len + AES_GCM_TAG_LEN;
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_size * sizeof(unsigned char));
    if (!ciphertext) {
        flb_debug("Failed to allocate memory for ciphertext.\n");
        perror("Failed to allocate memory for ciphertext");
        free(iv);
        return NULL;
    }
    memset(ciphertext, 0, ciphertext_size);
    flb_debug("Ciphertext buffer allocated and zero-initialized at %p.\n", (void*)ciphertext);

    unsigned char tag[AES_GCM_TAG_LEN] = {0};

    int ciphertext_len = aes_gcm_encrypt_deterministic(plaintext, plaintext_len,
                                                       additional, aad_len,
                                                       key,
                                                       iv, AES_GCM_IV_LEN,
                                                       ciphertext, tag);
    if (ciphertext_len < 0) {
        flb_debug("AES-GCM encryption failed.\n");
        free(ciphertext);
        free(iv);
        return NULL;
    }
    flb_debug("AES-GCM encryption succeeded. Ciphertext length: %d\n", ciphertext_len);

    // Concatenate ciphertext and tag
    char *ciphertext_tag = concaten(ciphertext, ciphertext_len, tag, AES_GCM_TAG_LEN);
    if (ciphertext_tag == NULL) {
        flb_debug("Failed to concatenate ciphertext and tag.\n");
        free(ciphertext);
        free(iv);
        return NULL;
    }
    flb_debug("Ciphertext and tag concatenated successfully.\n");
    free(ciphertext);
    flb_debug("Ciphertext buffer freed.\n");

    // Concatenate IV and ciphertext_tag
    char *iv_ciphertext_tag = concaten(iv, AES_GCM_IV_LEN, (unsigned char*)ciphertext_tag, ciphertext_len + AES_GCM_TAG_LEN);
    if (iv_ciphertext_tag == NULL) {
        flb_debug("Failed to concatenate IV and ciphertext_tag.\n");
        free(ciphertext_tag);
        free(iv);
        return NULL;
    }
    flb_debug("IV and ciphertext_tag concatenated successfully.\n");
    free(ciphertext_tag);
    flb_debug("Ciphertext_tag buffer freed.\n");
    free(iv);
    flb_debug("IV buffer freed.\n");

    int iv_ciphertext_tag_len = AES_GCM_IV_LEN + ciphertext_len + AES_GCM_TAG_LEN;
    flb_debug("Combined IV and ciphertext_tag length: %d\n", iv_ciphertext_tag_len);

    // Base64 encode the combined data
    char *iv_ciphertext_tag_b64 = base64encode(iv_ciphertext_tag, iv_ciphertext_tag_len);
    if (iv_ciphertext_tag_b64 == NULL) {
        flb_debug("Base64 encoding failed.\n");
        free(iv_ciphertext_tag);
        return NULL;
    }
    flb_debug("Base64 encoding succeeded.\n");
    free(iv_ciphertext_tag);
    flb_debug("IV_ciphertext_tag buffer freed.\n");

    // Do NOT free(hash_result) since it points to stack memory (result_buffer)

    flb_debug("Exiting aes_128_gcm_encrypt_deterministic.\n");
    return iv_ciphertext_tag_b64;
}

int aes_gcm_encrypt_deterministic(unsigned char *plaintext, int plaintext_len,
                                  unsigned char *aad, int aad_len,
                                  unsigned char *key,
                                  unsigned char *iv, int iv_len,
                                  unsigned char *ciphertext,
                                  unsigned char *tag) {
    flb_debug("Entering aes_gcm_encrypt_deterministic.\n");
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        flb_debug("EVP_CIPHER_CTX_new failed.\n");
        handleErrorsAesGcmHmac();
    }
    flb_debug("EVP_CIPHER_CTX_new succeeded.\n");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        flb_debug("EVP_EncryptInit_ex failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }
    flb_debug("EVP_EncryptInit_ex (GCM) succeeded.\n");

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        flb_debug("EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }
    flb_debug("EVP_CIPHER_CTX_ctrl (SET_IVLEN) succeeded.\n");

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        flb_debug("EVP_EncryptInit_ex (key and IV) failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }
    flb_debug("EVP_EncryptInit_ex (key and IV) succeeded.\n");

    if (aad && aad_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
            flb_debug("EVP_EncryptUpdate (AAD) failed.\n");
            EVP_CIPHER_CTX_free(ctx);
            handleErrorsAesGcmHmac();
        }
        flb_debug("AAD processed successfully.\n");
    }

    if (plaintext && plaintext_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
            flb_debug("EVP_EncryptUpdate (plaintext) failed.\n");
            EVP_CIPHER_CTX_free(ctx);
            handleErrorsAesGcmHmac();
        }
        ciphertext_len = len;
        flb_debug("Plaintext encrypted successfully. Partial ciphertext length: %d\n", ciphertext_len);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        flb_debug("EVP_EncryptFinal_ex failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }
    ciphertext_len += len;
    flb_debug("EVP_EncryptFinal_ex succeeded. Total ciphertext length: %d\n", ciphertext_len);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, tag)) {
        flb_debug("EVP_CIPHER_CTX_ctrl (GET_TAG) failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        handleErrorsAesGcmHmac();
    }
    flb_debug("Tag retrieved successfully.\n");

    EVP_CIPHER_CTX_free(ctx);
    flb_debug("EVP_CIPHER_CTX freed.\n");
    flb_debug("Exiting aes_gcm_encrypt_deterministic.\n");
    return ciphertext_len;
}

int aes_gcm_decrypt_deterministic(unsigned char *ciphertext, int ciphertext_len,
                                  unsigned char *aad, int aad_len,
                                  unsigned char *tag,
                                  unsigned char *key,
                                  unsigned char *iv, int iv_len,
                                  unsigned char *plaintext)
{
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

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, tag)) {
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