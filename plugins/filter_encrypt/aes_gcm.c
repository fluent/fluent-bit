#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "aes_gcm.h"

#define BILLION  1000000000L
#define TO_HEX(i) (i <= 9 ? '0' + i : 'A' - 10 + i)

//determined by autoconf
#ifdef WORDS_BIGENDIAN
//sigh, older version of the code was not byte-order safe; this is needed
//to ensure backward compatibility AND compatibility with BE-systems.
#include <byteswap.h>
#define cryptopant_swap32(x) bswap_32(x)
#else
#define cryptopant_swap32(x) (x)
#endif

void handleErrorsAesGcm(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


char* aes_128_gcm_encrypt(unsigned char *plaintext,
                        int plaintext_len,
                        unsigned char *key)
{

    /* A 128 bit IV */
    const int IV_LEN = 16;
    unsigned char iv_buf[IV_LEN];
    long int ns;
    uint64_t all;
    time_t sec;
    struct timespec tspec;
    if(clock_gettime(CLOCK_REALTIME, &tspec))
        perror("error clock_gettime\n");
    sec = tspec.tv_sec;
    ns = tspec.tv_nsec;

    all = (uint64_t) sec * BILLION + (uint64_t) ns;
    //printf("tspec.tv_sec: %d, tspec.tv_nsec: %d, all: % " PRIu64 " \n",tspec.tv_sec, tspec.tv_nsec, all);
    //another way is to use :
    //  - https://stackoverflow.com/questions/2572366/how-to-use-dev-random-or-urandom-in-c
    //  - https://paragonie.com/blog/2016/05/how-generate-secure-random-numbers-in-various-programming-languages
    srandom(all);
    int num;
    int i;
    for (i = 0; i < IV_LEN; i++) {
        num = random();
        iv_buf[i] = num;
    }
    size_t iv_len = IV_LEN;

    /* Additional data */
    unsigned char *additional =
        (unsigned char *)"";

    /* Needs to be large enough - reserved the double the size of plaintext */
    const int ciphertext_size = strlen(plaintext)*2;
    unsigned char ciphertext[ciphertext_size];
    memset(ciphertext, 0, sizeof ciphertext);

    /* Buffer for the tag */
    const int TAG_LEN = 16;
    unsigned char tag[17] = {0};

    int ciphertext_len;

    ciphertext_len = aes_gcm_encrypt(plaintext, strlen(plaintext),
                                     additional, strlen ((char *)additional),
                                     key,
                                     iv_buf, IV_LEN,
                                     ciphertext, tag);

    char *ciphertext_tag = concaten(ciphertext, ciphertext_len, tag, TAG_LEN);

    char *iv_ciphertext_tag = concaten(iv_buf, IV_LEN, ciphertext_tag, ciphertext_len + TAG_LEN);

    int iv_ciphertext_tag_len = IV_LEN + ciphertext_len + TAG_LEN;

    char *iv_ciphertext_tag_b64 = base64encode(iv_ciphertext_tag, iv_ciphertext_tag_len);

    free(ciphertext_tag);
    free(iv_ciphertext_tag);

    return iv_ciphertext_tag_b64;
}


int aes_gcm_encrypt(unsigned char *plaintext,
                    int plaintext_len,
                    unsigned char *aad, int aad_len,
                    unsigned char *key,
                    unsigned char *iv, int iv_len,
                    unsigned char *ciphertext,
                    unsigned char *tag)
{
    const int TAG_LEN = 16;

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsAesGcm();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrorsAesGcm();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrorsAesGcm();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrorsAesGcm();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrorsAesGcm();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrorsAesGcm();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrorsAesGcm();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
        handleErrorsAesGcm();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
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

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsAesGcm();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrorsAesGcm();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrorsAesGcm();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrorsAesGcm();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrorsAesGcm();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrorsAesGcm();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
        handleErrorsAesGcm();

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


int aes_gcm_256_encrypt(unsigned char *plaintext,
                    int plaintext_len,
                    unsigned char *aad, int aad_len,
                    unsigned char *key,
                    unsigned char *iv, int iv_len,
                    unsigned char *ciphertext,
                    unsigned char *tag)
{
    const int TAG_LEN = 16;

    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsAesGcm();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrorsAesGcm();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrorsAesGcm();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrorsAesGcm();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrorsAesGcm();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrorsAesGcm();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrorsAesGcm();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
        handleErrorsAesGcm();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_gcm_256_decrypt(unsigned char *ciphertext, int ciphertext_len,
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

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsAesGcm();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrorsAesGcm();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrorsAesGcm();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrorsAesGcm();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrorsAesGcm();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrorsAesGcm();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
        handleErrorsAesGcm();

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