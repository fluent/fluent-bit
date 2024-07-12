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

#define IV_LEN 16
#define TAG_LEN 16

#ifdef _WIN32
#include <windows.h>
#include <time.h>
#define srandom srand
#define random rand
#else
#include <sys/time.h>
#include <unistd.h>
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
    unsigned char iv_buf[IV_LEN];
    long int ns;
    uint64_t all;
    time_t sec;

#ifdef _WIN32
    struct timespec tspec;
    timespec_get(&tspec, TIME_UTC);
#else
    struct timespec tspec;
    clock_gettime(CLOCK_REALTIME, &tspec);
#endif

    sec = tspec.tv_sec;
    ns = tspec.tv_nsec;

    all = (uint64_t) sec * BILLION + (uint64_t) ns;
    srandom((unsigned int)all);

    for (int i = 0; i < IV_LEN; i++) {
        iv_buf[i] = (unsigned char)random();
    }

    unsigned char *additional = (unsigned char *)"";

    const int ciphertext_size = plaintext_len * 2;
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_size);
    if (!ciphertext) {
        perror("Failed to allocate memory for ciphertext");
        return NULL;
    }
    memset(ciphertext, 0, ciphertext_size);

    unsigned char tag[TAG_LEN] = {0};

    int ciphertext_len = aes_gcm_encrypt(plaintext, plaintext_len,
                                         additional, strlen((char *)additional),
                                         key,
                                         iv_buf, IV_LEN,
                                         ciphertext, tag);

    char *ciphertext_tag = concaten(ciphertext, ciphertext_len, tag, TAG_LEN);
    free(ciphertext);

    if (!ciphertext_tag) {
        return NULL;
    }

    char *iv_ciphertext_tag = concaten(iv_buf, IV_LEN, ciphertext_tag, ciphertext_len + TAG_LEN);
    free(ciphertext_tag);

    if (!iv_ciphertext_tag) {
        return NULL;
    }

    int iv_ciphertext_tag_len = IV_LEN + ciphertext_len + TAG_LEN;

    char *iv_ciphertext_tag_b64 = base64encode(iv_ciphertext_tag, iv_ciphertext_tag_len);
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
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsAesGcm();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrorsAesGcm();

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrorsAesGcm();

    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrorsAesGcm();

    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrorsAesGcm();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrorsAesGcm();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrorsAesGcm();
    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
        handleErrorsAesGcm();

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
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsAesGcm();

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrorsAesGcm();

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrorsAesGcm();

    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrorsAesGcm();

    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrorsAesGcm();

    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrorsAesGcm();
    plaintext_len = len;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
        handleErrorsAesGcm();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
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
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsAesGcm();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrorsAesGcm();

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrorsAesGcm();

    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrorsAesGcm();

    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrorsAesGcm();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrorsAesGcm();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrorsAesGcm();
    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
        handleErrorsAesGcm();

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
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrorsAesGcm();

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrorsAesGcm();

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrorsAesGcm();

    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrorsAesGcm();

    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrorsAesGcm();

    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrorsAesGcm();
    plaintext_len = len;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
        handleErrorsAesGcm();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;
    }
}