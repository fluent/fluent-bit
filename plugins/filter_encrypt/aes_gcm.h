#ifndef AES_GCM_H_
#define AES_GCM_H_

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

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

void handleErrors(void);
int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                    unsigned char *aad, int aad_len,
                    unsigned char *key,
                    unsigned char *iv, int iv_len,
                    unsigned char *ciphertext,
                    unsigned char *tag);
int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *aad, int aad_len,
                    unsigned char *tag,
                    unsigned char *key,
                    unsigned char *iv, int iv_len,
                    unsigned char *plaintext);

int aes_gcm_256_encrypt(unsigned char *plaintext, int plaintext_len,
                        unsigned char *aad, int aad_len,
                        unsigned char *key,
                        unsigned char *iv, int iv_len,
                        unsigned char *ciphertext,
                        unsigned char *tag);

int aes_gcm_256_decrypt(unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *aad, int aad_len,
                        unsigned char *tag,
                        unsigned char *key,
                        unsigned char *iv, int iv_len,
                        unsigned char *plaintext);

char* aes_128_gcm_encrypt(unsigned char *plaintext,
                          int plaintext_len,
                          unsigned char *key);
#endif // AES_GCM_H_
