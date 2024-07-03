//
// Created by alisrasic on 10/11/22.
//

#ifndef AES_GCM_H_
#define AES_GCM_H_

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
#endif //AES_AES_DET_GCM_AES_TEST_GCM_H_
