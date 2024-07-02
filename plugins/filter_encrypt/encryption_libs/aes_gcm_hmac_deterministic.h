//
// Created by alisrasic on 10/11/22.
//

#ifndef AES_GCM_HMAC_DET_H_
#define AES_GCM_HMAC_DET_H_

void handleErrorsAesGcmHmac(void);
char* aes_128_gcm_encrypt_deterministic(unsigned char *plaintext,
                                        int plaintext_len,
                                        unsigned char *key);
int aes_gcm_encrypt_deterministic(unsigned char *plaintext, int plaintext_len,
                                  unsigned char *aad, int aad_len,
                                  unsigned char *key,
                                  unsigned char *iv, int iv_len,
                                  unsigned char *ciphertext,
                                  unsigned char *tag);
int aes_gcm_decrypt_deterministic(unsigned char *ciphertext, int ciphertext_len,
                                  unsigned char *aad, int aad_len,
                                  unsigned char *tag,
                                  unsigned char *key,
                                  unsigned char *iv, int iv_len,
                                  unsigned char *plaintext);

#endif // AES_GCM_HMAC_DET_H_
