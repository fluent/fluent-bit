#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_log.h>
#include "aes_deterministic.h"
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "utils.h"
#include "cmac.h"

#define KEY_LEN      32
#define KEK_KEY_LEN  128
#define ITERATION     100

#define PBKD2_ENCRYPTION_KEY_LEN      16
#define PBKD2_ENCRYPTION_ITERATIONS      2

/* A 128 bit IV */
const unsigned char *iv = (unsigned char *) "0";

/* salt: Ks */
const char SALT[] = {0x4B, 0x73, 0x00};

/* encryption salt */
const unsigned char ENCRYPTION_SALT[5] = {0x31,0x32,0x33,0x34,0x00};


void generate_key_from_pbkdf2(char *passphrase, const unsigned char *pbkdf2_salt, unsigned char *out, int iters, int key_length){
    size_t i;

    size_t len = strlen(pbkdf2_salt);

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("pass: %s\n", passphrase);
        flb_debug("ITERATION: %u\n", iters);
        flb_debug("salt: ");
        for (i = 0; i < len; i++) { printf("%02x", pbkdf2_salt[i]); }
        printf("\n");

        flb_debug("strlen(pbkdf2_salt): %u\n", len);
    }

    if( PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), pbkdf2_salt, len, iters, key_length, out) != 0 )
    {
        if (flb_log_check(FLB_LOG_TRACE)) {
            flb_debug("out in hex: ");
            for (i = 0; i < key_length; i++) {
                printf("%02x", out[i]);
            }
            printf("\n");
        }
    }
    else
    {
        fprintf(stderr, "PKCS5_PBKDF2_HMAC_SHA1 failed\n");
    }

}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt_aes_128_ctr(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1!=EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1!=EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1!=EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_aes_128_ctr(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * When using aes_256_cbc, we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1!=EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1!=EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1!=EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void generate_derived_key(const unsigned char * master_key, unsigned char* derived_key){
    unsigned char salt_copy[KEY_LEN] = {0x00};
    unsigned char key[KEY_LEN] = {0x00};

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("generate_derived_key master_key:\n");
    }
    if (flb_log_check(FLB_LOG_TRACE)) {
        print_bytes(master_key, KEY_LEN + 1);
    }

    memcpy(salt_copy, SALT, strlen(SALT));
    memcpy(key, master_key, strlen(master_key));

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("salt len:%d\n", strlen(SALT));
        flb_debug("encryption_key len:%d\n", strlen(master_key));
        BIO_dump_fp(stdout, (const unsigned char *) master_key, strlen((const char unsigned *) master_key));
    }

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("Salt (hex)\n");
        BIO_dump_fp(stdout, (const char *) SALT, KEY_LEN + 1);
        flb_debug("Message (hex)\n");
        BIO_dump_fp(stdout, (const char *) salt_copy, KEY_LEN + 1);

        flb_debug("Key (master_key)\n");
        BIO_dump_fp(stdout, (const unsigned char *) master_key, KEY_LEN + 1);

        flb_debug("Key (key)\n");
        BIO_dump_fp(stdout, (const char *) key, KEY_LEN + 1);
    }
    aes_cmac((unsigned char*)(salt_copy), strlen(salt_copy) , (unsigned char*)derived_key, master_key);

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("AES-128-CMAC Result (derived_key)\n");
        BIO_dump_fp(stdout, (const char *) derived_key, strlen(derived_key));
    }
}

void generate_encryption_iv(unsigned char* derived_key, unsigned char* encryption_iv){
    unsigned char message[16] = {0x00};
    char msg[] = "0";
    memcpy(message, msg, strlen(msg));
    aes_cmac((unsigned char*)(msg), strlen(msg) , (unsigned char*)encryption_iv, derived_key);
    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("AES-128-CMAC Result (encryption_iv)\n");
        BIO_dump_fp(stdout, (const char *) encryption_iv, strlen(encryption_iv));
    }
}


char *
aes_det(const char* plaintext, const char* KEY128, const char* MASTER_KEY_SALT) {

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("KEY128 in hex:\n");
        print_bytes(KEY128, 32);
        flb_debug("MASTER_KEY_SALT in hex:\n");
        print_bytes(MASTER_KEY_SALT, 32);
    }
    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("key: %s\n", KEY128);
        BIO_dump_fp(stdout, (const char *) KEY128, strlen((char *) KEY128));
        flb_debug("iv : %s\n", iv);
        BIO_dump_fp(stdout, (const char *) iv, strlen((char *) iv));

        flb_debug("Message in clear is:\n");
        print_bytes(plaintext, strlen((char *) plaintext));
        BIO_dump_fp(stdout, (const char *) plaintext, strlen((char *) plaintext));
    }

    /* convert key to base64 */
    int bytes_to_encode = strlen(KEY128);
    char *key128_base64_encoded = base64encode(KEY128, bytes_to_encode);   //Base-64 encoding.

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("generate_key_from_pbkdf2_and_encode_b64\n");
        flb_debug("keyBase64 in hex:\n");
        //print_bytes(key128_base64_encoded, KEY_LEN);
        flb_debug("salt in hex:\n");
        print_bytes(MASTER_KEY_SALT, KEY_LEN);
    }

    unsigned char master_key[KEY_LEN + 1] = {0x00};

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("sizeof(unsigned char) * KEY_LEN=%d\n", sizeof(unsigned char)*KEY_LEN + 1);
        flb_debug("declared variable master_key with 0x00\n");
        //print_bytes(master_key, KEY_LEN + 1);

        flb_debug("executing generate_key_from_pbkdf2\n");
    }

    generate_key_from_pbkdf2(KEY128, MASTER_KEY_SALT, master_key, ITERATION, KEY_LEN);

    if (flb_log_check(FLB_LOG_TRACE)) flb_debug("printing master_key once again\n");
    if (flb_log_check(FLB_LOG_TRACE)) print_bytes(master_key, KEY_LEN + 1);
    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("encryption_key in hex:\n");
        BIO_dump_fp(stdout, (const char *) master_key, strlen((char *) master_key));
    }

    unsigned char derived_key[KEY_LEN + 1] = {0x00};
    generate_derived_key(master_key, derived_key);

    unsigned char encryption_iv[KEY_LEN + 1] = {0x00};
    generate_encryption_iv(derived_key, encryption_iv);

    int encryption_iv_len = strlen(encryption_iv);
    if (flb_log_check(FLB_LOG_TRACE)) flb_debug("AES-128-CMAC Result(encryption_iv)\n");
    if (flb_log_check(FLB_LOG_TRACE)) print_bytes(encryption_iv, encryption_iv_len);


    /* convert key to base64 */
    int derived_key_len = strlen(derived_key);
    char *derived_key_base64_encoded = base64encode(derived_key, derived_key_len);   //Base-64 encoding.

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("generate_key_from_pbkdf2_and_encode_b64\n");
        flb_debug("derived_key_base64_encoded in b64: %s\n", derived_key_base64_encoded);
        flb_debug("keyBase64 in hex:\n");
        print_bytes(derived_key_base64_encoded, strlen(derived_key_base64_encoded));
    }

    unsigned char encryption_key[KEY_LEN + 1] = {0x00};

    generate_key_from_pbkdf2(derived_key_base64_encoded, ENCRYPTION_SALT, encryption_key, PBKD2_ENCRYPTION_ITERATIONS, PBKD2_ENCRYPTION_KEY_LEN);

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("encryption_key in hex:\n");
    }

    if (flb_log_check(FLB_LOG_TRACE)) {
        BIO_dump_fp(stdout, (const char *) encryption_key, strlen((char *) encryption_key));
    }

    /* Encrypt the plaintext */
    ciphertext_len = encrypt_aes_128_ctr(plaintext, strlen((char *) plaintext), encryption_key, encryption_iv,
                             ciphertext);

    /* Do something useful with the ciphertext here */
    if (flb_log_check(FLB_LOG_TRACE)) flb_debug("Ciphertext is:\n");
    if (flb_log_check(FLB_LOG_TRACE)) BIO_dump_fp(stdout, (const char *) ciphertext, ciphertext_len);

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("strlen(encryption_iv) = %d\n", strlen(encryption_iv));
        flb_debug("strlen(ciphertext) = %d\n", strlen(ciphertext));
        flb_debug("sizeof(ciphertext) = %d\n", sizeof(ciphertext));
        flb_debug("ciphertext_len = %d\n", ciphertext_len);
    }

    char *iv_ciphertext = concat(encryption_iv, strlen(encryption_iv), ciphertext, ciphertext_len);

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("iv_ciphtertext: \n");
        flb_debug("iv_ciphtertext size: %d\n", strlen(iv_ciphertext));
        BIO_dump_fp(stdout, (const char *) iv_ciphertext, encryption_iv_len + ciphertext_len);
    }

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt_aes_128_ctr(ciphertext, ciphertext_len, encryption_key, encryption_iv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    if (flb_log_check(FLB_LOG_TRACE)) flb_debug("Decrypted text is:\n");
    if (flb_log_check(FLB_LOG_TRACE)) flb_debug("%s\n", decryptedtext);

    /* convert iv_ciphertext to base64 */
    int iv_ciphertext_bytes_to_encode = encryption_iv_len + ciphertext_len;
    char *iv_ciphertext_base64_encoded = base64encode(iv_ciphertext, iv_ciphertext_bytes_to_encode);   //Base-64 encoding.

    if (flb_log_check(FLB_LOG_TRACE)) {
        flb_debug("iv_ciphertext_base64_encoded: %s\n", iv_ciphertext_base64_encoded);
        BIO_dump_fp(stdout, (const char *) iv_ciphertext_base64_encoded, strlen(iv_ciphertext_base64_encoded));
    }

    return iv_ciphertext_base64_encoded;
}