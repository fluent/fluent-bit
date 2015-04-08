/*
 * Minimal configuration for TLS 1.2 with PSK and AES-CCM ciphersuites
 * Distinguishing features:
 * - no bignum, no PK, no X509
 * - fully modern and secure (provided the pre-shared keys have high entropy)
 * - very low record overhead with CCM-8
 * - optimized for low RAM usage
 *
 * See README.txt for usage instructions.
 */
#ifndef POLARSSL_CONFIG_H
#define POLARSSL_CONFIG_H

/* System support */
//#define POLARSSL_HAVE_IPV6 /* Optional */
//#define POLARSSL_HAVE_TIME /* Optionally used in Hello messages */
/* Other POLARSSL_HAVE_XXX flags irrelevant for this configuration */

/* mbed TLS feature support */
#define POLARSSL_KEY_EXCHANGE_PSK_ENABLED
#define POLARSSL_SSL_PROTO_TLS1_2
#define POLARSSL_SSL_DISABLE_RENEGOTIATION

/* mbed TLS modules */
#define POLARSSL_AES_C
#define POLARSSL_CCM_C
#define POLARSSL_CIPHER_C
#define POLARSSL_CTR_DRBG_C
#define POLARSSL_ENTROPY_C
#define POLARSSL_MD_C
#define POLARSSL_NET_C
#define POLARSSL_SHA256_C
#define POLARSSL_SSL_CLI_C
#define POLARSSL_SSL_SRV_C
#define POLARSSL_SSL_TLS_C

/* Save RAM at the expense of ROM */
#define POLARSSL_AES_ROM_TABLES

/* Save some RAM by adjusting to your exact needs */
#define POLARSSL_PSK_MAX_LEN    16 /* 128-bits keys are generally enough */

/*
 * You should adjust this to the exact number of sources you're using: default
 * is the "platform_entropy_poll" source, but you may want to add other ones
 * Minimum is 2 for the entropy test suite.
 */
#define ENTROPY_MAX_SOURCES 2

/*
 * Use only CCM_8 ciphersuites, and
 * save ROM and a few bytes of RAM by specifying our own ciphersuite list
 */
#define SSL_CIPHERSUITES                        \
        TLS_PSK_WITH_AES_256_CCM_8,             \
        TLS_PSK_WITH_AES_128_CCM_8

/*
 * Save RAM at the expense of interoperability: do this only if you control
 * both ends of the connection!  (See comments in "polarssl/ssl.h".)
 * The optimal size here depends on the typical size of records.
 */
#define SSL_MAX_CONTENT_LEN             512

#include "check_config.h"

#endif /* POLARSSL_CONFIG_H */
