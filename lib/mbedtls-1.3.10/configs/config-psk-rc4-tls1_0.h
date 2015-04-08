/*
 * Custom compact configuration for TLS 1.0 with PSK and RC4
 * Distinguishing features: no bignum, no PK, no X509.
 *
 * WARNING: RC4 is in the process of being deprecated!
 * This configuration is kept for testing purposes only, DO NOT USE it!
 * For a safe and lean PSK-based configuration, see config-ccm-psk-tls1_2.h
 *
 * See README.txt for usage instructions.
 */
#ifndef POLARSSL_CONFIG_H
#define POLARSSL_CONFIG_H

/* System support */
//#define POLARSSL_HAVE_IPV6 /* Optional */
//#define POLARSSL_HAVE_TIME /* Optionnaly used in Hello messages */
/* Other POLARSSL_HAVE_XXX flags irrelevant for this configuration */

/* mbed TLS feature support */
#define POLARSSL_KEY_EXCHANGE_PSK_ENABLED
#define POLARSSL_SSL_PROTO_TLS1
#define POLARSSL_SSL_DISABLE_RENEGOTIATION

/* mbed TLS modules */
#define POLARSSL_AES_C
#define POLARSSL_ARC4_C
#define POLARSSL_CIPHER_C
#define POLARSSL_CTR_DRBG_C
#define POLARSSL_ENTROPY_C
#define POLARSSL_MD_C
#define POLARSSL_MD5_C
#define POLARSSL_NET_C
#define POLARSSL_SHA1_C
#define POLARSSL_SHA256_C
#define POLARSSL_SSL_CLI_C
#define POLARSSL_SSL_SRV_C
#define POLARSSL_SSL_TLS_C

#include "polarssl/check_config.h"

#endif /* POLARSSL_CONFIG_H */
