/*
 * Minimal configuration for TLS NSA Suite B Profile (RFC 6460)
 *
 * Distinguishing features:
 * - no RSA or classic DH, fully based on ECC
 * - optimized for low RAM usage
 *
 * Possible improvements:
 * - if 128-bit security is enough, disable secp384r1 and SHA-512
 * - use embedded certs in DER format and disable PEM_PARSE_C and BASE64_C
 *
 * See README.txt for usage instructions.
 */

#ifndef POLARSSL_CONFIG_H
#define POLARSSL_CONFIG_H

/* System support */
#define POLARSSL_HAVE_ASM
#define POLARSSL_HAVE_TIME
#define POLARSSL_HAVE_IPV6

/* mbed TLS feature support */
#define POLARSSL_ECP_DP_SECP256R1_ENABLED
#define POLARSSL_ECP_DP_SECP384R1_ENABLED
#define POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define POLARSSL_SSL_PROTO_TLS1_2
#define POLARSSL_SSL_DISABLE_RENEGOTIATION

/* mbed TLS modules */
#define POLARSSL_AES_C
#define POLARSSL_ASN1_PARSE_C
#define POLARSSL_ASN1_WRITE_C
#define POLARSSL_BIGNUM_C
#define POLARSSL_CIPHER_C
#define POLARSSL_CTR_DRBG_C
#define POLARSSL_ECDH_C
#define POLARSSL_ECDSA_C
#define POLARSSL_ECP_C
#define POLARSSL_ENTROPY_C
#define POLARSSL_GCM_C
#define POLARSSL_MD_C
#define POLARSSL_NET_C
#define POLARSSL_OID_C
#define POLARSSL_PK_C
#define POLARSSL_PK_PARSE_C
#define POLARSSL_SHA256_C
#define POLARSSL_SHA512_C
#define POLARSSL_SSL_CLI_C
#define POLARSSL_SSL_SRV_C
#define POLARSSL_SSL_TLS_C
#define POLARSSL_X509_CRT_PARSE_C
#define POLARSSL_X509_USE_C

/* For test certificates */
#define POLARSSL_BASE64_C
#define POLARSSL_CERTS_C
#define POLARSSL_PEM_PARSE_C

/* Save RAM at the expense of ROM */
#define POLARSSL_AES_ROM_TABLES

/* Save RAM by adjusting to our exact needs */
#define POLARSSL_ECP_MAX_BITS   384
#define POLARSSL_MPI_MAX_SIZE    48 // 384 bits is 48 bytes

/* Save RAM at the expense of speed, see ecp.h */
#define POLARSSL_ECP_WINDOW_SIZE        2
#define POLARSSL_ECP_FIXED_POINT_OPTIM  0

/* Uncomment for a significant speed benefit at the expense of some ROM */
//#define POLARSSL_ECP_NIST_OPTIM

/*
 * You should adjust this to the exact number of sources you're using: default
 * is the "platform_entropy_poll" source, but you may want to add other ones.
 * Minimum is 2 for the entropy test suite.
 */
#define ENTROPY_MAX_SOURCES 2

/* Save ROM and a few bytes of RAM by specifying our own ciphersuite list */
#define SSL_CIPHERSUITES                        \
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,    \
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

/*
 * Save RAM at the expense of interoperability: do this only if you control
 * both ends of the connection!  (See coments in "polarssl/ssl.h".)
 * The minimum size here depends on the certificate chain used as well as the
 * typical size of records.
 */
#define SSL_MAX_CONTENT_LEN             1024

#include "polarssl/check_config.h"

#endif /* POLARSSL_CONFIG_H */
