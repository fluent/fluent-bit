/*
 * Minimal configuration for TLS 1.1 (RFC 4346), implementing only the
 * required ciphersuite: TLS_RSA_WITH_3DES_EDE_CBC_SHA
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
#define POLARSSL_CIPHER_MODE_CBC
#define POLARSSL_PKCS1_V15
#define POLARSSL_KEY_EXCHANGE_RSA_ENABLED
#define POLARSSL_SSL_PROTO_TLS1_1
#define POLARSSL_SSL_DISABLE_RENEGOTIATION

/* mbed TLS modules */
#define POLARSSL_AES_C
#define POLARSSL_ASN1_PARSE_C
#define POLARSSL_ASN1_WRITE_C
#define POLARSSL_BIGNUM_C
#define POLARSSL_CIPHER_C
#define POLARSSL_CTR_DRBG_C
#define POLARSSL_DES_C
#define POLARSSL_ENTROPY_C
#define POLARSSL_MD_C
#define POLARSSL_MD5_C
#define POLARSSL_NET_C
#define POLARSSL_OID_C
#define POLARSSL_PK_C
#define POLARSSL_PK_PARSE_C
#define POLARSSL_RSA_C
#define POLARSSL_SHA1_C
#define POLARSSL_SHA256_C
#define POLARSSL_SSL_CLI_C
#define POLARSSL_SSL_SRV_C
#define POLARSSL_SSL_TLS_C
#define POLARSSL_X509_CRT_PARSE_C
#define POLARSSL_X509_USE_C

/* For test certificates */
#define POLARSSL_BASE64_C
#define POLARSSL_CERTS_C
#define POLARSSL_PEM_PARSE_C

/* For testing with compat.sh */
#define POLARSSL_FS_IO

#include "polarssl/check_config.h"

#endif /* POLARSSL_CONFIG_H */
