/*
 * Reduced configuration used by Picocoin.
 *
 * See README.txt for usage instructions.
 *
 * Distinguishing features:
 * - no SSL/TLS;
 * - no X.509;
 * - ECDSA/PK and some other chosen crypto bits.
 */

#ifndef POLARSSL_CONFIG_H
#define POLARSSL_CONFIG_H

/* System support */
#define POLARSSL_HAVE_LONGLONG
#define POLARSSL_HAVE_ASM
#define POLARSSL_HAVE_TIME
#define POLARSSL_HAVE_IPV6

/* mbed TLS feature support */
#define POLARSSL_CIPHER_MODE_CBC
#define POLARSSL_CIPHER_PADDING_PKCS7
#define POLARSSL_ECP_DP_SECP256K1_ENABLED
#define POLARSSL_ECDSA_DETERMINISTIC
#define POLARSSL_PK_PARSE_EC_EXTENDED
#define POLARSSL_ERROR_STRERROR_DUMMY
#define POLARSSL_FS_IO

/* mbed TLS modules */
#define POLARSSL_AESNI_C
#define POLARSSL_AES_C
#define POLARSSL_ASN1_PARSE_C
#define POLARSSL_ASN1_WRITE_C
#define POLARSSL_BASE64_C
#define POLARSSL_BIGNUM_C
#define POLARSSL_ECDSA_C
#define POLARSSL_ECP_C
#define POLARSSL_ENTROPY_C
#define POLARSSL_HMAC_DRBG_C
#define POLARSSL_MD_C
#define POLARSSL_OID_C
#define POLARSSL_PADLOCK_C
#define POLARSSL_PK_C
#define POLARSSL_PK_PARSE_C
#define POLARSSL_PK_WRITE_C
#define POLARSSL_RIPEMD160_C
#define POLARSSL_SHA1_C
#define POLARSSL_SHA256_C

#include "check_config.h"

#endif /* POLARSSL_CONFIG_H */
