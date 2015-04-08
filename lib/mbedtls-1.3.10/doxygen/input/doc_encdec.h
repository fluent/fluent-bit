/**
 * @file
 * Encryption/decryption module documentation file.
 */

/**
 * @addtogroup encdec_module Encryption/decryption module
 *
 * The Encryption/decryption module provides encryption/decryption functions.
 * One can differentiate between symmetric and asymmetric algorithms; the
 * symmetric ones are mostly used for message confidentiality and the asymmetric
 * ones for key exchange and message integrity.
 * Some symmetric algorithms provide different block cipher modes, mainly
 * Electronic Code Book (ECB) which is used for short (64-bit) messages and
 * Cipher Block Chaining (CBC) which provides the structure needed for longer
 * messages. In addition the Cipher Feedback Mode (CFB-128) stream cipher mode,
 * Counter mode (CTR) and Galois Counter Mode (GCM) are implemented for
 * specific algorithms.
 *
 * All symmetric encryption algorithms are accessible via the generic cipher layer
 * (see \c cipher_init_ctx()).
 *
 * The asymmetric encryptrion algorithms are accessible via the generic public
 * key layer (see \c pk_init()).
 *
 * The following algorithms are provided:
 * - Symmetric:
 *   - AES (see \c aes_crypt_ecb(), \c aes_crypt_cbc(), \c aes_crypt_cfb128() and
 *     \c aes_crypt_ctr()).
 *   - ARCFOUR (see \c arc4_crypt()).
 *   - Blowfish / BF (see \c blowfish_crypt_ecb(), \c blowfish_crypt_cbc(),
 *     \c blowfish_crypt_cfb64() and \c blowfish_crypt_ctr())
 *   - Camellia (see \c camellia_crypt_ecb(), \c camellia_crypt_cbc(),
 *     \c camellia_crypt_cfb128() and \c camellia_crypt_ctr()).
 *   - DES/3DES (see \c des_crypt_ecb(), \c des_crypt_cbc(), \c des3_crypt_ecb()
 *     and \c des3_crypt_cbc()).
 *   - GCM (AES-GCM and CAMELLIA-GCM) (see \c gcm_init())
 *   - XTEA (see \c xtea_crypt_ecb()).
 * - Asymmetric:
 *   - Diffie-Hellman-Merkle (see \c dhm_read_public(), \c dhm_make_public()
 *     and \c dhm_calc_secret()).
 *   - RSA (see \c rsa_public() and \c rsa_private()).
 *   - Elliptic Curves over GF(p) (see \c ecp_point_init()).
 *   - Elliptic Curve Digital Signature Algorithm (ECDSA) (see \c ecdsa_init()).
 *   - Elliptic Curve Diffie Hellman (ECDH) (see \c ecdh_init()).
 *
 * This module provides encryption/decryption which can be used to provide
 * secrecy.
 *
 * It also provides asymmetric key functions which can be used for
 * confidentiality, integrity, authentication and non-repudiation.
 */
