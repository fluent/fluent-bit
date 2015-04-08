/*
 *  Test application that shows some mbed TLS and OpenSSL compatibility
 *
 *  Copyright (C) 2011-2012 ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://polarssl.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#define polarssl_printf     printf
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include <openssl/rsa.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "polarssl/pk.h"
#include "polarssl/x509.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_RSA_C) ||         \
    !defined(POLARSSL_PK_PARSE_C) || !defined(POLARSSL_FS_IO)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_PK_PARSE_C and/or POLARSSL_FS_IO not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    int ret;
    FILE *key_file;
    size_t olen;
    pk_context p_pk;
    rsa_context *p_rsa;
    RSA *o_rsa;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    unsigned char input[1024];
    unsigned char p_pub_encrypted[512];
    unsigned char o_pub_encrypted[512];
    unsigned char p_pub_decrypted[512];
    unsigned char o_pub_decrypted[512];
    unsigned char p_priv_encrypted[512];
    unsigned char o_priv_encrypted[512];
    unsigned char p_priv_decrypted[512];
    unsigned char o_priv_decrypted[512];
    const char *pers = "o_p_test_example";

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                    (const unsigned char *) pers,
                    strlen( pers ) ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }
    ERR_load_crypto_strings();

    ret = 1;

    if( argc != 3 )
    {
        polarssl_printf( "usage: o_p_test <keyfile with private_key> <string of max 100 characters>\n" );

#ifdef WIN32
        polarssl_printf( "\n" );
#endif

        goto exit;
    }

    polarssl_printf( "  . Reading private key from %s into mbed TLS ...", argv[1] );
    fflush( stdout );

    pk_init( &p_pk );
    if( pk_parse_keyfile( &p_pk, argv[1], NULL ) != 0 )
    {
        ret = 1;
        polarssl_printf( " failed\n  ! Could not load key.\n\n" );
        goto exit;
    }

    if( !pk_can_do( &p_pk, POLARSSL_PK_RSA ) )
    {
        ret = 1;
        polarssl_printf( " failed\n  ! Key is not an RSA key\n" );
        goto exit;
    }

    p_rsa = pk_rsa( p_pk );

    polarssl_printf( " passed\n");

    polarssl_printf( "  . Reading private key from %s into OpenSSL  ...", argv[1] );
    fflush( stdout );

    key_file = fopen( argv[1], "r" );
    o_rsa = PEM_read_RSAPrivateKey(key_file, 0, 0, 0);
    fclose(key_file);
    if( o_rsa == NULL )
    {
        ret = 1;
        polarssl_printf( " failed\n  ! Could not load key.\n\n" );
        goto exit;
    }

    polarssl_printf( " passed\n");
    polarssl_printf( "\n" );

    if( strlen( argv[1] ) > 100 )
    {
        polarssl_printf( " Input data larger than 100 characters.\n\n" );
        goto exit;
    }

    memcpy( input, argv[2], strlen( argv[2] ) );

    /*
     * Calculate the RSA encryption with public key.
     */
    polarssl_printf( "  . Generating the RSA encrypted value with mbed TLS (RSA_PUBLIC)  ..." );
    fflush( stdout );

    if( ( ret = rsa_pkcs1_encrypt( p_rsa, ctr_drbg_random, &ctr_drbg, RSA_PUBLIC, strlen( argv[2] ), input, p_pub_encrypted ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! rsa_pkcs1_encrypt returned %d\n\n", ret );
        goto exit;
    }
    else
        polarssl_printf( " passed\n");

    polarssl_printf( "  . Generating the RSA encrypted value with OpenSSL (PUBLIC)       ..." );
    fflush( stdout );

    if( ( ret = RSA_public_encrypt( strlen( argv[2] ), input, o_pub_encrypted, o_rsa, RSA_PKCS1_PADDING ) ) == -1 )
    {
        unsigned long code = ERR_get_error();
        polarssl_printf( " failed\n  ! RSA_public_encrypt returned %d %s\n\n", ret, ERR_error_string( code, NULL ) );
        goto exit;
    }
    else
        polarssl_printf( " passed\n");

    /*
     * Calculate the RSA encryption with private key.
     */
    polarssl_printf( "  . Generating the RSA encrypted value with mbed TLS (RSA_PRIVATE) ..." );
    fflush( stdout );

    if( ( ret = rsa_pkcs1_encrypt( p_rsa, ctr_drbg_random, &ctr_drbg, RSA_PRIVATE, strlen( argv[2] ), input, p_priv_encrypted ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! rsa_pkcs1_encrypt returned %d\n\n", ret );
        goto exit;
    }
    else
        polarssl_printf( " passed\n");

    polarssl_printf( "  . Generating the RSA encrypted value with OpenSSL (PRIVATE)      ..." );
    fflush( stdout );

    if( ( ret = RSA_private_encrypt( strlen( argv[2] ), input, o_priv_encrypted, o_rsa, RSA_PKCS1_PADDING ) ) == -1 )
    {
        unsigned long code = ERR_get_error();
        polarssl_printf( " failed\n  ! RSA_private_encrypt returned %d %s\n\n", ret, ERR_error_string( code, NULL ) );
        goto exit;
    }
    else
        polarssl_printf( " passed\n");

    polarssl_printf( "\n" );

    /*
     * Calculate the RSA decryption with private key.
     */
    polarssl_printf( "  . Generating the RSA decrypted value for OpenSSL (PUBLIC) with mbed TLS (PRIVATE) ..." );
    fflush( stdout );

    if( ( ret = rsa_pkcs1_decrypt( p_rsa, ctr_drbg_random, &ctr_drbg, RSA_PRIVATE, &olen, o_pub_encrypted, p_pub_decrypted, 1024 ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! rsa_pkcs1_decrypt returned %d\n\n", ret );
    }
    else
        polarssl_printf( " passed\n");

    polarssl_printf( "  . Generating the RSA decrypted value for mbed TLS (PUBLIC) with OpenSSL (PRIVATE) ..." );
    fflush( stdout );

    if( ( ret = RSA_private_decrypt( p_rsa->len, p_pub_encrypted, o_pub_decrypted, o_rsa, RSA_PKCS1_PADDING ) ) == -1 )
    {
        unsigned long code = ERR_get_error();
        polarssl_printf( " failed\n  ! RSA_private_decrypt returned %d %s\n\n", ret, ERR_error_string( code, NULL ) );
    }
    else
        polarssl_printf( " passed\n");

    /*
     * Calculate the RSA decryption with public key.
     */
    polarssl_printf( "  . Generating the RSA decrypted value for OpenSSL (PRIVATE) with mbed TLS (PUBLIC) ..." );
    fflush( stdout );

    if( ( ret = rsa_pkcs1_decrypt( p_rsa, NULL, NULL, RSA_PUBLIC, &olen, o_priv_encrypted, p_priv_decrypted, 1024 ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! rsa_pkcs1_decrypt returned %d\n\n", ret );
    }
    else
        polarssl_printf( " passed\n");

    polarssl_printf( "  . Generating the RSA decrypted value for mbed TLS (PRIVATE) with OpenSSL (PUBLIC) ..." );
    fflush( stdout );

    if( ( ret = RSA_public_decrypt( p_rsa->len, p_priv_encrypted, o_priv_decrypted, o_rsa, RSA_PKCS1_PADDING ) ) == -1 )
    {
        unsigned long code = ERR_get_error();
        polarssl_printf( " failed\n  ! RSA_public_decrypt returned %d %s\n\n", ret, ERR_error_string( code, NULL ) );
    }
    else
        polarssl_printf( " passed\n");

    polarssl_printf( "\n" );
    polarssl_printf( "String value (OpenSSL Public Encrypt, mbed TLS Private Decrypt): '%s'\n", p_pub_decrypted );
    polarssl_printf( "String value (mbed TLS Public Encrypt, OpenSSL Private Decrypt): '%s'\n", o_pub_decrypted );
    polarssl_printf( "String value (OpenSSL Private Encrypt, mbed TLS Public Decrypt): '%s'\n", p_priv_decrypted );
    polarssl_printf( "String value (mbed TLS Private Encrypt, OpenSSL Public Decrypt): '%s'\n", o_priv_decrypted );

exit:
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#ifdef WIN32
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_RSA_C &&
          POLARSSL_PK_PARSE_C && POLARSSL_FS_IO */
