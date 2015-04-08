/*
 *  Public key-based simple decryption program
 *
 *  Copyright (C) 2006-2013, ARM Limited, All Rights Reserved
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

#include "polarssl/error.h"
#include "polarssl/pk.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_PK_PARSE_C) ||  \
    !defined(POLARSSL_FS_IO) || !defined(POLARSSL_ENTROPY_C) || \
    !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_PK_PARSE_C and/or "
           "POLARSSL_FS_IO and/or POLARSSL_ENTROPY_C and/or "
           "POLARSSL_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int ret, c;
    size_t i, olen = 0;
    pk_context pk;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    unsigned char result[1024];
    unsigned char buf[512];
    const char *pers = "pk_decrypt";
    ((void) argv);

    memset(result, 0, sizeof( result ) );
    ret = 1;

    if( argc != 2 )
    {
        polarssl_printf( "usage: pk_decrypt <key_file>\n" );

#if defined(_WIN32)
        polarssl_printf( "\n" );
#endif

        goto exit;
    }

    polarssl_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    polarssl_printf( "\n  . Reading private key from '%s'", argv[1] );
    fflush( stdout );

    pk_init( &pk );

    if( ( ret = pk_parse_keyfile( &pk, argv[1], "" ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! pk_parse_keyfile returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * Extract the RSA encrypted value from the text file
     */
    ret = 1;

    if( ( f = fopen( "result-enc.txt", "rb" ) ) == NULL )
    {
        polarssl_printf( "\n  ! Could not open %s\n\n", "result-enc.txt" );
        goto exit;
    }

    i = 0;

    while( fscanf( f, "%02X", &c ) > 0 &&
           i < (int) sizeof( buf ) )
        buf[i++] = (unsigned char) c;

    fclose( f );

    /*
     * Decrypt the encrypted RSA data and print the result.
     */
    polarssl_printf( "\n  . Decrypting the encrypted data" );
    fflush( stdout );

    if( ( ret = pk_decrypt( &pk, buf, i, result, &olen, sizeof(result),
                            ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! pk_decrypt returned -0x%04x\n", -ret );
        goto exit;
    }

    polarssl_printf( "\n  . OK\n\n" );

    polarssl_printf( "The decrypted result is: '%s'\n\n", result );

    ret = 0;

exit:
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(POLARSSL_ERROR_C)
    polarssl_strerror( ret, (char *) buf, sizeof(buf) );
    polarssl_printf( "  !  Last error was: %s\n", buf );
#endif

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_PK_PARSE_C && POLARSSL_FS_IO &&
          POLARSSL_ENTROPY_C && POLARSSL_CTR_DRBG_C */
