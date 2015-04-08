/*
 *  Public key-based signature creation program
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
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/md.h"
#include "polarssl/pk.h"
#include "polarssl/sha1.h"

#if defined _MSC_VER && !defined snprintf
#define snprintf _snprintf
#endif

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_ENTROPY_C) ||  \
    !defined(POLARSSL_SHA1_C) ||                                    \
    !defined(POLARSSL_PK_PARSE_C) || !defined(POLARSSL_FS_IO) ||    \
    !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_ENTROPY_C and/or "
           "POLARSSL_SHA1_C and/or "
           "POLARSSL_PK_PARSE_C and/or POLARSSL_FS_IO and/or "
           "POLARSSL_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int ret = 1;
    pk_context pk;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    unsigned char hash[20];
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];
    char filename[512];
    const char *pers = "pk_sign";
    size_t olen = 0;

    entropy_init( &entropy );
    pk_init( &pk );

    if( argc != 3 )
    {
        polarssl_printf( "usage: pk_sign <key_file> <filename>\n" );

#if defined(_WIN32)
        polarssl_printf( "\n" );
#endif

        goto exit;
    }

    polarssl_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ctr_drbg_init returned -0x%04x\n", -ret );
        goto exit;
    }

    polarssl_printf( "\n  . Reading private key from '%s'", argv[1] );
    fflush( stdout );

    if( ( ret = pk_parse_keyfile( &pk, argv[1], "" ) ) != 0 )
    {
        ret = 1;
        polarssl_printf( " failed\n  ! Could not open '%s'\n", argv[1] );
        goto exit;
    }

    /*
     * Compute the SHA-1 hash of the input file,
     * then calculate the signature of the hash.
     */
    polarssl_printf( "\n  . Generating the SHA-1 signature" );
    fflush( stdout );

    if( ( ret = sha1_file( argv[2], hash ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! Could not open or read %s\n\n", argv[2] );
        goto exit;
    }

    if( ( ret = pk_sign( &pk, POLARSSL_MD_SHA1, hash, 0, buf, &olen,
                         ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! pk_sign returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * Write the signature into <filename>-sig.txt
     */
    snprintf( filename, sizeof(filename), "%s.sig", argv[2] );

    if( ( f = fopen( filename, "wb+" ) ) == NULL )
    {
        ret = 1;
        polarssl_printf( " failed\n  ! Could not create %s\n\n", filename );
        goto exit;
    }

    if( fwrite( buf, 1, olen, f ) != olen )
    {
        polarssl_printf( "failed\n  ! fwrite failed\n\n" );
        goto exit;
    }

    fclose( f );

    polarssl_printf( "\n  . Done (created \"%s\")\n\n", filename );

exit:
    pk_free( &pk );
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
#endif /* POLARSSL_BIGNUM_C && POLARSSL_ENTROPY_C &&
          POLARSSL_SHA1_C && POLARSSL_PK_PARSE_C && POLARSSL_FS_IO &&
          POLARSSL_CTR_DRBG_C */
