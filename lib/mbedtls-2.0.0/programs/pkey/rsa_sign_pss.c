/*
 *  RSASSA-PSS/SHA-256 signature creation program
 *
 *  Copyright (C) 2006-2011, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_snprintf   snprintf
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_MD_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_SHA256_C) ||        \
    !defined(MBEDTLS_PK_PARSE_C) || !defined(MBEDTLS_FS_IO) ||    \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_MD_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_RSA_C and/or MBEDTLS_SHA256_C and/or "
           "MBEDTLS_PK_PARSE_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "mbedtls/x509.h"

#include <stdio.h>
#include <string.h>

int main( int argc, char *argv[] )
{
    FILE *f;
    int ret = 1;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char hash[20];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    char filename[512];
    const char *pers = "rsa_sign_pss";
    size_t olen = 0;

    mbedtls_entropy_init( &entropy );
    mbedtls_pk_init( &pk );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    if( argc != 3 )
    {
        mbedtls_printf( "usage: rsa_sign_pss <key_file> <filename>\n" );

#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif

        goto exit;
    }

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( "\n  . Reading private key from '%s'", argv[1] );
    fflush( stdout );

    if( ( ret = mbedtls_pk_parse_keyfile( &pk, argv[1], "" ) ) != 0 )
    {
        ret = 1;
        mbedtls_printf( " failed\n  ! Could not read key from '%s'\n", argv[1] );
        mbedtls_printf( "  ! mbedtls_pk_parse_public_keyfile returned %d\n\n", ret );
        goto exit;
    }

    if( !mbedtls_pk_can_do( &pk, MBEDTLS_PK_RSA ) )
    {
        ret = 1;
        mbedtls_printf( " failed\n  ! Key is not an RSA key\n" );
        goto exit;
    }

    mbedtls_rsa_set_padding( mbedtls_pk_rsa( pk ), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256 );

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the RSA signature of the hash.
     */
    mbedtls_printf( "\n  . Generating the RSA/SHA-256 signature" );
    fflush( stdout );

    if( ( ret = mbedtls_md_file(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    argv[2], hash ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not open or read %s\n\n", argv[2] );
        goto exit;
    }

    if( ( ret = mbedtls_pk_sign( &pk, MBEDTLS_MD_SHA256, hash, 0, buf, &olen,
                         mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_sign returned %d\n\n", ret );
        goto exit;
    }

    /*
     * Write the signature into <filename>-sig.txt
     */
    mbedtls_snprintf( filename, 512, "%s.sig", argv[2] );

    if( ( f = fopen( filename, "wb+" ) ) == NULL )
    {
        ret = 1;
        mbedtls_printf( " failed\n  ! Could not create %s\n\n", filename );
        goto exit;
    }

    if( fwrite( buf, 1, olen, f ) != olen )
    {
        mbedtls_printf( "failed\n  ! fwrite failed\n\n" );
        goto exit;
    }

    fclose( f );

    mbedtls_printf( "\n  . Done (created \"%s\")\n\n", filename );

exit:
    mbedtls_pk_free( &pk );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_RSA_C &&
          MBEDTLS_SHA256_C && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO &&
          MBEDTLS_CTR_DRBG_C */
