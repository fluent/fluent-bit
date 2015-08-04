/*
 *  RSA/SHA-256 signature creation program
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
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_RSA_C) ||  \
    !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_FS_IO)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_RSA_C and/or "
            "MBEDLTS_MD_C and/or "
            "MBEDTLS_SHA256_C and/or MBEDTLS_FS_IO not defined.\n");
    return( 0 );
}
#else

#include "mbedtls/rsa.h"
#include "mbedtls/md.h"

#include <stdio.h>
#include <string.h>

int main( int argc, char *argv[] )
{
    FILE *f;
    int ret;
    size_t i;
    mbedtls_rsa_context rsa;
    unsigned char hash[20];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];

    ret = 1;

    if( argc != 2 )
    {
        mbedtls_printf( "usage: rsa_sign <filename>\n" );

#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif

        goto exit;
    }

    mbedtls_printf( "\n  . Reading private key from rsa_priv.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_priv.txt", "rb" ) ) == NULL )
    {
        ret = 1;
        mbedtls_printf( " failed\n  ! Could not open rsa_priv.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    if( ( ret = mbedtls_mpi_read_file( &rsa.N , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.E , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.D , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.P , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.Q , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.DP, 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.DQ, 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.QP, 16, f ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n\n", ret );
        goto exit;
    }

    rsa.len = ( mbedtls_mpi_bitlen( &rsa.N ) + 7 ) >> 3;

    fclose( f );

    mbedtls_printf( "\n  . Checking the private key" );
    fflush( stdout );
    if( ( ret = mbedtls_rsa_check_privkey( &rsa ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_check_privkey failed with -0x%0x\n", -ret );
        goto exit;
    }

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the RSA signature of the hash.
     */
    mbedtls_printf( "\n  . Generating the RSA/SHA-256 signature" );
    fflush( stdout );

    if( ( ret = mbedtls_md_file(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    argv[1], hash ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not open or read %s\n\n", argv[1] );
        goto exit;
    }

    if( ( ret = mbedtls_rsa_pkcs1_sign( &rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                20, hash, buf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", -ret );
        goto exit;
    }

    /*
     * Write the signature into <filename>-sig.txt
     */
    memcpy( argv[1] + strlen( argv[1] ), ".sig", 5 );

    if( ( f = fopen( argv[1], "wb+" ) ) == NULL )
    {
        ret = 1;
        mbedtls_printf( " failed\n  ! Could not create %s\n\n", argv[1] );
        goto exit;
    }

    for( i = 0; i < rsa.len; i++ )
        mbedtls_fprintf( f, "%02X%s", buf[i],
                 ( i + 1 ) % 16 == 0 ? "\r\n" : " " );

    fclose( f );

    mbedtls_printf( "\n  . Done (created \"%s\")\n\n", argv[1] );

exit:

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_RSA_C && MBEDTLS_SHA256_C &&
          MBEDTLS_FS_IO */
