/*
 *  RSA/SHA-1 signature verification program
 *
 *  Copyright (C) 2006-2011, ARM Limited, All Rights Reserved
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

#include "polarssl/rsa.h"
#include "polarssl/sha1.h"

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_RSA_C) ||  \
    !defined(POLARSSL_SHA1_C) || !defined(POLARSSL_FS_IO)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_SHA1_C and/or POLARSSL_FS_IO not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int ret, c;
    size_t i;
    rsa_context rsa;
    unsigned char hash[20];
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];

    ret = 1;
    if( argc != 2 )
    {
        polarssl_printf( "usage: rsa_verify <filename>\n" );

#if defined(_WIN32)
        polarssl_printf( "\n" );
#endif

        goto exit;
    }

    polarssl_printf( "\n  . Reading public key from rsa_pub.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_pub.txt", "rb" ) ) == NULL )
    {
        polarssl_printf( " failed\n  ! Could not open rsa_pub.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    rsa_init( &rsa, RSA_PKCS_V15, 0 );

    if( ( ret = mpi_read_file( &rsa.N, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.E, 16, f ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! mpi_read_file returned %d\n\n", ret );
        goto exit;
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;

    fclose( f );

    /*
     * Extract the RSA signature from the text file
     */
    ret = 1;
    i = strlen( argv[1] );
    memcpy( argv[1] + i, ".sig", 5 );

    if( ( f = fopen( argv[1], "rb" ) ) == NULL )
    {
        polarssl_printf( "\n  ! Could not open %s\n\n", argv[1] );
        goto exit;
    }

    argv[1][i] = '\0', i = 0;

    while( fscanf( f, "%02X", &c ) > 0 &&
           i < (int) sizeof( buf ) )
        buf[i++] = (unsigned char) c;

    fclose( f );

    if( i != rsa.len )
    {
        polarssl_printf( "\n  ! Invalid RSA signature format\n\n" );
        goto exit;
    }

    /*
     * Compute the SHA-1 hash of the input file and compare
     * it with the hash decrypted from the RSA signature.
     */
    polarssl_printf( "\n  . Verifying the RSA/SHA-1 signature" );
    fflush( stdout );

    if( ( ret = sha1_file( argv[1], hash ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! Could not open or read %s\n\n", argv[1] );
        goto exit;
    }

    if( ( ret = rsa_pkcs1_verify( &rsa, NULL, NULL, RSA_PUBLIC,
                                  POLARSSL_MD_SHA1, 20, hash, buf ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! rsa_pkcs1_verify returned -0x%0x\n\n", -ret );
        goto exit;
    }

    polarssl_printf( "\n  . OK (the decrypted SHA-1 hash matches)\n\n" );

    ret = 0;

exit:

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_RSA_C && POLARSSL_SHA1_C &&
          POLARSSL_FS_IO */
