/*
 *  Public key-based signature verification program
 *
 *  Copyright (C) 2006-2013, ARM Limited, All Rights Reserved
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

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_PK_PARSE_C) ||   \
    !defined(MBEDTLS_FS_IO)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_MD_C and/or "
           "MBEDTLS_SHA256_C and/or MBEDTLS_PK_PARSE_C and/or "
           "MBEDTLS_FS_IO not defined.\n");
    return( 0 );
}
#else

#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#include <stdio.h>
#include <string.h>

int main( int argc, char *argv[] )
{
    FILE *f;
    int ret = 1;
    size_t i;
    mbedtls_pk_context pk;
    unsigned char hash[20];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    char filename[512];

    mbedtls_pk_init( &pk );

    if( argc != 3 )
    {
        mbedtls_printf( "usage: mbedtls_pk_verify <key_file> <filename>\n" );

#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif

        goto exit;
    }

    mbedtls_printf( "\n  . Reading public key from '%s'", argv[1] );
    fflush( stdout );

    if( ( ret = mbedtls_pk_parse_public_keyfile( &pk, argv[1] ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * Extract the signature from the text file
     */
    ret = 1;
    mbedtls_snprintf( filename, sizeof(filename), "%s.sig", argv[2] );

    if( ( f = fopen( filename, "rb" ) ) == NULL )
    {
        mbedtls_printf( "\n  ! Could not open %s\n\n", filename );
        goto exit;
    }


    i = fread( buf, 1, sizeof(buf), f );

    fclose( f );

    /*
     * Compute the SHA-256 hash of the input file and compare
     * it with the hash decrypted from the signature.
     */
    mbedtls_printf( "\n  . Verifying the SHA-256 signature" );
    fflush( stdout );

    if( ( ret = mbedtls_md_file(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    argv[2], hash ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not open or read %s\n\n", argv[2] );
        goto exit;
    }

    if( ( ret = mbedtls_pk_verify( &pk, MBEDTLS_MD_SHA256, hash, 0,
                           buf, i ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_verify returned -0x%04x\n", -ret );
        goto exit;
    }

    mbedtls_printf( "\n  . OK (the decrypted SHA-256 hash matches)\n\n" );

    ret = 0;

exit:
    mbedtls_pk_free( &pk );

#if defined(MBEDTLS_ERROR_C)
    mbedtls_strerror( ret, (char *) buf, sizeof(buf) );
    mbedtls_printf( "  !  Last error was: %s\n", buf );
#endif

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_SHA256_C &&
          MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO */
