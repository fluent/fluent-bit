/*
 *  Public key-based signature verification program
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
#include "polarssl/md.h"
#include "polarssl/pk.h"
#include "polarssl/sha1.h"

#if defined _MSC_VER && !defined snprintf
#define snprintf _snprintf
#endif

#if !defined(POLARSSL_BIGNUM_C) ||                                  \
    !defined(POLARSSL_SHA1_C) || !defined(POLARSSL_PK_PARSE_C) ||   \
    !defined(POLARSSL_FS_IO)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_BIGNUM_C and/or "
           "POLARSSL_SHA1_C and/or POLARSSL_PK_PARSE_C and/or "
           "POLARSSL_FS_IO not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int ret = 1;
    size_t i;
    pk_context pk;
    unsigned char hash[20];
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];
    char filename[512];

    pk_init( &pk );

    if( argc != 3 )
    {
        polarssl_printf( "usage: pk_verify <key_file> <filename>\n" );

#if defined(_WIN32)
        polarssl_printf( "\n" );
#endif

        goto exit;
    }

    polarssl_printf( "\n  . Reading public key from '%s'", argv[1] );
    fflush( stdout );

    if( ( ret = pk_parse_public_keyfile( &pk, argv[1] ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! pk_parse_public_keyfile returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * Extract the signature from the text file
     */
    ret = 1;
    snprintf( filename, sizeof(filename), "%s.sig", argv[2] );

    if( ( f = fopen( filename, "rb" ) ) == NULL )
    {
        polarssl_printf( "\n  ! Could not open %s\n\n", filename );
        goto exit;
    }


    i = fread( buf, 1, sizeof(buf), f );

    fclose( f );

    /*
     * Compute the SHA-1 hash of the input file and compare
     * it with the hash decrypted from the signature.
     */
    polarssl_printf( "\n  . Verifying the SHA-1 signature" );
    fflush( stdout );

    if( ( ret = sha1_file( argv[2], hash ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! Could not open or read %s\n\n", argv[2] );
        goto exit;
    }

    if( ( ret = pk_verify( &pk, POLARSSL_MD_SHA1, hash, 0,
                           buf, i ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! pk_verify returned -0x%04x\n", -ret );
        goto exit;
    }

    polarssl_printf( "\n  . OK (the decrypted SHA-1 hash matches)\n\n" );

    ret = 0;

exit:
    pk_free( &pk );

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
#endif /* POLARSSL_BIGNUM_C && POLARSSL_SHA1_C &&
          POLARSSL_PK_PARSE_C && POLARSSL_FS_IO */
