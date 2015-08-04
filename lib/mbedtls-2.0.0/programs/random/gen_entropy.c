/**
 *  \brief Use and generate multiple entropies calls into a file
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

#if defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_FS_IO)
#include "mbedtls/entropy.h"

#include <stdio.h>
#endif

#if !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_FS_IO)
int main( void )
{
    mbedtls_printf("MBEDTLS_ENTROPY_C and/or MBEDTLS_FS_IO not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int i, k, ret;
    mbedtls_entropy_context entropy;
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];

    if( argc < 2 )
    {
        mbedtls_fprintf( stderr, "usage: %s <output filename>\n", argv[0] );
        return( 1 );
    }

    if( ( f = fopen( argv[1], "wb+" ) ) == NULL )
    {
        mbedtls_printf( "failed to open '%s' for writing.\n", argv[1] );
        return( 1 );
    }

    mbedtls_entropy_init( &entropy );

    for( i = 0, k = 768; i < k; i++ )
    {
        ret = mbedtls_entropy_func( &entropy, buf, sizeof( buf ) );
        if( ret != 0 )
        {
            mbedtls_printf("failed!\n");
            goto cleanup;
        }

        fwrite( buf, 1, sizeof( buf ), f );

        mbedtls_printf( "Generating %ldkb of data in file '%s'... %04.1f" \
                "%% done\r", (long)(sizeof(buf) * k / 1024), argv[1], (100 * (float) (i + 1)) / k );
        fflush( stdout );
    }

    ret = 0;

cleanup:
    mbedtls_printf( "\n" );

    fclose( f );
    mbedtls_entropy_free( &entropy );

    return( ret );
}
#endif /* MBEDTLS_ENTROPY_C */
