/**
 *  \brief Generate random data into a file
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
#define polarssl_fprintf    fprintf
#endif

#include "polarssl/havege.h"

#include <time.h>
#include <stdio.h>

#if !defined(POLARSSL_HAVEGE_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_HAVEGE_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    time_t t;
    int i, k, ret = 0;
    havege_state hs;
    unsigned char buf[1024];

    if( argc < 2 )
    {
        polarssl_fprintf( stderr, "usage: %s <output filename>\n", argv[0] );
        return( 1 );
    }

    if( ( f = fopen( argv[1], "wb+" ) ) == NULL )
    {
        polarssl_printf( "failed to open '%s' for writing.\n", argv[1] );
        return( 1 );
    }

    havege_init( &hs );

    t = time( NULL );

    for( i = 0, k = 768; i < k; i++ )
    {
        if( havege_random( &hs, buf, sizeof( buf ) ) != 0 )
        {
            polarssl_printf( "Failed to get random from source.\n" );

            ret = 1;
            goto exit;
        }

        fwrite( buf, sizeof( buf ), 1, f );

        polarssl_printf( "Generating %ldkb of data in file '%s'... %04.1f" \
                "%% done\r", (long)(sizeof(buf) * k / 1024), argv[1], (100 * (float) (i + 1)) / k );
        fflush( stdout );
    }

    if( t == time( NULL ) )
        t--;

    polarssl_printf(" \n ");

exit:
    havege_free( &hs );
    fclose( f );
    return( ret );
}
#endif /* POLARSSL_HAVEGE_C */
