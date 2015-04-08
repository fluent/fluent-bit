/*
 *  Classic "Hello, world" demonstration program
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

#include <stdio.h>

#include "polarssl/md5.h"

#if !defined(POLARSSL_MD5_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_MD5_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    int i;
    unsigned char digest[16];
    char str[] = "Hello, world!";

    ((void) argc);
    ((void) argv);

    polarssl_printf( "\n  MD5('%s') = ", str );

    md5( (unsigned char *) str, 13, digest );

    for( i = 0; i < 16; i++ )
        polarssl_printf( "%02x", digest[i] );

    polarssl_printf( "\n\n" );

#if defined(_WIN32)
    polarssl_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( 0 );
}
#endif /* POLARSSL_MD5_C */
