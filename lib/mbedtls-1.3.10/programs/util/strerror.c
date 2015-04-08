/*
 *  Translate error code to error string
 *
 *  Copyright (C) 2006-2012, ARM Limited, All Rights Reserved
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "polarssl/error.h"

#define USAGE \
    "\n usage: strerror <errorcode>\n" \
    "\n where <errorcode> can be a decimal or hexadecimal (starts with 0x or -0x)\n"

#if !defined(POLARSSL_ERROR_C) && !defined(POLARSSL_ERROR_STRERROR_DUMMY)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_ERROR_C and/or POLARSSL_ERROR_STRERROR_DUMMY not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    long int val;
    char *end = argv[1];

    if( argc != 2 )
    {
        polarssl_printf( USAGE );
        return( 0 );
    }

    val = strtol( argv[1], &end, 10 );
    if( *end != '\0' )
    {
        val = strtol( argv[1], &end, 16 );
        if( *end != '\0' )
        {
            polarssl_printf( USAGE );
            return( 0 );
        }
    }
    if( val > 0 )
        val = -val;

    if( val != 0 )
    {
        char error_buf[200];
        polarssl_strerror( val, error_buf, 200 );
        polarssl_printf("Last error was: -0x%04x - %s\n\n", (int) -val, error_buf );
    }

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( val );
}
#endif /* POLARSSL_ERROR_C */
