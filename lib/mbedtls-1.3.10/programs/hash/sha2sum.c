/*
 *  sha256sum demonstration program
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
#define polarssl_fprintf    fprintf
#endif

#include <string.h>
#include <stdio.h>

#include "polarssl/sha256.h"

#if !defined(POLARSSL_SHA256_C) || !defined(POLARSSL_FS_IO)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_SHA256_C and/or POLARSSL_FS_IO not defined.\n");
    return( 0 );
}
#else
static int sha256_wrapper( char *filename, unsigned char *sum )
{
    int ret = sha256_file( filename, sum, 0 );

    if( ret == 1 )
        polarssl_fprintf( stderr, "failed to open: %s\n", filename );

    if( ret == 2 )
        polarssl_fprintf( stderr, "failed to read: %s\n", filename );

    return( ret );
}

static int sha256_print( char *filename )
{
    int i;
    unsigned char sum[32];

    if( sha256_wrapper( filename, sum ) != 0 )
        return( 1 );

    for( i = 0; i < 32; i++ )
        polarssl_printf( "%02x", sum[i] );

    polarssl_printf( "  %s\n", filename );
    return( 0 );
}

static int sha256_check( char *filename )
{
    int i;
    size_t n;
    FILE *f;
    int nb_err1, nb_err2;
    int nb_tot1, nb_tot2;
    unsigned char sum[32];
    char buf[65], line[1024];
    char diff;

    if( ( f = fopen( filename, "rb" ) ) == NULL )
    {
        polarssl_printf( "failed to open: %s\n", filename );
        return( 1 );
    }

    nb_err1 = nb_err2 = 0;
    nb_tot1 = nb_tot2 = 0;

    memset( line, 0, sizeof( line ) );

    n = sizeof( line );

    while( fgets( line, (int) n - 1, f ) != NULL )
    {
        n = strlen( line );

        if( n < 68 )
            continue;

        if( line[64] != ' ' || line[65] != ' ' )
            continue;

        if( line[n - 1] == '\n' ) { n--; line[n] = '\0'; }
        if( line[n - 1] == '\r' ) { n--; line[n] = '\0'; }

        nb_tot1++;

        if( sha256_wrapper( line + 66, sum ) != 0 )
        {
            nb_err1++;
            continue;
        }

        nb_tot2++;

        for( i = 0; i < 32; i++ )
            sprintf( buf + i * 2, "%02x", sum[i] );

        /* Use constant-time buffer comparison */
        diff = 0;
        for( i = 0; i < 64; i++ )
            diff |= line[i] ^ buf[i];

        if( diff != 0 )
        {
            nb_err2++;
            polarssl_fprintf( stderr, "wrong checksum: %s\n", line + 66 );
        }

        n = sizeof( line );
    }

    fclose( f );

    if( nb_err1 != 0 )
    {
        polarssl_printf( "WARNING: %d (out of %d) input files could "
                "not be read\n", nb_err1, nb_tot1 );
    }

    if( nb_err2 != 0 )
    {
        polarssl_printf( "WARNING: %d (out of %d) computed checksums did "
                "not match\n", nb_err2, nb_tot2 );
    }

    return( nb_err1 != 0 || nb_err2 != 0 );
}

int main( int argc, char *argv[] )
{
    int ret, i;

    if( argc == 1 )
    {
        polarssl_printf( "print mode:  sha256sum <file> <file> ...\n" );
        polarssl_printf( "check mode:  sha256sum -c <checksum file>\n" );

#if defined(_WIN32)
        polarssl_printf( "\n  Press Enter to exit this program.\n" );
        fflush( stdout ); getchar();
#endif

        return( 1 );
    }

    if( argc == 3 && strcmp( "-c", argv[1] ) == 0 )
        return( sha256_check( argv[2] ) );

    ret = 0;
    for( i = 1; i < argc; i++ )
        ret |= sha256_print( argv[i] );

    return( ret );
}
#endif /* POLARSSL_SHA256_C && POLARSSL_FS_IO */
