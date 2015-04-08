/*
 *  generic message digest layer demonstration program
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

#include <string.h>
#include <stdio.h>

#include "polarssl/md.h"

#if !defined(POLARSSL_MD_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_MD_C not defined.\n");
    return( 0 );
}
#else
static int generic_wrapper( const md_info_t *md_info, char *filename, unsigned char *sum )
{
    int ret = md_file( md_info, filename, sum );

    if( ret == 1 )
        polarssl_fprintf( stderr, "failed to open: %s\n", filename );

    if( ret == 2 )
        polarssl_fprintf( stderr, "failed to read: %s\n", filename );

    return( ret );
}

static int generic_print( const md_info_t *md_info, char *filename )
{
    int i;
    unsigned char sum[POLARSSL_MD_MAX_SIZE];

    if( generic_wrapper( md_info, filename, sum ) != 0 )
        return( 1 );

    for( i = 0; i < md_info->size; i++ )
        polarssl_printf( "%02x", sum[i] );

    polarssl_printf( "  %s\n", filename );
    return( 0 );
}

static int generic_check( const md_info_t *md_info, char *filename )
{
    int i;
    size_t n;
    FILE *f;
    int nb_err1, nb_err2;
    int nb_tot1, nb_tot2;
    unsigned char sum[POLARSSL_MD_MAX_SIZE];
    char buf[POLARSSL_MD_MAX_SIZE * 2 + 1], line[1024];
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

        if( n < (size_t) 2 * md_info->size + 4 )
        {
            polarssl_printf("No '%s' hash found on line.\n", md_info->name);
            continue;
        }

        if( line[2 * md_info->size] != ' ' || line[2 * md_info->size + 1] != ' ' )
        {
            polarssl_printf("No '%s' hash found on line.\n", md_info->name);
            continue;
        }

        if( line[n - 1] == '\n' ) { n--; line[n] = '\0'; }
        if( line[n - 1] == '\r' ) { n--; line[n] = '\0'; }

        nb_tot1++;

        if( generic_wrapper( md_info, line + 2 + 2 * md_info->size, sum ) != 0 )
        {
            nb_err1++;
            continue;
        }

        nb_tot2++;

        for( i = 0; i < md_info->size; i++ )
            sprintf( buf + i * 2, "%02x", sum[i] );

        /* Use constant-time buffer comparison */
        diff = 0;
        for( i = 0; i < 2 * md_info->size; i++ )
            diff |= line[i] ^ buf[i];

        if( diff != 0 )
        {
            nb_err2++;
            polarssl_fprintf( stderr, "wrong checksum: %s\n", line + 66 );
        }

        n = sizeof( line );
    }

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

    fclose( f );

    return( nb_err1 != 0 || nb_err2 != 0 );
}

int main( int argc, char *argv[] )
{
    int ret, i;
    const md_info_t *md_info;
    md_context_t md_ctx;

    md_init( &md_ctx );

    if( argc == 1 )
    {
        const int *list;

        polarssl_printf( "print mode:  generic_sum <md> <file> <file> ...\n" );
        polarssl_printf( "check mode:  generic_sum <md> -c <checksum file>\n" );

        polarssl_printf( "\nAvailable message digests:\n" );
        list = md_list();
        while( *list )
        {
            md_info = md_info_from_type( *list );
            polarssl_printf( "  %s\n", md_info->name );
            list++;
        }

#if defined(_WIN32)
        polarssl_printf( "\n  Press Enter to exit this program.\n" );
        fflush( stdout ); getchar();
#endif

        return( 1 );
    }

    /*
     * Read the MD from the command line
     */
    md_info = md_info_from_string( argv[1] );
    if( md_info == NULL )
    {
        polarssl_fprintf( stderr, "Message Digest '%s' not found\n", argv[1] );
        return( 1 );
    }
    if( md_init_ctx( &md_ctx, md_info) )
    {
        polarssl_fprintf( stderr, "Failed to initialize context.\n" );
        return( 1 );
    }

    ret = 0;
    if( argc == 4 && strcmp( "-c", argv[2] ) == 0 )
    {
        ret |= generic_check( md_info, argv[3] );
        goto exit;
    }

    for( i = 2; i < argc; i++ )
        ret |= generic_print( md_info, argv[i] );

exit:
    md_free( &md_ctx );

    return( ret );
}
#endif /* POLARSSL_MD_C */
