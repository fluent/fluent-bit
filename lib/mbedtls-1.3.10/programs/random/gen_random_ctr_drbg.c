/**
 *  \brief Use and generate random data into a file via the CTR_DBRG based on AES
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

#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#include <stdio.h>

#if !defined(POLARSSL_CTR_DRBG_C) || !defined(POLARSSL_ENTROPY_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_CTR_DRBG_C or POLARSSL_ENTROPY_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int i, k, ret;
    ctr_drbg_context ctr_drbg;
    entropy_context entropy;
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

    entropy_init( &entropy );
    ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy, (const unsigned char *) "RANDOM_GEN", 10 );
    if( ret != 0 )
    {
        polarssl_printf( "failed in ctr_drbg_init: %d\n", ret );
        goto cleanup;
    }
    ctr_drbg_set_prediction_resistance( &ctr_drbg, CTR_DRBG_PR_OFF );

#if defined(POLARSSL_FS_IO)
    ret = ctr_drbg_update_seed_file( &ctr_drbg, "seedfile" );

    if( ret == POLARSSL_ERR_CTR_DRBG_FILE_IO_ERROR )
    {
        polarssl_printf( "Failed to open seedfile. Generating one.\n" );
        ret = ctr_drbg_write_seed_file( &ctr_drbg, "seedfile" );
        if( ret != 0 )
        {
            polarssl_printf( "failed in ctr_drbg_write_seed_file: %d\n", ret );
            goto cleanup;
        }
    }
    else if( ret != 0 )
    {
        polarssl_printf( "failed in ctr_drbg_update_seed_file: %d\n", ret );
        goto cleanup;
    }
#endif

    for( i = 0, k = 768; i < k; i++ )
    {
        ret = ctr_drbg_random( &ctr_drbg, buf, sizeof( buf ) );
        if( ret != 0 )
        {
            polarssl_printf("failed!\n");
            goto cleanup;
        }

        fwrite( buf, 1, sizeof( buf ), f );

        polarssl_printf( "Generating %ldkb of data in file '%s'... %04.1f" \
                "%% done\r", (long)(sizeof(buf) * k / 1024), argv[1], (100 * (float) (i + 1)) / k );
        fflush( stdout );
    }

    ret = 0;

cleanup:
    polarssl_printf("\n");

    fclose( f );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

    return( ret );
}
#endif /* POLARSSL_CTR_DRBG_C && POLARSSL_ENTROPY_C */
