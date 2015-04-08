/*
 *  Key generation application
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
#include <stdlib.h>
#include <stdio.h>

#if !defined(_WIN32) && defined(POLARSSL_FS_IO)
#include <unistd.h>
#endif /* !_WIN32 && POLARSSL_FS_IO */

#include "polarssl/error.h"
#include "polarssl/pk.h"
#include "polarssl/ecdsa.h"
#include "polarssl/rsa.h"
#include "polarssl/error.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#if !defined(POLARSSL_PK_WRITE_C) || !defined(POLARSSL_FS_IO) ||    \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf( "POLARSSL_PK_WRITE_C and/or POLARSSL_FS_IO and/or "
            "POLARSSL_ENTROPY_C and/or POLARSSL_CTR_DRBG_C "
            "not defined.\n" );
    return( 0 );
}
#else

#define FORMAT_PEM              0
#define FORMAT_DER              1

#define DFL_TYPE                POLARSSL_PK_RSA
#define DFL_RSA_KEYSIZE         4096
#define DFL_FILENAME            "keyfile.key"
#define DFL_FORMAT              FORMAT_PEM
#define DFL_USE_DEV_RANDOM      0

#if defined(POLARSSL_ECP_C)
#define DFL_EC_CURVE            ecp_curve_list()->grp_id
#else
#define DFL_EC_CURVE            0
#endif

/*
 * global options
 */
struct options
{
    int type;                   /* the type of key to generate          */
    int rsa_keysize;            /* length of key in bits                */
    int ec_curve;               /* curve identifier for EC keys         */
    const char *filename;       /* filename of the key file             */
    int format;                 /* the output format to use             */
    int use_dev_random;         /* use /dev/random as entropy source    */
} opt;

#if !defined(_WIN32) && defined(POLARSSL_FS_IO)

#define DEV_RANDOM_THRESHOLD        32

int dev_random_entropy_poll( void *data, unsigned char *output,
                             size_t len, size_t *olen )
{
    FILE *file;
    size_t ret, left = len;
    unsigned char *p = output;
    ((void) data);

    *olen = 0;

    file = fopen( "/dev/random", "rb" );
    if( file == NULL )
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );

    while( left > 0 )
    {
        /* /dev/random can return much less than requested. If so, try again */
        ret = fread( p, 1, left, file );
        if( ret == 0 && ferror( file ) )
        {
            fclose( file );
            return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );
        }

        p += ret;
        left -= ret;
        sleep( 1 );
    }
    fclose( file );
    *olen = len;

    return( 0 );
}
#endif /* !_WIN32 && POLARSSL_FS_IO */

static int write_private_key( pk_context *key, const char *output_file )
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);
    if( opt.format == FORMAT_PEM )
    {
        if( ( ret = pk_write_key_pem( key, output_buf, 16000 ) ) != 0 )
            return( ret );

        len = strlen( (char *) output_buf );
    }
    else
    {
        if( ( ret = pk_write_key_der( key, output_buf, 16000 ) ) < 0 )
            return( ret );

        len = ret;
        c = output_buf + sizeof(output_buf) - len;
    }

    if( ( f = fopen( output_file, "wb" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

#if !defined(_WIN32) && defined(POLARSSL_FS_IO)
#define USAGE_DEV_RANDOM \
    "    use_dev_random=0|1    default: 0\n"
#else
#define USAGE_DEV_RANDOM ""
#endif /* !_WIN32 && POLARSSL_FS_IO */

#define USAGE \
    "\n usage: gen_key param=<>...\n"                   \
    "\n acceptable parameters:\n"                       \
    "    type=rsa|ec           default: rsa\n"          \
    "    rsa_keysize=%%d        default: 4096\n"        \
    "    ec_curve=%%s           see below\n"            \
    "    filename=%%s           default: keyfile.key\n" \
    "    format=pem|der        default: pem\n"          \
    USAGE_DEV_RANDOM                                    \
    "\n"

int main( int argc, char *argv[] )
{
    int ret = 0;
    pk_context key;
    char buf[1024];
    int i;
    char *p, *q;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";
#if defined(POLARSSL_ECP_C)
    const ecp_curve_info *curve_info;
#endif

    /*
     * Set to sane values
     */
    pk_init( &key );
    memset( buf, 0, sizeof( buf ) );

    if( argc == 0 )
    {
    usage:
        ret = 1;
        polarssl_printf( USAGE );
#if defined(POLARSSL_ECP_C)
        polarssl_printf( " availabled ec_curve values:\n" );
        curve_info = ecp_curve_list();
        polarssl_printf( "    %s (default)\n", curve_info->name );
        while( ( ++curve_info )->name != NULL )
            polarssl_printf( "    %s\n", curve_info->name );
#endif
        goto exit;
    }

    opt.type                = DFL_TYPE;
    opt.rsa_keysize         = DFL_RSA_KEYSIZE;
    opt.ec_curve            = DFL_EC_CURVE;
    opt.filename            = DFL_FILENAME;
    opt.format              = DFL_FORMAT;
    opt.use_dev_random      = DFL_USE_DEV_RANDOM;

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "type" ) == 0 )
        {
            if( strcmp( q, "rsa" ) == 0 )
                opt.type = POLARSSL_PK_RSA;
            else if( strcmp( q, "ec" ) == 0 )
                opt.type = POLARSSL_PK_ECKEY;
            else
                goto usage;
        }
        else if( strcmp( p, "format" ) == 0 )
        {
            if( strcmp( q, "pem" ) == 0 )
                opt.format = FORMAT_PEM;
            else if( strcmp( q, "der" ) == 0 )
                opt.format = FORMAT_DER;
            else
                goto usage;
        }
        else if( strcmp( p, "rsa_keysize" ) == 0 )
        {
            opt.rsa_keysize = atoi( q );
            if( opt.rsa_keysize < 1024 ||
                opt.rsa_keysize > POLARSSL_MPI_MAX_BITS )
                goto usage;
        }
#if defined(POLARSSL_ECP_C)
        else if( strcmp( p, "ec_curve" ) == 0 )
        {
            if( ( curve_info = ecp_curve_info_from_name( q ) ) == NULL )
                goto usage;
            opt.ec_curve = curve_info->grp_id;
        }
#endif
        else if( strcmp( p, "filename" ) == 0 )
            opt.filename = q;
        else if( strcmp( p, "use_dev_random" ) == 0 )
        {
            opt.use_dev_random = atoi( q );
            if( opt.use_dev_random < 0 || opt.use_dev_random > 1 )
                goto usage;
        }
        else
            goto usage;
    }

    polarssl_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
#if !defined(_WIN32) && defined(POLARSSL_FS_IO)
    if( opt.use_dev_random )
    {
        if( ( ret = entropy_add_source( &entropy, dev_random_entropy_poll,
                                        NULL, DEV_RANDOM_THRESHOLD ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! entropy_add_source returned -0x%04x\n", -ret );
            goto exit;
        }

        polarssl_printf("\n    Using /dev/random, so can take a long time! " );
        fflush( stdout );
    }
#endif /* !_WIN32 && POLARSSL_FS_IO */

    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ctr_drbg_init returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * 1.1. Generate the key
     */
    polarssl_printf( "\n  . Generating the private key ..." );
    fflush( stdout );

    if( ( ret = pk_init_ctx( &key, pk_info_from_type( opt.type ) ) ) != 0 )
    {
        polarssl_printf( " failed\n  !  pk_init_ctx returned -0x%04x", -ret );
        goto exit;
    }

#if defined(POLARSSL_RSA_C) && defined(POLARSSL_GENPRIME)
    if( opt.type == POLARSSL_PK_RSA )
    {
        ret = rsa_gen_key( pk_rsa( key ), ctr_drbg_random, &ctr_drbg,
                           opt.rsa_keysize, 65537 );
        if( ret != 0 )
        {
            polarssl_printf( " failed\n  !  rsa_gen_key returned -0x%04x", -ret );
            goto exit;
        }
    }
    else
#endif /* POLARSSL_RSA_C */
#if defined(POLARSSL_ECP_C)
    if( opt.type == POLARSSL_PK_ECKEY )
    {
        ret = ecp_gen_key( opt.ec_curve, pk_ec( key ),
                          ctr_drbg_random, &ctr_drbg );
        if( ret != 0 )
        {
            polarssl_printf( " failed\n  !  rsa_gen_key returned -0x%04x", -ret );
            goto exit;
        }
    }
    else
#endif /* POLARSSL_ECP_C */
    {
        polarssl_printf( " failed\n  !  key type not supported\n" );
        goto exit;
    }

    /*
     * 1.2 Print the key
     */
    polarssl_printf( " ok\n  . Key information:\n" );

#if defined(POLARSSL_RSA_C)
    if( pk_get_type( &key ) == POLARSSL_PK_RSA )
    {
        rsa_context *rsa = pk_rsa( key );
        mpi_write_file( "N:  ",  &rsa->N,  16, NULL );
        mpi_write_file( "E:  ",  &rsa->E,  16, NULL );
        mpi_write_file( "D:  ",  &rsa->D,  16, NULL );
        mpi_write_file( "P:  ",  &rsa->P,  16, NULL );
        mpi_write_file( "Q:  ",  &rsa->Q,  16, NULL );
        mpi_write_file( "DP: ",  &rsa->DP, 16, NULL );
        mpi_write_file( "DQ:  ", &rsa->DQ, 16, NULL );
        mpi_write_file( "QP:  ", &rsa->QP, 16, NULL );
    }
    else
#endif
#if defined(POLARSSL_ECP_C)
    if( pk_get_type( &key ) == POLARSSL_PK_ECKEY )
    {
        ecp_keypair *ecp = pk_ec( key );
        polarssl_printf( "curve: %s\n",
                ecp_curve_info_from_grp_id( ecp->grp.id )->name );
        mpi_write_file( "X_Q:   ", &ecp->Q.X, 16, NULL );
        mpi_write_file( "Y_Q:   ", &ecp->Q.Y, 16, NULL );
        mpi_write_file( "D:     ", &ecp->d  , 16, NULL );
    }
    else
#endif
        polarssl_printf("  ! key type not supported\n");

    /*
     * 1.3 Export key
     */
    polarssl_printf( "  . Writing key to file..." );

    if( ( ret = write_private_key( &key, opt.filename ) ) != 0 )
    {
        polarssl_printf( " failed\n" );
        goto exit;
    }

    polarssl_printf( " ok\n" );

exit:

    if( ret != 0 && ret != 1)
    {
#ifdef POLARSSL_ERROR_C
        polarssl_strerror( ret, buf, sizeof( buf ) );
        polarssl_printf( " - %s\n", buf );
#else
        polarssl_printf("\n");
#endif
    }

    pk_free( &key );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_PK_WRITE_C && POLARSSL_FS_IO */
