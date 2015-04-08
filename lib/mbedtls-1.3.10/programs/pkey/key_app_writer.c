/*
 *  Key writing application
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

#include "polarssl/error.h"
#include "polarssl/pk.h"
#include "polarssl/error.h"

#if !defined(POLARSSL_PK_WRITE_C) || !defined(POLARSSL_FS_IO)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf( "POLARSSL_PK_WRITE_C and/or POLARSSL_FS_IO not defined.\n" );
    return( 0 );
}
#else

#define MODE_NONE               0
#define MODE_PRIVATE            1
#define MODE_PUBLIC             2

#define OUTPUT_MODE_NONE               0
#define OUTPUT_MODE_PRIVATE            1
#define OUTPUT_MODE_PUBLIC             2

#define OUTPUT_FORMAT_PEM              0
#define OUTPUT_FORMAT_DER              1

#define DFL_MODE                MODE_NONE
#define DFL_FILENAME            "keyfile.key"
#define DFL_DEBUG_LEVEL         0
#define DFL_OUTPUT_MODE         OUTPUT_MODE_NONE
#if defined(POLARSSL_PEM_WRITE_C)
#define DFL_OUTPUT_FILENAME     "keyfile.pem"
#define DFL_OUTPUT_FORMAT       OUTPUT_FORMAT_PEM
#else
#define DFL_OUTPUT_FILENAME     "keyfile.der"
#define DFL_OUTPUT_FORMAT       OUTPUT_FORMAT_DER
#endif

/*
 * global options
 */
struct options
{
    int mode;                   /* the mode to run the application in   */
    const char *filename;       /* filename of the key file             */
    int output_mode;            /* the output mode to use               */
    const char *output_file;    /* where to store the constructed key file  */
    int output_format;          /* the output format to use             */
} opt;

static int write_public_key( pk_context *key, const char *output_file )
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);

#if defined(POLARSSL_PEM_WRITE_C)
    if( opt.output_format == OUTPUT_FORMAT_PEM )
    {
        if( ( ret = pk_write_pubkey_pem( key, output_buf, 16000 ) ) != 0 )
            return( ret );

        len = strlen( (char *) output_buf );
    }
    else
#endif
    {
        if( ( ret = pk_write_pubkey_der( key, output_buf, 16000 ) ) < 0 )
            return( ret );

        len = ret;
        c = output_buf + sizeof(output_buf) - len - 1;
    }

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

static int write_private_key( pk_context *key, const char *output_file )
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);

#if defined(POLARSSL_PEM_WRITE_C)
    if( opt.output_format == OUTPUT_FORMAT_PEM )
    {
        if( ( ret = pk_write_key_pem( key, output_buf, 16000 ) ) != 0 )
            return( ret );

        len = strlen( (char *) output_buf );
    }
    else
#endif
    {
        if( ( ret = pk_write_key_der( key, output_buf, 16000 ) ) < 0 )
            return( ret );

        len = ret;
        c = output_buf + sizeof(output_buf) - len - 1;
    }

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

#if defined(POLARSSL_PEM_WRITE_C)
#define USAGE_OUT \
    "    output_file=%%s      default: keyfile.pem\n"   \
    "    output_format=pem|der default: pem\n"
#else
#define USAGE_OUT \
    "    output_file=%%s      default: keyfile.der\n"   \
    "    output_format=der     default: der\n"
#endif

#define USAGE \
    "\n usage: key_app param=<>...\n"                   \
    "\n acceptable parameters:\n"                       \
    "    mode=private|public default: none\n"           \
    "    filename=%%s         default: keyfile.key\n"   \
    "    output_mode=private|public default: none\n"    \
    USAGE_OUT                                           \
    "\n"

int main( int argc, char *argv[] )
{
    int ret = 0;
    pk_context key;
    char buf[1024];
    int i;
    char *p, *q;

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
        goto exit;
    }

    opt.mode                = DFL_MODE;
    opt.filename            = DFL_FILENAME;
    opt.output_mode         = DFL_OUTPUT_MODE;
    opt.output_file         = DFL_OUTPUT_FILENAME;
    opt.output_format       = DFL_OUTPUT_FORMAT;

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "mode" ) == 0 )
        {
            if( strcmp( q, "private" ) == 0 )
                opt.mode = MODE_PRIVATE;
            else if( strcmp( q, "public" ) == 0 )
                opt.mode = MODE_PUBLIC;
            else
                goto usage;
        }
        else if( strcmp( p, "output_mode" ) == 0 )
        {
            if( strcmp( q, "private" ) == 0 )
                opt.output_mode = OUTPUT_MODE_PRIVATE;
            else if( strcmp( q, "public" ) == 0 )
                opt.output_mode = OUTPUT_MODE_PUBLIC;
            else
                goto usage;
        }
        else if( strcmp( p, "output_format" ) == 0 )
        {
#if defined(POLARSSL_PEM_WRITE_C)
            if( strcmp( q, "pem" ) == 0 )
                opt.output_format = OUTPUT_FORMAT_PEM;
            else
#endif
            if( strcmp( q, "der" ) == 0 )
                opt.output_format = OUTPUT_FORMAT_DER;
            else
                goto usage;
        }
        else if( strcmp( p, "filename" ) == 0 )
            opt.filename = q;
        else if( strcmp( p, "output_file" ) == 0 )
            opt.output_file = q;
        else
            goto usage;
    }

    if( opt.mode == MODE_NONE && opt.output_mode != OUTPUT_MODE_NONE )
    {
        polarssl_printf( "\nCannot output a key without reading one.\n");
        goto exit;
    }

    if( opt.mode == MODE_PUBLIC && opt.output_mode == OUTPUT_MODE_PRIVATE )
    {
        polarssl_printf( "\nCannot output a private key from a public key.\n");
        goto exit;
    }

    if( opt.mode == MODE_PRIVATE )
    {
        /*
         * 1.1. Load the key
         */
        polarssl_printf( "\n  . Loading the private key ..." );
        fflush( stdout );

        ret = pk_parse_keyfile( &key, opt.filename, NULL );

        if( ret != 0 )
        {
            polarssl_strerror( ret, (char *) buf, sizeof(buf) );
            polarssl_printf( " failed\n  !  pk_parse_keyfile returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        polarssl_printf( " ok\n" );

        /*
         * 1.2 Print the key
         */
        polarssl_printf( "  . Key information    ...\n" );

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
            mpi_write_file( "Q(X): ", &ecp->Q.X, 16, NULL );
            mpi_write_file( "Q(Y): ", &ecp->Q.Y, 16, NULL );
            mpi_write_file( "Q(Z): ", &ecp->Q.Z, 16, NULL );
            mpi_write_file( "D   : ", &ecp->d  , 16, NULL );
        }
        else
#endif
            polarssl_printf("key type not supported yet\n");

    }
    else if( opt.mode == MODE_PUBLIC )
    {
        /*
         * 1.1. Load the key
         */
        polarssl_printf( "\n  . Loading the public key ..." );
        fflush( stdout );

        ret = pk_parse_public_keyfile( &key, opt.filename );

        if( ret != 0 )
        {
            polarssl_strerror( ret, (char *) buf, sizeof(buf) );
            polarssl_printf( " failed\n  !  pk_parse_public_key returned -0x%04x - %s\n\n", -ret, buf );
            goto exit;
        }

        polarssl_printf( " ok\n" );

        /*
         * 1.2 Print the key
         */
        polarssl_printf( "  . Key information    ...\n" );

#if defined(POLARSSL_RSA_C)
        if( pk_get_type( &key ) == POLARSSL_PK_RSA )
        {
            rsa_context *rsa = pk_rsa( key );
            mpi_write_file( "N: ", &rsa->N, 16, NULL );
            mpi_write_file( "E: ", &rsa->E, 16, NULL );
        }
        else
#endif
#if defined(POLARSSL_ECP_C)
        if( pk_get_type( &key ) == POLARSSL_PK_ECKEY )
        {
            ecp_keypair *ecp = pk_ec( key );
            mpi_write_file( "Q(X): ", &ecp->Q.X, 16, NULL );
            mpi_write_file( "Q(Y): ", &ecp->Q.Y, 16, NULL );
            mpi_write_file( "Q(Z): ", &ecp->Q.Z, 16, NULL );
        }
        else
#endif
            polarssl_printf("key type not supported yet\n");
    }
    else
        goto usage;

    if( opt.output_mode == OUTPUT_MODE_PUBLIC )
    {
        write_public_key( &key, opt.output_file );
    }
    if( opt.output_mode == OUTPUT_MODE_PRIVATE )
    {
        write_private_key( &key, opt.output_file );
    }

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

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_X509_WRITE_C && POLARSSL_FS_IO */
