/*
 *  Key reading application
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
#include "polarssl/rsa.h"
#include "polarssl/x509.h"

#if !defined(POLARSSL_BIGNUM_C) ||                                  \
    !defined(POLARSSL_PK_PARSE_C) || !defined(POLARSSL_FS_IO)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_BIGNUM_C and/or "
           "POLARSSL_PK_PARSE_C and/or POLARSSL_FS_IO not defined.\n");
    return( 0 );
}
#else

#define MODE_NONE               0
#define MODE_PRIVATE            1
#define MODE_PUBLIC             2

#define DFL_MODE                MODE_NONE
#define DFL_FILENAME            "keyfile.key"
#define DFL_PASSWORD            ""
#define DFL_PASSWORD_FILE       ""
#define DFL_DEBUG_LEVEL         0

/*
 * global options
 */
struct options
{
    int mode;                   /* the mode to run the application in   */
    const char *filename;       /* filename of the key file             */
    const char *password;       /* password for the private key         */
    const char *password_file;  /* password_file for the private key    */
} opt;

#define USAGE \
    "\n usage: key_app param=<>...\n"                   \
    "\n acceptable parameters:\n"                       \
    "    mode=private|public default: none\n"           \
    "    filename=%%s         default: keyfile.key\n"   \
    "    password=%%s         default: \"\"\n"          \
    "    password_file=%%s    default: \"\"\n"          \
    "\n"

int main( int argc, char *argv[] )
{
    int ret = 0;
    pk_context pk;
    char buf[1024];
    int i;
    char *p, *q;

    /*
     * Set to sane values
     */
    pk_init( &pk );
    memset( buf, 0, sizeof(buf) );

    if( argc == 0 )
    {
    usage:
        polarssl_printf( USAGE );
        goto exit;
    }

    opt.mode                = DFL_MODE;
    opt.filename            = DFL_FILENAME;
    opt.password            = DFL_PASSWORD;
    opt.password_file       = DFL_PASSWORD_FILE;

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
        else if( strcmp( p, "filename" ) == 0 )
            opt.filename = q;
        else if( strcmp( p, "password" ) == 0 )
            opt.password = q;
        else if( strcmp( p, "password_file" ) == 0 )
            opt.password_file = q;
        else
            goto usage;
    }

    if( opt.mode == MODE_PRIVATE )
    {
        if( strlen( opt.password ) && strlen( opt.password_file ) )
        {
            polarssl_printf( "Error: cannot have both password and password_file\n" );
            goto usage;
        }

        if( strlen( opt.password_file ) )
        {
            FILE *f;

            polarssl_printf( "\n  . Loading the password file ..." );
            if( ( f = fopen( opt.password_file, "rb" ) ) == NULL )
            {
                polarssl_printf( " failed\n  !  fopen returned NULL\n" );
                goto exit;
            }
            if( fgets( buf, sizeof(buf), f ) == NULL )
            {
                fclose( f );
                polarssl_printf( "Error: fgets() failed to retrieve password\n" );
                goto exit;
            }
            fclose( f );

            i = (int) strlen( buf );
            if( buf[i - 1] == '\n' ) buf[i - 1] = '\0';
            if( buf[i - 2] == '\r' ) buf[i - 2] = '\0';
            opt.password = buf;
        }

        /*
         * 1.1. Load the key
         */
        polarssl_printf( "\n  . Loading the private key ..." );
        fflush( stdout );

        ret = pk_parse_keyfile( &pk, opt.filename, opt.password );

        if( ret != 0 )
        {
            polarssl_printf( " failed\n  !  pk_parse_keyfile returned -0x%04x\n", -ret );
            goto exit;
        }

        polarssl_printf( " ok\n" );

        /*
         * 1.2 Print the key
         */
        polarssl_printf( "  . Key information    ...\n" );
#if defined(POLARSSL_RSA_C)
        if( pk_get_type( &pk ) == POLARSSL_PK_RSA )
        {
            rsa_context *rsa = pk_rsa( pk );
            mpi_write_file( "N:  ", &rsa->N, 16, NULL );
            mpi_write_file( "E:  ", &rsa->E, 16, NULL );
            mpi_write_file( "D:  ", &rsa->D, 16, NULL );
            mpi_write_file( "P:  ", &rsa->P, 16, NULL );
            mpi_write_file( "Q:  ", &rsa->Q, 16, NULL );
            mpi_write_file( "DP: ", &rsa->DP, 16, NULL );
            mpi_write_file( "DQ:  ", &rsa->DQ, 16, NULL );
            mpi_write_file( "QP:  ", &rsa->QP, 16, NULL );
        }
        else
#endif
#if defined(POLARSSL_ECP_C)
        if( pk_get_type( &pk ) == POLARSSL_PK_ECKEY )
        {
            ecp_keypair *ecp = pk_ec( pk );
            mpi_write_file( "Q(X): ", &ecp->Q.X, 16, NULL );
            mpi_write_file( "Q(Y): ", &ecp->Q.Y, 16, NULL );
            mpi_write_file( "Q(Z): ", &ecp->Q.Z, 16, NULL );
            mpi_write_file( "D   : ", &ecp->d  , 16, NULL );
        }
        else
#endif
        {
            polarssl_printf("Do not know how to print key information for this type\n" );
            goto exit;
        }
    }
    else if( opt.mode == MODE_PUBLIC )
    {
        /*
         * 1.1. Load the key
         */
        polarssl_printf( "\n  . Loading the public key ..." );
        fflush( stdout );

        ret = pk_parse_public_keyfile( &pk, opt.filename );

        if( ret != 0 )
        {
            polarssl_printf( " failed\n  !  pk_parse_public_keyfile returned -0x%04x\n", -ret );
            goto exit;
        }

        polarssl_printf( " ok\n" );

        polarssl_printf( "  . Key information    ...\n" );
#if defined(POLARSSL_RSA_C)
        if( pk_get_type( &pk ) == POLARSSL_PK_RSA )
        {
            rsa_context *rsa = pk_rsa( pk );
            mpi_write_file( "N:  ", &rsa->N, 16, NULL );
            mpi_write_file( "E:  ", &rsa->E, 16, NULL );
        }
        else
#endif
#if defined(POLARSSL_ECP_C)
        if( pk_get_type( &pk ) == POLARSSL_PK_ECKEY )
        {
            ecp_keypair *ecp = pk_ec( pk );
            mpi_write_file( "Q(X): ", &ecp->Q.X, 16, NULL );
            mpi_write_file( "Q(Y): ", &ecp->Q.Y, 16, NULL );
            mpi_write_file( "Q(Z): ", &ecp->Q.Z, 16, NULL );
        }
        else
#endif
        {
            polarssl_printf("Do not know how to print key information for this type\n" );
            goto exit;
        }
    }
    else
        goto usage;

exit:

#if defined(POLARSSL_ERROR_C)
    polarssl_strerror( ret, buf, sizeof(buf) );
    polarssl_printf( "  !  Last error was: %s\n", buf );
#endif

    pk_free( &pk );

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_PK_PARSE_C && POLARSSL_FS_IO */
