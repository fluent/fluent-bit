/*
 *  Certificate request reading application
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

#include "polarssl/x509_csr.h"

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_RSA_C) ||  \
    !defined(POLARSSL_X509_CSR_PARSE_C) || !defined(POLARSSL_FS_IO)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_X509_CSR_PARSE_C and/or POLARSSL_FS_IO not defined.\n");
    return( 0 );
}
#else

#define DFL_FILENAME            "cert.req"
#define DFL_DEBUG_LEVEL         0

/*
 * global options
 */
struct options
{
    const char *filename;       /* filename of the certificate request  */
} opt;

#define USAGE \
    "\n usage: req_app param=<>...\n"                   \
    "\n acceptable parameters:\n"                       \
    "    filename=%%s         default: cert.req\n"      \
    "\n"

int main( int argc, char *argv[] )
{
    int ret = 0;
    unsigned char buf[100000];
    x509_csr csr;
    int i;
    char *p, *q;

    /*
     * Set to sane values
     */
    x509_csr_init( &csr );

    if( argc == 0 )
    {
    usage:
        polarssl_printf( USAGE );
        goto exit;
    }

    opt.filename            = DFL_FILENAME;

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "filename" ) == 0 )
            opt.filename = q;
        else
            goto usage;
    }

    /*
     * 1.1. Load the CSR
     */
    polarssl_printf( "\n  . Loading the CSR ..." );
    fflush( stdout );

    ret = x509_csr_parse_file( &csr, opt.filename );

    if( ret != 0 )
    {
        polarssl_printf( " failed\n  !  x509_csr_parse_file returned %d\n\n", ret );
        x509_csr_free( &csr );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    /*
     * 1.2 Print the CSR
     */
    polarssl_printf( "  . CSR information    ...\n" );
    ret = x509_csr_info( (char *) buf, sizeof( buf ) - 1, "      ", &csr );
    if( ret == -1 )
    {
        polarssl_printf( " failed\n  !  x509_csr_info returned %d\n\n", ret );
        x509_csr_free( &csr );
        goto exit;
    }

    polarssl_printf( "%s\n", buf );

exit:
    x509_csr_free( &csr );

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_RSA_C && POLARSSL_X509_CSR_PARSE_C &&
          POLARSSL_FS_IO */
