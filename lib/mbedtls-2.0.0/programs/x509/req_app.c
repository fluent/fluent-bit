/*
 *  Certificate request reading application
 *
 *  Copyright (C) 2006-2013, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_RSA_C) ||  \
    !defined(MBEDTLS_X509_CSR_PARSE_C) || !defined(MBEDTLS_FS_IO)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_X509_CSR_PARSE_C and/or MBEDTLS_FS_IO not defined.\n");
    return( 0 );
}
#else

#include "mbedtls/x509_csr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DFL_FILENAME            "cert.req"
#define DFL_DEBUG_LEVEL         0

#define USAGE \
    "\n usage: req_app param=<>...\n"                   \
    "\n acceptable parameters:\n"                       \
    "    filename=%%s         default: cert.req\n"      \
    "\n"

/*
 * global options
 */
struct options
{
    const char *filename;       /* filename of the certificate request  */
} opt;

int main( int argc, char *argv[] )
{
    int ret = 0;
    unsigned char buf[100000];
    mbedtls_x509_csr csr;
    int i;
    char *p, *q;

    /*
     * Set to sane values
     */
    mbedtls_x509_csr_init( &csr );

    if( argc == 0 )
    {
    usage:
        mbedtls_printf( USAGE );
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
    mbedtls_printf( "\n  . Loading the CSR ..." );
    fflush( stdout );

    ret = mbedtls_x509_csr_parse_file( &csr, opt.filename );

    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_csr_parse_file returned %d\n\n", ret );
        mbedtls_x509_csr_free( &csr );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 1.2 Print the CSR
     */
    mbedtls_printf( "  . CSR information    ...\n" );
    ret = mbedtls_x509_csr_info( (char *) buf, sizeof( buf ) - 1, "      ", &csr );
    if( ret == -1 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_csr_info returned %d\n\n", ret );
        mbedtls_x509_csr_free( &csr );
        goto exit;
    }

    mbedtls_printf( "%s\n", buf );

exit:
    mbedtls_x509_csr_free( &csr );

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_RSA_C && MBEDTLS_X509_CSR_PARSE_C &&
          MBEDTLS_FS_IO */
