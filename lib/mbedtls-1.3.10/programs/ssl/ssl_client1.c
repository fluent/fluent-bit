/*
 *  SSL client demonstration program
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

#include "polarssl/net.h"
#include "polarssl/debug.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/error.h"
#include "polarssl/certs.h"

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_ENTROPY_C) ||  \
    !defined(POLARSSL_SSL_TLS_C) || !defined(POLARSSL_SSL_CLI_C) || \
    !defined(POLARSSL_NET_C) || !defined(POLARSSL_RSA_C) ||         \
    !defined(POLARSSL_CTR_DRBG_C) || !defined(POLARSSL_X509_CRT_PARSE_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_ENTROPY_C and/or "
           "POLARSSL_SSL_TLS_C and/or POLARSSL_SSL_CLI_C and/or "
           "POLARSSL_NET_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_CTR_DRBG_C and/or POLARSSL_X509_CRT_PARSE_C "
           "not defined.\n");
    return( 0 );
}
#else

#define SERVER_PORT 4433
#define SERVER_NAME "localhost"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define DEBUG_LEVEL 1

static void my_debug( void *ctx, int level, const char *str )
{
    ((void) level);

    polarssl_fprintf( (FILE *) ctx, "%s", str );
    fflush(  (FILE *) ctx  );
}

int main( int argc, char *argv[] )
{
    int ret, len, server_fd = -1;
    unsigned char buf[1024];
    const char *pers = "ssl_client1";

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;
    x509_crt cacert;

    ((void) argc);
    ((void) argv);

#if defined(POLARSSL_DEBUG_C)
    debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * 0. Initialize the RNG and the session data
     */
    memset( &ssl, 0, sizeof( ssl_context ) );
    x509_crt_init( &cacert );

    polarssl_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    /*
     * 0. Initialize certificates
     */
    polarssl_printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

#if defined(POLARSSL_CERTS_C)
    ret = x509_crt_parse( &cacert, (const unsigned char *) test_ca_list,
                          strlen( test_ca_list ) );
#else
    ret = 1;
    polarssl_printf("POLARSSL_CERTS_C not defined.");
#endif

    if( ret < 0 )
    {
        polarssl_printf( " failed\n  !  x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

    polarssl_printf( " ok (%d skipped)\n", ret );

    /*
     * 1. Start the connection
     */
    polarssl_printf( "  . Connecting to tcp/%s/%4d...", SERVER_NAME,
                                               SERVER_PORT );
    fflush( stdout );

    if( ( ret = net_connect( &server_fd, SERVER_NAME,
                                         SERVER_PORT ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! net_connect returned %d\n\n", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    /*
     * 2. Setup stuff
     */
    polarssl_printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );

    if( ( ret = ssl_init( &ssl ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_init returned %d\n\n", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    ssl_set_endpoint( &ssl, SSL_IS_CLIENT );
    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    ssl_set_authmode( &ssl, SSL_VERIFY_OPTIONAL );
    ssl_set_ca_chain( &ssl, &cacert, NULL, "PolarSSL Server 1" );

    /* SSLv3 is deprecated, set minimum to TLS 1.0 */
    ssl_set_min_version( &ssl, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_1 );
    /* RC4 is deprecated, disable it */
    ssl_set_arc4_support( &ssl, SSL_ARC4_DISABLED );

    ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );
    ssl_set_dbg( &ssl, my_debug, stdout );
    ssl_set_bio( &ssl, net_recv, &server_fd,
                       net_send, &server_fd );

    /*
     * 4. Handshake
     */
    polarssl_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            polarssl_printf( " failed\n  ! ssl_handshake returned -0x%x\n\n", -ret );
            goto exit;
        }
    }

    polarssl_printf( " ok\n" );

    /*
     * 5. Verify the server certificate
     */
    polarssl_printf( "  . Verifying peer X.509 certificate..." );

    /* In real life, we may want to bail out when ret != 0 */
    if( ( ret = ssl_get_verify_result( &ssl ) ) != 0 )
    {
        polarssl_printf( " failed\n" );

        if( ( ret & BADCERT_EXPIRED ) != 0 )
            polarssl_printf( "  ! server certificate has expired\n" );

        if( ( ret & BADCERT_REVOKED ) != 0 )
            polarssl_printf( "  ! server certificate has been revoked\n" );

        if( ( ret & BADCERT_CN_MISMATCH ) != 0 )
            polarssl_printf( "  ! CN mismatch (expected CN=%s)\n", "PolarSSL Server 1" );

        if( ( ret & BADCERT_NOT_TRUSTED ) != 0 )
            polarssl_printf( "  ! self-signed or not signed by a trusted CA\n" );

        polarssl_printf( "\n" );
    }
    else
        polarssl_printf( " ok\n" );

    /*
     * 3. Write the GET request
     */
    polarssl_printf( "  > Write to server:" );
    fflush( stdout );

    len = sprintf( (char *) buf, GET_REQUEST );

    while( ( ret = ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            polarssl_printf( " failed\n  ! ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    polarssl_printf( " %d bytes written\n\n%s", len, (char *) buf );

    /*
     * 7. Read the HTTP response
     */
    polarssl_printf( "  < Read from server:" );
    fflush( stdout );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = ssl_read( &ssl, buf, len );

        if( ret == POLARSSL_ERR_NET_WANT_READ || ret == POLARSSL_ERR_NET_WANT_WRITE )
            continue;

        if( ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY )
            break;

        if( ret < 0 )
        {
            polarssl_printf( "failed\n  ! ssl_read returned %d\n\n", ret );
            break;
        }

        if( ret == 0 )
        {
            polarssl_printf( "\n\nEOF\n\n" );
            break;
        }

        len = ret;
        polarssl_printf( " %d bytes read\n\n%s", len, (char *) buf );
    }
    while( 1 );

    ssl_close_notify( &ssl );

exit:

#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        polarssl_strerror( ret, error_buf, 100 );
        polarssl_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    if( server_fd != -1 )
        net_close( server_fd );

    x509_crt_free( &cacert );
    ssl_free( &ssl );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

    memset( &ssl, 0, sizeof( ssl ) );

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_ENTROPY_C && POLARSSL_SSL_TLS_C &&
          POLARSSL_SSL_CLI_C && POLARSSL_NET_C && POLARSSL_RSA_C &&
          POLARSSL_CTR_DRBG_C */
