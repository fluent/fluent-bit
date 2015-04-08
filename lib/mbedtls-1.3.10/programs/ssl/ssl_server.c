/*
 *  SSL server demonstration program
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

#if defined(_WIN32)
#include <windows.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/ssl.h"
#include "polarssl/net.h"
#include "polarssl/error.h"
#include "polarssl/debug.h"

#if defined(POLARSSL_SSL_CACHE_C)
#include "polarssl/ssl_cache.h"
#endif

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_CERTS_C) ||    \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_SSL_TLS_C) || \
    !defined(POLARSSL_SSL_SRV_C) || !defined(POLARSSL_NET_C) ||     \
    !defined(POLARSSL_RSA_C) || !defined(POLARSSL_CTR_DRBG_C) ||    \
    !defined(POLARSSL_X509_CRT_PARSE_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_CERTS_C and/or POLARSSL_ENTROPY_C "
           "and/or POLARSSL_SSL_TLS_C and/or POLARSSL_SSL_SRV_C and/or "
           "POLARSSL_NET_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_CTR_DRBG_C and/or POLARSSL_X509_CRT_PARSE_C "
           "not defined.\n");
    return( 0 );
}
#else

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

static void my_debug( void *ctx, int level, const char *str )
{
    ((void) level);

    polarssl_fprintf( (FILE *) ctx, "%s", str );
    fflush(  (FILE *) ctx  );
}

int main( int argc, char *argv[] )
{
    int ret, len;
    int listen_fd;
    int client_fd = -1;
    unsigned char buf[1024];
    const char *pers = "ssl_server";

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;
    x509_crt srvcert;
    pk_context pkey;
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_context cache;
#endif

    ((void) argc);
    ((void) argv);

    memset( &ssl, 0, sizeof(ssl_context) );
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_init( &cache );
#endif
    x509_crt_init( &srvcert );
    pk_init( &pkey );
    entropy_init( &entropy );

#if defined(POLARSSL_DEBUG_C)
    debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * 1. Load the certificates and private RSA key
     */
    polarssl_printf( "\n  . Loading the server cert. and key..." );
    fflush( stdout );

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use x509_crt_parse_file() to read the
     * server and CA certificates, as well as pk_parse_keyfile().
     */
    ret = x509_crt_parse( &srvcert, (const unsigned char *) test_srv_crt,
                          strlen( test_srv_crt ) );
    if( ret != 0 )
    {
        polarssl_printf( " failed\n  !  x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret = x509_crt_parse( &srvcert, (const unsigned char *) test_ca_list,
                          strlen( test_ca_list ) );
    if( ret != 0 )
    {
        polarssl_printf( " failed\n  !  x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret =  pk_parse_key( &pkey, (const unsigned char *) test_srv_key,
                         strlen( test_srv_key ), NULL, 0 );
    if( ret != 0 )
    {
        polarssl_printf( " failed\n  !  pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    /*
     * 2. Setup the listening TCP socket
     */
    polarssl_printf( "  . Bind on https://localhost:4433/ ..." );
    fflush( stdout );

    if( ( ret = net_bind( &listen_fd, NULL, 4433 ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! net_bind returned %d\n\n", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    /*
     * 3. Seed the RNG
     */
    polarssl_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    /*
     * 4. Setup stuff
     */
    polarssl_printf( "  . Setting up the SSL data...." );
    fflush( stdout );

    if( ( ret = ssl_init( &ssl ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_init returned %d\n\n", ret );
        goto exit;
    }

    ssl_set_endpoint( &ssl, SSL_IS_SERVER );
    ssl_set_authmode( &ssl, SSL_VERIFY_NONE );

    /* SSLv3 is deprecated, set minimum to TLS 1.0 */
    ssl_set_min_version( &ssl, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_1 );
    /* RC4 is deprecated, disable it */
    ssl_set_arc4_support( &ssl, SSL_ARC4_DISABLED );

    ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );
    ssl_set_dbg( &ssl, my_debug, stdout );

#if defined(POLARSSL_SSL_CACHE_C)
    ssl_set_session_cache( &ssl, ssl_cache_get, &cache,
                                 ssl_cache_set, &cache );
#endif

    ssl_set_ca_chain( &ssl, srvcert.next, NULL, NULL );
    if( ( ret = ssl_set_own_cert( &ssl, &srvcert, &pkey ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_set_own_cert returned %d\n\n", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

reset:
#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        polarssl_strerror( ret, error_buf, 100 );
        polarssl_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    if( client_fd != -1 )
        net_close( client_fd );

    ssl_session_reset( &ssl );

    /*
     * 3. Wait until a client connects
     */
    client_fd = -1;

    polarssl_printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = net_accept( listen_fd, &client_fd, NULL ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! net_accept returned %d\n\n", ret );
        goto exit;
    }

    ssl_set_bio( &ssl, net_recv, &client_fd,
                       net_send, &client_fd );

    polarssl_printf( " ok\n" );

    /*
     * 5. Handshake
     */
    polarssl_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            polarssl_printf( " failed\n  ! ssl_handshake returned %d\n\n", ret );
            goto reset;
        }
    }

    polarssl_printf( " ok\n" );

    /*
     * 6. Read the HTTP Request
     */
    polarssl_printf( "  < Read from client:" );
    fflush( stdout );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = ssl_read( &ssl, buf, len );

        if( ret == POLARSSL_ERR_NET_WANT_READ || ret == POLARSSL_ERR_NET_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
                    polarssl_printf( " connection was closed gracefully\n" );
                    break;

                case POLARSSL_ERR_NET_CONN_RESET:
                    polarssl_printf( " connection was reset by peer\n" );
                    break;

                default:
                    polarssl_printf( " ssl_read returned -0x%x\n", -ret );
                    break;
            }

            break;
        }

        len = ret;
        polarssl_printf( " %d bytes read\n\n%s", len, (char *) buf );

        if( ret > 0 )
            break;
    }
    while( 1 );

    /*
     * 7. Write the 200 Response
     */
    polarssl_printf( "  > Write to client:" );
    fflush( stdout );

    len = sprintf( (char *) buf, HTTP_RESPONSE,
                   ssl_get_ciphersuite( &ssl ) );

    while( ( ret = ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret == POLARSSL_ERR_NET_CONN_RESET )
        {
            polarssl_printf( " failed\n  ! peer closed the connection\n\n" );
            goto reset;
        }

        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            polarssl_printf( " failed\n  ! ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    polarssl_printf( " %d bytes written\n\n%s\n", len, (char *) buf );

    polarssl_printf( "  . Closing the connection..." );

    while( ( ret = ssl_close_notify( &ssl ) ) < 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ &&
            ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            polarssl_printf( " failed\n  ! ssl_close_notify returned %d\n\n", ret );
            goto reset;
        }
    }

    polarssl_printf( " ok\n" );

    ret = 0;
    goto reset;

exit:

#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        polarssl_strerror( ret, error_buf, 100 );
        polarssl_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    if( client_fd != -1 )
        net_close( client_fd );

    x509_crt_free( &srvcert );
    pk_free( &pkey );
    ssl_free( &ssl );
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_free( &cache );
#endif
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(_WIN32)
    polarssl_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_CERTS_C && POLARSSL_ENTROPY_C &&
          POLARSSL_SSL_TLS_C && POLARSSL_SSL_SRV_C && POLARSSL_NET_C &&
          POLARSSL_RSA_C && POLARSSL_CTR_DRBG_C */
