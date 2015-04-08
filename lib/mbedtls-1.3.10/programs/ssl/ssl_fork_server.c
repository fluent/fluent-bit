/*
 *  SSL server demonstration program using fork() for handling multiple clients
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
#include <signal.h>

#if !defined(_MSC_VER) || defined(EFIX64) || defined(EFI32)
#include <unistd.h>
#endif

#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/ssl.h"
#include "polarssl/net.h"
#include "polarssl/timing.h"

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_CERTS_C) ||    \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_SSL_TLS_C) || \
    !defined(POLARSSL_SSL_SRV_C) || !defined(POLARSSL_NET_C) ||     \
    !defined(POLARSSL_RSA_C) || !defined(POLARSSL_CTR_DRBG_C) ||    \
    !defined(POLARSSL_X509_CRT_PARSE_C) || !defined(POLARSSL_TIMING_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_CERTS_C and/or POLARSSL_ENTROPY_C "
           "and/or POLARSSL_SSL_TLS_C and/or POLARSSL_SSL_SRV_C and/or "
           "POLARSSL_NET_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_CTR_DRBG_C and/or POLARSSL_X509_CRT_PARSE_C and/or "
           "POLARSSL_TIMING_C not defined.\n");
    return( 0 );
}
#elif defined(_WIN32)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("_WIN32 defined. This application requires fork() and signals "
           "to work correctly.\n");
    return( 0 );
}
#else

#define DEBUG_LEVEL 0

static void my_debug( void *ctx, int level, const char *str )
{
    if( level < DEBUG_LEVEL )
    {
        polarssl_fprintf( (FILE *) ctx, "%s", str );
        fflush(  (FILE *) ctx  );
    }
}

int main( int argc, char *argv[] )
{
    int ret, len, cnt = 0, pid;
    int listen_fd;
    int client_fd = -1;
    unsigned char buf[1024];
    const char *pers = "ssl_fork_server";

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;
    x509_crt srvcert;
    pk_context pkey;

    ((void) argc);
    ((void) argv);

    memset( &ssl, 0, sizeof(ssl_context) );

    entropy_init( &entropy );
    pk_init( &pkey );
    x509_crt_init( &srvcert );

    signal( SIGCHLD, SIG_IGN );

    /*
     * 0. Initial seeding of the RNG
     */
    polarssl_printf( "\n  . Initial seeding of the random generator..." );
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
     * 1. Load the certificates and private RSA key
     */
    polarssl_printf( "  . Loading the server cert. and key..." );
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

    while( 1 )
    {
        /*
         * 3. Wait until a client connects
         */
        client_fd = -1;
        memset( &ssl, 0, sizeof( ssl ) );

        polarssl_printf( "  . Waiting for a remote connection ..." );
        fflush( stdout );

        if( ( ret = net_accept( listen_fd, &client_fd, NULL ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! net_accept returned %d\n\n", ret );
            goto exit;
        }

        polarssl_printf( " ok\n" );

        /*
         * 3.5. Forking server thread
         */

        pid = fork();

        polarssl_printf( "  . Forking to handle connection ..." );
        fflush( stdout );

        if( pid < 0 )
        {
            polarssl_printf(" failed\n  ! fork returned %d\n\n", pid );
            goto exit;
        }

        polarssl_printf( " ok\n" );

        if( pid != 0 )
        {
            if( ( ret = ctr_drbg_reseed( &ctr_drbg,
                                         (const unsigned char *) "parent",
                                         6 ) ) != 0 )
            {
                polarssl_printf( " failed\n  ! ctr_drbg_reseed returned %d\n", ret );
                goto exit;
            }

            close( client_fd );
            continue;
        }

        close( listen_fd );

        /*
         * 4. Setup stuff
         */
        polarssl_printf( "  . Setting up the SSL data...." );
        fflush( stdout );

        if( ( ret = ctr_drbg_reseed( &ctr_drbg,
                                     (const unsigned char *) "child",
                                     5 ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! ctr_drbg_reseed returned %d\n", ret );
            goto exit;
        }

        if( ( ret = ssl_init( &ssl ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! ssl_init returned %d\n\n", ret );
            goto exit;
        }

        polarssl_printf( " ok\n" );

        ssl_set_endpoint( &ssl, SSL_IS_SERVER );
        ssl_set_authmode( &ssl, SSL_VERIFY_NONE );

        /* SSLv3 is deprecated, set minimum to TLS 1.0 */
        ssl_set_min_version( &ssl, SSL_MAJOR_VERSION_3,
                                   SSL_MINOR_VERSION_1 );
        /* RC4 is deprecated, disable it */
        ssl_set_arc4_support( &ssl, SSL_ARC4_DISABLED );

        ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );
        ssl_set_dbg( &ssl, my_debug, stdout );
        ssl_set_bio( &ssl, net_recv, &client_fd,
                           net_send, &client_fd );

        ssl_set_ca_chain( &ssl, srvcert.next, NULL, NULL );
        if( ( ret = ssl_set_own_cert( &ssl, &srvcert, &pkey ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! ssl_set_own_cert returned %d\n\n", ret );
            goto exit;
        }

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
                goto exit;
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
                        polarssl_printf( " ssl_read returned %d\n", ret );
                        break;
                }

                break;
            }

            len = ret;
            polarssl_printf( " %d bytes read\n\n%s", len, (char *) buf );
        }
        while( 0 );

        /*
         * 7. Write the 200 Response
         */
        polarssl_printf( "  > Write to client:" );
        fflush( stdout );

        len = sprintf( (char *) buf, HTTP_RESPONSE,
                ssl_get_ciphersuite( &ssl ) );

        while( cnt++ < 100 )
        {
            while( ( ret = ssl_write( &ssl, buf, len ) ) <= 0 )
            {
                if( ret == POLARSSL_ERR_NET_CONN_RESET )
                {
                    polarssl_printf( " failed\n  ! peer closed the connection\n\n" );
                    goto exit;
                }

                if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
                {
                    polarssl_printf( " failed\n  ! ssl_write returned %d\n\n", ret );
                    goto exit;
                }
            }
            len = ret;
            polarssl_printf( " %d bytes written\n\n%s\n", len, (char *) buf );

            m_sleep( 1000 );
        }

        ssl_close_notify( &ssl );
        goto exit;
    }

exit:

    if( client_fd != -1 )
        net_close( client_fd );

    x509_crt_free( &srvcert );
    pk_free( &pkey );
    ssl_free( &ssl );
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
