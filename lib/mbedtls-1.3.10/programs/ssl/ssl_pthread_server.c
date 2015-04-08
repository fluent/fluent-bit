/*
 *  SSL server demonstration program using pthread for handling multiple
 *  clients.
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

#if defined(POLARSSL_SSL_CACHE_C)
#include "polarssl/ssl_cache.h"
#endif

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
#include "polarssl/memory_buffer_alloc.h"
#endif

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_CERTS_C) ||            \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_SSL_TLS_C) ||         \
    !defined(POLARSSL_SSL_SRV_C) || !defined(POLARSSL_NET_C) ||             \
    !defined(POLARSSL_RSA_C) || !defined(POLARSSL_CTR_DRBG_C) ||            \
    !defined(POLARSSL_X509_CRT_PARSE_C) ||                                  \
    !defined(POLARSSL_THREADING_C) || !defined(POLARSSL_THREADING_PTHREAD)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_BIGNUM_C and/or POLARSSL_CERTS_C and/or POLARSSL_ENTROPY_C "
           "and/or POLARSSL_SSL_TLS_C and/or POLARSSL_SSL_SRV_C and/or "
           "POLARSSL_NET_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_CTR_DRBG_C and/or POLARSSL_X509_CRT_PARSE_C and/or "
           "POLARSSL_THREADING_C and/or POLARSSL_THREADING_PTHREAD "
           "not defined.\n");
    return( 0 );
}
#else

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

threading_mutex_t debug_mutex;

static void my_mutexed_debug( void *ctx, int level, const char *str )
{
    polarssl_mutex_lock( &debug_mutex );
    if( level < DEBUG_LEVEL )
    {
        polarssl_fprintf( (FILE *) ctx, "%s", str );
        fflush(  (FILE *) ctx  );
    }
    polarssl_mutex_unlock( &debug_mutex );
}

typedef struct {
    int client_fd;
    int thread_complete;
    entropy_context *entropy;
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_context *cache;
#endif
    x509_crt *ca_chain;
    x509_crt *server_cert;
    pk_context *server_key;
} thread_info_t;

typedef struct {
    int active;
    thread_info_t   data;
    pthread_t       thread;
} pthread_info_t;

#define MAX_NUM_THREADS 5

static thread_info_t    base_info;
static pthread_info_t   threads[MAX_NUM_THREADS];

static void *handle_ssl_connection( void *data )
{
    int ret, len;
    thread_info_t *thread_info = (thread_info_t *) data;
    int client_fd = thread_info->client_fd;
    int thread_id = (int) pthread_self();
    unsigned char buf[1024];
    char pers[50];
    ssl_context ssl;
    ctr_drbg_context ctr_drbg;

    /* Make sure memory references are valid */
    memset( &ssl, 0, sizeof( ssl_context ) );
    memset( &ctr_drbg, 0, sizeof( ctr_drbg_context ) );

    snprintf( pers, sizeof(pers), "SSL Pthread Thread %d", thread_id );
    polarssl_printf( "  [ #%d ]  Client FD %d\n", thread_id, client_fd );
    polarssl_printf( "  [ #%d ]  Seeding the random number generator...\n", thread_id );

    /* entropy_func() is thread-safe if POLARSSL_THREADING_C is set
     */
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, thread_info->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        polarssl_printf( "  [ #%d ]  failed: ctr_drbg_init returned -0x%04x\n",
                thread_id, -ret );
        goto thread_exit;
    }

    polarssl_printf( "  [ #%d ]  ok\n", thread_id );

    /*
     * 4. Setup stuff
     */
    polarssl_printf( "  [ #%d ]  Setting up the SSL data....\n", thread_id );

    if( ( ret = ssl_init( &ssl ) ) != 0 )
    {
        polarssl_printf( "  [ #%d ]  failed: ssl_init returned -0x%04x\n",
                thread_id, -ret );
        goto thread_exit;
    }

    ssl_set_endpoint( &ssl, SSL_IS_SERVER );
    ssl_set_authmode( &ssl, SSL_VERIFY_NONE );

    /* SSLv3 is deprecated, set minimum to TLS 1.0 */
    ssl_set_min_version( &ssl, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_1 );
    /* RC4 is deprecated, disable it */
    ssl_set_arc4_support( &ssl, SSL_ARC4_DISABLED );

    ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );
    ssl_set_dbg( &ssl, my_mutexed_debug, stdout );

    /* ssl_cache_get() and ssl_cache_set() are thread-safe if
     * POLARSSL_THREADING_C is set.
     */
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_set_session_cache( &ssl, ssl_cache_get, thread_info->cache,
                                 ssl_cache_set, thread_info->cache );
#endif

    ssl_set_ca_chain( &ssl, thread_info->ca_chain, NULL, NULL );
    if( ( ret = ssl_set_own_cert( &ssl, thread_info->server_cert, thread_info->server_key ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_set_own_cert returned %d\n\n", ret );
        goto thread_exit;
    }

    polarssl_printf( "  [ #%d ]  ok\n", thread_id );

    ssl_set_bio( &ssl, net_recv, &client_fd,
                       net_send, &client_fd );

    polarssl_printf( "  [ #%d ]  ok\n", thread_id );

    /*
     * 5. Handshake
     */
    polarssl_printf( "  [ #%d ]  Performing the SSL/TLS handshake\n", thread_id );

    while( ( ret = ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            polarssl_printf( "  [ #%d ]  failed: ssl_handshake returned -0x%04x\n",
                    thread_id, -ret );
            goto thread_exit;
        }
    }

    polarssl_printf( "  [ #%d ]  ok\n", thread_id );

    /*
     * 6. Read the HTTP Request
     */
    polarssl_printf( "  [ #%d ]  < Read from client\n", thread_id );

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
                    polarssl_printf( "  [ #%d ]  connection was closed gracefully\n",
                            thread_id );
                    goto thread_exit;

                case POLARSSL_ERR_NET_CONN_RESET:
                    polarssl_printf( "  [ #%d ]  connection was reset by peer\n",
                            thread_id );
                    goto thread_exit;

                default:
                    polarssl_printf( "  [ #%d ]  ssl_read returned -0x%04x\n",
                            thread_id, -ret );
                    goto thread_exit;
            }
        }

        len = ret;
        polarssl_printf( "  [ #%d ]  %d bytes read\n=====\n%s\n=====\n",
                thread_id, len, (char *) buf );

        if( ret > 0 )
            break;
    }
    while( 1 );

    /*
     * 7. Write the 200 Response
     */
    polarssl_printf( "  [ #%d ]  > Write to client:\n", thread_id );

    len = sprintf( (char *) buf, HTTP_RESPONSE,
                   ssl_get_ciphersuite( &ssl ) );

    while( ( ret = ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret == POLARSSL_ERR_NET_CONN_RESET )
        {
            polarssl_printf( "  [ #%d ]  failed: peer closed the connection\n",
                    thread_id );
            goto thread_exit;
        }

        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            polarssl_printf( "  [ #%d ]  failed: ssl_write returned -0x%04x\n",
                    thread_id, ret );
            goto thread_exit;
        }
    }

    len = ret;
    polarssl_printf( "  [ #%d ]  %d bytes written\n=====\n%s\n=====\n",
            thread_id, len, (char *) buf );

    polarssl_printf( "  [ #%d ]  . Closing the connection...", thread_id );

    while( ( ret = ssl_close_notify( &ssl ) ) < 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ &&
            ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            polarssl_printf( "  [ #%d ]  failed: ssl_close_notify returned -0x%04x\n",
                    thread_id, ret );
            goto thread_exit;
        }
    }

    polarssl_printf( " ok\n" );

    ret = 0;

thread_exit:

#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        polarssl_strerror( ret, error_buf, 100 );
        polarssl_printf("  [ #%d ]  Last error was: -0x%04x - %s\n\n",
               thread_id, -ret, error_buf );
    }
#endif

    net_close( client_fd );
    ctr_drbg_free( &ctr_drbg );
    ssl_free( &ssl );

    thread_info->thread_complete = 1;

    return( NULL );
}

static int thread_create( int client_fd )
{
    int ret, i;

    /*
     * Find in-active or finished thread slot
     */
    for( i = 0; i < MAX_NUM_THREADS; i++ )
    {
        if( threads[i].active == 0 )
            break;

        if( threads[i].data.thread_complete == 1 )
        {
            polarssl_printf( "  [ main ]  Cleaning up thread %d\n", i );
            pthread_join(threads[i].thread, NULL );
            memset( &threads[i], 0, sizeof(pthread_info_t) );
            break;
        }
    }

    if( i == MAX_NUM_THREADS )
        return( -1 );

    /*
     * Fill thread-info for thread
     */
    memcpy( &threads[i].data, &base_info, sizeof(base_info) );
    threads[i].active = 1;
    threads[i].data.client_fd = client_fd;

    if( ( ret = pthread_create( &threads[i].thread, NULL, handle_ssl_connection,                                &threads[i].data ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int main( int argc, char *argv[] )
{
    int ret;
    int listen_fd;
    int client_fd = -1;

    entropy_context entropy;
    x509_crt srvcert;
    pk_context pkey;
#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[100000];
#endif
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_context cache;
#endif

    ((void) argc);
    ((void) argv);

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
    memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_init( &cache );
    base_info.cache = &cache;
#endif

    memset( threads, 0, sizeof(threads) );

    polarssl_mutex_init( &debug_mutex );

    /*
     * We use only a single entropy source that is used in all the threads.
     */
    entropy_init( &entropy );
    base_info.entropy = &entropy;

    /*
     * 1. Load the certificates and private RSA key
     */
    polarssl_printf( "\n  . Loading the server cert. and key..." );
    fflush( stdout );

    x509_crt_init( &srvcert );

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

    pk_init( &pkey );
    ret =  pk_parse_key( &pkey, (const unsigned char *) test_srv_key,
                         strlen( test_srv_key ), NULL, 0 );
    if( ret != 0 )
    {
        polarssl_printf( " failed\n  !  pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    base_info.ca_chain = srvcert.next;
    base_info.server_cert = &srvcert;
    base_info.server_key = &pkey;

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

reset:
#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        polarssl_strerror( ret, error_buf, 100 );
        polarssl_printf( "  [ main ]  Last error was: -0x%04x - %s\n", -ret, error_buf );
    }
#endif

    /*
     * 3. Wait until a client connects
     */
    client_fd = -1;

    polarssl_printf( "  [ main ]  Waiting for a remote connection\n" );

    if( ( ret = net_accept( listen_fd, &client_fd, NULL ) ) != 0 )
    {
        polarssl_printf( "  [ main ] failed: net_accept returned -0x%04x\n", ret );
        goto exit;
    }

    polarssl_printf( "  [ main ]  ok\n" );
    polarssl_printf( "  [ main ]  Creating a new thread\n" );

    if( ( ret = thread_create( client_fd ) ) != 0 )
    {
        polarssl_printf( "  [ main ]  failed: thread_create returned %d\n", ret );
        net_close( client_fd );
        goto reset;
    }

    ret = 0;
    goto reset;

exit:
    x509_crt_free( &srvcert );
    pk_free( &pkey );
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_free( &cache );
#endif
    entropy_free( &entropy );

    polarssl_mutex_free( &debug_mutex );

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
    memory_buffer_alloc_free();
#endif

#if defined(_WIN32)
    polarssl_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}

#endif /* POLARSSL_BIGNUM_C && POLARSSL_CERTS_C && POLARSSL_ENTROPY_C &&
          POLARSSL_SSL_TLS_C && POLARSSL_SSL_SRV_C && POLARSSL_NET_C &&
          POLARSSL_RSA_C && POLARSSL_CTR_DRBG_C && POLARSSL_THREADING_C &&
          POLARSSL_THREADING_PTHREAD */
