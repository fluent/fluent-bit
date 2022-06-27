/*
 *  Common source code for SSL test programs. This file is included by
 *  both ssl_client2.c and ssl_server2.c and is intended for source
 *  code that is textually identical in both programs, but that cannot be
 *  compiled separately because it refers to types or macros that are
 *  different in the two programs, or because it would have an incomplete
 *  type.
 *
 *  This file is meant to be #include'd and cannot be compiled separately.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#if defined(MBEDTLS_SSL_EXPORT_KEYS)
int eap_tls_key_derivation( void *p_expkey,
                            const unsigned char *ms,
                            const unsigned char *kb,
                            size_t maclen,
                            size_t keylen,
                            size_t ivlen,
                            const unsigned char client_random[32],
                            const unsigned char server_random[32],
                            mbedtls_tls_prf_types tls_prf_type )
{
    eap_tls_keys *keys = (eap_tls_keys *)p_expkey;

    ( ( void ) kb );
    memcpy( keys->master_secret, ms, sizeof( keys->master_secret ) );
    memcpy( keys->randbytes, client_random, 32 );
    memcpy( keys->randbytes + 32, server_random, 32 );
    keys->tls_prf_type = tls_prf_type;

    if( opt.debug_level > 2 )
    {
        mbedtls_printf("exported maclen is %u\n", (unsigned)maclen);
        mbedtls_printf("exported keylen is %u\n", (unsigned)keylen);
        mbedtls_printf("exported ivlen is %u\n", (unsigned)ivlen);
    }
    return( 0 );
}

int nss_keylog_export( void *p_expkey,
                       const unsigned char *ms,
                       const unsigned char *kb,
                       size_t maclen,
                       size_t keylen,
                       size_t ivlen,
                       const unsigned char client_random[32],
                       const unsigned char server_random[32],
                       mbedtls_tls_prf_types tls_prf_type )
{
    char nss_keylog_line[ 200 ];
    size_t const client_random_len = 32;
    size_t const master_secret_len = 48;
    size_t len = 0;
    size_t j;
    int ret = 0;

    ((void) p_expkey);
    ((void) kb);
    ((void) maclen);
    ((void) keylen);
    ((void) ivlen);
    ((void) server_random);
    ((void) tls_prf_type);

    len += sprintf( nss_keylog_line + len,
                    "%s", "CLIENT_RANDOM " );

    for( j = 0; j < client_random_len; j++ )
    {
        len += sprintf( nss_keylog_line + len,
                        "%02x", client_random[j] );
    }

    len += sprintf( nss_keylog_line + len, " " );

    for( j = 0; j < master_secret_len; j++ )
    {
        len += sprintf( nss_keylog_line + len,
                        "%02x", ms[j] );
    }

    len += sprintf( nss_keylog_line + len, "\n" );
    nss_keylog_line[ len ] = '\0';

    mbedtls_printf( "\n" );
    mbedtls_printf( "---------------- NSS KEYLOG -----------------\n" );
    mbedtls_printf( "%s", nss_keylog_line );
    mbedtls_printf( "---------------------------------------------\n" );

    if( opt.nss_keylog_file != NULL )
    {
        FILE *f;

        if( ( f = fopen( opt.nss_keylog_file, "a" ) ) == NULL )
        {
            ret = -1;
            goto exit;
        }

        if( fwrite( nss_keylog_line, 1, len, f ) != len )
        {
            ret = -1;
            fclose( f );
            goto exit;
        }

        fclose( f );
    }

exit:
    mbedtls_platform_zeroize( nss_keylog_line,
                              sizeof( nss_keylog_line ) );
    return( ret );
}

#if defined( MBEDTLS_SSL_DTLS_SRTP )
int dtls_srtp_key_derivation( void *p_expkey,
                              const unsigned char *ms,
                              const unsigned char *kb,
                              size_t maclen,
                              size_t keylen,
                              size_t ivlen,
                              const unsigned char client_random[32],
                              const unsigned char server_random[32],
                              mbedtls_tls_prf_types tls_prf_type )
{
    dtls_srtp_keys *keys = (dtls_srtp_keys *)p_expkey;

    ( ( void ) kb );
    memcpy( keys->master_secret, ms, sizeof( keys->master_secret ) );
    memcpy( keys->randbytes, client_random, 32 );
    memcpy( keys->randbytes + 32, server_random, 32 );
    keys->tls_prf_type = tls_prf_type;

    if( opt.debug_level > 2 )
    {
        mbedtls_printf( "exported maclen is %u\n", (unsigned) maclen );
        mbedtls_printf( "exported keylen is %u\n", (unsigned) keylen );
        mbedtls_printf( "exported ivlen is %u\n", (unsigned) ivlen );
    }
    return( 0 );
}
#endif /* MBEDTLS_SSL_DTLS_SRTP */

#endif /* MBEDTLS_SSL_EXPORT_KEYS */

#if defined(MBEDTLS_SSL_RECORD_CHECKING)
int ssl_check_record( mbedtls_ssl_context const *ssl,
                      unsigned char const *buf, size_t len )
{
    int my_ret = 0, ret_cr1, ret_cr2;
    unsigned char *tmp_buf;

    /* Record checking may modify the input buffer,
     * so make a copy. */
    tmp_buf = mbedtls_calloc( 1, len );
    if( tmp_buf == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    memcpy( tmp_buf, buf, len );

    ret_cr1 = mbedtls_ssl_check_record( ssl, tmp_buf, len );
    if( ret_cr1 != MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE )
    {
        /* Test-only: Make sure that mbedtls_ssl_check_record()
         *            doesn't alter state. */
        memcpy( tmp_buf, buf, len ); /* Restore buffer */
        ret_cr2 = mbedtls_ssl_check_record( ssl, tmp_buf, len );
        if( ret_cr2 != ret_cr1 )
        {
            mbedtls_printf( "mbedtls_ssl_check_record() returned inconsistent results.\n" );
            my_ret = -1;
            goto cleanup;
        }

        switch( ret_cr1 )
        {
            case 0:
                break;

            case MBEDTLS_ERR_SSL_INVALID_RECORD:
                if( opt.debug_level > 1 )
                    mbedtls_printf( "mbedtls_ssl_check_record() detected invalid record.\n" );
                break;

            case MBEDTLS_ERR_SSL_INVALID_MAC:
                if( opt.debug_level > 1 )
                    mbedtls_printf( "mbedtls_ssl_check_record() detected unauthentic record.\n" );
                break;

            case MBEDTLS_ERR_SSL_UNEXPECTED_RECORD:
                if( opt.debug_level > 1 )
                    mbedtls_printf( "mbedtls_ssl_check_record() detected unexpected record.\n" );
                break;

            default:
                mbedtls_printf( "mbedtls_ssl_check_record() failed fatally with -%#04x.\n", (unsigned int) -ret_cr1 );
                my_ret = -1;
                goto cleanup;
        }

        /* Regardless of the outcome, forward the record to the stack. */
    }

cleanup:
    mbedtls_free( tmp_buf );

    return( my_ret );
}
#endif /* MBEDTLS_SSL_RECORD_CHECKING */

int recv_cb( void *ctx, unsigned char *buf, size_t len )
{
    io_ctx_t *io_ctx = (io_ctx_t*) ctx;
    size_t recv_len;
    int ret;

    if( opt.nbio == 2 )
        ret = delayed_recv( io_ctx->net, buf, len );
    else
        ret = mbedtls_net_recv( io_ctx->net, buf, len );
    if( ret < 0 )
        return( ret );
    recv_len = (size_t) ret;

    if( opt.transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        /* Here's the place to do any datagram/record checking
         * in between receiving the packet from the underlying
         * transport and passing it on to the TLS stack. */
#if defined(MBEDTLS_SSL_RECORD_CHECKING)
        if( ssl_check_record( io_ctx->ssl, buf, recv_len ) != 0 )
            return( -1 );
#endif /* MBEDTLS_SSL_RECORD_CHECKING */
    }

    return( (int) recv_len );
}

int recv_timeout_cb( void *ctx, unsigned char *buf, size_t len,
                     uint32_t timeout )
{
    io_ctx_t *io_ctx = (io_ctx_t*) ctx;
    int ret;
    size_t recv_len;

    ret = mbedtls_net_recv_timeout( io_ctx->net, buf, len, timeout );
    if( ret < 0 )
        return( ret );
    recv_len = (size_t) ret;

    if( opt.transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        /* Here's the place to do any datagram/record checking
         * in between receiving the packet from the underlying
         * transport and passing it on to the TLS stack. */
#if defined(MBEDTLS_SSL_RECORD_CHECKING)
        if( ssl_check_record( io_ctx->ssl, buf, recv_len ) != 0 )
            return( -1 );
#endif /* MBEDTLS_SSL_RECORD_CHECKING */
    }

    return( (int) recv_len );
}

int send_cb( void *ctx, unsigned char const *buf, size_t len )
{
    io_ctx_t *io_ctx = (io_ctx_t*) ctx;

    if( opt.nbio == 2 )
        return( delayed_send( io_ctx->net, buf, len ) );

    return( mbedtls_net_send( io_ctx->net, buf, len ) );
}

#if defined(MBEDTLS_X509_CRT_PARSE_C)
int ssl_sig_hashes_for_test[] = {
#if defined(MBEDTLS_SHA512_C)
    MBEDTLS_MD_SHA512,
    MBEDTLS_MD_SHA384,
#endif
#if defined(MBEDTLS_SHA256_C)
    MBEDTLS_MD_SHA256,
    MBEDTLS_MD_SHA224,
#endif
#if defined(MBEDTLS_SHA1_C)
    /* Allow SHA-1 as we use it extensively in tests. */
    MBEDTLS_MD_SHA1,
#endif
    MBEDTLS_MD_NONE
};
#endif /* MBEDTLS_X509_CRT_PARSE_C */
