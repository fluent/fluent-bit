/*
 *  SSL client with certificate authentication
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

#if !defined(POLARSSL_ENTROPY_C) ||  \
    !defined(POLARSSL_SSL_TLS_C) || !defined(POLARSSL_SSL_CLI_C) || \
    !defined(POLARSSL_NET_C) || !defined(POLARSSL_CTR_DRBG_C)
#include <stdio.h>
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_ENTROPY_C and/or "
           "POLARSSL_SSL_TLS_C and/or POLARSSL_SSL_CLI_C and/or "
           "POLARSSL_NET_C and/or POLARSSL_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/error.h"
#include "polarssl/debug.h"

#if defined(POLARSSL_TIMING_C)
#include "polarssl/timing.h"
#endif

#if defined(_MSC_VER) && !defined(EFIX64) && !defined(EFI32)
#if !defined  snprintf
#define  snprintf  _snprintf
#endif
#endif

#define DFL_SERVER_NAME         "localhost"
#define DFL_SERVER_ADDR         NULL
#define DFL_SERVER_PORT         4433
#define DFL_REQUEST_PAGE        "/"
#define DFL_REQUEST_SIZE        -1
#define DFL_DEBUG_LEVEL         0
#define DFL_NBIO                0
#define DFL_CA_FILE             ""
#define DFL_CA_PATH             ""
#define DFL_CRT_FILE            ""
#define DFL_KEY_FILE            ""
#define DFL_PSK                 ""
#define DFL_PSK_IDENTITY        "Client_identity"
#define DFL_FORCE_CIPHER        0
#define DFL_RENEGOTIATION       SSL_RENEGOTIATION_DISABLED
#define DFL_ALLOW_LEGACY        -2
#define DFL_RENEGOTIATE         0
#define DFL_EXCHANGES           1
#define DFL_MIN_VERSION         SSL_MINOR_VERSION_1
#define DFL_MAX_VERSION         -1
#define DFL_ARC4                SSL_ARC4_DISABLED
#define DFL_AUTH_MODE           SSL_VERIFY_REQUIRED
#define DFL_MFL_CODE            SSL_MAX_FRAG_LEN_NONE
#define DFL_TRUNC_HMAC          -1
#define DFL_RECSPLIT            -1
#define DFL_RECONNECT           0
#define DFL_RECO_DELAY          0
#define DFL_TICKETS             SSL_SESSION_TICKETS_ENABLED
#define DFL_ALPN_STRING         NULL
#define DFL_FALLBACK            -1
#define DFL_EXTENDED_MS         -1
#define DFL_ETM                 -1

#define GET_REQUEST "GET %s HTTP/1.0\r\nExtra-header: "
#define GET_REQUEST_END "\r\n\r\n"

/*
 * global options
 */
struct options
{
    const char *server_name;    /* hostname of the server (client only)     */
    const char *server_addr;    /* address of the server (client only)      */
    int server_port;            /* port on which the ssl service runs       */
    int debug_level;            /* level of debugging                       */
    int nbio;                   /* should I/O be blocking?                  */
    const char *request_page;   /* page on server to request                */
    int request_size;           /* pad request with header to requested size */
    const char *ca_file;        /* the file with the CA certificate(s)      */
    const char *ca_path;        /* the path with the CA certificate(s) reside */
    const char *crt_file;       /* the file with the client certificate     */
    const char *key_file;       /* the file with the client key             */
    const char *psk;            /* the pre-shared key                       */
    const char *psk_identity;   /* the pre-shared key identity              */
    int force_ciphersuite[2];   /* protocol/ciphersuite to use, or all      */
    int renegotiation;          /* enable / disable renegotiation           */
    int allow_legacy;           /* allow legacy renegotiation               */
    int renegotiate;            /* attempt renegotiation?                   */
    int renego_delay;           /* delay before enforcing renegotiation     */
    int exchanges;              /* number of data exchanges                 */
    int min_version;            /* minimum protocol version accepted        */
    int max_version;            /* maximum protocol version accepted        */
    int arc4;                   /* flag for arc4 suites support             */
    int auth_mode;              /* verify mode for connection               */
    unsigned char mfl_code;     /* code for maximum fragment length         */
    int trunc_hmac;             /* negotiate truncated hmac or not          */
    int recsplit;               /* enable record splitting?                 */
    int reconnect;              /* attempt to resume session                */
    int reco_delay;             /* delay in seconds before resuming session */
    int tickets;                /* enable / disable session tickets         */
    const char *alpn_string;    /* ALPN supported protocols                 */
    int fallback;               /* is this a fallback connection?           */
    int extended_ms;            /* negotiate extended master secret?        */
    int etm;                    /* negotiate encrypt then mac?              */
} opt;

static void my_debug( void *ctx, int level, const char *str )
{
    ((void) level);

    polarssl_fprintf( (FILE *) ctx, "%s", str );
    fflush(  (FILE *) ctx  );
}

/*
 * Test recv/send functions that make sure each try returns
 * WANT_READ/WANT_WRITE at least once before sucesseding
 */
static int my_recv( void *ctx, unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( POLARSSL_ERR_NET_WANT_READ );
    }

    ret = net_recv( ctx, buf, len );
    if( ret != POLARSSL_ERR_NET_WANT_READ )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

static int my_send( void *ctx, const unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( POLARSSL_ERR_NET_WANT_WRITE );
    }

    ret = net_send( ctx, buf, len );
    if( ret != POLARSSL_ERR_NET_WANT_WRITE )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

#if defined(POLARSSL_X509_CRT_PARSE_C)
/*
 * Enabled if debug_level > 1 in code below
 */
static int my_verify( void *data, x509_crt *crt, int depth, int *flags )
{
    char buf[1024];
    ((void) data);

    polarssl_printf( "\nVerify requested for (Depth %d):\n", depth );
    x509_crt_info( buf, sizeof( buf ) - 1, "", crt );
    polarssl_printf( "%s", buf );

    if( ( (*flags) & BADCERT_EXPIRED ) != 0 )
        polarssl_printf( "  ! server certificate has expired\n" );

    if( ( (*flags) & BADCERT_REVOKED ) != 0 )
        polarssl_printf( "  ! server certificate has been revoked\n" );

    if( ( (*flags) & BADCERT_CN_MISMATCH ) != 0 )
        polarssl_printf( "  ! CN mismatch\n" );

    if( ( (*flags) & BADCERT_NOT_TRUSTED ) != 0 )
        polarssl_printf( "  ! self-signed or not signed by a trusted CA\n" );

    if( ( (*flags) & BADCRL_NOT_TRUSTED ) != 0 )
        polarssl_printf( "  ! CRL not trusted\n" );

    if( ( (*flags) & BADCRL_EXPIRED ) != 0 )
        polarssl_printf( "  ! CRL expired\n" );

    if( ( (*flags) & BADCERT_OTHER ) != 0 )
        polarssl_printf( "  ! other (unknown) flag\n" );

    if ( ( *flags ) == 0 )
        polarssl_printf( "  This certificate has no flags\n" );

    return( 0 );
}
#endif /* POLARSSL_X509_CRT_PARSE_C */

#if defined(POLARSSL_X509_CRT_PARSE_C)
#if defined(POLARSSL_FS_IO)
#define USAGE_IO \
    "    ca_file=%%s          The single file containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (pre-loaded)\n" \
    "    ca_path=%%s          The path containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (pre-loaded) (overrides ca_file)\n" \
    "    crt_file=%%s         Your own cert and chain (in bottom to top order, top may be omitted)\n" \
    "                        default: \"\" (pre-loaded)\n" \
    "    key_file=%%s         default: \"\" (pre-loaded)\n"
#else
#define USAGE_IO \
    "    No file operations available (POLARSSL_FS_IO not defined)\n"
#endif /* POLARSSL_FS_IO */
#else
#define USAGE_IO ""
#endif /* POLARSSL_X509_CRT_PARSE_C */

#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
#define USAGE_PSK                                                   \
    "    psk=%%s              default: \"\" (in hex, without 0x)\n" \
    "    psk_identity=%%s     default: \"Client_identity\"\n"
#else
#define USAGE_PSK ""
#endif /* POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(POLARSSL_SSL_SESSION_TICKETS)
#define USAGE_TICKETS                                       \
    "    tickets=%%d          default: 1 (enabled)\n"
#else
#define USAGE_TICKETS ""
#endif /* POLARSSL_SSL_SESSION_TICKETS */

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
#define USAGE_TRUNC_HMAC                                    \
    "    trunc_hmac=%%d       default: library default\n"
#else
#define USAGE_TRUNC_HMAC ""
#endif /* POLARSSL_SSL_TRUNCATED_HMAC */

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
#define USAGE_MAX_FRAG_LEN                                      \
    "    max_frag_len=%%d     default: 16384 (tls default)\n"   \
    "                        options: 512, 1024, 2048, 4096\n"
#else
#define USAGE_MAX_FRAG_LEN ""
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

#if defined(POLARSSL_SSL_CBC_RECORD_SPLITTING)
#define USAGE_RECSPLIT \
    "    recplit=%%d          default: (library default)\n"
#else
#define USAGE_RECSPLIT
#endif

#if defined(POLARSSL_TIMING_C)
#define USAGE_TIME \
    "    reco_delay=%%d       default: 0 seconds\n"
#else
#define USAGE_TIME ""
#endif /* POLARSSL_TIMING_C */

#if defined(POLARSSL_SSL_ALPN)
#define USAGE_ALPN \
    "    alpn=%%s             default: \"\" (disabled)\n"   \
    "                        example: spdy/1,http/1.1\n"
#else
#define USAGE_ALPN ""
#endif /* POLARSSL_SSL_ALPN */

#if defined(POLARSSL_SSL_FALLBACK_SCSV)
#define USAGE_FALLBACK \
    "    fallback=0/1        default: (library default: off)\n"
#else
#define USAGE_FALLBACK ""
#endif

#if defined(POLARSSL_SSL_EXTENDED_MASTER_SECRET)
#define USAGE_EMS \
    "    extended_ms=0/1     default: (library default: on)\n"
#else
#define USAGE_EMS ""
#endif

#if defined(POLARSSL_SSL_ENCRYPT_THEN_MAC)
#define USAGE_ETM \
    "    etm=0/1             default: (library default: on)\n"
#else
#define USAGE_ETM ""
#endif

#if defined(POLARSSL_SSL_RENEGOTIATION)
#define USAGE_RENEGO \
    "    renegotiation=%%d    default: 0 (disabled)\n"      \
    "    renegotiate=%%d      default: 0 (disabled)\n"
#else
#define USAGE_RENEGO ""
#endif

#define USAGE \
    "\n usage: ssl_client2 param=<>...\n"                   \
    "\n acceptable parameters:\n"                           \
    "    server_name=%%s      default: localhost\n"         \
    "    server_addr=%%s      default: given by name\n"     \
    "    server_port=%%d      default: 4433\n"              \
    "    request_page=%%s     default: \".\"\n"             \
    "    request_size=%%d     default: about 34 (basic request)\n" \
    "                        (minimum: 0, max: 16384)\n" \
    "    debug_level=%%d      default: 0 (disabled)\n"      \
    "    nbio=%%d             default: 0 (blocking I/O)\n"  \
    "                        options: 1 (non-blocking), 2 (added delays)\n" \
    "\n"                                                    \
    "    auth_mode=%%s        default: \"required\"\n"      \
    "                        options: none, optional, required\n" \
    USAGE_IO                                                \
    "\n"                                                    \
    USAGE_PSK                                               \
    "\n"                                                    \
    "    allow_legacy=%%d     default: (library default: no)\n"      \
    USAGE_RENEGO                                            \
    "    exchanges=%%d        default: 1\n"                 \
    "    reconnect=%%d        default: 0 (disabled)\n"      \
    USAGE_TIME                                              \
    USAGE_TICKETS                                           \
    USAGE_MAX_FRAG_LEN                                      \
    USAGE_TRUNC_HMAC                                        \
    USAGE_ALPN                                              \
    USAGE_FALLBACK                                          \
    USAGE_EMS                                               \
    USAGE_ETM                                               \
    USAGE_RECSPLIT                                          \
    "\n"                                                    \
    "    min_version=%%s      default: \"\" (ssl3)\n"       \
    "    max_version=%%s      default: \"\" (tls1_2)\n"     \
    "    arc4=%%d             default: 0 (disabled)\n"      \
    "    force_version=%%s    default: \"\" (none)\n"       \
    "                        options: ssl3, tls1, tls1_1, tls1_2\n" \
    "\n"                                                    \
    "    force_ciphersuite=<name>    default: all enabled\n"\
    " acceptable ciphersuite names:\n"

int main( int argc, char *argv[] )
{
    int ret = 0, len, tail_len, server_fd, i, written, frags;
    unsigned char buf[SSL_MAX_CONTENT_LEN + 1];
#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
    unsigned char psk[POLARSSL_PSK_MAX_LEN];
    size_t psk_len = 0;
#endif
#if defined(POLARSSL_SSL_ALPN)
    const char *alpn_list[10];
#endif
    const char *pers = "ssl_client2";

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;
    ssl_session saved_session;
#if defined(POLARSSL_X509_CRT_PARSE_C)
    x509_crt cacert;
    x509_crt clicert;
    pk_context pkey;
#endif
    char *p, *q;
    const int *list;

    /*
     * Make sure memory references are valid.
     */
    server_fd = 0;
    memset( &ssl, 0, sizeof( ssl_context ) );
    memset( &saved_session, 0, sizeof( ssl_session ) );
#if defined(POLARSSL_X509_CRT_PARSE_C)
    x509_crt_init( &cacert );
    x509_crt_init( &clicert );
    pk_init( &pkey );
#endif
#if defined(POLARSSL_SSL_ALPN)
    memset( (void * ) alpn_list, 0, sizeof( alpn_list ) );
#endif

    if( argc == 0 )
    {
    usage:
        if( ret == 0 )
            ret = 1;

        polarssl_printf( USAGE );

        list = ssl_list_ciphersuites();
        while( *list )
        {
            polarssl_printf(" %-42s", ssl_get_ciphersuite_name( *list ) );
            list++;
            if( !*list )
                break;
            polarssl_printf(" %s\n", ssl_get_ciphersuite_name( *list ) );
            list++;
        }
        polarssl_printf("\n");
        goto exit;
    }

    opt.server_name         = DFL_SERVER_NAME;
    opt.server_addr         = DFL_SERVER_ADDR;
    opt.server_port         = DFL_SERVER_PORT;
    opt.debug_level         = DFL_DEBUG_LEVEL;
    opt.nbio                = DFL_NBIO;
    opt.request_page        = DFL_REQUEST_PAGE;
    opt.request_size        = DFL_REQUEST_SIZE;
    opt.ca_file             = DFL_CA_FILE;
    opt.ca_path             = DFL_CA_PATH;
    opt.crt_file            = DFL_CRT_FILE;
    opt.key_file            = DFL_KEY_FILE;
    opt.psk                 = DFL_PSK;
    opt.psk_identity        = DFL_PSK_IDENTITY;
    opt.force_ciphersuite[0]= DFL_FORCE_CIPHER;
    opt.renegotiation       = DFL_RENEGOTIATION;
    opt.allow_legacy        = DFL_ALLOW_LEGACY;
    opt.renegotiate         = DFL_RENEGOTIATE;
    opt.exchanges           = DFL_EXCHANGES;
    opt.min_version         = DFL_MIN_VERSION;
    opt.max_version         = DFL_MAX_VERSION;
    opt.arc4                = DFL_ARC4;
    opt.auth_mode           = DFL_AUTH_MODE;
    opt.mfl_code            = DFL_MFL_CODE;
    opt.trunc_hmac          = DFL_TRUNC_HMAC;
    opt.recsplit            = DFL_RECSPLIT;
    opt.reconnect           = DFL_RECONNECT;
    opt.reco_delay          = DFL_RECO_DELAY;
    opt.tickets             = DFL_TICKETS;
    opt.alpn_string         = DFL_ALPN_STRING;
    opt.fallback            = DFL_FALLBACK;
    opt.extended_ms         = DFL_EXTENDED_MS;
    opt.etm                 = DFL_ETM;

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "server_name" ) == 0 )
            opt.server_name = q;
        else if( strcmp( p, "server_addr" ) == 0 )
            opt.server_addr = q;
        else if( strcmp( p, "server_port" ) == 0 )
        {
            opt.server_port = atoi( q );
            if( opt.server_port < 1 || opt.server_port > 65535 )
                goto usage;
        }
        else if( strcmp( p, "debug_level" ) == 0 )
        {
            opt.debug_level = atoi( q );
            if( opt.debug_level < 0 || opt.debug_level > 65535 )
                goto usage;
        }
        else if( strcmp( p, "nbio" ) == 0 )
        {
            opt.nbio = atoi( q );
            if( opt.nbio < 0 || opt.nbio > 2 )
                goto usage;
        }
        else if( strcmp( p, "request_page" ) == 0 )
            opt.request_page = q;
        else if( strcmp( p, "request_size" ) == 0 )
        {
            opt.request_size = atoi( q );
            if( opt.request_size < 0 || opt.request_size > SSL_MAX_CONTENT_LEN )
                goto usage;
        }
        else if( strcmp( p, "ca_file" ) == 0 )
            opt.ca_file = q;
        else if( strcmp( p, "ca_path" ) == 0 )
            opt.ca_path = q;
        else if( strcmp( p, "crt_file" ) == 0 )
            opt.crt_file = q;
        else if( strcmp( p, "key_file" ) == 0 )
            opt.key_file = q;
        else if( strcmp( p, "psk" ) == 0 )
            opt.psk = q;
        else if( strcmp( p, "psk_identity" ) == 0 )
            opt.psk_identity = q;
        else if( strcmp( p, "force_ciphersuite" ) == 0 )
        {
            opt.force_ciphersuite[0] = ssl_get_ciphersuite_id( q );

            if( opt.force_ciphersuite[0] == 0 )
            {
                ret = 2;
                goto usage;
            }
            opt.force_ciphersuite[1] = 0;
        }
        else if( strcmp( p, "renegotiation" ) == 0 )
        {
            opt.renegotiation = (atoi( q )) ? SSL_RENEGOTIATION_ENABLED :
                                              SSL_RENEGOTIATION_DISABLED;
        }
        else if( strcmp( p, "allow_legacy" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case -1: opt.allow_legacy = SSL_LEGACY_BREAK_HANDSHAKE; break;
                case 0:  opt.allow_legacy = SSL_LEGACY_NO_RENEGOTIATION; break;
                case 1:  opt.allow_legacy = SSL_LEGACY_ALLOW_RENEGOTIATION; break;
                default: goto usage;
            }
        }
        else if( strcmp( p, "renegotiate" ) == 0 )
        {
            opt.renegotiate = atoi( q );
            if( opt.renegotiate < 0 || opt.renegotiate > 1 )
                goto usage;
        }
        else if( strcmp( p, "exchanges" ) == 0 )
        {
            opt.exchanges = atoi( q );
            if( opt.exchanges < 1 )
                goto usage;
        }
        else if( strcmp( p, "reconnect" ) == 0 )
        {
            opt.reconnect = atoi( q );
            if( opt.reconnect < 0 || opt.reconnect > 2 )
                goto usage;
        }
        else if( strcmp( p, "reco_delay" ) == 0 )
        {
            opt.reco_delay = atoi( q );
            if( opt.reco_delay < 0 )
                goto usage;
        }
        else if( strcmp( p, "tickets" ) == 0 )
        {
            opt.tickets = atoi( q );
            if( opt.tickets < 0 || opt.tickets > 2 )
                goto usage;
        }
        else if( strcmp( p, "alpn" ) == 0 )
        {
            opt.alpn_string = q;
        }
        else if( strcmp( p, "fallback" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case 0: opt.fallback = SSL_IS_NOT_FALLBACK; break;
                case 1: opt.fallback = SSL_IS_FALLBACK; break;
                default: goto usage;
            }
        }
        else if( strcmp( p, "extended_ms" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case 0: opt.extended_ms = SSL_EXTENDED_MS_DISABLED; break;
                case 1: opt.extended_ms = SSL_EXTENDED_MS_ENABLED; break;
                default: goto usage;
            }
        }
        else if( strcmp( p, "etm" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case 0: opt.etm = SSL_ETM_DISABLED; break;
                case 1: opt.etm = SSL_ETM_ENABLED; break;
                default: goto usage;
            }
        }
        else if( strcmp( p, "min_version" ) == 0 )
        {
            if( strcmp( q, "ssl3" ) == 0 )
                opt.min_version = SSL_MINOR_VERSION_0;
            else if( strcmp( q, "tls1" ) == 0 )
                opt.min_version = SSL_MINOR_VERSION_1;
            else if( strcmp( q, "tls1_1" ) == 0 )
                opt.min_version = SSL_MINOR_VERSION_2;
            else if( strcmp( q, "tls1_2" ) == 0 )
                opt.min_version = SSL_MINOR_VERSION_3;
            else
                goto usage;
        }
        else if( strcmp( p, "max_version" ) == 0 )
        {
            if( strcmp( q, "ssl3" ) == 0 )
                opt.max_version = SSL_MINOR_VERSION_0;
            else if( strcmp( q, "tls1" ) == 0 )
                opt.max_version = SSL_MINOR_VERSION_1;
            else if( strcmp( q, "tls1_1" ) == 0 )
                opt.max_version = SSL_MINOR_VERSION_2;
            else if( strcmp( q, "tls1_2" ) == 0 )
                opt.max_version = SSL_MINOR_VERSION_3;
            else
                goto usage;
        }
        else if( strcmp( p, "arc4" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case 0:     opt.arc4 = SSL_ARC4_DISABLED;   break;
                case 1:     opt.arc4 = SSL_ARC4_ENABLED;    break;
                default:    goto usage;
            }
        }
        else if( strcmp( p, "force_version" ) == 0 )
        {
            if( strcmp( q, "ssl3" ) == 0 )
            {
                opt.min_version = SSL_MINOR_VERSION_0;
                opt.max_version = SSL_MINOR_VERSION_0;
            }
            else if( strcmp( q, "tls1" ) == 0 )
            {
                opt.min_version = SSL_MINOR_VERSION_1;
                opt.max_version = SSL_MINOR_VERSION_1;
            }
            else if( strcmp( q, "tls1_1" ) == 0 )
            {
                opt.min_version = SSL_MINOR_VERSION_2;
                opt.max_version = SSL_MINOR_VERSION_2;
            }
            else if( strcmp( q, "tls1_2" ) == 0 )
            {
                opt.min_version = SSL_MINOR_VERSION_3;
                opt.max_version = SSL_MINOR_VERSION_3;
            }
            else
                goto usage;
        }
        else if( strcmp( p, "auth_mode" ) == 0 )
        {
            if( strcmp( q, "none" ) == 0 )
                opt.auth_mode = SSL_VERIFY_NONE;
            else if( strcmp( q, "optional" ) == 0 )
                opt.auth_mode = SSL_VERIFY_OPTIONAL;
            else if( strcmp( q, "required" ) == 0 )
                opt.auth_mode = SSL_VERIFY_REQUIRED;
            else
                goto usage;
        }
        else if( strcmp( p, "max_frag_len" ) == 0 )
        {
            if( strcmp( q, "512" ) == 0 )
                opt.mfl_code = SSL_MAX_FRAG_LEN_512;
            else if( strcmp( q, "1024" ) == 0 )
                opt.mfl_code = SSL_MAX_FRAG_LEN_1024;
            else if( strcmp( q, "2048" ) == 0 )
                opt.mfl_code = SSL_MAX_FRAG_LEN_2048;
            else if( strcmp( q, "4096" ) == 0 )
                opt.mfl_code = SSL_MAX_FRAG_LEN_4096;
            else
                goto usage;
        }
        else if( strcmp( p, "trunc_hmac" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case 0: opt.trunc_hmac = SSL_TRUNC_HMAC_DISABLED; break;
                case 1: opt.trunc_hmac = SSL_TRUNC_HMAC_ENABLED; break;
                default: goto usage;
            }
        }
        else if( strcmp( p, "recsplit" ) == 0 )
        {
            opt.recsplit = atoi( q );
            if( opt.recsplit < 0 || opt.recsplit > 1 )
                goto usage;
        }
        else
            goto usage;
    }

#if defined(POLARSSL_DEBUG_C)
    debug_set_threshold( opt.debug_level );
#endif

    if( opt.force_ciphersuite[0] > 0 )
    {
        const ssl_ciphersuite_t *ciphersuite_info;
        ciphersuite_info = ssl_ciphersuite_from_id( opt.force_ciphersuite[0] );

        if( opt.max_version != -1 &&
            ciphersuite_info->min_minor_ver > opt.max_version )
        {
            polarssl_printf("forced ciphersuite not allowed with this protocol version\n");
            ret = 2;
            goto usage;
        }
        if( opt.min_version != -1 &&
            ciphersuite_info->max_minor_ver < opt.min_version )
        {
            polarssl_printf("forced ciphersuite not allowed with this protocol version\n");
            ret = 2;
            goto usage;
        }
        if( opt.max_version > ciphersuite_info->max_minor_ver )
            opt.max_version = ciphersuite_info->max_minor_ver;
        if( opt.min_version < ciphersuite_info->min_minor_ver )
            opt.min_version = ciphersuite_info->min_minor_ver;
    }

#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
    /*
     * Unhexify the pre-shared key if any is given
     */
    if( strlen( opt.psk ) )
    {
        unsigned char c;
        size_t j;

        if( strlen( opt.psk ) % 2 != 0 )
        {
            polarssl_printf("pre-shared key not valid hex\n");
            goto exit;
        }

        psk_len = strlen( opt.psk ) / 2;

        for( j = 0; j < strlen( opt.psk ); j += 2 )
        {
            c = opt.psk[j];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                polarssl_printf("pre-shared key not valid hex\n");
                goto exit;
            }
            psk[ j / 2 ] = c << 4;

            c = opt.psk[j + 1];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                polarssl_printf("pre-shared key not valid hex\n");
                goto exit;
            }
            psk[ j / 2 ] |= c;
        }
    }
#endif /* POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(POLARSSL_SSL_ALPN)
    if( opt.alpn_string != NULL )
    {
        p = (char *) opt.alpn_string;
        i = 0;

        /* Leave room for a final NULL in alpn_list */
        while( i < (int) sizeof alpn_list - 1 && *p != '\0' )
        {
            alpn_list[i++] = p;

            /* Terminate the current string and move on to next one */
            while( *p != ',' && *p != '\0' )
                p++;
            if( *p == ',' )
                *p++ = '\0';
        }
    }
#endif /* POLARSSL_SSL_ALPN */

    /*
     * 0. Initialize the RNG and the session data
     */
    polarssl_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ctr_drbg_init returned -0x%x\n", -ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

#if defined(POLARSSL_X509_CRT_PARSE_C)
    /*
     * 1.1. Load the trusted CA
     */
    polarssl_printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

#if defined(POLARSSL_FS_IO)
    if( strlen( opt.ca_path ) )
        if( strcmp( opt.ca_path, "none" ) == 0 )
            ret = 0;
        else
            ret = x509_crt_parse_path( &cacert, opt.ca_path );
    else if( strlen( opt.ca_file ) )
        if( strcmp( opt.ca_file, "none" ) == 0 )
            ret = 0;
        else
            ret = x509_crt_parse_file( &cacert, opt.ca_file );
    else
#endif
#if defined(POLARSSL_CERTS_C)
        ret = x509_crt_parse( &cacert, (const unsigned char *) test_ca_list,
                strlen( test_ca_list ) );
#else
    {
        ret = 1;
        polarssl_printf("POLARSSL_CERTS_C not defined.");
    }
#endif
    if( ret < 0 )
    {
        polarssl_printf( " failed\n  !  x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

    polarssl_printf( " ok (%d skipped)\n", ret );

    /*
     * 1.2. Load own certificate and private key
     *
     * (can be skipped if client authentication is not required)
     */
    polarssl_printf( "  . Loading the client cert. and key..." );
    fflush( stdout );

#if defined(POLARSSL_FS_IO)
    if( strlen( opt.crt_file ) )
        if( strcmp( opt.crt_file, "none" ) == 0 )
            ret = 0;
        else
            ret = x509_crt_parse_file( &clicert, opt.crt_file );
    else
#endif
#if defined(POLARSSL_CERTS_C)
        ret = x509_crt_parse( &clicert, (const unsigned char *) test_cli_crt,
                strlen( test_cli_crt ) );
#else
    {
        ret = 1;
        polarssl_printf("POLARSSL_CERTS_C not defined.");
    }
#endif
    if( ret != 0 )
    {
        polarssl_printf( " failed\n  !  x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

#if defined(POLARSSL_FS_IO)
    if( strlen( opt.key_file ) )
        if( strcmp( opt.key_file, "none" ) == 0 )
            ret = 0;
        else
            ret = pk_parse_keyfile( &pkey, opt.key_file, "" );
    else
#endif
#if defined(POLARSSL_CERTS_C)
        ret = pk_parse_key( &pkey, (const unsigned char *) test_cli_key,
                strlen( test_cli_key ), NULL, 0 );
#else
    {
        ret = 1;
        polarssl_printf("POLARSSL_CERTS_C not defined.");
    }
#endif
    if( ret != 0 )
    {
        polarssl_printf( " failed\n  !  pk_parse_key returned -0x%x\n\n", -ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );
#endif /* POLARSSL_X509_CRT_PARSE_C */

    /*
     * 2. Start the connection
     */
    if( opt.server_addr == NULL)
        opt.server_addr = opt.server_name;

    polarssl_printf( "  . Connecting to tcp/%s/%-4d...", opt.server_addr,
                                                opt.server_port );
    fflush( stdout );

    if( ( ret = net_connect( &server_fd, opt.server_addr,
                                         opt.server_port ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! net_connect returned -0x%x\n\n", -ret );
        goto exit;
    }

    if( opt.nbio > 0 )
        ret = net_set_nonblock( server_fd );
    else
        ret = net_set_block( server_fd );
    if( ret != 0 )
    {
        polarssl_printf( " failed\n  ! net_set_(non)block() returned -0x%x\n\n", -ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    /*
     * 3. Setup stuff
     */
    polarssl_printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );

    if( ( ret = ssl_init( &ssl ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_init returned -0x%x\n\n", -ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

#if defined(POLARSSL_X509_CRT_PARSE_C)
    if( opt.debug_level > 0 )
        ssl_set_verify( &ssl, my_verify, NULL );
#endif

    ssl_set_endpoint( &ssl, SSL_IS_CLIENT );
    ssl_set_authmode( &ssl, opt.auth_mode );

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
    if( ( ret = ssl_set_max_frag_len( &ssl, opt.mfl_code ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_set_max_frag_len returned %d\n\n", ret );
        goto exit;
    }
#endif

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
    if( opt.trunc_hmac != DFL_TRUNC_HMAC )
        ssl_set_truncated_hmac( &ssl, opt.trunc_hmac );
#endif

#if defined(POLARSSL_SSL_EXTENDED_MASTER_SECRET)
    if( opt.extended_ms != DFL_EXTENDED_MS )
        ssl_set_extended_master_secret( &ssl, opt.extended_ms );
#endif

#if defined(POLARSSL_SSL_ENCRYPT_THEN_MAC)
    if( opt.etm != DFL_ETM )
        ssl_set_encrypt_then_mac( &ssl, opt.etm );
#endif

#if defined(POLARSSL_SSL_CBC_RECORD_SPLITTING)
    if( opt.recsplit != DFL_RECSPLIT )
        ssl_set_cbc_record_splitting( &ssl, opt.recsplit
                                    ? SSL_CBC_RECORD_SPLITTING_ENABLED
                                    : SSL_CBC_RECORD_SPLITTING_DISABLED );
#endif

#if defined(POLARSSL_SSL_ALPN)
    if( opt.alpn_string != NULL )
        if( ( ret = ssl_set_alpn_protocols( &ssl, alpn_list ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! ssl_set_alpn_protocols returned %d\n\n", ret );
            goto exit;
        }
#endif

    ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );
    ssl_set_dbg( &ssl, my_debug, stdout );

    if( opt.nbio == 2 )
        ssl_set_bio( &ssl, my_recv, &server_fd, my_send, &server_fd );
    else
        ssl_set_bio( &ssl, net_recv, &server_fd, net_send, &server_fd );

#if defined(POLARSSL_SSL_SESSION_TICKETS)
    if( ( ret = ssl_set_session_tickets( &ssl, opt.tickets ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_set_session_tickets returned %d\n\n", ret );
        goto exit;
    }
#endif

    /* RC4 setting is redundant if we use only one ciphersuite */
    if( opt.force_ciphersuite[0] != DFL_FORCE_CIPHER )
        ssl_set_ciphersuites( &ssl, opt.force_ciphersuite );
    else
        ssl_set_arc4_support( &ssl, opt.arc4 );

    if( opt.allow_legacy != DFL_ALLOW_LEGACY )
        ssl_legacy_renegotiation( &ssl, opt.allow_legacy );
#if defined(POLARSSL_SSL_RENEGOTIATION)
    ssl_set_renegotiation( &ssl, opt.renegotiation );
#endif

#if defined(POLARSSL_X509_CRT_PARSE_C)
    if( strcmp( opt.ca_path, "none" ) != 0 &&
        strcmp( opt.ca_file, "none" ) != 0 )
    {
        ssl_set_ca_chain( &ssl, &cacert, NULL, opt.server_name );
    }
    if( strcmp( opt.crt_file, "none" ) != 0 &&
        strcmp( opt.key_file, "none" ) != 0 )
    {
        if( ( ret = ssl_set_own_cert( &ssl, &clicert, &pkey ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! ssl_set_own_cert returned %d\n\n", ret );
            goto exit;
        }
    }
#endif

#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
    if( ( ret = ssl_set_psk( &ssl, psk, psk_len,
                             (const unsigned char *) opt.psk_identity,
                             strlen( opt.psk_identity ) ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_set_psk returned %d\n\n", ret );
        goto exit;
    }
#endif

#if defined(POLARSSL_SSL_SERVER_NAME_INDICATION)
    if( ( ret = ssl_set_hostname( &ssl, opt.server_name ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }
#endif

    if( opt.min_version != -1 )
        ssl_set_min_version( &ssl, SSL_MAJOR_VERSION_3, opt.min_version );
    if( opt.max_version != -1 )
        ssl_set_max_version( &ssl, SSL_MAJOR_VERSION_3, opt.max_version );
#if defined(POLARSSL_SSL_FALLBACK_SCSV)
    if( opt.fallback != DFL_FALLBACK )
        ssl_set_fallback( &ssl, opt.fallback );
#endif

    /*
     * 4. Handshake
     */
    polarssl_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            polarssl_printf( " failed\n  ! ssl_handshake returned -0x%x\n", -ret );
            if( ret == POLARSSL_ERR_X509_CERT_VERIFY_FAILED )
                polarssl_printf(
                    "    Unable to verify the server's certificate. "
                        "Either it is invalid,\n"
                    "    or you didn't set ca_file or ca_path "
                        "to an appropriate value.\n"
                    "    Alternatively, you may want to use "
                        "auth_mode=optional for testing purposes.\n" );
            polarssl_printf( "\n" );
            goto exit;
        }
    }

    polarssl_printf( " ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n",
            ssl_get_version( &ssl ), ssl_get_ciphersuite( &ssl ) );

#if defined(POLARSSL_SSL_ALPN)
    if( opt.alpn_string != NULL )
    {
        const char *alp = ssl_get_alpn_protocol( &ssl );
        polarssl_printf( "    [ Application Layer Protocol is %s ]\n",
                alp ? alp : "(none)" );
    }
#endif

    if( opt.reconnect != 0 )
    {
        polarssl_printf("  . Saving session for reuse..." );
        fflush( stdout );

        if( ( ret = ssl_get_session( &ssl, &saved_session ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! ssl_get_session returned -0x%x\n\n", -ret );
            goto exit;
        }

        polarssl_printf( " ok\n" );
    }

#if defined(POLARSSL_X509_CRT_PARSE_C)
    /*
     * 5. Verify the server certificate
     */
    polarssl_printf( "  . Verifying peer X.509 certificate..." );

    if( ( ret = ssl_get_verify_result( &ssl ) ) != 0 )
    {
        polarssl_printf( " failed\n" );

        if( ( ret & BADCERT_EXPIRED ) != 0 )
            polarssl_printf( "  ! server certificate has expired\n" );

        if( ( ret & BADCERT_REVOKED ) != 0 )
            polarssl_printf( "  ! server certificate has been revoked\n" );

        if( ( ret & BADCERT_CN_MISMATCH ) != 0 )
            polarssl_printf( "  ! CN mismatch (expected CN=%s)\n", opt.server_name );

        if( ( ret & BADCERT_NOT_TRUSTED ) != 0 )
            polarssl_printf( "  ! self-signed or not signed by a trusted CA\n" );

        polarssl_printf( "\n" );
    }
    else
        polarssl_printf( " ok\n" );

    if( ssl_get_peer_cert( &ssl ) != NULL )
    {
        polarssl_printf( "  . Peer certificate information    ...\n" );
        x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ",
                       ssl_get_peer_cert( &ssl ) );
        polarssl_printf( "%s\n", buf );
    }
#endif /* POLARSSL_X509_CRT_PARSE_C */

#if defined(POLARSSL_SSL_RENEGOTIATION)
    if( opt.renegotiate )
    {
        /*
         * Perform renegotiation (this must be done when the server is waiting
         * for input from our side).
         */
        polarssl_printf( "  . Performing renegotiation..." );
        fflush( stdout );
        while( ( ret = ssl_renegotiate( &ssl ) ) != 0 )
        {
            if( ret != POLARSSL_ERR_NET_WANT_READ &&
                ret != POLARSSL_ERR_NET_WANT_WRITE )
            {
                polarssl_printf( " failed\n  ! ssl_renegotiate returned %d\n\n", ret );
                goto exit;
            }
        }
        polarssl_printf( " ok\n" );
    }
#endif /* POLARSSL_SSL_RENEGOTIATION */

    /*
     * 6. Write the GET request
     */
send_request:
    polarssl_printf( "  > Write to server:" );
    fflush( stdout );

    len = snprintf( (char *) buf, sizeof(buf) - 1, GET_REQUEST,
                    opt.request_page );
    tail_len = strlen( GET_REQUEST_END );

    /* Add padding to GET request to reach opt.request_size in length */
    if( opt.request_size != DFL_REQUEST_SIZE &&
        len + tail_len < opt.request_size )
    {
        memset( buf + len, 'A', opt.request_size - len - tail_len );
        len += opt.request_size - len - tail_len;
    }

    strncpy( (char *) buf + len, GET_REQUEST_END, sizeof(buf) - len - 1 );
    len += tail_len;

    /* Truncate if request size is smaller than the "natural" size */
    if( opt.request_size != DFL_REQUEST_SIZE &&
        len > opt.request_size )
    {
        len = opt.request_size;

        /* Still end with \r\n unless that's really not possible */
        if( len >= 2 ) buf[len - 2] = '\r';
        if( len >= 1 ) buf[len - 1] = '\n';
    }

    for( written = 0, frags = 0; written < len; written += ret, frags++ )
    {
        while( ( ret = ssl_write( &ssl, buf + written, len - written ) ) <= 0 )
        {
            if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
            {
                polarssl_printf( " failed\n  ! ssl_write returned -0x%x\n\n", -ret );
                goto exit;
            }
        }
    }

    buf[written] = '\0';
    polarssl_printf( " %d bytes written in %d fragments\n\n%s\n", written, frags, (char *) buf );

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

        if( ret == POLARSSL_ERR_NET_WANT_READ ||
            ret == POLARSSL_ERR_NET_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
                    polarssl_printf( " connection was closed gracefully\n" );
                    ret = 0;
                    goto close_notify;

                case 0:
                case POLARSSL_ERR_NET_CONN_RESET:
                    polarssl_printf( " connection was reset by peer\n" );
                    ret = 0;
                    goto reconnect;

                default:
                    polarssl_printf( " ssl_read returned -0x%x\n", -ret );
                    goto exit;
            }
        }

        len = ret;
        buf[len] = '\0';
        polarssl_printf( " %d bytes read\n\n%s", len, (char *) buf );

        /* End of message should be detected according to the syntax of the
         * application protocol (eg HTTP), just use a dummy test here. */
        if( ret > 0 && buf[len-1] == '\n' )
        {
            ret = 0;
            break;
        }
    }
    while( 1 );

    /*
     * 7b. Continue doing data exchanges?
     */
    if( --opt.exchanges > 0 )
        goto send_request;

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    polarssl_printf( "  . Closing the connection..." );

    /* No error checking, the connection might be closed already */
    do ret = ssl_close_notify( &ssl );
    while( ret == POLARSSL_ERR_NET_WANT_WRITE );
    ret = 0;

    polarssl_printf( " done\n" );

    /*
     * 9. Reconnect?
     */
reconnect:
    if( opt.reconnect != 0 )
    {
        --opt.reconnect;

        net_close( server_fd );

#if defined(POLARSSL_TIMING_C)
        if( opt.reco_delay > 0 )
            m_sleep( 1000 * opt.reco_delay );
#endif

        polarssl_printf( "  . Reconnecting with saved session..." );
        fflush( stdout );

        if( ( ret = ssl_session_reset( &ssl ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! ssl_session_reset returned -0x%x\n\n", -ret );
            goto exit;
        }

        if( ( ret = ssl_set_session( &ssl, &saved_session ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! ssl_set_session returned %d\n\n", ret );
            goto exit;
        }

        if( ( ret = net_connect( &server_fd, opt.server_addr,
                                             opt.server_port ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! net_connect returned -0x%x\n\n", -ret );
            goto exit;
        }

        while( ( ret = ssl_handshake( &ssl ) ) != 0 )
        {
            if( ret != POLARSSL_ERR_NET_WANT_READ &&
                ret != POLARSSL_ERR_NET_WANT_WRITE )
            {
                polarssl_printf( " failed\n  ! ssl_handshake returned -0x%x\n\n", -ret );
                goto exit;
            }
        }

        polarssl_printf( " ok\n" );

        goto send_request;
    }

    /*
     * Cleanup and exit
     */
exit:
#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        polarssl_strerror( ret, error_buf, 100 );
        polarssl_printf("Last error was: -0x%X - %s\n\n", -ret, error_buf );
    }
#endif

    if( server_fd )
        net_close( server_fd );

#if defined(POLARSSL_X509_CRT_PARSE_C)
    x509_crt_free( &clicert );
    x509_crt_free( &cacert );
    pk_free( &pkey );
#endif
    ssl_session_free( &saved_session );
    ssl_free( &ssl );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    // Shell can not handle large exit numbers -> 1 for errors
    if( ret < 0 )
        ret = 1;

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_ENTROPY_C && POLARSSL_SSL_TLS_C &&
          POLARSSL_SSL_CLI_C && POLARSSL_NET_C && POLARSSL_RSA_C &&
          POLARSSL_CTR_DRBG_C */
