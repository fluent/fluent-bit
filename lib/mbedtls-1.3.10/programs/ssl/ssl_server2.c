/*
 *  SSL client with options
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
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

#if !defined(POLARSSL_ENTROPY_C) ||  \
    !defined(POLARSSL_SSL_TLS_C) || !defined(POLARSSL_SSL_SRV_C) || \
    !defined(POLARSSL_NET_C) || !defined(POLARSSL_CTR_DRBG_C)
#include <stdio.h>
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_ENTROPY_C and/or "
           "POLARSSL_SSL_TLS_C and/or POLARSSL_SSL_SRV_C and/or "
           "POLARSSL_NET_C and/or POLARSSL_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else

#if defined(POLARSSL_SSL_SERVER_NAME_INDICATION) && defined(POLARSSL_FS_IO)
#define POLARSSL_SNI
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if !defined(_WIN32)
#include <signal.h>
#endif

#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/error.h"
#include "polarssl/debug.h"

#if defined(POLARSSL_SSL_CACHE_C)
#include "polarssl/ssl_cache.h"
#endif

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
#include "polarssl/memory_buffer_alloc.h"
#endif

#define DFL_SERVER_ADDR         NULL
#define DFL_SERVER_PORT         4433
#define DFL_DEBUG_LEVEL         0
#define DFL_NBIO                0
#define DFL_CA_FILE             ""
#define DFL_CA_PATH             ""
#define DFL_CRT_FILE            ""
#define DFL_KEY_FILE            ""
#define DFL_CRT_FILE2           ""
#define DFL_KEY_FILE2           ""
#define DFL_PSK                 ""
#define DFL_PSK_IDENTITY        "Client_identity"
#define DFL_PSK_LIST            NULL
#define DFL_FORCE_CIPHER        0
#define DFL_VERSION_SUITES      NULL
#define DFL_RENEGOTIATION       SSL_RENEGOTIATION_DISABLED
#define DFL_ALLOW_LEGACY        -2
#define DFL_RENEGOTIATE         0
#define DFL_RENEGO_DELAY        -2
#define DFL_RENEGO_PERIOD       -1
#define DFL_EXCHANGES           1
#define DFL_MIN_VERSION         SSL_MINOR_VERSION_1
#define DFL_MAX_VERSION         -1
#define DFL_ARC4                SSL_ARC4_DISABLED
#define DFL_AUTH_MODE           SSL_VERIFY_OPTIONAL
#define DFL_MFL_CODE            SSL_MAX_FRAG_LEN_NONE
#define DFL_TRUNC_HMAC          -1
#define DFL_TICKETS             SSL_SESSION_TICKETS_ENABLED
#define DFL_TICKET_TIMEOUT      -1
#define DFL_CACHE_MAX           -1
#define DFL_CACHE_TIMEOUT       -1
#define DFL_SNI                 NULL
#define DFL_ALPN_STRING         NULL
#define DFL_DHM_FILE            NULL
#define DFL_EXTENDED_MS         -1
#define DFL_ETM                 -1

#define LONG_RESPONSE "<p>01-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n" \
    "02-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "03-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "04-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "05-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "06-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "07-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah</p>\r\n"

/* Uncomment LONG_RESPONSE at the end of HTTP_RESPONSE to test sending longer
 * packets (for fragmentation purposes) */
#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n" // LONG_RESPONSE

/*
 * Size of the basic I/O buffer. Able to hold our default response.
 *
 * You will need to adapt the ssl_get_bytes_avail() test in ssl-opt.sh
 * if you change this value to something outside the range <= 100 or > 500
 */
#define IO_BUF_LEN      200

/*
 * global options
 */
struct options
{
    const char *server_addr;    /* address on which the ssl service runs    */
    int server_port;            /* port on which the ssl service runs       */
    int debug_level;            /* level of debugging                       */
    int nbio;                   /* should I/O be blocking?                  */
    const char *ca_file;        /* the file with the CA certificate(s)      */
    const char *ca_path;        /* the path with the CA certificate(s) reside */
    const char *crt_file;       /* the file with the server certificate     */
    const char *key_file;       /* the file with the server key             */
    const char *crt_file2;      /* the file with the 2nd server certificate */
    const char *key_file2;      /* the file with the 2nd server key         */
    const char *psk;            /* the pre-shared key                       */
    const char *psk_identity;   /* the pre-shared key identity              */
    char *psk_list;             /* list of PSK id/key pairs for callback    */
    int force_ciphersuite[2];   /* protocol/ciphersuite to use, or all      */
    const char *version_suites; /* per-version ciphersuites                 */
    int renegotiation;          /* enable / disable renegotiation           */
    int allow_legacy;           /* allow legacy renegotiation               */
    int renegotiate;            /* attempt renegotiation?                   */
    int renego_delay;           /* delay before enforcing renegotiation     */
    int renego_period;          /* period for automatic renegotiation       */
    int exchanges;              /* number of data exchanges                 */
    int min_version;            /* minimum protocol version accepted        */
    int max_version;            /* maximum protocol version accepted        */
    int arc4;                   /* flag for arc4 suites support             */
    int auth_mode;              /* verify mode for connection               */
    unsigned char mfl_code;     /* code for maximum fragment length         */
    int trunc_hmac;             /* accept truncated hmac?                   */
    int tickets;                /* enable / disable session tickets         */
    int ticket_timeout;         /* session ticket lifetime                  */
    int cache_max;              /* max number of session cache entries      */
    int cache_timeout;          /* expiration delay of session cache entries */
    char *sni;                  /* string describing sni information        */
    const char *alpn_string;    /* ALPN supported protocols                 */
    const char *dhm_file;       /* the file with the DH parameters          */
    int extended_ms;            /* allow negotiation of extended MS?        */
    int etm;                    /* allow negotiation of encrypt-then-MAC?   */
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
#if defined(POLARSSL_FS_IO)
#define USAGE_IO \
    "    ca_file=%%s          The single file containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (pre-loaded)\n" \
    "    ca_path=%%s          The path containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (pre-loaded) (overrides ca_file)\n" \
    "    crt_file=%%s         Your own cert and chain (in bottom to top order, top may be omitted)\n" \
    "                        default: see note after key_file2\n" \
    "    key_file=%%s         default: see note after key_file2\n" \
    "    crt_file2=%%s        Your second cert and chain (in bottom to top order, top may be omitted)\n" \
    "                        default: see note after key_file2\n" \
    "    key_file2=%%s        default: see note below\n" \
    "                        note: if neither crt_file/key_file nor crt_file2/key_file2 are used,\n" \
    "                              preloaded certificate(s) and key(s) are used if available\n" \
    "    dhm_file=%%s        File containing Diffie-Hellman parameters\n" \
    "                       default: preloaded parameters\n"
#else
#define USAGE_IO \
    "\n"                                                    \
    "    No file operations available (POLARSSL_FS_IO not defined)\n" \
    "\n"
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
    "    tickets=%%d          default: 1 (enabled)\n"       \
    "    ticket_timeout=%%d   default: ticket default (1d)\n"
#else
#define USAGE_TICKETS ""
#endif /* POLARSSL_SSL_SESSION_TICKETS */

#if defined(POLARSSL_SSL_CACHE_C)
#define USAGE_CACHE                                             \
    "    cache_max=%%d        default: cache default (50)\n"    \
    "    cache_timeout=%%d    default: cache default (1d)\n"
#else
#define USAGE_CACHE ""
#endif /* POLARSSL_SSL_CACHE_C */

#if defined(POLARSSL_SNI)
#define USAGE_SNI                                                           \
    "    sni=%%s              name1,cert1,key1[,name2,cert2,key2[,...]]\n"  \
    "                         default: disabled\n"
#else
#define USAGE_SNI ""
#endif /* POLARSSL_SNI */

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
#define USAGE_MAX_FRAG_LEN                                      \
    "    max_frag_len=%%d     default: 16384 (tls default)\n"   \
    "                        options: 512, 1024, 2048, 4096\n"
#else
#define USAGE_MAX_FRAG_LEN ""
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

#if defined(POLARSSL_SSL_TRUNCATED_HMAC)
#define USAGE_TRUNC_HMAC \
    "    trunc_hmac=%%d       default: library default\n"
#else
#define USAGE_TRUNC_HMAC ""
#endif

#if defined(POLARSSL_SSL_ALPN)
#define USAGE_ALPN \
    "    alpn=%%s             default: \"\" (disabled)\n"   \
    "                        example: spdy/1,http/1.1\n"
#else
#define USAGE_ALPN ""
#endif /* POLARSSL_SSL_ALPN */

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
    "    renegotiate=%%d      default: 0 (disabled)\n"      \
    "    renego_delay=%%d     default: -2 (library default)\n" \
    "    renego_period=%%d    default: (library default)\n"
#else
#define USAGE_RENEGO ""
#endif

#define USAGE \
    "\n usage: ssl_server2 param=<>...\n"                   \
    "\n acceptable parameters:\n"                           \
    "    server_addr=%%d      default: (all interfaces)\n"  \
    "    server_port=%%d      default: 4433\n"              \
    "    debug_level=%%d      default: 0 (disabled)\n"      \
    "    nbio=%%d             default: 0 (blocking I/O)\n"  \
    "                        options: 1 (non-blocking), 2 (added delays)\n" \
    "\n"                                                    \
    "    auth_mode=%%s        default: \"optional\"\n"      \
    "                        options: none, optional, required\n" \
    USAGE_IO                                                \
    USAGE_SNI                                               \
    "\n"                                                    \
    USAGE_PSK                                               \
    "\n"                                                    \
    "    allow_legacy=%%d     default: (library default: no)\n"      \
    USAGE_RENEGO                                            \
    "    exchanges=%%d        default: 1\n"                 \
    USAGE_TICKETS                                           \
    USAGE_CACHE                                             \
    USAGE_MAX_FRAG_LEN                                      \
    USAGE_TRUNC_HMAC                                        \
    USAGE_ALPN                                              \
    USAGE_EMS                                               \
    USAGE_ETM                                               \
    "\n"                                                    \
    "    min_version=%%s      default: \"ssl3\"\n"          \
    "    max_version=%%s      default: \"tls1_2\"\n"        \
    "    arc4=%%d             default: 0 (disabled)\n"      \
    "    force_version=%%s    default: \"\" (none)\n"       \
    "                        options: ssl3, tls1, tls1_1, tls1_2\n"     \
    "\n"                                                                \
    "    version_suites=a,b,c,d      per-version ciphersuites\n"        \
    "                                in order from ssl3 to tls1_2\n"    \
    "                                default: all enabled\n"            \
    "    force_ciphersuite=<name>    default: all enabled\n"            \
    " acceptable ciphersuite names:\n"

/*
 * Used by sni_parse and psk_parse to handle coma-separated lists
 */
#define GET_ITEM( dst )         \
    dst = p;                    \
    while( *p != ',' )          \
        if( ++p > end )         \
            return( NULL );     \
    *p++ = '\0';

#if defined(POLARSSL_SNI)
typedef struct _sni_entry sni_entry;

struct _sni_entry {
    const char *name;
    x509_crt *cert;
    pk_context *key;
    sni_entry *next;
};

/*
 * Parse a string of triplets name1,crt1,key1[,name2,crt2,key2[,...]]
 * into a usable sni_entry list.
 *
 * Modifies the input string! This is not production quality!
 * (leaks memory if parsing fails, no error reporting, ...)
 */
sni_entry *sni_parse( char *sni_string )
{
    sni_entry *cur = NULL, *new = NULL;
    char *p = sni_string;
    char *end = p;
    char *crt_file, *key_file;

    while( *end != '\0' )
        ++end;
    *end = ',';

    while( p <= end )
    {
        if( ( new = polarssl_malloc( sizeof( sni_entry ) ) ) == NULL )
            return( NULL );

        memset( new, 0, sizeof( sni_entry ) );

        if( ( new->cert = polarssl_malloc( sizeof( x509_crt ) ) ) == NULL ||
            ( new->key = polarssl_malloc( sizeof( pk_context ) ) ) == NULL )
            return( NULL );

        x509_crt_init( new->cert );
        pk_init( new->key );

        GET_ITEM( new->name );
        GET_ITEM( crt_file );
        GET_ITEM( key_file );

        if( x509_crt_parse_file( new->cert, crt_file ) != 0 ||
            pk_parse_keyfile( new->key, key_file, "" ) != 0 )
            return( NULL );

        new->next = cur;
        cur = new;
    }

    return( cur );
}

void sni_free( sni_entry *head )
{
    sni_entry *cur = head, *next;

    while( cur != NULL )
    {
        x509_crt_free( cur->cert );
        polarssl_free( cur->cert );

        pk_free( cur->key );
        polarssl_free( cur->key );

        next = cur->next;
        polarssl_free( cur );
        cur = next;
    }
}

/*
 * SNI callback.
 */
int sni_callback( void *p_info, ssl_context *ssl,
                  const unsigned char *name, size_t name_len )
{
    sni_entry *cur = (sni_entry *) p_info;

    while( cur != NULL )
    {
        if( name_len == strlen( cur->name ) &&
            memcmp( name, cur->name, name_len ) == 0 )
        {
            return( ssl_set_own_cert( ssl, cur->cert, cur->key ) );
        }

        cur = cur->next;
    }

    return( -1 );
}

#endif /* POLARSSL_SNI */

#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)

#define HEX2NUM( c )                    \
        if( c >= '0' && c <= '9' )      \
            c -= '0';                   \
        else if( c >= 'a' && c <= 'f' ) \
            c -= 'a' - 10;              \
        else if( c >= 'A' && c <= 'F' ) \
            c -= 'A' - 10;              \
        else                            \
            return( -1 );

/*
 * Convert a hex string to bytes.
 * Return 0 on success, -1 on error.
 */
int unhexify( unsigned char *output, const char *input, size_t *olen )
{
    unsigned char c;
    size_t j;

    *olen = strlen( input );
    if( *olen % 2 != 0 || *olen / 2 > POLARSSL_PSK_MAX_LEN )
        return( -1 );
    *olen /= 2;

    for( j = 0; j < *olen * 2; j += 2 )
    {
        c = input[j];
        HEX2NUM( c );
        output[ j / 2 ] = c << 4;

        c = input[j + 1];
        HEX2NUM( c );
        output[ j / 2 ] |= c;
    }

    return( 0 );
}

typedef struct _psk_entry psk_entry;

struct _psk_entry
{
    const char *name;
    size_t key_len;
    unsigned char key[POLARSSL_PSK_MAX_LEN];
    psk_entry *next;
};

/*
 * Parse a string of pairs name1,key1[,name2,key2[,...]]
 * into a usable psk_entry list.
 *
 * Modifies the input string! This is not production quality!
 * (leaks memory if parsing fails, no error reporting, ...)
 */
psk_entry *psk_parse( char *psk_string )
{
    psk_entry *cur = NULL, *new = NULL;
    char *p = psk_string;
    char *end = p;
    char *key_hex;

    while( *end != '\0' )
        ++end;
    *end = ',';

    while( p <= end )
    {
        if( ( new = polarssl_malloc( sizeof( psk_entry ) ) ) == NULL )
            return( NULL );

        memset( new, 0, sizeof( psk_entry ) );

        GET_ITEM( new->name );
        GET_ITEM( key_hex );

        if( unhexify( new->key, key_hex, &new->key_len ) != 0 )
            return( NULL );

        new->next = cur;
        cur = new;
    }

    return( cur );
}

/*
 * Free a list of psk_entry's
 */
void psk_free( psk_entry *head )
{
    psk_entry *next;

    while( head != NULL )
    {
        next = head->next;
        polarssl_free( head );
        head = next;
    }
}

/*
 * PSK callback
 */
int psk_callback( void *p_info, ssl_context *ssl,
                  const unsigned char *name, size_t name_len )
{
    psk_entry *cur = (psk_entry *) p_info;

    while( cur != NULL )
    {
        if( name_len == strlen( cur->name ) &&
            memcmp( name, cur->name, name_len ) == 0 )
        {
            return( ssl_set_psk( ssl, cur->key, cur->key_len,
                                 name, name_len ) );
        }

        cur = cur->next;
    }

    return( -1 );
}
#endif /* POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED */

static int listen_fd, client_fd = -1;

/* Interruption handler to ensure clean exit (for valgrind testing) */
#if !defined(_WIN32)
static int received_sigterm = 0;
void term_handler( int sig )
{
    ((void) sig);
    received_sigterm = 1;
    net_close( listen_fd ); /* causes net_accept() to abort */
    net_close( client_fd ); /* causes net_read() to abort */
}
#endif

int main( int argc, char *argv[] )
{
    int ret = 0, len, written, frags, exchanges_left;
    int version_suites[4][2];
    unsigned char buf[IO_BUF_LEN];
#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
    unsigned char psk[POLARSSL_PSK_MAX_LEN];
    size_t psk_len = 0;
    psk_entry *psk_info = NULL;
#endif
    const char *pers = "ssl_server2";

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;
#if defined(POLARSSL_SSL_RENEGOTIATION)
    unsigned char renego_period[8] = { 0 };
#endif
#if defined(POLARSSL_X509_CRT_PARSE_C)
    x509_crt cacert;
    x509_crt srvcert;
    pk_context pkey;
    x509_crt srvcert2;
    pk_context pkey2;
    int key_cert_init = 0, key_cert_init2 = 0;
#endif
#if defined(POLARSSL_DHM_C) && defined(POLARSSL_FS_IO)
    dhm_context dhm;
#endif
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_context cache;
#endif
#if defined(POLARSSL_SNI)
    sni_entry *sni_info = NULL;
#endif
#if defined(POLARSSL_SSL_ALPN)
    const char *alpn_list[10];
#endif
#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[100000];
#endif

    int i;
    char *p, *q;
    const int *list;

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
    memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

    /*
     * Make sure memory references are valid in case we exit early.
     */
    listen_fd = 0;
    memset( &ssl, 0, sizeof( ssl_context ) );
#if defined(POLARSSL_X509_CRT_PARSE_C)
    x509_crt_init( &cacert );
    x509_crt_init( &srvcert );
    pk_init( &pkey );
    x509_crt_init( &srvcert2 );
    pk_init( &pkey2 );
#endif
#if defined(POLARSSL_DHM_C) && defined(POLARSSL_FS_IO)
    dhm_init( &dhm );
#endif
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_init( &cache );
#endif
#if defined(POLARSSL_SSL_ALPN)
    memset( (void *) alpn_list, 0, sizeof( alpn_list ) );
#endif

#if !defined(_WIN32)
    /* Abort cleanly on SIGTERM and SIGINT */
    signal( SIGTERM, term_handler );
    signal( SIGINT, term_handler );
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

    opt.server_addr         = DFL_SERVER_ADDR;
    opt.server_port         = DFL_SERVER_PORT;
    opt.debug_level         = DFL_DEBUG_LEVEL;
    opt.nbio                = DFL_NBIO;
    opt.ca_file             = DFL_CA_FILE;
    opt.ca_path             = DFL_CA_PATH;
    opt.crt_file            = DFL_CRT_FILE;
    opt.key_file            = DFL_KEY_FILE;
    opt.crt_file2           = DFL_CRT_FILE2;
    opt.key_file2           = DFL_KEY_FILE2;
    opt.psk                 = DFL_PSK;
    opt.psk_identity        = DFL_PSK_IDENTITY;
    opt.psk_list            = DFL_PSK_LIST;
    opt.force_ciphersuite[0]= DFL_FORCE_CIPHER;
    opt.version_suites      = DFL_VERSION_SUITES;
    opt.renegotiation       = DFL_RENEGOTIATION;
    opt.allow_legacy        = DFL_ALLOW_LEGACY;
    opt.renegotiate         = DFL_RENEGOTIATE;
    opt.renego_delay        = DFL_RENEGO_DELAY;
    opt.renego_period       = DFL_RENEGO_PERIOD;
    opt.exchanges           = DFL_EXCHANGES;
    opt.min_version         = DFL_MIN_VERSION;
    opt.max_version         = DFL_MAX_VERSION;
    opt.arc4                = DFL_ARC4;
    opt.auth_mode           = DFL_AUTH_MODE;
    opt.mfl_code            = DFL_MFL_CODE;
    opt.trunc_hmac          = DFL_TRUNC_HMAC;
    opt.tickets             = DFL_TICKETS;
    opt.ticket_timeout      = DFL_TICKET_TIMEOUT;
    opt.cache_max           = DFL_CACHE_MAX;
    opt.cache_timeout       = DFL_CACHE_TIMEOUT;
    opt.sni                 = DFL_SNI;
    opt.alpn_string         = DFL_ALPN_STRING;
    opt.dhm_file            = DFL_DHM_FILE;
    opt.extended_ms         = DFL_EXTENDED_MS;
    opt.etm                 = DFL_ETM;

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "server_port" ) == 0 )
        {
            opt.server_port = atoi( q );
            if( opt.server_port < 1 || opt.server_port > 65535 )
                goto usage;
        }
        else if( strcmp( p, "server_addr" ) == 0 )
            opt.server_addr = q;
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
        else if( strcmp( p, "ca_file" ) == 0 )
            opt.ca_file = q;
        else if( strcmp( p, "ca_path" ) == 0 )
            opt.ca_path = q;
        else if( strcmp( p, "crt_file" ) == 0 )
            opt.crt_file = q;
        else if( strcmp( p, "key_file" ) == 0 )
            opt.key_file = q;
        else if( strcmp( p, "crt_file2" ) == 0 )
            opt.crt_file2 = q;
        else if( strcmp( p, "key_file2" ) == 0 )
            opt.key_file2 = q;
        else if( strcmp( p, "dhm_file" ) == 0 )
            opt.dhm_file = q;
        else if( strcmp( p, "psk" ) == 0 )
            opt.psk = q;
        else if( strcmp( p, "psk_identity" ) == 0 )
            opt.psk_identity = q;
        else if( strcmp( p, "psk_list" ) == 0 )
            opt.psk_list = q;
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
        else if( strcmp( p, "version_suites" ) == 0 )
            opt.version_suites = q;
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
        else if( strcmp( p, "renego_delay" ) == 0 )
        {
            opt.renego_delay = atoi( q );
        }
        else if( strcmp( p, "renego_period" ) == 0 )
        {
            opt.renego_period = atoi( q );
            if( opt.renego_period < 2 || opt.renego_period > 255 )
                goto usage;
        }
        else if( strcmp( p, "exchanges" ) == 0 )
        {
            opt.exchanges = atoi( q );
            if( opt.exchanges < 1 )
                goto usage;
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
        else if( strcmp( p, "alpn" ) == 0 )
        {
            opt.alpn_string = q;
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
        else if( strcmp( p, "tickets" ) == 0 )
        {
            opt.tickets = atoi( q );
            if( opt.tickets < 0 || opt.tickets > 1 )
                goto usage;
        }
        else if( strcmp( p, "ticket_timeout" ) == 0 )
        {
            opt.ticket_timeout = atoi( q );
            if( opt.ticket_timeout < 0 )
                goto usage;
        }
        else if( strcmp( p, "cache_max" ) == 0 )
        {
            opt.cache_max = atoi( q );
            if( opt.cache_max < 0 )
                goto usage;
        }
        else if( strcmp( p, "cache_timeout" ) == 0 )
        {
            opt.cache_timeout = atoi( q );
            if( opt.cache_timeout < 0 )
                goto usage;
        }
        else if( strcmp( p, "sni" ) == 0 )
        {
            opt.sni = q;
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

    if( opt.version_suites != NULL )
    {
        const char *name[4] = { 0 };

        /* Parse 4-element coma-separated list */
        for( i = 0, p = (char *) opt.version_suites;
             i < 4 && *p != '\0';
             i++ )
        {
            name[i] = p;

            /* Terminate the current string and move on to next one */
            while( *p != ',' && *p != '\0' )
                p++;
            if( *p == ',' )
                *p++ = '\0';
        }

        if( i != 4 )
        {
            polarssl_printf( "too few values for version_suites\n" );
            ret = 1;
            goto exit;
        }

        memset( version_suites, 0, sizeof( version_suites ) );

        /* Get the suites identifiers from their name */
        for( i = 0; i < 4; i++ )
        {
            version_suites[i][0] = ssl_get_ciphersuite_id( name[i] );

            if( version_suites[i][0] == 0 )
            {
                polarssl_printf( "unknown ciphersuite: '%s'\n", name[i] );
                ret = 2;
                goto usage;
            }
        }
    }

#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
    /*
     * Unhexify the pre-shared key and parse the list if any given
     */
    if( unhexify( psk, opt.psk, &psk_len ) != 0 )
    {
        polarssl_printf( "pre-shared key not valid hex\n" );
        goto exit;
    }

    if( opt.psk_list != NULL )
    {
        if( ( psk_info = psk_parse( opt.psk_list ) ) == NULL )
        {
            polarssl_printf( "psk_list invalid" );
            goto exit;
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
     */
    polarssl_printf( "  . Loading the server cert. and key..." );
    fflush( stdout );

#if defined(POLARSSL_FS_IO)
    if( strlen( opt.crt_file ) && strcmp( opt.crt_file, "none" ) != 0 )
    {
        key_cert_init++;
        if( ( ret = x509_crt_parse_file( &srvcert, opt.crt_file ) ) != 0 )
        {
            polarssl_printf( " failed\n  !  x509_crt_parse_file returned -0x%x\n\n",
                    -ret );
            goto exit;
        }
    }
    if( strlen( opt.key_file ) && strcmp( opt.key_file, "none" ) != 0 )
    {
        key_cert_init++;
        if( ( ret = pk_parse_keyfile( &pkey, opt.key_file, "" ) ) != 0 )
        {
            polarssl_printf( " failed\n  !  pk_parse_keyfile returned -0x%x\n\n", -ret );
            goto exit;
        }
    }
    if( key_cert_init == 1 )
    {
        polarssl_printf( " failed\n  !  crt_file without key_file or vice-versa\n\n" );
        goto exit;
    }

    if( strlen( opt.crt_file2 ) && strcmp( opt.crt_file2, "none" ) != 0 )
    {
        key_cert_init2++;
        if( ( ret = x509_crt_parse_file( &srvcert2, opt.crt_file2 ) ) != 0 )
        {
            polarssl_printf( " failed\n  !  x509_crt_parse_file(2) returned -0x%x\n\n",
                    -ret );
            goto exit;
        }
    }
    if( strlen( opt.key_file2 ) && strcmp( opt.key_file2, "none" ) != 0 )
    {
        key_cert_init2++;
        if( ( ret = pk_parse_keyfile( &pkey2, opt.key_file2, "" ) ) != 0 )
        {
            polarssl_printf( " failed\n  !  pk_parse_keyfile(2) returned -0x%x\n\n",
                    -ret );
            goto exit;
        }
    }
    if( key_cert_init2 == 1 )
    {
        polarssl_printf( " failed\n  !  crt_file2 without key_file2 or vice-versa\n\n" );
        goto exit;
    }
#endif
    if( key_cert_init == 0 &&
        strcmp( opt.crt_file, "none" ) != 0 &&
        strcmp( opt.key_file, "none" ) != 0 &&
        key_cert_init2 == 0 &&
        strcmp( opt.crt_file2, "none" ) != 0 &&
        strcmp( opt.key_file2, "none" ) != 0 )
    {
#if !defined(POLARSSL_CERTS_C)
        polarssl_printf( "Not certificated or key provided, and \n"
                "POLARSSL_CERTS_C not defined!\n" );
        goto exit;
#else
#if defined(POLARSSL_RSA_C)
        if( ( ret = x509_crt_parse( &srvcert,
                                    (const unsigned char *) test_srv_crt_rsa,
                                    strlen( test_srv_crt_rsa ) ) ) != 0 )
        {
            polarssl_printf( " failed\n  !  x509_crt_parse returned -0x%x\n\n", -ret );
            goto exit;
        }
        if( ( ret = pk_parse_key( &pkey,
                                  (const unsigned char *) test_srv_key_rsa,
                                  strlen( test_srv_key_rsa ), NULL, 0 ) ) != 0 )
        {
            polarssl_printf( " failed\n  !  pk_parse_key returned -0x%x\n\n", -ret );
            goto exit;
        }
        key_cert_init = 2;
#endif /* POLARSSL_RSA_C */
#if defined(POLARSSL_ECDSA_C)
        if( ( ret = x509_crt_parse( &srvcert2,
                                    (const unsigned char *) test_srv_crt_ec,
                                    strlen( test_srv_crt_ec ) ) ) != 0 )
        {
            polarssl_printf( " failed\n  !  x509_crt_parse2 returned -0x%x\n\n", -ret );
            goto exit;
        }
        if( ( ret = pk_parse_key( &pkey2,
                                  (const unsigned char *) test_srv_key_ec,
                                  strlen( test_srv_key_ec ), NULL, 0 ) ) != 0 )
        {
            polarssl_printf( " failed\n  !  pk_parse_key2 returned -0x%x\n\n", -ret );
            goto exit;
        }
        key_cert_init2 = 2;
#endif /* POLARSSL_ECDSA_C */
#endif /* POLARSSL_CERTS_C */
    }

    polarssl_printf( " ok\n" );
#endif /* POLARSSL_X509_CRT_PARSE_C */

#if defined(POLARSSL_DHM_C) && defined(POLARSSL_FS_IO)
    if( opt.dhm_file != NULL )
    {
        polarssl_printf( "  . Loading DHM parameters..." );
        fflush( stdout );

        if( ( ret = dhm_parse_dhmfile( &dhm, opt.dhm_file ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! dhm_parse_dhmfile returned -0x%04X\n\n",
                     -ret );
            goto exit;
        }

        polarssl_printf( " ok\n" );
    }
#endif

#if defined(POLARSSL_SNI)
    if( opt.sni != NULL )
    {
        polarssl_printf( "  . Setting up SNI information..." );
        fflush( stdout );

        if( ( sni_info = sni_parse( opt.sni ) ) == NULL )
        {
            polarssl_printf( " failed\n" );
            goto exit;
        }

        polarssl_printf( " ok\n" );
    }
#endif /* POLARSSL_SNI */

    /*
     * 2. Setup the listening TCP socket
     */
    polarssl_printf( "  . Bind on tcp://localhost:%-4d/ ...", opt.server_port );
    fflush( stdout );

    if( ( ret = net_bind( &listen_fd, opt.server_addr,
                                      opt.server_port ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! net_bind returned -0x%x\n\n", -ret );
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

    ssl_set_endpoint( &ssl, SSL_IS_SERVER );
    ssl_set_authmode( &ssl, opt.auth_mode );

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
    if( ( ret = ssl_set_max_frag_len( &ssl, opt.mfl_code ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_set_max_frag_len returned %d\n\n", ret );
        goto exit;
    };
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

#if defined(POLARSSL_SSL_CACHE_C)
    if( opt.cache_max != -1 )
        ssl_cache_set_max_entries( &cache, opt.cache_max );

    if( opt.cache_timeout != -1 )
        ssl_cache_set_timeout( &cache, opt.cache_timeout );

    ssl_set_session_cache( &ssl, ssl_cache_get, &cache,
                                 ssl_cache_set, &cache );
#endif

#if defined(POLARSSL_SSL_SESSION_TICKETS)
    if( ( ret = ssl_set_session_tickets( &ssl, opt.tickets ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ssl_set_session_tickets returned %d\n\n", ret );
        goto exit;
    }

    if( opt.ticket_timeout != -1 )
        ssl_set_session_ticket_lifetime( &ssl, opt.ticket_timeout );
#endif

    if( opt.force_ciphersuite[0] != DFL_FORCE_CIPHER )
        ssl_set_ciphersuites( &ssl, opt.force_ciphersuite );
    else
        ssl_set_arc4_support( &ssl, opt.arc4 );

    if( opt.version_suites != NULL )
    {
        ssl_set_ciphersuites_for_version( &ssl, version_suites[0],
                                          SSL_MAJOR_VERSION_3,
                                          SSL_MINOR_VERSION_0 );
        ssl_set_ciphersuites_for_version( &ssl, version_suites[1],
                                          SSL_MAJOR_VERSION_3,
                                          SSL_MINOR_VERSION_1 );
        ssl_set_ciphersuites_for_version( &ssl, version_suites[2],
                                          SSL_MAJOR_VERSION_3,
                                          SSL_MINOR_VERSION_2 );
        ssl_set_ciphersuites_for_version( &ssl, version_suites[3],
                                          SSL_MAJOR_VERSION_3,
                                          SSL_MINOR_VERSION_3 );
    }

    if( opt.allow_legacy != DFL_ALLOW_LEGACY )
        ssl_legacy_renegotiation( &ssl, opt.allow_legacy );
#if defined(POLARSSL_SSL_RENEGOTIATION)
    ssl_set_renegotiation( &ssl, opt.renegotiation );

    if( opt.renego_delay != DFL_RENEGO_DELAY )
        ssl_set_renegotiation_enforced( &ssl, opt.renego_delay );

    if( opt.renego_period != DFL_RENEGO_PERIOD )
    {
        renego_period[7] = opt.renego_period;
        ssl_set_renegotiation_period( &ssl, renego_period );
    }
#endif

#if defined(POLARSSL_X509_CRT_PARSE_C)
    if( strcmp( opt.ca_path, "none" ) != 0 &&
        strcmp( opt.ca_file, "none" ) != 0 )
    {
        ssl_set_ca_chain( &ssl, &cacert, NULL, NULL );
    }
    if( key_cert_init )
        if( ( ret = ssl_set_own_cert( &ssl, &srvcert, &pkey ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! ssl_set_own_cert returned %d\n\n", ret );
            goto exit;
        }
    if( key_cert_init2 )
        if( ( ret = ssl_set_own_cert( &ssl, &srvcert2, &pkey2 ) ) != 0 )
        {
            polarssl_printf( " failed\n  ! ssl_set_own_cert returned %d\n\n", ret );
            goto exit;
        }
#endif

#if defined(POLARSSL_SNI)
    if( opt.sni != NULL )
        ssl_set_sni( &ssl, sni_callback, sni_info );
#endif

#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
    if( strlen( opt.psk ) != 0 && strlen( opt.psk_identity ) != 0 )
    {
        ret = ssl_set_psk( &ssl, psk, psk_len,
                           (const unsigned char *) opt.psk_identity,
                           strlen( opt.psk_identity ) );
        if( ret != 0 )
        {
            polarssl_printf( "  failed\n  ssl_set_psk returned -0x%04X\n\n", - ret );
            goto exit;
        }
    }

    if( opt.psk_list != NULL )
        ssl_set_psk_cb( &ssl, psk_callback, psk_info );
#endif

#if defined(POLARSSL_DHM_C)
    /*
     * Use different group than default DHM group
     */
#if defined(POLARSSL_FS_IO)
    if( opt.dhm_file != NULL )
        ret = ssl_set_dh_param_ctx( &ssl, &dhm );
    else
#endif
        ret = ssl_set_dh_param( &ssl, POLARSSL_DHM_RFC5114_MODP_2048_P,
                                      POLARSSL_DHM_RFC5114_MODP_2048_G );

    if( ret != 0 )
    {
        polarssl_printf( "  failed\n  ssl_set_dh_param returned -0x%04X\n\n", - ret );
        goto exit;
    }
#endif

    if( opt.min_version != -1 )
        ssl_set_min_version( &ssl, SSL_MAJOR_VERSION_3, opt.min_version );

    if( opt.max_version != -1 )
        ssl_set_max_version( &ssl, SSL_MAJOR_VERSION_3, opt.max_version );

    polarssl_printf( " ok\n" );

reset:
#if !defined(_WIN32)
    if( received_sigterm )
    {
        polarssl_printf( " interrupted by SIGTERM\n" );
        ret = 0;
        goto exit;
    }
#endif

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
#if !defined(_WIN32)
        if( received_sigterm )
        {
            polarssl_printf( " interrupted by signal\n" );
            ret = 0;
            goto exit;
        }
#endif

        polarssl_printf( " failed\n  ! net_accept returned -0x%x\n\n", -ret );
        goto exit;
    }

    if( opt.nbio > 0 )
        ret = net_set_nonblock( client_fd );
    else
        ret = net_set_block( client_fd );
    if( ret != 0 )
    {
        polarssl_printf( " failed\n  ! net_set_(non)block() returned -0x%x\n\n", -ret );
        goto exit;
    }

    if( opt.nbio == 2 )
        ssl_set_bio( &ssl, my_recv, &client_fd, my_send, &client_fd );
    else
        ssl_set_bio( &ssl, net_recv, &client_fd, net_send, &client_fd );

    polarssl_printf( " ok\n" );

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
            goto reset;
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

#if defined(POLARSSL_X509_CRT_PARSE_C)
    /*
     * 5. Verify the server certificate
     */
    polarssl_printf( "  . Verifying peer X.509 certificate..." );

    if( ( ret = ssl_get_verify_result( &ssl ) ) != 0 )
    {
        polarssl_printf( " failed\n" );

        if( !ssl_get_peer_cert( &ssl ) )
            polarssl_printf( "  ! no client certificate sent\n" );

        if( ( ret & BADCERT_EXPIRED ) != 0 )
            polarssl_printf( "  ! client certificate has expired\n" );

        if( ( ret & BADCERT_REVOKED ) != 0 )
            polarssl_printf( "  ! client certificate has been revoked\n" );

        if( ( ret & BADCERT_NOT_TRUSTED ) != 0 )
            polarssl_printf( "  ! self-signed or not signed by a trusted CA\n" );

        polarssl_printf( "\n" );
    }
    else
        polarssl_printf( " ok\n" );

    if( ssl_get_peer_cert( &ssl ) )
    {
        polarssl_printf( "  . Peer certificate information    ...\n" );
        x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ",
                       ssl_get_peer_cert( &ssl ) );
        polarssl_printf( "%s\n", buf );
    }
#endif /* POLARSSL_X509_CRT_PARSE_C */

    exchanges_left = opt.exchanges;
data_exchange:
    /*
     * 6. Read the HTTP Request
     */
    polarssl_printf( "  < Read from client:" );
    fflush( stdout );

    do
    {
        int terminated = 0;
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
                    goto close_notify;

                case 0:
                case POLARSSL_ERR_NET_CONN_RESET:
                    polarssl_printf( " connection was reset by peer\n" );
                    ret = POLARSSL_ERR_NET_CONN_RESET;
                    goto reset;

                default:
                    polarssl_printf( " ssl_read returned -0x%x\n", -ret );
                    goto reset;
            }
        }

        if( ssl_get_bytes_avail( &ssl ) == 0 )
        {
            len = ret;
            buf[len] = '\0';
            polarssl_printf( " %d bytes read\n\n%s\n", len, (char *) buf );

            /* End of message should be detected according to the syntax of the
             * application protocol (eg HTTP), just use a dummy test here. */
            if( buf[len - 1] == '\n' )
                terminated = 1;
        }
        else
        {
            int extra_len, ori_len;
            unsigned char *larger_buf;

            ori_len = ret;
            extra_len = ssl_get_bytes_avail( &ssl );

            larger_buf = polarssl_malloc( ori_len + extra_len + 1 );
            if( larger_buf == NULL )
            {
                polarssl_printf( "  ! memory allocation failed\n" );
                ret = 1;
                goto reset;
            }

            memset( larger_buf, 0, ori_len + extra_len );
            memcpy( larger_buf, buf, ori_len );

            /* This read should never fail and get the whole cached data */
            ret = ssl_read( &ssl, larger_buf + ori_len, extra_len );
            if( ret != extra_len ||
                ssl_get_bytes_avail( &ssl ) != 0 )
            {
                polarssl_printf( "  ! ssl_read failed on cached data\n" );
                ret = 1;
                goto reset;
            }

            larger_buf[ori_len + extra_len] = '\0';
            polarssl_printf( " %u bytes read (%u + %u)\n\n%s\n",
                    ori_len + extra_len, ori_len, extra_len,
                    (char *) larger_buf );

            /* End of message should be detected according to the syntax of the
             * application protocol (eg HTTP), just use a dummy test here. */
            if( larger_buf[ori_len + extra_len - 1] == '\n' )
                terminated = 1;

            polarssl_free( larger_buf );
        }

        if( terminated )
        {
            ret = 0;
            break;
        }
    }
    while( 1 );

    /*
     * 7a. Request renegotiation while client is waiting for input from us.
     * (only if we're going to exhange more data afterwards)
     */
#if defined(POLARSSL_SSL_RENEGOTIATION)
    if( opt.renegotiate && exchanges_left > 1 )
    {
        polarssl_printf( "  . Requestion renegotiation..." );
        fflush( stdout );

        while( ( ret = ssl_renegotiate( &ssl ) ) != 0 )
        {
            if( ret != POLARSSL_ERR_NET_WANT_READ &&
                ret != POLARSSL_ERR_NET_WANT_WRITE )
            {
                polarssl_printf( " failed\n  ! ssl_renegotiate returned %d\n\n", ret );
                goto reset;
            }
        }

        polarssl_printf( " ok\n" );
    }
#endif /* POLARSSL_SSL_RENEGOTIATION */

    /*
     * 7. Write the 200 Response
     */
    polarssl_printf( "  > Write to client:" );
    fflush( stdout );

    len = sprintf( (char *) buf, HTTP_RESPONSE,
                   ssl_get_ciphersuite( &ssl ) );

    for( written = 0, frags = 0; written < len; written += ret, frags++ )
    {
        while( ( ret = ssl_write( &ssl, buf + written, len - written ) ) <= 0 )
        {
            if( ret == POLARSSL_ERR_NET_CONN_RESET )
            {
                polarssl_printf( " failed\n  ! peer closed the connection\n\n" );
                goto reset;
            }

            if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
            {
                polarssl_printf( " failed\n  ! ssl_write returned %d\n\n", ret );
                goto reset;
            }
        }
    }

    buf[written] = '\0';
    polarssl_printf( " %d bytes written in %d fragments\n\n%s\n", written, frags, (char *) buf );
    ret = 0;

    /*
     * 7b. Continue doing data exchanges?
     */
    if( --exchanges_left > 0 )
        goto data_exchange;

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

    goto reset;

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

    polarssl_printf( "  . Cleaning up..." );
    fflush( stdout );

    if( client_fd != -1 )
        net_close( client_fd );

#if defined(POLARSSL_DHM_C) && defined(POLARSSL_FS_IO)
    dhm_free( &dhm );
#endif
#if defined(POLARSSL_X509_CRT_PARSE_C)
    x509_crt_free( &cacert );
    x509_crt_free( &srvcert );
    pk_free( &pkey );
    x509_crt_free( &srvcert2 );
    pk_free( &pkey2 );
#endif
#if defined(POLARSSL_SNI)
    sni_free( sni_info );
#endif
#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
    psk_free( psk_info );
#endif
#if defined(POLARSSL_DHM_C) && defined(POLARSSL_FS_IO)
    dhm_free( &dhm );
#endif

    ssl_free( &ssl );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_free( &cache );
#endif

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
#if defined(POLARSSL_MEMORY_DEBUG)
    memory_buffer_alloc_status();
#endif
    memory_buffer_alloc_free();
#endif

    polarssl_printf( " done.\n" );

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
          POLARSSL_SSL_SRV_C && POLARSSL_NET_C && POLARSSL_RSA_C &&
          POLARSSL_CTR_DRBG_C */
