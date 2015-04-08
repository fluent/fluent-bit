/*
 *  Certificate request generation
 *
 *  Copyright (C) 2006-2011, ARM Limited, All Rights Reserved
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
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/error.h"

#if !defined(POLARSSL_X509_CSR_WRITE_C) || !defined(POLARSSL_FS_IO) ||  \
    !defined(POLARSSL_PK_PARSE_C) ||                                    \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf( "POLARSSL_X509_CSR_WRITE_C and/or POLARSSL_FS_IO and/or "
            "POLARSSL_PK_PARSE_C and/or "
            "POLARSSL_ENTROPY_C and/or POLARSSL_CTR_DRBG_C "
            "not defined.\n");
    return( 0 );
}
#else

#define DFL_FILENAME            "keyfile.key"
#define DFL_DEBUG_LEVEL         0
#define DFL_OUTPUT_FILENAME     "cert.req"
#define DFL_SUBJECT_NAME        "CN=Cert,O=mbed TLS,C=UK"
#define DFL_KEY_USAGE           0
#define DFL_NS_CERT_TYPE        0

/*
 * global options
 */
struct options
{
    const char *filename;       /* filename of the key file             */
    int debug_level;            /* level of debugging                   */
    const char *output_file;    /* where to store the constructed key file  */
    const char *subject_name;   /* subject name for certificate request */
    unsigned char key_usage;    /* key usage flags                      */
    unsigned char ns_cert_type; /* NS cert type                         */
} opt;

int write_certificate_request( x509write_csr *req, const char *output_file,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng )
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    memset( output_buf, 0, 4096 );
    if( ( ret = x509write_csr_pem( req, output_buf, 4096, f_rng, p_rng ) ) < 0 )
        return( ret );

    len = strlen( (char *) output_buf );

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( output_buf, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

#define USAGE \
    "\n usage: cert_req param=<>...\n"                  \
    "\n acceptable parameters:\n"                       \
    "    filename=%%s         default: keyfile.key\n"   \
    "    debug_level=%%d      default: 0 (disabled)\n"  \
    "    output_file=%%s      default: cert.req\n"      \
    "    subject_name=%%s     default: CN=Cert,O=mbed TLS,C=UK\n"   \
    "    key_usage=%%s        default: (empty)\n"       \
    "                        Comma-separated-list of values:\n"     \
    "                          digital_signature\n"     \
    "                          non_repudiation\n"       \
    "                          key_encipherment\n"      \
    "                          data_encipherment\n"     \
    "                          key_agreement\n"         \
    "                          key_certificate_sign\n"  \
    "                          crl_sign\n"              \
    "    ns_cert_type=%%s     default: (empty)\n"       \
    "                        Comma-separated-list of values:\n"     \
    "                          ssl_client\n"            \
    "                          ssl_server\n"            \
    "                          email\n"                 \
    "                          object_signing\n"        \
    "                          ssl_ca\n"                \
    "                          email_ca\n"              \
    "                          object_signing_ca\n"     \
    "\n"

int main( int argc, char *argv[] )
{
    int ret = 0;
    pk_context key;
    char buf[1024];
    int i;
    char *p, *q, *r;
    x509write_csr req;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    const char *pers = "csr example app";

    /*
     * Set to sane values
     */
    x509write_csr_init( &req );
    x509write_csr_set_md_alg( &req, POLARSSL_MD_SHA1 );
    pk_init( &key );
    memset( buf, 0, sizeof( buf ) );

    if( argc == 0 )
    {
    usage:
        polarssl_printf( USAGE );
        ret = 1;
        goto exit;
    }

    opt.filename            = DFL_FILENAME;
    opt.debug_level         = DFL_DEBUG_LEVEL;
    opt.output_file         = DFL_OUTPUT_FILENAME;
    opt.subject_name        = DFL_SUBJECT_NAME;
    opt.key_usage           = DFL_KEY_USAGE;
    opt.ns_cert_type        = DFL_NS_CERT_TYPE;

    for( i = 1; i < argc; i++ )
    {

        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "filename" ) == 0 )
            opt.filename = q;
        else if( strcmp( p, "output_file" ) == 0 )
            opt.output_file = q;
        else if( strcmp( p, "debug_level" ) == 0 )
        {
            opt.debug_level = atoi( q );
            if( opt.debug_level < 0 || opt.debug_level > 65535 )
                goto usage;
        }
        else if( strcmp( p, "subject_name" ) == 0 )
        {
            opt.subject_name = q;
        }
        else if( strcmp( p, "key_usage" ) == 0 )
        {
            while( q != NULL )
            {
                if( ( r = strchr( q, ',' ) ) != NULL )
                    *r++ = '\0';

                if( strcmp( q, "digital_signature" ) == 0 )
                    opt.key_usage |= KU_DIGITAL_SIGNATURE;
                else if( strcmp( q, "non_repudiation" ) == 0 )
                    opt.key_usage |= KU_NON_REPUDIATION;
                else if( strcmp( q, "key_encipherment" ) == 0 )
                    opt.key_usage |= KU_KEY_ENCIPHERMENT;
                else if( strcmp( q, "data_encipherment" ) == 0 )
                    opt.key_usage |= KU_DATA_ENCIPHERMENT;
                else if( strcmp( q, "key_agreement" ) == 0 )
                    opt.key_usage |= KU_KEY_AGREEMENT;
                else if( strcmp( q, "key_cert_sign" ) == 0 )
                    opt.key_usage |= KU_KEY_CERT_SIGN;
                else if( strcmp( q, "crl_sign" ) == 0 )
                    opt.key_usage |= KU_CRL_SIGN;
                else
                    goto usage;

                q = r;
            }
        }
        else if( strcmp( p, "ns_cert_type" ) == 0 )
        {
            while( q != NULL )
            {
                if( ( r = strchr( q, ',' ) ) != NULL )
                    *r++ = '\0';

                if( strcmp( q, "ssl_client" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_SSL_CLIENT;
                else if( strcmp( q, "ssl_server" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_SSL_SERVER;
                else if( strcmp( q, "email" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_EMAIL;
                else if( strcmp( q, "object_signing" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_OBJECT_SIGNING;
                else if( strcmp( q, "ssl_ca" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_SSL_CA;
                else if( strcmp( q, "email_ca" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_EMAIL_CA;
                else if( strcmp( q, "object_signing_ca" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_OBJECT_SIGNING_CA;
                else
                    goto usage;

                q = r;
            }
        }
        else
            goto usage;
    }

    if( opt.key_usage )
        x509write_csr_set_key_usage( &req, opt.key_usage );

    if( opt.ns_cert_type )
        x509write_csr_set_ns_cert_type( &req, opt.ns_cert_type );

    /*
     * 0. Seed the PRNG
     */
    polarssl_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        polarssl_printf( " failed\n  !  ctr_drbg_init returned %d", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    /*
     * 1.0. Check the subject name for validity
     */
    polarssl_printf( "  . Checking subjet name..." );
    fflush( stdout );

    if( ( ret = x509write_csr_set_subject_name( &req, opt.subject_name ) ) != 0 )
    {
        polarssl_printf( " failed\n  !  x509write_csr_set_subject_name returned %d", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    /*
     * 1.1. Load the key
     */
    polarssl_printf( "  . Loading the private key ..." );
    fflush( stdout );

    ret = pk_parse_keyfile( &key, opt.filename, NULL );

    if( ret != 0 )
    {
        polarssl_printf( " failed\n  !  pk_parse_keyfile returned %d", ret );
        goto exit;
    }

    x509write_csr_set_key( &req, &key );

    polarssl_printf( " ok\n" );

    /*
     * 1.2. Writing the request
     */
    polarssl_printf( "  . Writing the certificate request ..." );
    fflush( stdout );

    if( ( ret = write_certificate_request( &req, opt.output_file,
                                           ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        polarssl_printf( " failed\n  !  write_certifcate_request %d", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

exit:

    if( ret != 0 && ret != 1)
    {
#ifdef POLARSSL_ERROR_C
        polarssl_strerror( ret, buf, sizeof( buf ) );
        polarssl_printf( " - %s\n", buf );
#else
        polarssl_printf("\n");
#endif
    }

    x509write_csr_free( &req );
    pk_free( &key );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_X509_CSR_WRITE_C && POLARSSL_PK_PARSE_C && POLARSSL_FS_IO &&
          POLARSSL_ENTROPY_C && POLARSSL_CTR_DRBG_C */
