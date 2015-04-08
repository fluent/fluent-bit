/*
 *  Certificate generation and signing
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

#if !defined(POLARSSL_X509_CRT_WRITE_C) ||                                  \
    !defined(POLARSSL_X509_CRT_PARSE_C) || !defined(POLARSSL_FS_IO) ||      \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_CTR_DRBG_C) ||        \
    !defined(POLARSSL_ERROR_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf( "POLARSSL_X509_CRT_WRITE_C and/or POLARSSL_X509_CRT_PARSE_C and/or "
            "POLARSSL_FS_IO and/or "
            "POLARSSL_ENTROPY_C and/or POLARSSL_CTR_DRBG_C and/or "
            "POLARSSL_ERROR_C not defined.\n");
    return( 0 );
}
#else

#include "polarssl/x509_crt.h"
#include "polarssl/x509_csr.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/error.h"

#define DFL_ISSUER_CRT          ""
#define DFL_REQUEST_FILE        ""
#define DFL_SUBJECT_KEY         "subject.key"
#define DFL_ISSUER_KEY          "ca.key"
#define DFL_SUBJECT_PWD         ""
#define DFL_ISSUER_PWD          ""
#define DFL_OUTPUT_FILENAME     "cert.crt"
#define DFL_SUBJECT_NAME        "CN=Cert,O=mbed TLS,C=UK"
#define DFL_ISSUER_NAME         "CN=CA,O=mbed TLS,C=UK"
#define DFL_NOT_BEFORE          "20010101000000"
#define DFL_NOT_AFTER           "20301231235959"
#define DFL_SERIAL              "1"
#define DFL_SELFSIGN            0
#define DFL_IS_CA               0
#define DFL_MAX_PATHLEN         -1
#define DFL_KEY_USAGE           0
#define DFL_NS_CERT_TYPE        0

/*
 * global options
 */
struct options
{
    const char *issuer_crt;     /* filename of the issuer certificate   */
    const char *request_file;   /* filename of the certificate request  */
    const char *subject_key;    /* filename of the subject key file     */
    const char *issuer_key;     /* filename of the issuer key file      */
    const char *subject_pwd;    /* password for the subject key file    */
    const char *issuer_pwd;     /* password for the issuer key file     */
    const char *output_file;    /* where to store the constructed key file  */
    const char *subject_name;   /* subject name for certificate         */
    const char *issuer_name;    /* issuer name for certificate          */
    const char *not_before;     /* validity period not before           */
    const char *not_after;      /* validity period not after            */
    const char *serial;         /* serial number string                 */
    int selfsign;               /* selfsign the certificate             */
    int is_ca;                  /* is a CA certificate                  */
    int max_pathlen;            /* maximum CA path length               */
    unsigned char key_usage;    /* key usage flags                      */
    unsigned char ns_cert_type; /* NS cert type                         */
} opt;

int write_certificate( x509write_cert *crt, const char *output_file,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    memset( output_buf, 0, 4096 );
    if( ( ret = x509write_crt_pem( crt, output_buf, 4096, f_rng, p_rng ) ) < 0 )
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

#if defined(POLARSSL_X509_CSR_PARSE_C)
#define USAGE_CSR                                                           \
    "    request_file=%%s     default: (empty)\n"                           \
    "                        If request_file is specified, subject_key,\n"  \
    "                        subject_pwd and subject_name are ignored!\n"
#else
#define USAGE_CSR ""
#endif /* POLARSSL_X509_CSR_PARSE_C */

#define USAGE \
    "\n usage: cert_write param=<>...\n"                \
    "\n acceptable parameters:\n"                       \
    USAGE_CSR                                           \
    "    subject_key=%%s      default: subject.key\n"   \
    "    subject_pwd=%%s      default: (empty)\n"       \
    "    subject_name=%%s     default: CN=Cert,O=mbed TLS,C=UK\n"   \
    "\n"                                                \
    "    issuer_crt=%%s       default: (empty)\n"       \
    "                        If issuer_crt is specified, issuer_name is\n"  \
    "                        ignored!\n"                \
    "    issuer_name=%%s      default: CN=CA,O=mbed TLS,C=UK\n"     \
    "\n"                                                \
    "    selfsign=%%d         default: 0 (false)\n"     \
    "                        If selfsign is enabled, issuer_name and\n" \
    "                        issuer_key are required (issuer_crt and\n" \
    "                        subject_* are ignored\n"   \
    "    issuer_key=%%s       default: ca.key\n"        \
    "    issuer_pwd=%%s       default: (empty)\n"       \
    "    output_file=%%s      default: cert.crt\n"      \
    "    serial=%%s           default: 1\n"             \
    "    not_before=%%s       default: 20010101000000\n"\
    "    not_after=%%s        default: 20301231235959\n"\
    "    is_ca=%%d            default: 0 (disabled)\n"  \
    "    max_pathlen=%%d      default: -1 (none)\n"     \
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
    x509_crt issuer_crt;
    pk_context loaded_issuer_key, loaded_subject_key;
    pk_context *issuer_key = &loaded_issuer_key,
                *subject_key = &loaded_subject_key;
    char buf[1024];
    char issuer_name[128];
    int i;
    char *p, *q, *r;
#if defined(POLARSSL_X509_CSR_PARSE_C)
    char subject_name[128];
    x509_csr csr;
#endif
    x509write_cert crt;
    mpi serial;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    const char *pers = "crt example app";

    /*
     * Set to sane values
     */
    x509write_crt_init( &crt );
    x509write_crt_set_md_alg( &crt, POLARSSL_MD_SHA1 );
    pk_init( &loaded_issuer_key );
    pk_init( &loaded_subject_key );
    mpi_init( &serial );
#if defined(POLARSSL_X509_CSR_PARSE_C)
    x509_csr_init( &csr );
#endif
    x509_crt_init( &issuer_crt );
    memset( buf, 0, 1024 );

    if( argc == 0 )
    {
    usage:
        polarssl_printf( USAGE );
        ret = 1;
        goto exit;
    }

    opt.issuer_crt          = DFL_ISSUER_CRT;
    opt.request_file        = DFL_REQUEST_FILE;
    opt.request_file        = DFL_REQUEST_FILE;
    opt.subject_key         = DFL_SUBJECT_KEY;
    opt.issuer_key          = DFL_ISSUER_KEY;
    opt.subject_pwd         = DFL_SUBJECT_PWD;
    opt.issuer_pwd          = DFL_ISSUER_PWD;
    opt.output_file         = DFL_OUTPUT_FILENAME;
    opt.subject_name        = DFL_SUBJECT_NAME;
    opt.issuer_name         = DFL_ISSUER_NAME;
    opt.not_before          = DFL_NOT_BEFORE;
    opt.not_after           = DFL_NOT_AFTER;
    opt.serial              = DFL_SERIAL;
    opt.selfsign            = DFL_SELFSIGN;
    opt.is_ca               = DFL_IS_CA;
    opt.max_pathlen         = DFL_MAX_PATHLEN;
    opt.key_usage           = DFL_KEY_USAGE;
    opt.ns_cert_type        = DFL_NS_CERT_TYPE;

    for( i = 1; i < argc; i++ )
    {

        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "request_file" ) == 0 )
            opt.request_file = q;
        else if( strcmp( p, "subject_key" ) == 0 )
            opt.subject_key = q;
        else if( strcmp( p, "issuer_key" ) == 0 )
            opt.issuer_key = q;
        else if( strcmp( p, "subject_pwd" ) == 0 )
            opt.subject_pwd = q;
        else if( strcmp( p, "issuer_pwd" ) == 0 )
            opt.issuer_pwd = q;
        else if( strcmp( p, "issuer_crt" ) == 0 )
            opt.issuer_crt = q;
        else if( strcmp( p, "output_file" ) == 0 )
            opt.output_file = q;
        else if( strcmp( p, "subject_name" ) == 0 )
        {
            opt.subject_name = q;
        }
        else if( strcmp( p, "issuer_name" ) == 0 )
        {
            opt.issuer_name = q;
        }
        else if( strcmp( p, "not_before" ) == 0 )
        {
            opt.not_before = q;
        }
        else if( strcmp( p, "not_after" ) == 0 )
        {
            opt.not_after = q;
        }
        else if( strcmp( p, "serial" ) == 0 )
        {
            opt.serial = q;
        }
        else if( strcmp( p, "selfsign" ) == 0 )
        {
            opt.selfsign = atoi( q );
            if( opt.selfsign < 0 || opt.selfsign > 1 )
                goto usage;
        }
        else if( strcmp( p, "is_ca" ) == 0 )
        {
            opt.is_ca = atoi( q );
            if( opt.is_ca < 0 || opt.is_ca > 1 )
                goto usage;
        }
        else if( strcmp( p, "max_pathlen" ) == 0 )
        {
            opt.max_pathlen = atoi( q );
            if( opt.max_pathlen < -1 || opt.max_pathlen > 127 )
                goto usage;
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

    polarssl_printf("\n");

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
        polarssl_strerror( ret, buf, 1024 );
        polarssl_printf( " failed\n  !  ctr_drbg_init returned %d - %s\n", ret, buf );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    // Parse serial to MPI
    //
    polarssl_printf( "  . Reading serial number..." );
    fflush( stdout );

    if( ( ret = mpi_read_string( &serial, 10, opt.serial ) ) != 0 )
    {
        polarssl_strerror( ret, buf, 1024 );
        polarssl_printf( " failed\n  !  mpi_read_string returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    // Parse issuer certificate if present
    //
    if( !opt.selfsign && strlen( opt.issuer_crt ) )
    {
        /*
         * 1.0.a. Load the certificates
         */
        polarssl_printf( "  . Loading the issuer certificate ..." );
        fflush( stdout );

        if( ( ret = x509_crt_parse_file( &issuer_crt, opt.issuer_crt ) ) != 0 )
        {
            polarssl_strerror( ret, buf, 1024 );
            polarssl_printf( " failed\n  !  x509_crt_parse_file returned -0x%02x - %s\n\n", -ret, buf );
            goto exit;
        }

        ret = x509_dn_gets( issuer_name, sizeof(issuer_name),
                                 &issuer_crt.subject );
        if( ret < 0 )
        {
            polarssl_strerror( ret, buf, 1024 );
            polarssl_printf( " failed\n  !  x509_dn_gets returned -0x%02x - %s\n\n", -ret, buf );
            goto exit;
        }

        opt.issuer_name = issuer_name;

        polarssl_printf( " ok\n" );
    }

#if defined(POLARSSL_X509_CSR_PARSE_C)
    // Parse certificate request if present
    //
    if( !opt.selfsign && strlen( opt.request_file ) )
    {
        /*
         * 1.0.b. Load the CSR
         */
        polarssl_printf( "  . Loading the certificate request ..." );
        fflush( stdout );

        if( ( ret = x509_csr_parse_file( &csr, opt.request_file ) ) != 0 )
        {
            polarssl_strerror( ret, buf, 1024 );
            polarssl_printf( " failed\n  !  x509_csr_parse_file returned -0x%02x - %s\n\n", -ret, buf );
            goto exit;
        }

        ret = x509_dn_gets( subject_name, sizeof(subject_name),
                                 &csr.subject );
        if( ret < 0 )
        {
            polarssl_strerror( ret, buf, 1024 );
            polarssl_printf( " failed\n  !  x509_dn_gets returned -0x%02x - %s\n\n", -ret, buf );
            goto exit;
        }

        opt.subject_name = subject_name;
        subject_key = &csr.pk;

        polarssl_printf( " ok\n" );
    }
#endif /* POLARSSL_X509_CSR_PARSE_C */

    /*
     * 1.1. Load the keys
     */
    if( !opt.selfsign && !strlen( opt.request_file ) )
    {
        polarssl_printf( "  . Loading the subject key ..." );
        fflush( stdout );

        ret = pk_parse_keyfile( &loaded_subject_key, opt.subject_key,
                                 opt.subject_pwd );
        if( ret != 0 )
        {
            polarssl_strerror( ret, buf, 1024 );
            polarssl_printf( " failed\n  !  pk_parse_keyfile returned -0x%02x - %s\n\n", -ret, buf );
            goto exit;
        }

        polarssl_printf( " ok\n" );
    }

    polarssl_printf( "  . Loading the issuer key ..." );
    fflush( stdout );

    ret = pk_parse_keyfile( &loaded_issuer_key, opt.issuer_key,
                             opt.issuer_pwd );
    if( ret != 0 )
    {
        polarssl_strerror( ret, buf, 1024 );
        polarssl_printf( " failed\n  !  pk_parse_keyfile returned -x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    // Check if key and issuer certificate match
    //
    if( strlen( opt.issuer_crt ) )
    {
        if( !pk_can_do( &issuer_crt.pk, POLARSSL_PK_RSA ) ||
            mpi_cmp_mpi( &pk_rsa( issuer_crt.pk )->N,
                         &pk_rsa( *issuer_key )->N ) != 0 ||
            mpi_cmp_mpi( &pk_rsa( issuer_crt.pk )->E,
                         &pk_rsa( *issuer_key )->E ) != 0 )
        {
            polarssl_printf( " failed\n  !  issuer_key does not match issuer certificate\n\n" );
            ret = -1;
            goto exit;
        }
    }

    polarssl_printf( " ok\n" );

    if( opt.selfsign )
    {
        opt.subject_name = opt.issuer_name;
        subject_key = issuer_key;
    }

    x509write_crt_set_subject_key( &crt, subject_key );
    x509write_crt_set_issuer_key( &crt, issuer_key );

    /*
     * 1.0. Check the names for validity
     */
    if( ( ret = x509write_crt_set_subject_name( &crt, opt.subject_name ) ) != 0 )
    {
        polarssl_strerror( ret, buf, 1024 );
        polarssl_printf( " failed\n  !  x509write_crt_set_subject_name returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    if( ( ret = x509write_crt_set_issuer_name( &crt, opt.issuer_name ) ) != 0 )
    {
        polarssl_strerror( ret, buf, 1024 );
        polarssl_printf( " failed\n  !  x509write_crt_set_issuer_name returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    polarssl_printf( "  . Setting certificate values ..." );
    fflush( stdout );

    ret = x509write_crt_set_serial( &crt, &serial );
    if( ret != 0 )
    {
        polarssl_strerror( ret, buf, 1024 );
        polarssl_printf( " failed\n  !  x509write_crt_set_serial returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    ret = x509write_crt_set_validity( &crt, opt.not_before, opt.not_after );
    if( ret != 0 )
    {
        polarssl_strerror( ret, buf, 1024 );
        polarssl_printf( " failed\n  !  x509write_crt_set_validity returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    polarssl_printf( "  . Adding the Basic Constraints extension ..." );
    fflush( stdout );

    ret = x509write_crt_set_basic_constraints( &crt, opt.is_ca,
                                               opt.max_pathlen );
    if( ret != 0 )
    {
        polarssl_strerror( ret, buf, 1024 );
        polarssl_printf( " failed\n  !  x509write_crt_set_basic_contraints returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    polarssl_printf( " ok\n" );

#if defined(POLARSSL_SHA1_C)
    polarssl_printf( "  . Adding the Subject Key Identifier ..." );
    fflush( stdout );

    ret = x509write_crt_set_subject_key_identifier( &crt );
    if( ret != 0 )
    {
        polarssl_strerror( ret, buf, 1024 );
        polarssl_printf( " failed\n  !  x509write_crt_set_subject_key_identifier returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    polarssl_printf( "  . Adding the Authority Key Identifier ..." );
    fflush( stdout );

    ret = x509write_crt_set_authority_key_identifier( &crt );
    if( ret != 0 )
    {
        polarssl_strerror( ret, buf, 1024 );
        polarssl_printf( " failed\n  !  x509write_crt_set_authority_key_identifier returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    polarssl_printf( " ok\n" );
#endif /* POLARSSL_SHA1_C */

    if( opt.key_usage )
    {
        polarssl_printf( "  . Adding the Key Usage extension ..." );
        fflush( stdout );

        ret = x509write_crt_set_key_usage( &crt, opt.key_usage );
        if( ret != 0 )
        {
            polarssl_strerror( ret, buf, 1024 );
            polarssl_printf( " failed\n  !  x509write_crt_set_key_usage returned -0x%02x - %s\n\n", -ret, buf );
            goto exit;
        }

        polarssl_printf( " ok\n" );
    }

    if( opt.ns_cert_type )
    {
        polarssl_printf( "  . Adding the NS Cert Type extension ..." );
        fflush( stdout );

        ret = x509write_crt_set_ns_cert_type( &crt, opt.ns_cert_type );
        if( ret != 0 )
        {
            polarssl_strerror( ret, buf, 1024 );
            polarssl_printf( " failed\n  !  x509write_crt_set_ns_cert_type returned -0x%02x - %s\n\n", -ret, buf );
            goto exit;
        }

        polarssl_printf( " ok\n" );
    }

    /*
     * 1.2. Writing the request
     */
    polarssl_printf( "  . Writing the certificate..." );
    fflush( stdout );

    if( ( ret = write_certificate( &crt, opt.output_file,
                                   ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        polarssl_strerror( ret, buf, 1024 );
        polarssl_printf( " failed\n  !  write_certifcate -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    polarssl_printf( " ok\n" );

exit:
    x509write_crt_free( &crt );
    pk_free( &loaded_subject_key );
    pk_free( &loaded_issuer_key );
    mpi_free( &serial );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_X509_CRT_WRITE_C && POLARSSL_X509_CRT_PARSE_C &&
          POLARSSL_FS_IO && POLARSSL_ENTROPY_C && POLARSSL_CTR_DRBG_C &&
          POLARSSL_ERROR_C */
