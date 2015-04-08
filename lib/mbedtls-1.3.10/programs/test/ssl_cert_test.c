/*
 *  SSL certificate functionality tests
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
#include <stdio.h>

#if !defined(POLARSSL_RSA_C) || !defined(POLARSSL_X509_CRT_PARSE_C) || \
    !defined(POLARSSL_FS_IO) || !defined(POLARSSL_X509_CRL_PARSE_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_RSA_C and/or POLARSSL_X509_CRT_PARSE_C "
           "POLARSSL_FS_IO and/or POLARSSL_X509_CRL_PARSE_C "
           "not defined.\n");
    return( 0 );
}
#else

#include "polarssl/certs.h"
#include "polarssl/x509_crt.h"

#if defined _MSC_VER && !defined snprintf
#define snprintf _snprintf
#endif


#define MAX_CLIENT_CERTS    8

const char *client_certificates[MAX_CLIENT_CERTS] =
{
    "client1.crt",
    "client2.crt",
    "server1.crt",
    "server2.crt",
    "cert_sha224.crt",
    "cert_sha256.crt",
    "cert_sha384.crt",
    "cert_sha512.crt"
};

const char *client_private_keys[MAX_CLIENT_CERTS] =
{
    "client1.key",
    "client2.key",
    "server1.key",
    "server2.key",
    "cert_digest.key",
    "cert_digest.key",
    "cert_digest.key",
    "cert_digest.key"
};

int main( int argc, char *argv[] )
{
    int ret, i;
    x509_crt cacert;
    x509_crl crl;
    char buf[10240];

    ((void) argc);
    ((void) argv);

    x509_crt_init( &cacert );
    x509_crl_init( &crl );

    /*
     * 1.1. Load the trusted CA
     */
    polarssl_printf( "\n  . Loading the CA root certificate ..." );
    fflush( stdout );

    /*
     * Alternatively, you may load the CA certificates from a .pem or
     * .crt file by calling x509_crt_parse_file( &cacert, "myca.crt" ).
     */
    ret = x509_crt_parse_file( &cacert, "ssl/test-ca/test-ca.crt" );
    if( ret != 0 )
    {
        polarssl_printf( " failed\n  !  x509_crt_parse_file returned %d\n\n", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    x509_crt_info( buf, 1024, "CRT: ", &cacert );
    polarssl_printf("%s\n", buf );

    /*
     * 1.2. Load the CRL
     */
    polarssl_printf( "  . Loading the CRL ..." );
    fflush( stdout );

    ret = x509_crl_parse_file( &crl, "ssl/test-ca/crl.pem" );
    if( ret != 0 )
    {
        polarssl_printf( " failed\n  !  x509_crl_parse_file returned %d\n\n", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

    x509_crl_info( buf, 1024, "CRL: ", &crl );
    polarssl_printf("%s\n", buf );

    for( i = 0; i < MAX_CLIENT_CERTS; i++ )
    {
        /*
         * 1.3. Load own certificate
         */
        char    name[512];
        int flags;
        x509_crt clicert;
        pk_context pk;

        x509_crt_init( &clicert );
        pk_init( &pk );

        snprintf(name, 512, "ssl/test-ca/%s", client_certificates[i]);

        polarssl_printf( "  . Loading the client certificate %s...", name );
        fflush( stdout );

        ret = x509_crt_parse_file( &clicert, name );
        if( ret != 0 )
        {
            polarssl_printf( " failed\n  !  x509_crt_parse_file returned %d\n\n", ret );
            goto exit;
        }

        polarssl_printf( " ok\n" );

        /*
         * 1.4. Verify certificate validity with CA certificate
         */
        polarssl_printf( "  . Verify the client certificate with CA certificate..." );
        fflush( stdout );

        ret = x509_crt_verify( &clicert, &cacert, &crl, NULL, &flags, NULL,
                               NULL );
        if( ret != 0 )
        {
            if( ret == POLARSSL_ERR_X509_CERT_VERIFY_FAILED )
            {
                if( flags & BADCERT_CN_MISMATCH )
                    polarssl_printf( " CN_MISMATCH " );
                if( flags & BADCERT_EXPIRED )
                    polarssl_printf( " EXPIRED " );
                if( flags & BADCERT_REVOKED )
                    polarssl_printf( " REVOKED " );
                if( flags & BADCERT_NOT_TRUSTED )
                    polarssl_printf( " NOT_TRUSTED " );
                if( flags & BADCRL_NOT_TRUSTED )
                    polarssl_printf( " CRL_NOT_TRUSTED " );
                if( flags & BADCRL_EXPIRED )
                    polarssl_printf( " CRL_EXPIRED " );
            } else {
                polarssl_printf( " failed\n  !  x509_crt_verify returned %d\n\n", ret );
                goto exit;
            }
        }

        polarssl_printf( " ok\n" );

        /*
         * 1.5. Load own private key
         */
        snprintf(name, 512, "ssl/test-ca/%s", client_private_keys[i]);

        polarssl_printf( "  . Loading the client private key %s...", name );
        fflush( stdout );

        ret = pk_parse_keyfile( &pk, name, NULL );
        if( ret != 0 )
        {
            polarssl_printf( " failed\n  !  pk_parse_keyfile returned %d\n\n", ret );
            goto exit;
        }

        polarssl_printf( " ok\n" );

        /*
         * 1.6. Verify certificate validity with private key
         */
        polarssl_printf( "  . Verify the client certificate with private key..." );
        fflush( stdout );


        /* EC NOT IMPLEMENTED YET */
        if( ! pk_can_do( &clicert.pk, POLARSSL_PK_RSA ) )
        {
            polarssl_printf( " failed\n  !  certificate's key is not RSA\n\n" );
            ret = POLARSSL_ERR_X509_FEATURE_UNAVAILABLE;
            goto exit;
        }

        ret = mpi_cmp_mpi(&pk_rsa( pk )->N, &pk_rsa( clicert.pk )->N);
        if( ret != 0 )
        {
            polarssl_printf( " failed\n  !  mpi_cmp_mpi for N returned %d\n\n", ret );
            goto exit;
        }

        ret = mpi_cmp_mpi(&pk_rsa( pk )->E, &pk_rsa( clicert.pk )->E);
        if( ret != 0 )
        {
            polarssl_printf( " failed\n  !  mpi_cmp_mpi for E returned %d\n\n", ret );
            goto exit;
        }

        ret = rsa_check_privkey( pk_rsa( pk ) );
        if( ret != 0 )
        {
            polarssl_printf( " failed\n  !  rsa_check_privkey returned %d\n\n", ret );
            goto exit;
        }

        polarssl_printf( " ok\n" );

        x509_crt_free( &clicert );
        pk_free( &pk );
    }

exit:
    x509_crt_free( &cacert );
    x509_crl_free( &crl );

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_RSA_C && POLARSSL_X509_CRT_PARSE_C && POLARSSL_FS_IO &&
          POLARSSL_X509_CRL_PARSE_C */
