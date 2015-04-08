/*
 *  Example ECDSA program
 *
 *  Copyright (C) 2013, ARM Limited, All Rights Reserved
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

#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/ecdsa.h"

#include <string.h>
#include <stdio.h>

/*
 * Uncomment to show key and signature details
 */
#define VERBOSE

/*
 * Uncomment to force use of a specific curve
 */
#define ECPARAMS    POLARSSL_ECP_DP_SECP192R1

#if !defined(ECPARAMS)
#define ECPARAMS    ecp_curve_list()->grp_id
#endif

#if !defined(POLARSSL_ECDSA_C) || \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_ECDSA_C and/or "
           "POLARSSL_ENTROPY_C and/or POLARSSL_CTR_DRBG_C not defined\n");
    return( 0 );
}
#else

#if defined(VERBOSE)
static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    polarssl_printf( "%s", title );
    for( i = 0; i < len; i++ )
        polarssl_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    polarssl_printf( "\n" );
}

static void dump_pubkey( const char *title, ecdsa_context *key )
{
    unsigned char buf[300];
    size_t len;

    if( ecp_point_write_binary( &key->grp, &key->Q,
                POLARSSL_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        polarssl_printf("internal error\n");
        return;
    }

    dump_buf( title, buf, len );
}
#else
#define dump_buf( a, b, c )
#define dump_pubkey( a, b )
#endif

int main( int argc, char *argv[] )
{
    int ret;
    ecdsa_context ctx_sign, ctx_verify;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    unsigned char hash[] = "This should be the hash of a message.";
    unsigned char sig[512];
    size_t sig_len;
    const char *pers = "ecdsa";
    ((void) argv);

    ecdsa_init( &ctx_sign );
    ecdsa_init( &ctx_verify );

    memset(sig, 0, sizeof( sig ) );
    ret = 1;

    if( argc != 1 )
    {
        polarssl_printf( "usage: ecdsa\n" );

#if defined(_WIN32)
        polarssl_printf( "\n" );
#endif

        goto exit;
    }

    /*
     * Generate a key pair for signing
     */
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

    polarssl_printf( " ok\n  . Generating key pair..." );
    fflush( stdout );

    if( ( ret = ecdsa_genkey( &ctx_sign, ECPARAMS,
                              ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ecdsa_genkey returned %d\n", ret );
        goto exit;
    }

    polarssl_printf( " ok (key size: %d bits)\n", (int) ctx_sign.grp.pbits );

    dump_pubkey( "  + Public key: ", &ctx_sign );

    /*
     * Sign some message hash
     */
    polarssl_printf( "  . Signing message..." );
    fflush( stdout );

    if( ( ret = ecdsa_write_signature( &ctx_sign,
                                       hash, sizeof( hash ),
                                       sig, &sig_len,
                                       ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ecdsa_genkey returned %d\n", ret );
        goto exit;
    }
    polarssl_printf( " ok (signature length = %u)\n", (unsigned int) sig_len );

    dump_buf( "  + Hash: ", hash, sizeof hash );
    dump_buf( "  + Signature: ", sig, sig_len );

    /*
     * Signature is serialized as defined by RFC 4492 p. 20,
     * but one can also access 'r' and 's' directly from the context
     */
#ifdef POLARSSL_FS_IO
    mpi_write_file( "    r = ", &ctx_sign.r, 16, NULL );
    mpi_write_file( "    s = ", &ctx_sign.s, 16, NULL );
#endif

    /*
     * Transfer public information to verifying context
     *
     * We could use the same context for verification and signatures, but we
     * chose to use a new one in order to make it clear that the verifying
     * context only needs the public key (Q), and not the private key (d).
     */
    polarssl_printf( "  . Preparing verification context..." );
    fflush( stdout );

    if( ( ret = ecp_group_copy( &ctx_verify.grp, &ctx_sign.grp ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ecp_group_copy returned %d\n", ret );
        goto exit;
    }

    if( ( ret = ecp_copy( &ctx_verify.Q, &ctx_sign.Q ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ecp_copy returned %d\n", ret );
        goto exit;
    }

    ret = 0;

    /*
     * Verify signature
     */
    polarssl_printf( " ok\n  . Verifying signature..." );
    fflush( stdout );

    if( ( ret = ecdsa_read_signature( &ctx_verify,
                                      hash, sizeof( hash ),
                                      sig, sig_len ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ecdsa_read_signature returned %d\n", ret );
        goto exit;
    }

    polarssl_printf( " ok\n" );

exit:

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    ecdsa_free( &ctx_verify );
    ecdsa_free( &ctx_sign );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

    return( ret );
}
#endif /* POLARSSL_ECDSA_C && POLARSSL_ENTROPY_C && POLARSSL_CTR_DRBG_C &&
          ECPARAMS */
