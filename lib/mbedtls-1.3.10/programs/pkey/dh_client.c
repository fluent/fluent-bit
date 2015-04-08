/*
 *  Diffie-Hellman-Merkle key exchange (client side)
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

#include "polarssl/net.h"
#include "polarssl/aes.h"
#include "polarssl/dhm.h"
#include "polarssl/rsa.h"
#include "polarssl/sha1.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#define SERVER_NAME "localhost"
#define SERVER_PORT 11999

#if !defined(POLARSSL_AES_C) || !defined(POLARSSL_DHM_C) ||     \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_NET_C) ||  \
    !defined(POLARSSL_RSA_C) || !defined(POLARSSL_SHA1_C) ||    \
    !defined(POLARSSL_FS_IO) || !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    polarssl_printf("POLARSSL_AES_C and/or POLARSSL_DHM_C and/or POLARSSL_ENTROPY_C "
           "and/or POLARSSL_NET_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_SHA1_C and/or POLARSSL_FS_IO and/or "
           "POLARSSL_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;

    int ret;
    size_t n, buflen;
    int server_fd = -1;

    unsigned char *p, *end;
    unsigned char buf[2048];
    unsigned char hash[20];
    const char *pers = "dh_client";

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    rsa_context rsa;
    dhm_context dhm;
    aes_context aes;

    ((void) argc);
    ((void) argv);

    memset( &rsa, 0, sizeof( rsa ) );
    dhm_init( &dhm );
    aes_init( &aes );

    /*
     * 1. Setup the RNG
     */
    polarssl_printf( "\n  . Seeding the random number generator" );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    /*
     * 2. Read the server's public RSA key
     */
    polarssl_printf( "\n  . Reading public key from rsa_pub.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_pub.txt", "rb" ) ) == NULL )
    {
        ret = 1;
        polarssl_printf( " failed\n  ! Could not open rsa_pub.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    rsa_init( &rsa, RSA_PKCS_V15, 0 );

    if( ( ret = mpi_read_file( &rsa.N, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.E, 16, f ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! mpi_read_file returned %d\n\n", ret );
        goto exit;
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;

    fclose( f );

    /*
     * 3. Initiate the connection
     */
    polarssl_printf( "\n  . Connecting to tcp/%s/%d", SERVER_NAME,
                                             SERVER_PORT );
    fflush( stdout );

    if( ( ret = net_connect( &server_fd, SERVER_NAME,
                                         SERVER_PORT ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! net_connect returned %d\n\n", ret );
        goto exit;
    }

    /*
     * 4a. First get the buffer length
     */
    polarssl_printf( "\n  . Receiving the server's DH parameters" );
    fflush( stdout );

    memset( buf, 0, sizeof( buf ) );

    if( ( ret = net_recv( &server_fd, buf, 2 ) ) != 2 )
    {
        polarssl_printf( " failed\n  ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    n = buflen = ( buf[0] << 8 ) | buf[1];
    if( buflen < 1 || buflen > sizeof( buf ) )
    {
        polarssl_printf( " failed\n  ! Got an invalid buffer length\n\n" );
        goto exit;
    }

    /*
     * 4b. Get the DHM parameters: P, G and Ys = G^Xs mod P
     */
    memset( buf, 0, sizeof( buf ) );

    if( ( ret = net_recv( &server_fd, buf, n ) ) != (int) n )
    {
        polarssl_printf( " failed\n  ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    p = buf, end = buf + buflen;

    if( ( ret = dhm_read_params( &dhm, &p, end ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! dhm_read_params returned %d\n\n", ret );
        goto exit;
    }

    if( dhm.len < 64 || dhm.len > 512 )
    {
        ret = 1;
        polarssl_printf( " failed\n  ! Invalid DHM modulus size\n\n" );
        goto exit;
    }

    /*
     * 5. Check that the server's RSA signature matches
     *    the SHA-1 hash of (P,G,Ys)
     */
    polarssl_printf( "\n  . Verifying the server's RSA signature" );
    fflush( stdout );

    p += 2;

    if( ( n = (size_t) ( end - p ) ) != rsa.len )
    {
        ret = 1;
        polarssl_printf( " failed\n  ! Invalid RSA signature size\n\n" );
        goto exit;
    }

    sha1( buf, (int)( p - 2 - buf ), hash );

    if( ( ret = rsa_pkcs1_verify( &rsa, NULL, NULL, RSA_PUBLIC,
                                  POLARSSL_MD_SHA1, 0, hash, p ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! rsa_pkcs1_verify returned %d\n\n", ret );
        goto exit;
    }

    /*
     * 6. Send our public value: Yc = G ^ Xc mod P
     */
    polarssl_printf( "\n  . Sending own public value to server" );
    fflush( stdout );

    n = dhm.len;
    if( ( ret = dhm_make_public( &dhm, (int) dhm.len, buf, n,
                                 ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! dhm_make_public returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = net_send( &server_fd, buf, n ) ) != (int) n )
    {
        polarssl_printf( " failed\n  ! net_send returned %d\n\n", ret );
        goto exit;
    }

    /*
     * 7. Derive the shared secret: K = Ys ^ Xc mod P
     */
    polarssl_printf( "\n  . Shared secret: " );
    fflush( stdout );

    n = dhm.len;
    if( ( ret = dhm_calc_secret( &dhm, buf, &n,
                                 ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        polarssl_printf( " failed\n  ! dhm_calc_secret returned %d\n\n", ret );
        goto exit;
    }

    for( n = 0; n < 16; n++ )
        polarssl_printf( "%02x", buf[n] );

    /*
     * 8. Setup the AES-256 decryption key
     *
     * This is an overly simplified example; best practice is
     * to hash the shared secret with a random value to derive
     * the keying material for the encryption/decryption keys,
     * IVs and MACs.
     */
    polarssl_printf( "...\n  . Receiving and decrypting the ciphertext" );
    fflush( stdout );

    aes_setkey_dec( &aes, buf, 256 );

    memset( buf, 0, sizeof( buf ) );

    if( ( ret = net_recv( &server_fd, buf, 16 ) ) != 16 )
    {
        polarssl_printf( " failed\n  ! net_recv returned %d\n\n", ret );
        goto exit;
    }

    aes_crypt_ecb( &aes, AES_DECRYPT, buf, buf );
    buf[16] = '\0';
    polarssl_printf( "\n  . Plaintext is \"%s\"\n\n", (char *) buf );

exit:

    if( server_fd != -1 )
        net_close( server_fd );

    aes_free( &aes );
    rsa_free( &rsa );
    dhm_free( &dhm );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(_WIN32)
    polarssl_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_AES_C && POLARSSL_DHM_C && POLARSSL_ENTROPY_C &&
          POLARSSL_NET_C && POLARSSL_RSA_C && POLARSSL_SHA1_C && 
          POLARSSL_FS_IO && POLARSSL_CTR_DRBG_C */
