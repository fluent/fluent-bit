/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_IO_TLS_H
#define FLB_IO_TLS_H

#include <fluent-bit/flb_info.h>

#ifdef FLB_HAVE_TLS

#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define FLB_TLS_CA_ROOT          1
#define FLB_TLS_CERT             2
#define FLB_TLS_PRIV_KEY         4

/* mbedTLS library context */
struct flb_tls_context {
    int verify;                    /* FLB_TRUE | FLB_FALSE      */
    int debug;                     /* mbedtls debug level       */
    uint16_t    certs_set;         /* CA_ROOT | CERT | PRIV_KEY */
    mbedtls_x509_crt ca_cert;      /* CA Root      */
    mbedtls_x509_crt cert;         /* Certificate  */
    mbedtls_pk_context priv_key;   /* Private key  */
    mbedtls_dhm_context dhm;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
};

/* TLS connected session */
struct flb_tls_session {
    struct mbedtls_ssl_context ssl;
    struct mbedtls_ssl_config conf;
};

/* TLS instance, library context + active sessions */
struct flb_tls {
    struct flb_tls_context *context;
};

struct flb_tls_context *flb_tls_context_new();
void flb_tls_context_destroy(struct flb_tls_context *ctx);
int flb_tls_session_destroy(struct flb_tls_session *session);
int net_io_tls_handshake(void *u_conn, void *th);

#endif /* FLB_HAVE_TLS */
#endif
