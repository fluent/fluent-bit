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

#ifndef FLB_SSL_INTERNAL_H
#define FLB_SSL_INTERNAL_H

#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>

#define FLB_SSL_CLIENT      1
#define FLB_SSL_SERVER      2
#define FLB_SSL_SERVER_CONN 4

#define FLB_SSL_CONNECTED           1
#define FLB_SSL_HANDSHAKE_COMPLETE  2

struct flb_ssl_config {
    const char *ca_path;
    const char *ca_file;
    int verify;
    int verify_client;
    int debug;
    const char *cert_file;
    const char *key_file;
    const char *key_passwd;
};

struct flb_ssl {
    struct flb_ssl_config *config;
    unsigned int flags;
    unsigned int state;
    mbedtls_ssl_context mbed_ssl;
    mbedtls_ssl_config mbed_config;
    mbedtls_entropy_context mbed_entropy;
    mbedtls_ctr_drbg_context mbed_ctr_drbg;
    mbedtls_x509_crt mbed_ca_cert;
    mbedtls_x509_crt mbed_cert;
    mbedtls_pk_context mbed_key;
    mbedtls_net_context mbed_conn;
};

int flb_ssl_handshake(struct flb_ssl *ctx);
int flb_ssl_configure_server(struct flb_ssl *ctx);

void flb_ssl_debug(void *ctx, int level, const char *file, int line,
                   const char *str);

void flb_ssl_error_internal(int ret, char *file, int line);

#define flb_ssl_error(ret) flb_ssl_error_internal(ret, __FILE__, __LINE__)

#endif
