/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>

#include <fluent-bit/flb_config.h>

static int tls_config_init(struct flb_config *config)
{
    struct flb_tls_context *tls;

    tls = malloc(sizeof(struct flb_tls_context));
    if (!tls) {
        perror("malloc");
        return -1;
    }

    mbedtls_entropy_init(&tls->entropy);
}

static struct mbedtls_ssl_context *tls_context_new()
{
    struct mbedtls_ssl_context *ssl;
    struct mbedtls_ssl_config conf;

    ssl = malloc(sizeof(struct mbedtls_ssl_context));
    if (!ssl) {
        return NULL;
    }

    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(&conf);
}
