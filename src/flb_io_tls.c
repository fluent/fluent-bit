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

#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>

#define FLB_TLS_CLIENT   "Fluent Bit"

struct flb_tls_context *flb_tls_context_new()
{
    int ret;
    struct flb_tls_context *tls;

    tls = malloc(sizeof(struct flb_tls_context));
    if (!tls) {
        perror("malloc");
        return NULL;
    }

    mbedtls_entropy_init(&tls->entropy);
    ret = mbedtls_ctr_drbg_seed(&tls->ctr_drbg,
                                mbedtls_entropy_func,
                                &tls->entropy,
                                (const unsigned char *) FLB_TLS_CLIENT,
                                sizeof(FLB_TLS_CLIENT) -1);
    if (ret == -1) {
        flb_error("[tls] failed drbg_seed");
        goto error;
    }

    return tls;

 error:
    free(tls);
    return NULL;
}

struct flb_tls_session *flb_tls_session_new(struct flb_tls_context *tls)
{
    int ret;
    struct flb_tls_session *session;

    session = malloc(sizeof(struct flb_tls_session));
    if (!session) {
        return NULL;
    }

    session->tls_context = tls;
    mbedtls_ssl_init(&session->ssl);
    mbedtls_ssl_config_init(&session->conf);

    mbedtls_ssl_conf_rng(&session->conf,
                         mbedtls_ctr_drbg_random,
                         &tls->ctr_drbg);
    mbedtls_ssl_conf_authmode(&session->conf, MBEDTLS_SSL_VERIFY_NONE);

    ret = mbedtls_ssl_setup(&session->ssl, &session->conf);
    if (ret == -1) {
        flb_error("[tls] ssl_setup");
        goto error;
    }

 error:
    free(session);
    return NULL;
}

int tls_session_destroy(struct flb_tls_session *session)
{
    mbedtls_ssl_free(&session->ssl);
    mbedtls_ssl_config_free(&session->conf);

    return 0;
}


int io_tls_write(struct flb_thread *th, struct flb_output_plugin *out,
                 void *data, size_t len, size_t *out_len)
{
    struct flb_io_upstream *u;

    u = out->upstream;
    if (!u->tls_session) {
        u->tls_session = flb_tls_session_new(&out->tls_context);

    }
    printf("tls write!\n");
    return 0;
}
