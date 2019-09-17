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

/* This module is loosely inspired by libtls */

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>

#include <fluent-bit/ssl/flb_ssl.h>
#include "flb_ssl_internal.h"

static struct flb_ssl *flb_ssl_new(void)
{
    struct flb_ssl *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_ssl));
    if (ctx == NULL) {
        flb_errno();
        return NULL;
    }

    mbedtls_ssl_init(&ctx->mbed_ssl);
    mbedtls_ssl_config_init(&ctx->mbed_config);
    mbedtls_entropy_init(&ctx->mbed_entropy);
    mbedtls_ctr_drbg_init(&ctx->mbed_ctr_drbg);
    mbedtls_x509_crt_init(&ctx->mbed_ca_cert);
    mbedtls_x509_crt_init(&ctx->mbed_cert);
    mbedtls_pk_init(&ctx->mbed_key);
    mbedtls_net_init(&ctx->mbed_conn);

    return ctx;
}

struct flb_ssl *flb_ssl_server(void)
{
    struct flb_ssl *ctx = flb_ssl_new();

    if (ctx == NULL) {
        return NULL;
    }

    ctx->flags |= FLB_SSL_SERVER;

    return ctx;
}

struct flb_ssl *flb_ssl_server_conn(struct flb_ssl *ctx)
{
    struct flb_ssl *cctx = flb_ssl_new();

    if (cctx == NULL) {
        return NULL;
    }

    cctx->config = ctx->config;

    cctx->flags |= FLB_SSL_SERVER_CONN;

    return cctx;
}

void flb_ssl_free(struct flb_ssl *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_ssl_close_notify(&ctx->mbed_ssl);
    mbedtls_net_free(&ctx->mbed_conn);
    mbedtls_ssl_free(&ctx->mbed_ssl);
    mbedtls_entropy_free(&ctx->mbed_entropy);
    mbedtls_ctr_drbg_free(&ctx->mbed_ctr_drbg);
    mbedtls_ssl_config_free(&ctx->mbed_config);
    mbedtls_x509_crt_free(&ctx->mbed_cert);
    mbedtls_pk_free(&ctx->mbed_key);
    flb_free(ctx);
}

int flb_ssl_bind(struct flb_ssl *ctx, const char *ip, const char *port)
{
    int ret;

    ret = mbedtls_net_bind(&ctx->mbed_conn, ip, port, MBEDTLS_NET_PROTO_TCP);
    if (ret) {
        flb_ssl_error(ret);
        return -1;
    }

    return 0;
}

int flb_ssl_getfd(struct flb_ssl *ctx)
{
    return ctx->mbed_conn.fd;
}

int flb_ssl_accept(struct flb_ssl *ctx, struct flb_ssl **cctx)
{
    int ret;

    *cctx = flb_ssl_server_conn(ctx);
    if (*cctx == NULL) {
        flb_errno();
        return -1;
    }

    ret = mbedtls_ssl_setup(&(*cctx)->mbed_ssl, &ctx->mbed_config);
    if (ret) {
        flb_ssl_error(ret);
        return -1;
    }

    ret = mbedtls_net_accept(&ctx->mbed_conn, &(*cctx)->mbed_conn,
                             NULL, 0, NULL);
    if (ret) {
        flb_ssl_error(ret);
        flb_ssl_free(*cctx);
        return -1;
    }

    mbedtls_ssl_set_bio(&(*cctx)->mbed_ssl, &(*cctx)->mbed_conn,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

    return 0;
}

int flb_ssl_handshake(struct flb_ssl *ctx)
{
    int ret;

    ret = mbedtls_ssl_handshake(&ctx->mbed_ssl);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        return FLB_SSL_WANT_POLLIN;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return FLB_SSL_WANT_POLLOUT;
    }
    if (ret) {
        flb_ssl_error(ret);
        return -1;
    }
    ctx->state |= FLB_SSL_HANDSHAKE_COMPLETE;
    return 0;
}

int flb_ssl_read(struct flb_ssl *ctx, char *buf, int len)
{
    int ret;

    if ((ctx->state & FLB_SSL_HANDSHAKE_COMPLETE) == 0) {
        ret = flb_ssl_handshake(ctx);
        if (ret < 0) {
            return ret;
        }
    }

    ret = mbedtls_ssl_read(&ctx->mbed_ssl, (unsigned char *) buf, len);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        return FLB_SSL_WANT_POLLIN;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return FLB_SSL_WANT_POLLOUT;
    }
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        return 0;
    }
    if (ret < 0) {
        flb_ssl_error(ret);
        return -1;
    }
    return ret;
}

int flb_ssl_configure(struct flb_ssl *ctx, struct flb_ssl_config *config)
{
    int ret;

    ctx->config = config;

    ret = mbedtls_ctr_drbg_seed(&ctx->mbed_ctr_drbg,
                                mbedtls_entropy_func,
                                &ctx->mbed_entropy,
                                NULL,
                                0);
    if (ret) {
        flb_ssl_error(ret);
        return -1;
    }

    mbedtls_ssl_conf_rng(&ctx->mbed_config,
                         mbedtls_ctr_drbg_random,
                         &ctx->mbed_ctr_drbg);

    if (config->debug > -1) {
        mbedtls_debug_set_threshold(config->debug);
        mbedtls_ssl_conf_dbg(&ctx->mbed_config, flb_ssl_debug, NULL);
    }

    if (ctx->flags & FLB_SSL_SERVER) {
        return flb_ssl_configure_server(ctx);
    }

    return 0;
}

int flb_ssl_configure_server(struct flb_ssl *ctx)
{
    int ret;

    if (ctx->config->cert_file == NULL || ctx->config->key_file == NULL)  {
        flb_error("[SSL] must set both cert and key");
        return -1;
    }

    ret = mbedtls_ssl_config_defaults(&ctx->mbed_config,
                                      MBEDTLS_SSL_IS_SERVER,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret) {
        flb_ssl_error(ret);
        return -1;
    }

    if (ctx->config->verify_client) {
        mbedtls_ssl_conf_authmode(&ctx->mbed_config,
                                  MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    else {
        mbedtls_ssl_conf_authmode(&ctx->mbed_config, MBEDTLS_SSL_VERIFY_NONE);
    }

    ret = mbedtls_x509_crt_parse_file(&ctx->mbed_cert,
                                      ctx->config->cert_file);
    if (ret) {
        flb_ssl_error(ret);
        return -1;
    }

    ret = mbedtls_pk_parse_keyfile(&ctx->mbed_key,
                                   ctx->config->key_file,
                                   ctx->config->key_passwd);
    if (ret) {
        flb_ssl_error(ret);
        return -1;
    }

    ret = mbedtls_ssl_conf_own_cert(&ctx->mbed_config,
                                    &ctx->mbed_cert,
                                    &ctx->mbed_key);
    if (ret) {
        flb_ssl_error(ret);
        return -1;
    }

    return 0;
}

void flb_ssl_debug(void *ctx, int level, const char *file, int line,
                   const char *str)
{
    (void) level;
    flb_debug("[ssl] %s %04d: %.*s", file, line, strlen(str) - 1, str);
}

void flb_ssl_error_internal(int ret, char *file, int line)
{
    char buf[72];
    mbedtls_strerror(ret, buf, sizeof(buf));
    flb_error("[ssl] %s:%04d: %s", file, line, buf);
}
