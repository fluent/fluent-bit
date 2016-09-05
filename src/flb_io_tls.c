/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2016 Treasure Data Inc.
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

#include <unistd.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>

#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_tls.h>
#include <fluent-bit/flb_io_tls.h>
#include <fluent-bit/flb_stats.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_engine.h>

#define FLB_TLS_CLIENT   "Fluent Bit"

#define io_tls_error(ret) _io_tls_error(ret, __FILE__, __LINE__)

void _io_tls_error(int ret, char *file, int line)
{
    char err_buf[72];

    mbedtls_strerror(ret, err_buf, sizeof(err_buf));
    flb_error("[io_tls] flb_io_tls.c:%i %s", line, err_buf);
}

static inline int io_tls_event_switch(struct flb_upstream_conn *u_conn,
                                      int mask)
{
    int ret;
    struct mk_event *event;
    struct flb_upstream *u = u_conn->u;

    event = &u_conn->event;
    if ((event->mask & mask) == 0) {
        ret = mk_event_add(u->evl,
                           event->fd,
                           FLB_ENGINE_EV_THREAD,
                           mask, &u_conn->event);
        if (ret == -1) {
            flb_error("[io_tls] error changing mask to %i", mask);
            return -1;
        }
    }

    return 0;
}

struct flb_tls_context *flb_tls_context_new(int verify,
                                            char *ca_file, char *crt_file,
                                            char *key_file, char *key_passwd)
{
    int ret;
    struct flb_tls_context *ctx;

    ctx = malloc(sizeof(struct flb_tls_context));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }
    ctx->verify    = verify;
    ctx->certs_set = 0;

    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg,
                                mbedtls_entropy_func,
                                &ctx->entropy,
                                (const unsigned char *) FLB_TLS_CLIENT,
                                sizeof(FLB_TLS_CLIENT) -1);
    if (ret == -1) {
        io_tls_error(ret);
        goto error;
    }

    /* Load root certificates */
    if (!ca_file) {
        ca_file = "/etc/ssl/certs/ca-certificates.crt";
    }
    mbedtls_x509_crt_init(&ctx->ca_cert);
    ret = mbedtls_x509_crt_parse_file(&ctx->ca_cert, ca_file);
    if (ret != 0) {
        flb_error("[TLS] Invalid CA file: %s", ca_file);
        goto error;
    }
    ctx->certs_set |= FLB_TLS_CA_ROOT;

    if (crt_file) {
        mbedtls_x509_crt_init(&ctx->cert);
        ret = mbedtls_x509_crt_parse_file(&ctx->cert, crt_file);
        if (ret != 0) {
            flb_error("[TLS] Invalid Certificate file: %s", crt_file);
            goto error;
        }
        ctx->certs_set |= FLB_TLS_CERT;
    }

    if (key_file) {
        mbedtls_pk_init(&ctx->priv_key);
        ret = mbedtls_pk_parse_keyfile(&ctx->priv_key, key_file, key_passwd);
        if (ret != 0) {
            flb_error("[TLS] Invalid Key file: %s", key_file);
            goto error;
        }
        ctx->certs_set |= FLB_TLS_PRIV_KEY;
    }

    return ctx;

 error:
    free(ctx);
    return NULL;
}

void flb_tls_context_destroy(struct flb_tls_context *ctx)
{
    free(ctx);
}

struct flb_tls_session *flb_tls_session_new(struct flb_tls_context *ctx)
{
    int ret;
    struct flb_tls_session *session;

    session = malloc(sizeof(struct flb_tls_session));
    if (!session) {
        return NULL;
    }

    mbedtls_ssl_init(&session->ssl);
    mbedtls_ssl_config_init(&session->conf);

    ret = mbedtls_ssl_config_defaults(&session->conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        io_tls_error(ret);
    }

    mbedtls_ssl_conf_rng(&session->conf,
                         mbedtls_ctr_drbg_random,
                         &ctx->ctr_drbg);

    if (ctx->verify == FLB_TRUE) {
        mbedtls_ssl_conf_authmode(&session->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }
    else {
        mbedtls_ssl_conf_authmode(&session->conf, MBEDTLS_SSL_VERIFY_NONE);
    }


    /* CA Root */
    if (ctx->certs_set & FLB_TLS_CA_ROOT) {
        mbedtls_ssl_conf_ca_chain(&session->conf, &ctx->ca_cert, NULL);
    }

    /* Specific Cert */
    if (ctx->certs_set & FLB_TLS_CERT) {
        ret = mbedtls_ssl_conf_own_cert(&session->conf,
                                        &ctx->cert,
                                        &ctx->priv_key);
        if (ret != 0) {
            flb_error("[TLS] Error loading certificate with private key");
            goto error;
        }
    }


    ret = mbedtls_ssl_setup(&session->ssl, &session->conf);
    if (ret == -1) {
        flb_error("[tls] ssl_setup");
        goto error;
    }

    return session;

 error:
    free(session);
    return NULL;
}

int tls_session_destroy(struct flb_tls_session *session)
{
    if (session) {
        mbedtls_ssl_free(&session->ssl);
        mbedtls_ssl_config_free(&session->conf);
        free(session);
    }

    return 0;
}

/* Perform a TLS handshake */
int net_io_tls_handshake(void *_u_conn, void *_th)
{
    int ret;
    int flag;
    struct flb_tls_session *session;
    struct flb_upstream_conn *u_conn = _u_conn;
    struct flb_upstream *u = u_conn->u;

    struct flb_thread *th = _th;

    session = flb_tls_session_new(u->tls->context);
    if (!session) {
        flb_error("[io_tls] could not create tls session");
        return -1;
    }

    u_conn->tls_session = session;
    mbedtls_ssl_set_bio(&session->ssl,
                        u_conn,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

 retry_handshake:
    ret = mbedtls_ssl_handshake(&session->ssl);

    if (ret != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret !=  MBEDTLS_ERR_SSL_WANT_WRITE) {
            io_tls_error(ret);
            goto error;
        }

        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            flag = MK_EVENT_WRITE;
        }
        else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            flag = MK_EVENT_READ;
        }
        else {

        }

        /*
         * FIXME: if we need multiple reads we are invoking the same
         * system call multiple times.
         */
        ret = mk_event_add(u->evl,
                           u_conn->event.fd,
                           FLB_ENGINE_EV_THREAD,
                           flag, &u_conn->event);
        if (ret == -1) {
            goto error;
        }

        flb_thread_yield(th, FLB_FALSE);
        goto retry_handshake;
    }
    else {
        flb_trace("[io_tls] Handshake OK");
    }

    if (u_conn->event.status & MK_EVENT_REGISTERED) {
        mk_event_del(u->evl, &u_conn->event);
        MK_EVENT_NEW(&u_conn->event);
    }
    flb_trace("[io_tls] connection OK");
    return 0;

 error:
    if (u_conn->event.status & MK_EVENT_REGISTERED) {
        mk_event_del(u->evl, &u_conn->event);
    }
    tls_session_destroy(u_conn->tls_session);
    u_conn->tls_session = NULL;

    return -1;
}

FLB_INLINE int net_io_tls_read(struct flb_thread *th,
                               struct flb_upstream_conn *u_conn,
                               void *buf, size_t len)
{
    int ret;
    struct flb_upstream *u = u_conn->u;

 retry_read:
    ret = mbedtls_ssl_read(&u_conn->tls_session->ssl, buf, len);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        u_conn->thread = th;
        io_tls_event_switch(u_conn, MK_EVENT_READ);
        flb_thread_yield(th, FLB_FALSE);
        goto retry_read;
    }
    else if (ret < 0) {
        char err_buf[72];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        flb_error("[tls] SSL error: %s", err_buf);

        /* There was an error transmitting data */
        mk_event_del(u->evl, &u_conn->event);
        tls_session_destroy(u_conn->tls_session);
        u_conn->tls_session = NULL;
        return -1;
    }

    return ret;
}

FLB_INLINE int net_io_tls_write(struct flb_thread *th,
                                struct flb_upstream_conn *u_conn,
                                void *data, size_t len, size_t *out_len)
{
    int ret;
    size_t total = 0;
    struct flb_upstream *u = u_conn->u;

    u_conn->thread = th;

 retry_write:
    ret = mbedtls_ssl_write(&u_conn->tls_session->ssl,
                            data + total,
                            len - total);
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        io_tls_event_switch(u_conn, MK_EVENT_WRITE);
        flb_thread_yield(th, FLB_FALSE);
        goto retry_write;
    }
    else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        io_tls_event_switch(u_conn, MK_EVENT_READ);
        flb_thread_yield(th, FLB_FALSE);
        goto retry_write;
    }
    else if (ret < 0) {
        char err_buf[72];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        flb_error("[tls] SSL error: %s", err_buf);

        /* There was an error transmitting data */
        mk_event_del(u->evl, &u_conn->event);
        tls_session_destroy(u_conn->tls_session);
        u_conn->tls_session = NULL;
        return -1;
    }

    /* Update statistics */
    //flb_stats_update(out->stats_fd, ret, 0);

    /* Update counter and check if we need to continue writing */
    total += ret;
    if (total < len) {
        io_tls_event_switch(u_conn, MK_EVENT_WRITE);
        flb_thread_yield(th, FLB_FALSE);
        goto retry_write;
    }

    *out_len = total;
    mk_event_del(u->evl, &u_conn->event);
    return 0;
}
