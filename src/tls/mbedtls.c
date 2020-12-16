/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/tls/flb_tls.h>

#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/error.h>

#define tls_error(ret) _io_tls_error(ret, __FILE__, __LINE__)

struct tls_session {
    struct mbedtls_ssl_context ssl;
    struct mbedtls_ssl_config conf;
    mbedtls_net_context net_context;
};

/* mbedTLS library context */
struct tls_context {
    uint16_t certs_set;                /* CA_ROOT | CERT | PRIV_KEY */
    mbedtls_x509_crt ca_cert;          /* CA Root      */
    mbedtls_x509_crt cert;             /* Certificate  */
    mbedtls_pk_context priv_key;       /* Private key  */
    mbedtls_dhm_context dhm;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
};

/* Error formatter */
static void _io_tls_error(int ret, char *file, int line)
{
    char err_buf[72];

    mbedtls_strerror(ret, err_buf, sizeof(err_buf));
    flb_error("[tls] %s:%i %s", file, line, err_buf);
}

static void tls_debug(void *ctx, int level,
                      const char *file, int line,
                      const char *str)
{
    (void) level;

    flb_debug("[io_tls] %s %04i: %s", file + sizeof(FLB_SOURCE_DIR) - 1,
              line, str);
}

#ifdef _MSC_VER
static int windows_load_system_certificates(struct tls_context *ctx)
{
    int ret;

    HANDLE h;
    PCCERT_CONTEXT cert = NULL;

    h = CertOpenSystemStoreA(NULL, "Root");
    if (h == NULL) {
        flb_error("[tls] Cannot open cert store: %i", GetLastError());
        return -1;
    }

    while (cert = CertEnumCertificatesInStore(h, cert)) {
        if (cert->dwCertEncodingType & X509_ASN_ENCODING) {
            ret = mbedtls_x509_crt_parse(&ctx->ca_cert,
                                         cert->pbCertEncoded,
                                         cert->cbCertEncoded);
            if (ret) {
                flb_debug("[tls] cannot parse a certificate. skipping...");
            }
        }
    }

    if (!CertCloseStore(h, 0)) {
        flb_error("[tks] Cannot close cert store: %i", GetLastError());
        return -1;
    }
    return 0;
}
#endif

static int load_system_certificates(struct tls_context *ctx)
{
    int ret;
    const char ca_path[] = "/etc/ssl/certs/";

    /* For Windows use specific API to read the certs store */
#ifdef _MSC_VER
    return windows_load_system_certificates(ctx);
#endif

    /* Other systems certs handling */
    ret = mbedtls_x509_crt_parse_path(&ctx->ca_cert, ca_path);
    if (ret < 0) {
        flb_error("[tls] Cannot read certificates from %s", ca_path);
        return -1;
    }

    return 0;
}

static void tls_context_destroy(void *ctx_backend)
{
    struct tls_context *ctx = ctx_backend;

    if (ctx->certs_set & FLB_TLS_CA_ROOT) {
        mbedtls_x509_crt_free(&ctx->ca_cert);
    }

    if (ctx->certs_set & FLB_TLS_CERT) {
        mbedtls_x509_crt_free(&ctx->cert);
    }

    if (ctx->certs_set & FLB_TLS_PRIV_KEY) {
        mbedtls_pk_free(&ctx->priv_key);
    }

    flb_free(ctx);
}

static void *tls_context_create(int verify, int debug,
                                const char *vhost,
                                const char *ca_path,
                                const char *ca_file, const char *crt_file,
                                const char *key_file, const char *key_passwd)
{
    int ret;
    struct tls_context *ctx;

    ctx = flb_calloc(1, sizeof(struct tls_context));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg,
                                mbedtls_entropy_func,
                                &ctx->entropy,
                                (const unsigned char *) FLB_TLS_CLIENT,
                                sizeof(FLB_TLS_CLIENT) -1);
    if (ret == -1) {
        tls_error(ret);
        goto error;
    }

    /* CA (Certificate Authority) */
    mbedtls_x509_crt_init(&ctx->ca_cert);
    if (ca_file) {
        ret = mbedtls_x509_crt_parse_file(&ctx->ca_cert, ca_file);
        if (ret < 0) {
            tls_error(ret);
            flb_error("[TLS] Invalid CA file: %s", ca_file);
            goto error;
        }
    }
    else if (ca_path) {
        ret = mbedtls_x509_crt_parse_path(&ctx->ca_cert, ca_path);
        if (ret < 0) {
            tls_error(ret);
            flb_error("[TLS] error reading certificates from %s", ca_path);
            goto error;
        }
    }
    else {
        ret = load_system_certificates(ctx);
        if (ret < 0) {
            goto error;
        }
    }
    ctx->certs_set |= FLB_TLS_CA_ROOT;

    /* Certificate file */
    if (crt_file) {
        mbedtls_x509_crt_init(&ctx->cert);
        ret = mbedtls_x509_crt_parse_file(&ctx->cert, crt_file);
        if (ret < 0) {
            tls_error(ret);
            flb_error("[TLS] Invalid Certificate file: %s", crt_file);
            goto error;
        }
        ctx->certs_set |= FLB_TLS_CERT;
    }

    /* Certificate key file */
    if (key_file) {
        mbedtls_pk_init(&ctx->priv_key);
        ret = mbedtls_pk_parse_keyfile(&ctx->priv_key, key_file, key_passwd);
        if (ret < 0) {
            tls_error(ret);
            flb_error("[TLS] Invalid Key file: %s", key_file);
            goto error;
        }
        ctx->certs_set |= FLB_TLS_PRIV_KEY;
    }

    return ctx;

 error:
    tls_context_destroy(ctx);
    return NULL;
}

static void *tls_session_create(struct flb_tls *tls,
                                struct flb_upstream_conn *u_conn)
{
    int ret;
    struct tls_session *session;
    struct tls_context *ctx = tls->ctx;

    session = flb_calloc(1, sizeof(struct tls_session));
    if (!session) {
        flb_errno();
        return NULL;
    }

    mbedtls_ssl_config_init(&session->conf);
    ret = mbedtls_ssl_config_defaults(&session->conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        tls_error(ret);
    }

    mbedtls_ssl_conf_rng(&session->conf,
                         mbedtls_ctr_drbg_random,
                         &ctx->ctr_drbg);
    if (tls->debug >= 0) {
        mbedtls_ssl_conf_dbg(&session->conf, tls_debug, NULL);
        mbedtls_debug_set_threshold(tls->debug);
    }

    if (tls->verify == FLB_TRUE) {
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

    session->net_context.fd = u_conn->fd;

    mbedtls_ssl_set_hostname(&session->ssl, tls->vhost);
    mbedtls_ssl_set_bio(&session->ssl,
                        &session->net_context,//&u_conn->tls_net_context,
                        mbedtls_net_send, mbedtls_net_recv, NULL);
    return session;

 error:
    flb_free(session);
    return NULL;
}

static int tls_session_destroy(void *session)
{
    struct tls_session *ptr = session;

    if (!ptr) {
        return 0;
    }

    mbedtls_ssl_close_notify(&ptr->ssl);
    mbedtls_ssl_free(&ptr->ssl);
    mbedtls_ssl_config_free(&ptr->conf);
    flb_free(ptr);

    return 0;
}

static int tls_net_read(struct flb_upstream_conn *u_conn,
                        void *buf, size_t len)
{
    int ret;
    char err_buf[72];
    struct tls_session *session = (struct tls_session *) u_conn->tls_session;

    ret = mbedtls_ssl_read(&session->ssl, buf, len);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        return FLB_TLS_WANT_READ;
    }
    else if (ret < 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        flb_error("[tls] SSL error: %s", err_buf);
        return -1;
    }
    else if (ret == 0) {
        flb_debug("[tls] SSL connection closed by peer");
        return -1;
    }

    return ret;
}

static int tls_net_write(struct flb_upstream_conn *u_conn,
                         const void *data, size_t len)
{
    int ret;
    size_t total = 0;
    char err_buf[72];
    struct tls_session *session = (struct tls_session *) u_conn->tls_session;

    ret = mbedtls_ssl_write(&session->ssl,
                            (unsigned char *) data + total,
                            len - total);
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return FLB_TLS_WANT_WRITE;
    }
    else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        return FLB_TLS_WANT_READ;
    }
    else if (ret < 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        flb_error("[tls] SSL error: %s", err_buf);
        return -1;
    }

    /* Update counter and check if we need to continue writing */
    return ret;
}

static int tls_net_handshake(struct flb_tls *tls, void *ptr_session)
{
    int ret;
    struct tls_session *session = ptr_session;

    ret = mbedtls_ssl_handshake(&session->ssl);
    if (ret != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret !=  MBEDTLS_ERR_SSL_WANT_WRITE) {
            tls_error(ret);
            return -1;
        }

        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return FLB_TLS_WANT_WRITE;
        }
        else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            return FLB_TLS_WANT_READ;
        }
    }

    flb_trace("[tls] connection and handshake OK");
    return 0;
}

/* MbedTLS backend registration */
static struct flb_tls_backend tls_mbedtls = {
    .name            = "mbedtls",
    .context_create  = tls_context_create,
    .context_destroy = tls_context_destroy,
    .session_create  = tls_session_create,
    .session_destroy = tls_session_destroy,
    .net_read        = tls_net_read,
    .net_write       = tls_net_write,
    .net_handshake   = tls_net_handshake
};
