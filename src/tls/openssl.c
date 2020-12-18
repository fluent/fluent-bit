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

#include <openssl/ssl.h>
#include <openssl/err.h>

struct tls_session {
    SSL *ssl;
};

/* OpenSSL library context */
struct tls_context {
    int debug_level;
    SSL_CTX *ctx;
};

static void tls_info_callback(const SSL *s, int where, int ret)
{
    int w;
    int fd;
    const char *str;

    fd = SSL_get_fd(s);
    w = where & ~SSL_ST_MASK;
    if (w & SSL_ST_CONNECT) {
        str = "SSL_connect";
    }
    else if (w & SSL_ST_ACCEPT) {
        str = "SSL_accept";
    }
    else {
        str = "undefined";
    }

    if (where & SSL_CB_LOOP) {
        flb_debug("[tls] connection #%i %s: %s",
                  fd, str, SSL_state_string_long(s));
    }
    else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        flb_debug("[tls] connection #%i SSL3 alert %s:%s:%s",
                  fd, str,
                  SSL_alert_type_string_long(ret),
                  SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            flb_error("[tls] connection #%i %s: failed in %s",
                      fd, str, SSL_state_string_long(s));
        }
        else if (ret < 0) {
            ret = SSL_get_error(s, ret);
            if (ret == SSL_ERROR_WANT_WRITE) {
                flb_debug("[tls] connection #%i WANT_WRITE", fd);
            }
            else if (ret == SSL_ERROR_WANT_READ) {
                flb_debug("[tls] connection #%i WANT_READ", fd);
            }
            else {
                flb_error("[tls] connection #%i %s: error in %s",
                          fd, str, SSL_state_string_long(s));
            }
        }
    }
}

static void tls_context_destroy(void *ctx_backend)
{
    struct tls_context *ctx = ctx_backend;

    SSL_CTX_free(ctx->ctx);
    flb_free(ctx);
}

static int load_system_certificates(struct tls_context *ctx)
{
    int ret;
    const char ca_path[] = "/etc/ssl/certs/";

    /* For Windows use specific API to read the certs store */
#ifdef _MSC_VER
    //return windows_load_system_certificates(ctx);
#endif

    ret = SSL_CTX_load_verify_locations(ctx->ctx, NULL, ca_path);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
    }
    return 0;
}

static void *tls_context_create(int verify, int debug,
                                const char *vhost,
                                const char *ca_path,
                                const char *ca_file, const char *crt_file,
                                const char *key_file, const char *key_passwd)
{
    int ret;
    SSL_CTX *ssl_ctx;
    struct tls_context *ctx;

    /*
     * Init library ? based in the documentation on OpenSSL >= 1.1.0 is not longer
     * necessary since the library will initialize it self:
     *
     * https://wiki.openssl.org/index.php/Library_Initialization
     */

    /* Create OpenSSL context */
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        flb_error("[openssl] could not create context");
        return NULL;
    }

    ctx = flb_calloc(1, sizeof(struct tls_context));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ctx = ssl_ctx;
    ctx->debug_level = debug;

    /* Verify peer: by default OpenSSL always verify peer */
    if (verify == FLB_FALSE) {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    }

    /* ca_path | ca_file */
    if (!ca_path) {
        load_system_certificates(ctx);
    }
    else if (ca_file) {
        ret = SSL_CTX_load_verify_locations(ctx->ctx, ca_file, NULL);
        if (ret != 1) {
            flb_error("[tls] ca_file '%s' %lu: %s",
                      ca_file,
                      ERR_get_error(),
                      ERR_error_string(ERR_get_error(), NULL));
            goto error;
        }
    }

    /* crt_file */
    if (crt_file) {
        ret = SSL_CTX_use_certificate_chain_file(ssl_ctx, crt_file);
		if (ret != 1) {
            flb_error("[tls] crt_file '%s' %lu: %s",
                      crt_file,
                      ERR_get_error(),
                      ERR_error_string(ERR_get_error(), NULL));
            goto error;
        }
    }

    /* key_file */
    if (key_file) {
        if (key_passwd) {
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx,
                                                   (void *) key_passwd);
        }
        ret = SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file,
                                          SSL_FILETYPE_PEM);
        if (ret != 1) {
            flb_error("[tls] key_file '%s' %lu: %s",
                      key_file,
                      ERR_get_error(),
                      ERR_error_string(ERR_get_error(), NULL));
        }

        /* Make sure the key and certificate file match */
        if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
            flb_error("[tls] private_key '%s' and password don't match",
                      key_file);
            goto error;
        }
    }

    return ctx;

 error:
    tls_context_destroy(ctx);
    return NULL;
}

static void *tls_session_create(struct flb_tls *tls,
                                struct flb_upstream_conn *u_conn)
{
    struct tls_session *session;
    struct tls_context *ctx = tls->ctx;
    SSL *ssl;

    session = flb_calloc(1, sizeof(struct tls_session));
    if (!session) {
        flb_errno();
        return NULL;
    }

    ssl = SSL_new(ctx->ctx);
    if (!ssl) {
        flb_error("[openssl] could create new SSL context");
        flb_free(session);
        return NULL;
    }
    session->ssl = ssl;
    SSL_set_fd(ssl, u_conn->fd);

    /*
     * TLS Debug Levels:
     *
     *  0: No debug,
     *  1: Error
     *  2: State change
     *  3: Informational
     *  4: Verbose
     */
    if (tls->debug == 1) {
        SSL_set_info_callback(session->ssl, tls_info_callback);
    }
    SSL_set_connect_state(ssl);
    return session;
}

static int tls_session_destroy(void *session)
{
    struct tls_session *ptr = session;

    if (!ptr) {
        return 0;
    }

    SSL_shutdown(ptr->ssl);
    SSL_free(ptr->ssl);
    flb_free(ptr);

    return 0;
}

static int tls_net_read(struct flb_upstream_conn *u_conn,
                        void *buf, size_t len)
{
    int ret;
    struct tls_session *session = (struct tls_session *) u_conn->tls_session;

    ret = SSL_read(session->ssl, buf, len);
    if (ret <= 0) {
        ret = SSL_get_error(session->ssl, ret);
        if (ret == SSL_ERROR_WANT_READ) {
            return FLB_TLS_WANT_READ;
        }
        else if (ret < 0) {
            return -1;
        }
    }

    return ret;
}

static int tls_net_write(struct flb_upstream_conn *u_conn,
                         const void *data, size_t len)
{
    int ret;
    size_t total = 0;
    struct tls_session *session = (struct tls_session *) u_conn->tls_session;

    ret = SSL_write(session->ssl,
                    (unsigned char *) data + total,
                    len - total);
    if (ret <= 0) {
        ret = SSL_get_error(session->ssl, ret);
        if (ret == SSL_ERROR_WANT_WRITE) {
            return FLB_TLS_WANT_WRITE;
        }
        else if (ret == SSL_ERROR_WANT_READ) {
            return FLB_TLS_WANT_READ;
        }
        else {
            return -1;
        }
    }

    /* Update counter and check if we need to continue writing */
    return ret;
}

static int tls_net_handshake(struct flb_tls *tls, void *ptr_session)
{
    int ret;
    struct tls_session *session = ptr_session;

    if (tls->vhost) {
        SSL_set_tlsext_host_name(session->ssl, tls->vhost);
    }

    ret = SSL_connect(session->ssl);
    if (ret != 1) {
        ret = SSL_get_error(session->ssl, ret);
        if (ret != SSL_ERROR_WANT_READ &&
            ret != SSL_ERROR_WANT_WRITE) {
            ret = SSL_get_error(session->ssl, ret);
            return -1;
        }

        if (ret == SSL_ERROR_WANT_WRITE) {
            return FLB_TLS_WANT_WRITE;
        }
        else if (ret == SSL_ERROR_WANT_READ) {
            return FLB_TLS_WANT_READ;
        }
    }

    flb_trace("[tls] connection and handshake OK");
    return 0;
}

/* OpenSSL backend registration */
static struct flb_tls_backend tls_openssl = {
    .name            = "openssl",
    .context_create  = tls_context_create,
    .context_destroy = tls_context_destroy,
    .session_create  = tls_session_create,
    .session_destroy = tls_session_destroy,
    .net_read        = tls_net_read,
    .net_write       = tls_net_write,
    .net_handshake   = tls_net_handshake
};
