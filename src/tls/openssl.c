/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <stdio.h>
#include <stdlib.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/tls/flb_tls_info.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/x509v3.h>

#ifdef FLB_SYSTEM_MACOS
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <unistd.h>
#endif

#ifdef FLB_SYSTEM_WINDOWS
    #define strtok_r(str, delimiter, context) \
            strtok_s(str, delimiter, context)
#endif

/*
 * OPENSSL_VERSION_NUMBER has the following semantics
 *
 *     0x010100000L   M = major  F = fix    S = status
 *       MMNNFFPPS    N = minor  P = patch
 */
#define OPENSSL_1_1_0 0x010100000L

/* OpenSSL library context */
struct tls_context {
    int debug_level;
    SSL_CTX *ctx;
    int mode;
    char *alpn;
    pthread_mutex_t mutex;
};

struct tls_session {
    SSL *ssl;
    int fd;
    char alpn[FLB_TLS_ALPN_MAX_LENGTH];
    int continuation_flag;
    struct tls_context *parent;    /* parent struct tls_context ref */
};

static int tls_init(void)
{
/*
 * Explicit initialization is needed for older versions of
 * OpenSSL (before v1.1.0).
 *
 * https://wiki.openssl.org/index.php/Library_Initialization
 */
#if OPENSSL_VERSION_NUMBER < OPENSSL_1_1_0
    OPENSSL_add_all_algorithms_noconf();
    SSL_load_error_strings();
    SSL_library_init();
#endif

    return 0;
}

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

    pthread_mutex_lock(&ctx->mutex);

    SSL_CTX_free(ctx->ctx);

    if (ctx->alpn != NULL) {
        flb_free(ctx->alpn);

        ctx->alpn = NULL;
    }

    pthread_mutex_unlock(&ctx->mutex);

    flb_free(ctx);
}

static int tls_context_server_alpn_select_callback(SSL *ssl,
                                                   const unsigned char **out,
                                                   unsigned char *outlen,
                                                   const unsigned char *in,
                                                   unsigned int inlen,
                                                   void *arg)
{
    int                 result;
    struct tls_context *ctx;

    ctx = (struct tls_context *) arg;

    result = SSL_TLSEXT_ERR_NOACK;

    if (ctx->alpn != NULL) {
        result = SSL_select_next_proto((unsigned char **) out,
                                       outlen,
                                       (const unsigned char *) &ctx->alpn[1],
                                       (unsigned int) ctx->alpn[0],
                                       in,
                                       inlen);

        if (result == OPENSSL_NPN_NEGOTIATED) {
            result = SSL_TLSEXT_ERR_OK;
        }
        else if (result == OPENSSL_NPN_NO_OVERLAP) {
            result = SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }

    return result;
}

static int tls_context_client_alpn_select_callback(SSL *ssl,
                                                   unsigned char **out,
                                                   unsigned char *outlen,
                                                   const unsigned char *in,
                                                   unsigned int inlen,
                                                   void *arg)
{
    return tls_context_server_alpn_select_callback(ssl,
                                                   (const unsigned char **) out,
                                                   outlen,
                                                   in,
                                                   inlen,
                                                   arg);
}

int tls_context_alpn_set(void *ctx_backend, const char *alpn)
{
    size_t              wire_format_alpn_index;
    char               *alpn_token_context;
    char               *alpn_working_copy;
    char               *wire_format_alpn;
    char               *alpn_token;
    int                 result;
    struct tls_context *ctx;

    ctx = (struct tls_context *) ctx_backend;

    result = 0;

    if (alpn != NULL) {
        wire_format_alpn = flb_calloc(strlen(alpn) + 3,
                                      sizeof(char));

        if (wire_format_alpn == NULL) {
            return -1;
        }

        alpn_working_copy = strdup(alpn);

        if (alpn_working_copy == NULL) {
            flb_free(wire_format_alpn);

            return -1;
        }

        wire_format_alpn_index = 1;
        alpn_token_context = NULL;

        alpn_token = strtok_r(alpn_working_copy,
                              ",",
                              &alpn_token_context);

        while (alpn_token != NULL) {
            wire_format_alpn[wire_format_alpn_index] = \
                (char) strlen(alpn_token);

            strcpy(&wire_format_alpn[wire_format_alpn_index + 1],
                   alpn_token);

            wire_format_alpn_index += strlen(alpn_token) + 1;

            alpn_token = strtok_r(NULL,
                                  ",",
                                  &alpn_token_context);
        }

        if (wire_format_alpn_index > 1) {
            wire_format_alpn[0] = (char) wire_format_alpn_index - 1;
            ctx->alpn = wire_format_alpn;
        }

        free(alpn_working_copy);
    }

    if (result != 0) {
        result = -1;
    }
    else {
        if (ctx->mode == FLB_TLS_SERVER_MODE) {
            SSL_CTX_set_alpn_select_cb(
                ctx->ctx,
                tls_context_server_alpn_select_callback,
                ctx);
        }
        else {
            SSL_CTX_set_next_proto_select_cb(
                ctx->ctx,
                tls_context_client_alpn_select_callback,
                ctx);
        }
    }

    return result;
}

#ifdef _MSC_VER
static int windows_load_system_certificates(struct tls_context *ctx)
{
    int ret;
    HANDLE win_store;
    unsigned long err;
    PCCERT_CONTEXT win_cert = NULL;
    const unsigned char *win_cert_data;
    X509_STORE *ossl_store = SSL_CTX_get_cert_store(ctx->ctx);
    X509 *ossl_cert;

    /* Check if OpenSSL certificate store is available */
    if (!ossl_store) {
        flb_error("[tls] failed to retrieve openssl certificate store.");
        return -1;
    }

    /* Open the Windows system certificate store */
    win_store = CertOpenSystemStoreA(0, "Root");
    if (win_store == NULL) {
        flb_error("[tls] cannot open windows certificate store: %lu", GetLastError());
        return -1;
    }

    /* Iterate over certificates in the store */
    while ((win_cert = CertEnumCertificatesInStore(win_store, win_cert)) != NULL) {
        /* Check if the certificate is encoded in ASN.1 DER format */
        if (win_cert->dwCertEncodingType & X509_ASN_ENCODING) {
            /*
             * Decode the certificate into X509 struct.
             *
             * The additional pointer variable is necessary per OpenSSL docs because the
             * pointer is incremented by d2i_X509.
             */
            win_cert_data = win_cert->pbCertEncoded;
            ossl_cert = d2i_X509(NULL, &win_cert_data, win_cert->cbCertEncoded);

            if (!ossl_cert) {
                flb_debug("[tls] cannot parse a certificate, error code: %lu, skipping...", ERR_get_error());
                continue;
            }

            /* Add X509 struct to the openssl cert store */
            ret = X509_STORE_add_cert(ossl_store, ossl_cert);
            if (!ret) {
                err = ERR_get_error();
                if (err == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                    flb_debug("[tls] certificate already exists in the store, skipping.");
                }
                else {
                    flb_warn("[tls] failed to add certificate to openssl store. error code: %lu - %s",
                             err, ERR_error_string(err, NULL));
                }
            }
            X509_free(ossl_cert);
        }
    }

    /* Check for errors during enumeration */
    if (GetLastError() != CRYPT_E_NOT_FOUND) {
        flb_error("[tls] error occurred while enumerating certificates: %lu", GetLastError());
        CertCloseStore(win_store, 0);
        return -1;
    }

    /* Close the Windows system certificate store */
    if (!CertCloseStore(win_store, 0)) {
        flb_error("[tls] cannot close windows certificate store: %lu", GetLastError());
        return -1;
    }

    flb_debug("[tls] successfully loaded certificates from windows system store.");
    return 0;
}
#endif

#ifdef FLB_SYSTEM_MACOS
/* macOS-specific system certificate loading */
static int macos_load_system_certificates(struct tls_context *ctx)
{
    X509_STORE *store = NULL;
    X509 *x509 = NULL;
    SecCertificateRef cert = NULL;
    CFArrayRef certs = NULL;
    CFDataRef certData = NULL;
    CFIndex i = 0;
    const unsigned char *data = NULL;
    char *subject = NULL;
    char *issuer = NULL;
    OSStatus status;
    unsigned long err;
    int ret = -1;
    unsigned long loaded_cert_count = 0;

    /* Retrieve system certificates from macOS Keychain */
    status = SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainSystem, &certs);
    if (status != errSecSuccess || !certs) {
        flb_debug("[tls] failed to load system certificates from keychain, status: %d", status);
        return -1;
    }

    flb_debug("[tls] attempting to load certificates from system keychain of macOS");

    /* Get the SSL context's certificate store */
    store = SSL_CTX_get_cert_store(ctx->ctx);
    if (!store) {
        flb_debug("[tls] failed to get certificate store from SSL context");
        CFRelease(certs);
        return -1;
    }

    /* Load each certificate into the X509 store */
    for (i = 0; i < CFArrayGetCount(certs); i++) {
        cert = (SecCertificateRef) CFArrayGetValueAtIndex(certs, i);
        if (!cert) {
            flb_debug("[tls] invalid certificate reference at index %ld, skipping", i);
            continue;
        }

        certData = SecCertificateCopyData(cert);
        if (!certData) {
            flb_debug("[tls] failed to retrieve data for certificate %ld from keychain, skipping", i);
            continue;
        }

        /* Convert certificate data to X509 */
        data = CFDataGetBytePtr(certData);
        x509 = d2i_X509(NULL, &data, CFDataGetLength(certData));
        CFRelease(certData);

        if (!x509) {
            flb_debug("[tls] failed to parse certificate %ld from keychain, skipping", i);
            continue;
        }

        subject = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
        issuer = X509_NAME_oneline(X509_get_issuer_name(x509), NULL, 0);
        if (subject && issuer) {
            flb_debug("[tls] certificate %ld details - subject: %s, issuer: %s", i, subject, issuer);
        }

        /* Attempt to add certificate to trusted store */
        ret = X509_STORE_add_cert(store, x509);
        if (ret != 1) {
            err = ERR_get_error();
            if (ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                flb_debug("[tls] certificate %ld already exists in the trusted store (duplicate)", i);
            } else {
                flb_debug("[tls] failed to add certificate %ld to trusted store, error code: %lu", i, err);
            }
            X509_free(x509);
            continue;
        }

        loaded_cert_count++;
        flb_debug("[tls] successfully loaded and added certificate %ld to trusted store", i);

        if (subject) {
            OPENSSL_free(subject);
        }
        if (issuer) {
            OPENSSL_free(issuer);
        }
        X509_free(x509);
    }

    CFRelease(certs);
    flb_debug("[tls] finished loading keychain certificates, total loaded: %lu", loaded_cert_count);
    return 0;
}
#endif

static int load_system_certificates(struct tls_context *ctx)
{
    int ret;
    const char *ca_file = FLB_DEFAULT_SEARCH_CA_BUNDLE;

    (void) ret;
    (void) ca_file;

    /* For Windows use specific API to read the certs store */
#ifdef _MSC_VER
    return windows_load_system_certificates(ctx);
#elif defined(__APPLE__)
    return macos_load_system_certificates(ctx);
#else
    if (access(ca_file, R_OK) != 0) {
        ca_file = NULL;
    }

    ret = SSL_CTX_load_verify_locations(ctx->ctx, ca_file, FLB_DEFAULT_CA_DIR);

    if (ret != 1) {
        ERR_print_errors_fp(stderr);
    }
    return 0;
#endif
}

#ifdef FLB_HAVE_DEV
/* This is not thread safe */
static void ssl_key_logger(const SSL *ssl, const char *line)
{
    char *key_log_filename;
    FILE *key_log_file;

    key_log_filename = getenv("SSLKEYLOGFILE");

    if (key_log_filename == NULL) {
        return;
    }

    key_log_file = fopen(key_log_filename, "a");

    if (key_log_file == NULL) {
        return;
    }

    setvbuf(key_log_file, NULL, 0, _IOLBF);

    fprintf(key_log_file, "%s\n", line);

    fclose(key_log_file);
}
#endif

static void *tls_context_create(int verify,
                                int debug,
                                int mode,
                                const char *vhost,
                                const char *ca_path,
                                const char *ca_file,
                                const char *crt_file,
                                const char *key_file,
                                const char *key_passwd)
{
    int ret;
    SSL_CTX *ssl_ctx;
    struct tls_context *ctx;
    char err_buf[256];
    char *key_log_filename;

    /*
     * Init library ? based in the documentation on OpenSSL >= 1.1.0 is not longer
     * necessary since the library will initialize it self:
     *
     * https://wiki.openssl.org/index.php/Library_Initialization
     */

    /* Create OpenSSL context */
#if OPENSSL_VERSION_NUMBER < OPENSSL_1_1_0
    /*
     * SSLv23_method() is actually an equivalent of TLS_client_method()
     * in OpenSSL v1.0.x.
     *
     * https://www.openssl.org/docs/man1.0.2/man3/SSLv23_method.html
     */
    if (mode == FLB_TLS_SERVER_MODE) {
        ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    }
    else {
        ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    }

#else
    if (mode == FLB_TLS_SERVER_MODE) {
        ssl_ctx = SSL_CTX_new(TLS_server_method());
    }
    else {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
    }
#endif

    if (!ssl_ctx) {
        flb_error("[openssl] could not create context");
        return NULL;
    }

    ctx = flb_calloc(1, sizeof(struct tls_context));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

#ifdef FLB_HAVE_DEV
    key_log_filename = getenv("SSLKEYLOGFILE");

    if (key_log_filename != NULL) {
        SSL_CTX_set_keylog_callback(ssl_ctx, ssl_key_logger);
    }
#endif


    ctx->ctx = ssl_ctx;
    ctx->mode = mode;
    ctx->alpn = NULL;
    ctx->debug_level = debug;
    pthread_mutex_init(&ctx->mutex, NULL);

    /* Verify peer: by default OpenSSL always verify peer */
    if (verify == FLB_FALSE) {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    }
    else {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    }

    /* ca_path | ca_file */
    if (ca_path) {
        ret = SSL_CTX_load_verify_locations(ctx->ctx, NULL, ca_path);
        if (ret != 1) {
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf)-1);
            flb_error("[tls] ca_path '%s' %lu: %s",
                      ca_path, ERR_get_error(), err_buf);
            goto error;
        }
    }
    else if (ca_file) {
        ret = SSL_CTX_load_verify_locations(ctx->ctx, ca_file, NULL);
        if (ret != 1) {
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf)-1);
            flb_error("[tls] ca_file '%s' %lu: %s",
                      ca_file, ERR_get_error(), err_buf);
            goto error;
        }
    }
    else {
        load_system_certificates(ctx);
    }

    /* crt_file */
    if (crt_file) {
        ret = SSL_CTX_use_certificate_chain_file(ssl_ctx, crt_file);
        if (ret != 1) {
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf)-1);
            flb_error("[tls] crt_file '%s' %lu: %s",
                      crt_file, ERR_get_error(), err_buf);
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
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf)-1);
            flb_error("[tls] key_file '%s' %lu: %s",
                      crt_file, ERR_get_error(), err_buf);
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
                                int fd)
{
    struct tls_session *session;
    struct tls_context *ctx = tls->ctx;
    SSL *ssl;

    session = flb_calloc(1, sizeof(struct tls_session));
    if (!session) {
        flb_errno();
        return NULL;
    }
    session->parent = ctx;

    pthread_mutex_lock(&ctx->mutex);
    ssl = SSL_new(ctx->ctx);

    if (!ssl) {
        flb_error("[openssl] could create new SSL context");
        flb_free(session);
        pthread_mutex_unlock(&ctx->mutex);
        return NULL;
    }

    session->continuation_flag = FLB_FALSE;
    session->ssl = ssl;
    session->fd = fd;
    SSL_set_fd(ssl, fd);

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
    pthread_mutex_unlock(&ctx->mutex);
    return session;
}

static int tls_session_destroy(void *session)
{
    struct tls_session *ptr = session;
    struct tls_context *ctx;

    if (!ptr) {
        return 0;
    }
    ctx = ptr->parent;

    pthread_mutex_lock(&ctx->mutex);

    if (flb_socket_error(ptr->fd) == 0) {
        SSL_shutdown(ptr->ssl);
    }

    SSL_free(ptr->ssl);
    flb_free(ptr);

    pthread_mutex_unlock(&ctx->mutex);

    return 0;
}

static const char *tls_session_alpn_get(void *session_)
{
    const unsigned char    *backend_alpn_buffer;
    unsigned int            backend_alpn_length;
    struct tls_session     *backend_session;
    struct flb_tls_session *session;

    session = (struct flb_tls_session *) session_;
    backend_session = (struct tls_session *) session->ptr;

    if (backend_session->alpn[0] == '\0') {
        backend_alpn_buffer = NULL;

        SSL_get0_alpn_selected(backend_session->ssl,
                               &backend_alpn_buffer,
                               &backend_alpn_length);

        if (backend_alpn_buffer != NULL) {
            if (backend_alpn_length >= FLB_TLS_ALPN_MAX_LENGTH) {
                backend_alpn_length = FLB_TLS_ALPN_MAX_LENGTH - 1;
            }

            strncpy(backend_session->alpn,
                    (char *) backend_alpn_buffer,
                    backend_alpn_length);
        }
    }

    return backend_session->alpn;
}

static int tls_net_read(struct flb_tls_session *session,
                        void *buf, size_t len)
{
    int ret;
    char err_buf[256];
    struct tls_context *ctx;
    struct tls_session *backend_session;

    if (session->ptr == NULL) {
        flb_error("[tls] error: uninitialized backend session");

        return -1;
    }

    backend_session = (struct tls_session *) session->ptr;

    ctx = backend_session->parent;

    pthread_mutex_lock(&ctx->mutex);

    ERR_clear_error();

    ret = SSL_read(backend_session->ssl, buf, len);

    if (ret <= 0) {
        ret = SSL_get_error(backend_session->ssl, ret);

        if (ret == SSL_ERROR_WANT_READ) {
            ret = FLB_TLS_WANT_READ;
        }
        else if (ret == SSL_ERROR_WANT_WRITE) {
            ret = FLB_TLS_WANT_WRITE;
        }
        else if (ret == SSL_ERROR_SYSCALL) {
            flb_errno();
            ERR_error_string_n(ret, err_buf, sizeof(err_buf)-1);
            flb_error("[tls] syscall error: %s", err_buf);

            /* According to the documentation these are non-recoverable
             * errors so we don't need to screen them before saving them
             * to the net_error field.
             */

            session->connection->net_error = errno;

            ret = -1;
        }
        else if (ret < 0) {
            ERR_error_string_n(ret, err_buf, sizeof(err_buf)-1);
            flb_error("[tls] error: %s", err_buf);
        }
        else {
            ret = -1;
        }
    }

    pthread_mutex_unlock(&ctx->mutex);
    return ret;
}

static int tls_net_write(struct flb_tls_session *session,
                         const void *data, size_t len)
{
    int ret;
    int ssl_ret;
    int err_code;
    char err_buf[256];
    size_t total = 0;
    struct tls_context *ctx;
    struct tls_session *backend_session;

    if (session->ptr == NULL) {
        flb_error("[tls] error: uninitialized backend session");

        return -1;
    }

    backend_session = (struct tls_session *) session->ptr;
    ctx = backend_session->parent;

    pthread_mutex_lock(&ctx->mutex);

    ERR_clear_error();

    ret = SSL_write(backend_session->ssl,
                    (unsigned char *) data + total,
                    len - total);

    if (ret <= 0) {
        ssl_ret = SSL_get_error(backend_session->ssl, ret);

        if (ssl_ret == SSL_ERROR_WANT_WRITE) {
            ret = FLB_TLS_WANT_WRITE;
        }
        else if (ssl_ret == SSL_ERROR_WANT_READ) {
            ret = FLB_TLS_WANT_READ;
        }
        else if (ssl_ret == SSL_ERROR_SYSCALL) {
            if (ERR_get_error() == 0) {
                if (ret == 0) {
                    flb_debug("[tls] connection closed");
                }
                else {
                    flb_error("[tls] syscall error: %s", strerror(errno));
                }
            }
            else {
                err_code = ERR_get_error();
                ERR_error_string_n(err_code, err_buf, sizeof(err_buf) - 1);
                flb_error("[tls] syscall error: %s", err_buf);
            }

            /* According to the documentation these are non-recoverable
             * errors so we don't need to screen them before saving them
             * to the net_error field.
             */

            session->connection->net_error = errno;

            ret = -1;
        }
        else {
            err_code = ERR_get_error();
            if (err_code == 0) {
                flb_error("[tls] unknown error");
            }
            else {
                ERR_error_string_n(err_code, err_buf, sizeof(err_buf) - 1);
                flb_error("[tls] error: %s", err_buf);
            }

            ret = -1;
        }
    }

    pthread_mutex_unlock(&ctx->mutex);

    /* Update counter and check if we need to continue writing */
    return ret;
}

int setup_hostname_validation(struct tls_session *session, const char *hostname)
{
    X509_VERIFY_PARAM *param;

    param = SSL_get0_param(session->ssl);

    if (!param) {
        flb_error("[tls] error: ssl context is invalid");
        return -1;
    }

    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!X509_VERIFY_PARAM_set1_host(param, hostname, 0)) {
        flb_error("[tls] error: hostname parameter vailidation is failed : %s",
                  hostname);
        return -1;
    }

    return 0;
}

static int tls_net_handshake(struct flb_tls *tls,
                             char *vhost,
                             void *ptr_session)
{
    int ret = 0;
    long ssl_code = 0;
    char err_buf[256];
    struct tls_session *session = ptr_session;
    struct tls_context *ctx;
    const char *x509_err;

    ctx = session->parent;
    pthread_mutex_lock(&ctx->mutex);

    if (!session->continuation_flag) {
        if (tls->mode == FLB_TLS_CLIENT_MODE) {
            SSL_set_connect_state(session->ssl);

            if (ctx->alpn != NULL) {
                ret = SSL_set_alpn_protos(session->ssl,
                                          (const unsigned char *) &ctx->alpn[1],
                                          (unsigned int) ctx->alpn[0]);

                if (ret != 0) {
                    flb_error("[tls] error: alpn setup failed : %d", ret);
                    pthread_mutex_unlock(&ctx->mutex);
                    return -1;
                }
            }
        }
        else if (tls->mode == FLB_TLS_SERVER_MODE) {
            SSL_set_accept_state(session->ssl);
        }
        else {
            flb_error("[tls] error: invalid tls mode : %d", tls->mode);
            pthread_mutex_unlock(&ctx->mutex);
            return -1;
        }

        if (vhost != NULL) {
            SSL_set_tlsext_host_name(session->ssl, vhost);
        }
        else if (tls->vhost) {
            SSL_set_tlsext_host_name(session->ssl, tls->vhost);
        }
    }

    if (tls->verify == FLB_TRUE &&
        tls->verify_hostname == FLB_TRUE) {
        if (vhost != NULL) {
            ret = setup_hostname_validation(session, vhost);
        }
        else if (tls->vhost) {
            ret = setup_hostname_validation(session, tls->vhost);
        }

        if (ret != 0) {
            pthread_mutex_unlock(&ctx->mutex);
            return -1;
        }
    }

    ERR_clear_error();

    if (tls->mode == FLB_TLS_CLIENT_MODE) {
        ret = SSL_connect(session->ssl);
    }
    else if (tls->mode == FLB_TLS_SERVER_MODE) {
        ret = SSL_accept(session->ssl);
    }

    if (ret != 1) {
        ret = SSL_get_error(session->ssl, ret);
        if (ret != SSL_ERROR_WANT_READ &&
            ret != SSL_ERROR_WANT_WRITE) {
            ret = SSL_get_error(session->ssl, ret);
            /* The SSL_ERROR_SYSCALL with errno value of 0 indicates unexpected
             *  EOF from the peer. This is fixed in OpenSSL 3.0.
             */

            if (ret == 0) {
                ssl_code = SSL_get_verify_result(session->ssl);
                if (ssl_code != X509_V_OK) {
                    /* Refer to: https://x509errors.org/ */
                    x509_err = X509_verify_cert_error_string(ssl_code);
                    flb_error("[tls] certificate verification failed, reason: %s (X509 code: %ld)", x509_err, ssl_code);
                }
                else {
                    flb_error("[tls] error: unexpected EOF");
                }
            } else {
                ERR_error_string_n(ret, err_buf, sizeof(err_buf)-1);
                flb_error("[tls] error: %s", err_buf);
            }

            pthread_mutex_unlock(&ctx->mutex);

            return -1;
        }

        if (ret == SSL_ERROR_WANT_WRITE) {
            pthread_mutex_unlock(&ctx->mutex);

            session->continuation_flag = FLB_TRUE;

            return FLB_TLS_WANT_WRITE;
        }
        else if (ret == SSL_ERROR_WANT_READ) {
            pthread_mutex_unlock(&ctx->mutex);

            session->continuation_flag = FLB_TRUE;

            return FLB_TLS_WANT_READ;
        }
    }

    session->continuation_flag = FLB_FALSE;

    pthread_mutex_unlock(&ctx->mutex);
    flb_trace("[tls] connection and handshake OK");
    return 0;
}

/* OpenSSL backend registration */
static struct flb_tls_backend tls_openssl = {
    .name                 = "openssl",
    .context_create       = tls_context_create,
    .context_destroy      = tls_context_destroy,
    .context_alpn_set     = tls_context_alpn_set,
    .session_alpn_get     = tls_session_alpn_get,
    .session_create       = tls_session_create,
    .session_destroy      = tls_session_destroy,
    .net_read             = tls_net_read,
    .net_write            = tls_net_write,
    .net_handshake        = tls_net_handshake,
};
