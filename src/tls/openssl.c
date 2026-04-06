/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
    #include <wincrypt.h>
    #ifndef CERT_FIND_SHA256_HASH
        /* Older SDKs may not define this */
        #define CERT_FIND_SHA256_HASH  0x0001000d
    #endif
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
#if defined(FLB_SYSTEM_WINDOWS)
    char *certstore_name;
    int use_enterprise_store;
    CRYPT_HASH_BLOB *allowed_thumbprints;
    size_t allowed_thumbprints_count;
#endif
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

#if defined(FLB_SYSTEM_WINDOWS)
    if (ctx->certstore_name != NULL) {
        flb_free(ctx->certstore_name);

        ctx->certstore_name = NULL;
    }
    if (ctx->allowed_thumbprints) {
        /* We allocated each blob->pbData; free them too */
        for (size_t i = 0; i < ctx->allowed_thumbprints_count; i++) {
            if (ctx->allowed_thumbprints[i].pbData) {
                flb_free(ctx->allowed_thumbprints[i].pbData);
            }
        }
        flb_free(ctx->allowed_thumbprints);
        ctx->allowed_thumbprints = NULL;
        ctx->allowed_thumbprints_count = 0;
    }
#endif

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

int tls_context_alpn_set(void *ctx_backend, const char *alpn)
{
    size_t              wire_format_alpn_index;
    size_t              wire_format_alpn_length;
    size_t              alpn_token_length;
    unsigned int        active_alpn_length;
    char               *active_alpn;
    char               *alpn_token_context;
    char               *alpn_working_copy;
    char               *new_alpn;
    char               *wire_format_alpn;
    char               *alpn_token;
    int                 result;
    struct tls_context *ctx;

    ctx = (struct tls_context *) ctx_backend;

    result = 0;
    new_alpn = NULL;

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
            alpn_token_length = strlen(alpn_token);
            wire_format_alpn_length = wire_format_alpn_index - 1;

            if (alpn_token_length > 255) {
                flb_error("[tls] error: alpn token length exceeds 255 bytes");

                free(alpn_working_copy);
                flb_free(wire_format_alpn);
                return -1;
            }

            if (wire_format_alpn_length + alpn_token_length + 1 > 255) {
                flb_error("[tls] error: alpn wire format length exceeds "
                          "255 bytes");

                free(alpn_working_copy);
                flb_free(wire_format_alpn);
                return -1;
            }

            wire_format_alpn[wire_format_alpn_index] = \
                (char) alpn_token_length;

            memcpy(&wire_format_alpn[wire_format_alpn_index + 1],
                   alpn_token,
                   alpn_token_length);

            wire_format_alpn_index += alpn_token_length + 1;

            alpn_token = strtok_r(NULL,
                                  ",",
                                  &alpn_token_context);
        }

        if (wire_format_alpn_index > 1) {
            if (wire_format_alpn_index - 1 > 255) {
                flb_error("[tls] error: alpn wire format length exceeds "
                          "255 bytes");

                free(alpn_working_copy);
                flb_free(wire_format_alpn);
                return -1;
            }

            wire_format_alpn[0] = (char) (wire_format_alpn_index - 1);
            new_alpn = wire_format_alpn;
        }
        else {
            flb_free(wire_format_alpn);
        }

        free(alpn_working_copy);
    }

    active_alpn = ctx->alpn;

    if (alpn != NULL) {
        active_alpn = new_alpn;
    }

    if (ctx->mode == FLB_TLS_SERVER_MODE) {
        SSL_CTX_set_alpn_select_cb(
            ctx->ctx,
            tls_context_server_alpn_select_callback,
            ctx);
    }
    else {
        if (active_alpn == NULL) {
            result = -1;
        }
        else {
            active_alpn_length =
                (unsigned int) ((const unsigned char *) active_alpn)[0];

            if (SSL_CTX_set_alpn_protos(
                     ctx->ctx,
                     (const unsigned char *) &active_alpn[1],
                     active_alpn_length) != 0) {
                result = -1;
            }
        }
    }

    if (result == 0 && alpn != NULL) {
        if (ctx->alpn != NULL) {
            flb_free(ctx->alpn);
        }

        ctx->alpn = new_alpn;
        new_alpn = NULL;
    }

    if (new_alpn != NULL) {
        flb_free(new_alpn);
    }

    return result;
}

static int tls_context_set_verify_client(void *ctx_backend, int verify_client)
{
    struct tls_context *ctx = ctx_backend;
    int mode;

    if (ctx->mode == FLB_TLS_SERVER_MODE && verify_client == FLB_TRUE) {
        mode = SSL_CTX_get_verify_mode(ctx->ctx);
        mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        SSL_CTX_set_verify(ctx->ctx, mode, NULL);
    }

    return 0;
}

#ifdef _MSC_VER
/* Parse certstore_name prefix like
 *
 *   "My"                        -> no prefix, leave location untouched
 *   "CurrentUser\\My"           -> CERT_SYSTEM_STORE_CURRENT_USER, "My"
 *   "HKCU\\My"                  -> CERT_SYSTEM_STORE_CURRENT_USER, "My"
 *   "LocalMachine\\My"          -> CERT_SYSTEM_STORE_LOCAL_MACHINE, "My"
 *   "HKLM\\My"                  -> CERT_SYSTEM_STORE_LOCAL_MACHINE, "My"
 *   "LocalMachineEnterprise\\My"-> CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE, "My"
 *   "HKLME\\My"                 -> CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE, "My"
 *
 * Also accepts '/' as separator.
 *
 * If no known prefix is found, *store_name_out is left as-is and *location_flags
 * is not modified (so legacy behavior is preserved).
 */
static int windows_resolve_certstore_location(const char *configured_name,
                                              DWORD *location_flags,
                                              const char **store_name_out)
{
    const char *name;
    const char *sep;
    size_t prefix_len;
    char prefix_buf[32];
    size_t i;
    size_t len = 0;
    char c;

    if (!configured_name || !*configured_name) {
        return FLB_FALSE;
    }

    name = configured_name;
    len = strlen(name);

    /* Optional "Cert:\" prefix (PowerShell style) */
    if (len >= 6 &&
        strncasecmp(name, "cert:", 5) == 0 &&
        (name[5] == '\\' || name[5] == '/')) {
        name += 6;
    }

    /* Find first '\' or '/' separator */
    sep = name;
    while (*sep != '\0' && *sep != '\\' && *sep != '/') {
        sep++;
    }

    if (*sep == '\0') {
        /* No prefix, only store name (e.g. "My" or "Root")
         * -> keep legacy behavior (location_flags unchanged).
         */
        *store_name_out = name;

        return FLB_FALSE;
    }

    /* Copy and lowercase prefix into buffer */
    prefix_len = (size_t)(sep - name);
    if (prefix_len >= sizeof(prefix_buf)) {
        prefix_len = sizeof(prefix_buf) - 1;
    }

    for (i = 0; i < prefix_len; i++) {
        c = (char) name[i];

        if (c >= 'A' && c <= 'Z') {
            c = (char) (c - 'A' + 'a');
        }
        prefix_buf[i] = c;
    }
    prefix_buf[prefix_len] = '\0';

    /* Default: keep *location_flags as-is */
    if (strcmp(prefix_buf, "currentuser") == 0 ||
        strcmp(prefix_buf, "hkcu") == 0) {
        *location_flags = CERT_SYSTEM_STORE_CURRENT_USER;
    }
    else if (strcmp(prefix_buf, "localmachine") == 0 ||
             strcmp(prefix_buf, "hklm") == 0) {
        *location_flags = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    }
    else if (strcmp(prefix_buf, "localmachineenterprise") == 0 ||
             strcmp(prefix_buf, "hklme") == 0) {
        *location_flags = CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE;
    }
    else {
        /* Unknown prefix -> treat entire string as store name */
        *store_name_out = configured_name;

        return FLB_FALSE;
    }

    /* Store name part after the separator "\" or "/" */
    *store_name_out = sep + 1;

    return FLB_TRUE;
}

static int windows_load_system_certificates(struct tls_context *ctx)
{
    int ret;
    HANDLE win_store;
    unsigned long err;
    PCCERT_CONTEXT win_cert = NULL;
    const unsigned char *win_cert_data;
    X509_STORE *ossl_store = SSL_CTX_get_cert_store(ctx->ctx);
    X509 *ossl_cert;
    char *configured_name = "Root";
    const char *store_name = "Root";
    DWORD store_location = CERT_SYSTEM_STORE_CURRENT_USER;
    int has_location_prefix = FLB_FALSE;

    /* Check if OpenSSL certificate store is available */
    if (!ossl_store) {
        flb_error("[tls] failed to retrieve openssl certificate store.");
        return -1;
    }

    if (ctx->certstore_name) {
        configured_name = ctx->certstore_name;
        store_name = ctx->certstore_name;
    }

    /* First, resolve explicit prefix if present */
    has_location_prefix = windows_resolve_certstore_location(configured_name,
                                                             &store_location,
                                                             &store_name);

    /* Backward compatibility:
     * If no prefix was given (store_name == configured_name) and
     * use_enterprise_store is set, override location accordingly.
     */
    if (has_location_prefix == FLB_FALSE && ctx->use_enterprise_store) {
        store_location = CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE;
    }

    /* Open the Windows certificate store for the resolved location */
    if (store_location == CERT_SYSTEM_STORE_CURRENT_USER) {
        /* Keep using CertOpenSystemStoreA for current user to avoid
         * changing existing behavior.
         */
        win_store = CertOpenSystemStoreA(0, store_name);
    }
    else {
        win_store = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                  0,
                                  0,
                                  store_location,
                                  store_name);
    }

    if (win_store == NULL) {
        flb_error("[tls] cannot open windows certificate store: %lu", GetLastError());
        return -1;
    }

    if (ctx->allowed_thumbprints_count > 0) {
        size_t loaded = 0;
        DWORD find_type = 0;
        size_t i;

        for (i = 0; i < ctx->allowed_thumbprints_count; i++) {
            find_type = (ctx->allowed_thumbprints[i].cbData == 20)
                         ? CERT_FIND_SHA1_HASH
                         : CERT_FIND_SHA256_HASH;

            win_cert = NULL;
            while ((win_cert = CertFindCertificateInStore(win_store,
                                                          X509_ASN_ENCODING,
                                                          0,
                                                          find_type,
                                                          &ctx->allowed_thumbprints[i],
                                                          win_cert)) != NULL) {

                win_cert_data = win_cert->pbCertEncoded;
                ossl_cert = d2i_X509(NULL, &win_cert_data, win_cert->cbCertEncoded);
                if (!ossl_cert) {
                    flb_debug("[tls] parse failed for matched certificate (thumbprint idx %zu)", i);
                    continue;
                }

                ret = X509_STORE_add_cert(ossl_store, ossl_cert);
                if (ret != 1) {
                    unsigned long err = ERR_get_error();
                    if (ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                        flb_debug("[tls] certificate already present (thumbprint idx %zu).", i);
                    }
                    else {
                        flb_warn("[tls] add_cert failed: %s", ERR_error_string(err, NULL));
                    }
                }
                else {
                    loaded++;
                }
                X509_free(ossl_cert);
            }
        }

        if (!CertCloseStore(win_store, 0)) {
            flb_error("[tls] cannot close windows certificate store: %lu", GetLastError());
            return -1;
        }

        if (loaded == 0) {
            flb_warn("[tls] no certificates loaded by thumbprint from '%s'.", configured_name);
        }
        else {
            flb_debug("[tls] loaded %zu certificate(s) by thumbprint from '%s'.", loaded, configured_name);
        }
        return 0;
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

    flb_debug("[tls] successfully loaded certificates from windows system %s store.", 
              configured_name);
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
        SSL_CTX_free(ssl_ctx);
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
#if defined(FLB_SYSTEM_WINDOWS)
    ctx->certstore_name = NULL;
    ctx->use_enterprise_store = 0;
    ctx->allowed_thumbprints = NULL;
    ctx->allowed_thumbprints_count = 0;
#endif
    pthread_mutex_init(&ctx->mutex, NULL);

    /* Verify peer: by default OpenSSL always verify peer */
    if (verify == FLB_FALSE) {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
    }
    else {
        int verify_flags = SSL_VERIFY_PEER;
        SSL_CTX_set_verify(ssl_ctx, verify_flags, NULL);
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
                      key_file, ERR_get_error(), err_buf);
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

#if !defined(TLS1_3_VERSION)
#  define TLS1_3_VERSION 0x0304
#endif

struct tls_proto_def {
    char *name;
    int ver;
};

struct tls_proto_options {
    int ver;
    int no_opt;
};

static int parse_proto_version(const char *proto_ver)
{
    int i;
    struct tls_proto_def defs[] = {
        { "SSLv2", SSL2_VERSION },
        { "SSLv3", SSL3_VERSION },
        { "TLSv1", TLS1_VERSION },
        { "TLSv1.1", TLS1_1_VERSION },
        { "TLSv1.2", TLS1_2_VERSION },
#if defined(TLS1_3_VERSION)
        { "TLSv1.3", TLS1_3_VERSION },
#endif
        { NULL, 0 },
    };

    if (proto_ver == NULL) {
        return 0;
    }

    for (i = 0; defs[i].name != NULL; i++) {
        if (strncasecmp(defs[i].name, proto_ver, strlen(proto_ver)) == 0) {
            return defs[i].ver;
        }
    }

    return -1;
}

#if defined(TLS1_3_VERSION)
#define DEFAULT_MAX_VERSION TLS1_3_VERSION
#else
#define DEFAULT_MAX_VERSION TLS1_2_VERSION
#endif

static int tls_set_minmax_proto(struct flb_tls *tls,
                                const char *min_version,
                                const char *max_version)
{
    int i;
    unsigned long sum = 0, opts = 0;
    int min = TLS1_1_VERSION;
    int max = DEFAULT_MAX_VERSION;
    int val = -1;
    struct tls_context *ctx = tls->ctx;

    struct tls_proto_options tls_options[] = {
        { SSL2_VERSION, SSL_OP_NO_SSLv2 },
        { SSL3_VERSION, SSL_OP_NO_SSLv3 },
        { TLS1_VERSION, SSL_OP_NO_TLSv1 },
        { TLS1_1_VERSION, SSL_OP_NO_TLSv1_1 },
        { TLS1_2_VERSION, SSL_OP_NO_TLSv1_2 },
#if defined(TLS1_3_VERSION) && defined(SSL_OP_NO_TLSv1_3)
        { TLS1_3_VERSION, SSL_OP_NO_TLSv1_3 },
#endif
    };

    if (!ctx) {
        return -1;
    }

    val = parse_proto_version(min_version);
    if (val >= 0) {
        min = val;
    }

    val = parse_proto_version(max_version);
    if (val >= 0) {
        max = val;
    }

    pthread_mutex_lock(&ctx->mutex);

    for (i = 0; i < sizeof(tls_options) / sizeof(struct tls_proto_options); i++) {
        sum |= tls_options[i].no_opt;
        if ((min && min > tls_options[i].ver) ||
            (max && max < tls_options[i].ver)) {
            opts |= tls_options[i].no_opt;
        }
    }
    SSL_CTX_clear_options(ctx->ctx, sum);
    SSL_CTX_set_options(ctx->ctx, opts);

    pthread_mutex_unlock(&ctx->mutex);

    return 0;
}

static int tls_set_ciphers(struct flb_tls *tls, const char *ciphers)
{
    struct tls_context *ctx = tls->ctx;
    int ret;

    pthread_mutex_lock(&ctx->mutex);

    ret = SSL_CTX_set_cipher_list(ctx->ctx, ciphers);

    pthread_mutex_unlock(&ctx->mutex);

    if (ret == 0) {
        return -1;
    }

    return 0;
}

#if defined(FLB_SYSTEM_WINDOWS)
static int tls_set_certstore_name(struct flb_tls *tls, const char *certstore_name)
{
    struct tls_context *ctx = tls->ctx;

    pthread_mutex_lock(&ctx->mutex);

    ctx->certstore_name = flb_strdup(certstore_name);

    pthread_mutex_unlock(&ctx->mutex);

    return 0;
}

static int tls_set_use_enterprise_store(struct flb_tls *tls, int use_enterprise)
{
    struct tls_context *ctx = tls->ctx;

    pthread_mutex_lock(&ctx->mutex);

    ctx->use_enterprise_store = !!use_enterprise;

    pthread_mutex_unlock(&ctx->mutex);

    return 0;
}

static int hex_nibble(int c) {
    if      (c >= '0' && c <= '9') {
        return c - '0';
    }
    else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static char *compact_hex(const char *s) {
    size_t n = 0;
    size_t i;
    char *out = flb_calloc(1, strlen(s) + 1);

    if (!out) {
        return NULL;
    }

    for (i = 0; s[i]; i++) {
        int c = s[i];
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F')) {
            out[n++] = (char)c;
        }
    }
    out[n] = '\0';
    return out;
}

static unsigned char *hex_to_bytes(const char *hex, size_t *out_len) {
    unsigned char *buf = NULL;
    size_t i;
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        return NULL;
    }

    buf = flb_calloc(1, len / 2);
    if (!buf) {
        return NULL;
    }

    for (i = 0; i < len; i += 2) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i+1]);
        if (hi < 0 || lo < 0) {
            flb_free(buf);
            return NULL;
        }
        buf[i/2] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = len / 2;
    return buf;
}

static int windows_set_allowed_thumbprints(struct tls_context *ctx, const char *thumbprints) 
{
    char *token_ctx = NULL, *tok = NULL;
    size_t cap = 4, count = 0;
    char *hex = NULL;
    struct cfl_list *kvs;
    struct cfl_list *head;
    struct cfl_split_entry *cur;
    CRYPT_HASH_BLOB *arr;
    size_t bytes_len = 0;
    unsigned char *bytes = NULL;

    if (!thumbprints || !*thumbprints) {
        return 0;
    }

    arr = flb_calloc(cap, sizeof(*arr));
    if (!arr) {
        return -1;
    }

    kvs = cfl_utils_split(thumbprints, ',', -1);
    cfl_list_foreach(head, kvs) {
        cur = cfl_list_entry(head, struct cfl_split_entry, _head);
        tok = cur->value;
        hex = compact_hex(tok);
        if (hex && *hex) {
            bytes = hex_to_bytes(hex, &bytes_len);
            if (bytes && (bytes_len == 20 || bytes_len == 32)) {
                if (count == cap) {
                    cap *= 2;
                    CRYPT_HASH_BLOB *tmp = flb_realloc(arr, cap * sizeof(*arr));
                    if (!tmp) {
                        flb_free(bytes);
                        break;
                    }
                    arr = tmp;
                }
                arr[count].cbData = (DWORD)bytes_len;
                arr[count].pbData = bytes;
                count++;
            }
            else {
                flb_warn("[tls] ignoring thumbprint '%s' (length must be 40 or 64 hex chars after stripping).", tok);
                if (bytes) {
                    flb_free(bytes);
                }
            }
        }
        if (hex) {
            flb_free(hex);
        }
    }
    cfl_utils_split_free(kvs);

    if (count == 0) {
        if (arr) {
            flb_free(arr);
        }
        flb_warn("[tls] no valid thumbprints parsed.");
        return -1;
    }

    ctx->allowed_thumbprints = arr;
    ctx->allowed_thumbprints_count = count;
    flb_debug("[tls] parsed %zu allowed thumbprint(s).", count);

    return 0;
}

static int tls_set_client_thumbprints(struct flb_tls *tls, const char *thumbprints) {
    struct tls_context *ctx = tls->ctx;
    int rc = 0;

    pthread_mutex_lock(&ctx->mutex);

    if (ctx->allowed_thumbprints || ctx->allowed_thumbprints_count) {
        pthread_mutex_unlock(&ctx->mutex);
        return -1;
    }
    rc = windows_set_allowed_thumbprints(ctx, thumbprints);
    pthread_mutex_unlock(&ctx->mutex);
    return rc;
}

#endif

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

    if (ptr->fd >= 0 && flb_socket_error(ptr->fd) == 0) {
        SSL_shutdown(ptr->ssl);
    }

    SSL_free(ptr->ssl);
    flb_free(ptr);

    pthread_mutex_unlock(&ctx->mutex);

    return 0;
}

static void tls_session_invalidate(void *session)
{
    struct tls_session *ptr = session;
    struct tls_context *ctx;

    if (ptr == NULL) {
        return;
    }

    ctx = ptr->parent;
    if (ctx == NULL) {
        ptr->fd = -1;
        return;
    }

    pthread_mutex_lock(&ctx->mutex);

    if (ptr->fd >= 0 && flb_socket_error(ptr->fd) == 0) {
        SSL_shutdown(ptr->ssl);
    }

    ptr->fd = -1;

    pthread_mutex_unlock(&ctx->mutex);
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
    unsigned long err_code;
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

            err_code = ERR_get_error();

            if (err_code != 0) {
                ERR_error_string_n(err_code, err_buf, sizeof(err_buf)-1);
                flb_error("[tls] syscall error: %s", err_buf);
            }
            else {
                flb_error("[tls] syscall error: %s", strerror(errno));
            }

            /* According to the documentation these are non-recoverable
             * errors so we don't need to screen them before saving them
             * to the net_error field.
             */

            session->connection->net_error = errno;

            ret = -1;
        }
        else if (ret < 0) {
            err_code = ERR_get_error();

            if (err_code != 0) {
                ERR_error_string_n(err_code, err_buf, sizeof(err_buf)-1);
                flb_error("[tls] error: %s", err_buf);
            }
            else {
                flb_error("[tls] error: %s", strerror(errno));
            }
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
    unsigned long err_code;
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
            err_code = ERR_get_error();

            if (err_code == 0) {
                if (ret == 0) {
                    flb_debug("[tls] connection closed");
                }
                else {
                    flb_error("[tls] syscall error: %s", strerror(errno));
                }
            }
            else {
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
    int ssl_error = 0;
    long ssl_code = 0;
    unsigned long err_code = 0;
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
        ssl_error = SSL_get_error(session->ssl, ret);

        if (ssl_error != SSL_ERROR_WANT_READ &&
            ssl_error != SSL_ERROR_WANT_WRITE) {
            /* The SSL_ERROR_SYSCALL with errno value of 0 indicates unexpected
             *  EOF from the peer. This is fixed in OpenSSL 3.0.
             */

            if (ssl_error == SSL_ERROR_SYSCALL &&
                ERR_peek_error() == 0 &&
                errno == 0) {
                ssl_code = SSL_get_verify_result(session->ssl);
                if (ssl_code != X509_V_OK) {
                    /* Refer to: https://x509errors.org/ */
                    x509_err = X509_verify_cert_error_string(ssl_code);
                    flb_error("[tls] certificate verification failed, reason: %s (X509 code: %ld)", x509_err, ssl_code);
                }
                else {
                    flb_error("[tls] error: unexpected EOF");
                }
            }
            else {
                err_code = ERR_get_error();

                if (err_code != 0) {
                    ERR_error_string_n(err_code, err_buf, sizeof(err_buf)-1);
                    flb_error("[tls] error: %s", err_buf);
                }
                else {
                    flb_error("[tls] error: tls handshake failed (ssl_error=%d)",
                              ssl_error);
                }
            }

            pthread_mutex_unlock(&ctx->mutex);

            return -1;
        }

        if (ssl_error == SSL_ERROR_WANT_WRITE) {
            pthread_mutex_unlock(&ctx->mutex);

            session->continuation_flag = FLB_TRUE;

            return FLB_TLS_WANT_WRITE;
        }
        else if (ssl_error == SSL_ERROR_WANT_READ) {
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
    .context_set_verify_client = tls_context_set_verify_client,
    .session_alpn_get     = tls_session_alpn_get,
    .set_minmax_proto     = tls_set_minmax_proto,
    .set_ciphers          = tls_set_ciphers,
    .session_create       = tls_session_create,
    .session_invalidate   = tls_session_invalidate,
    .session_destroy      = tls_session_destroy,
    .net_read             = tls_net_read,
    .net_write            = tls_net_write,
    .net_handshake        = tls_net_handshake,
#if defined(FLB_SYSTEM_WINDOWS)
    .set_certstore_name   = tls_set_certstore_name,
    .set_use_enterprise_store = tls_set_use_enterprise_store,
    .set_client_thumbprints   = tls_set_client_thumbprints,
#endif
};
