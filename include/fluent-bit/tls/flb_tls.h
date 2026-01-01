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

#ifndef FLB_TLS_H
#define FLB_TLS_H

#ifdef FLB_HAVE_TLS

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_coro.h>
#include <stddef.h>

#define FLB_TLS_ALPN_MAX_LENGTH 16

#define FLB_TLS_CLIENT   "Fluent Bit"

/* TLS backend return status on read/write */
#define FLB_TLS_WANT_READ   -0x7e4
#define FLB_TLS_WANT_WRITE  -0x7e6

/* Cert Flags */
#define FLB_TLS_CA_ROOT          1
#define FLB_TLS_CERT             2
#define FLB_TLS_PRIV_KEY         4

#define FLB_TLS_UNKNOWN_CONNECTION    0
#define FLB_TLS_UPSTREAM_CONNECTION   1
#define FLB_TLS_DOWNSTREAM_CONNECTION 2

#define FLB_TLS_CLIENT_MODE 0
#define FLB_TLS_SERVER_MODE 1

struct flb_tls;
struct flb_connection;

struct flb_tls_session {
    /* opaque data type for backend session context */
    void                  *ptr;
    struct flb_tls        *tls;
    struct flb_connection *connection;
};

/*
 * Structure to connect a backend API library: every backend provided by
 * mbedtls.c or openssl.c use this structure to register it self.
 */
struct flb_tls_backend {
    /* library backend name */
    char *name;

    /* create backend context */
    void *(*context_create) (int, int, int,
                             const char *, const char *,
                             const char *, const char *,
                             const char *, const char *);

    /* destroy backend context */
    void (*context_destroy) (void *);

    /* Additional settings */
    int (*context_alpn_set) (void *, const char *);

    /* TLS Protocol version */
    int (*set_minmax_proto) (struct flb_tls *tls, const char *, const char *);
    /* TLS Ciphers */
    int (*set_ciphers) (struct flb_tls *tls, const char *);

    /* Session management */
    void *(*session_create) (struct flb_tls *, int);
    void (*session_invalidate) (void *);
    int (*session_destroy) (void *);
    const char *(*session_alpn_get) (void *);

    /* I/O */
    int (*net_read) (struct flb_tls_session *, void *, size_t);
    int (*net_write) (struct flb_tls_session *, const void *data,
                      size_t len);
    int (*net_handshake) (struct flb_tls *, char *, void *);

#if defined(FLB_SYSTEM_WINDOWS)
    int (*set_certstore_name)(struct flb_tls *tls, const char *certstore_name);
    int (*set_use_enterprise_store)(struct flb_tls *tls, int use_enterprise);
    int (*set_client_thumbprints)(struct flb_tls *tls, const char *thumbprints);
#endif
};

/* Main TLS context */
struct flb_tls {
    int verify;                       /* FLB_TRUE | FLB_FALSE      */
    int debug;                        /* Debug level               */
    char *vhost;                      /* Virtual hostname for SNI  */
    int mode;                         /* Client or Server          */
    int verify_hostname;              /* Verify hostname           */
#if defined(FLB_SYSTEM_WINDOWS)
    char *certstore_name;             /* Windows CertStore Name    */
    int use_enterprise_store;         /* Use Enterprise store or not */
#endif

    /* Bakend library for TLS */
    void *ctx;                        /* TLS context created */
    struct flb_tls_backend *api;      /* backend API */
};

int flb_tls_init();

struct flb_tls *flb_tls_create(int mode,
                               int verify,
                               int debug,
                               const char *vhost,
                               const char *ca_path,
                               const char *ca_file, const char *crt_file,
                               const char *key_file, const char *key_passwd);

int flb_tls_destroy(struct flb_tls *tls);

int flb_tls_set_alpn(struct flb_tls *tls, const char *alpn);

int flb_tls_set_verify_hostname(struct flb_tls *tls, int verify_hostname);
#if defined(FLB_SYSTEM_WINDOWS)
int flb_tls_set_certstore_name(struct flb_tls *tls, const char *certstore_name);
int flb_tls_set_use_enterprise_store(struct flb_tls *tls, int use_enterprise);
int flb_tls_set_client_thumbprints(struct flb_tls *tls, const char *thumbprints);
#endif

int flb_tls_load_system_certificates(struct flb_tls *tls);
int flb_tls_set_minmax_proto(struct flb_tls *tls,
                             const char *min_version, const char *max_version);
int flb_tls_set_ciphers(struct flb_tls *tls, const char *ciphers);

struct mk_list *flb_tls_get_config_map(struct flb_config *config);

int flb_tls_session_destroy(struct flb_tls_session *session);
int flb_tls_session_invalidate(struct flb_tls_session *session);

int flb_tls_session_create(struct flb_tls *tls,
                           struct flb_connection *connection,
                           struct flb_coro *co);

const char *flb_tls_session_get_alpn(struct flb_tls_session *session);

int flb_tls_net_read(struct flb_tls_session *session,
                     void *buf,
                     size_t len);

int flb_tls_net_read_async(struct flb_coro *th,
                           struct flb_tls_session *session,
                           void *buf, size_t len);

int flb_tls_net_write(struct flb_tls_session *session,
                      const void *data, size_t len, size_t *out_len);

int flb_tls_net_write_async(struct flb_coro *th,
                            struct flb_tls_session *session,
                            const void *data, size_t len, size_t *out_len);


#endif
#endif
