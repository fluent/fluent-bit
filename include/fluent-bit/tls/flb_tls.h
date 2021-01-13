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

#ifndef FLB_TLS_H
#define FLB_TLS_H

#ifdef FLB_HAVE_TLS

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_upstream.h>
#include <stddef.h>

#define FLB_TLS_CLIENT   "Fluent Bit"

/* TLS backend return status on read/write */
#define FLB_TLS_WANT_READ   -0x7e4
#define FLB_TLS_WANT_WRITE  -0x7e6

/* Cert Flags */
#define FLB_TLS_CA_ROOT          1
#define FLB_TLS_CERT             2
#define FLB_TLS_PRIV_KEY         4

struct flb_tls;

struct flb_tls_session {
    /* opaque data type for backend session context */
    void *ptr;
};

/*
 * Structure to connect a backend API library: every backend provided by
 * mbedtls.c or openssl.c use this structure to register it self.
 */
struct flb_tls_backend {
    /* library backend name */
    char *name;

    /* create backend context */
    void *(*context_create) (int, int,
                             const char *, const char *,
                             const char *, const char *,
                             const char *, const char *);

    /* destroy backend context */
    void (*context_destroy) (void *);

    /* Session management */
    void *(*session_create) (struct flb_tls *, struct flb_upstream_conn *);
    int (*session_destroy) (void *);

    /* I/O */
    int (*net_read) (struct flb_upstream_conn *, void *, size_t);
    int (*net_write) (struct flb_upstream_conn *, const void *data,
                      size_t len);
    int (*net_handshake) (struct flb_tls *, void *);
};

/* Main TLS context */
struct flb_tls {
    int verify;                       /* FLB_TRUE | FLB_FALSE      */
    int debug;                        /* mbedtls debug level       */
    char *vhost;                      /* Virtual hostname for SNI  */

    /* Bakend library for TLS */
    void *ctx;                        /* TLS context created */
    struct flb_tls_backend *api;      /* backend API */
};

int flb_tls_init();
struct flb_tls *flb_tls_create();
int flb_tls_destroy(struct flb_tls *tls);

int flb_tls_session_create(struct flb_tls *tls,
                           struct flb_upstream_conn *u_conn,
                           struct flb_coro *th);
int flb_tls_session_destroy(struct flb_tls *tls, struct flb_upstream_conn *u_conn);

int flb_tls_load_system_certificates(struct flb_tls *tls);
int flb_tls_net_read(struct flb_upstream_conn *u_conn, void *buf, size_t len);
int flb_tls_net_read_async(struct flb_coro *th, struct flb_upstream_conn *u_conn,
                           void *buf, size_t len);
int flb_tls_net_write(struct flb_upstream_conn *u_conn,
                      const void *data, size_t len, size_t *out_len);
int flb_tls_net_write_async(struct flb_coro *th, struct flb_upstream_conn *u_conn,
                            const void *data, size_t len, size_t *out_len);

#endif
#endif
