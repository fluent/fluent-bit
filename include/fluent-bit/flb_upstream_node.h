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

#ifndef FLB_UPSTREAM_NODE_H
#define FLB_UPSTREAM_NODE_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_upstream.h>
#include <monkey/mk_core.h>

struct flb_upstream_node {
    flb_sds_t name;
    flb_sds_t host;
    flb_sds_t port;

    int tls_enabled;          /* TLS enabled ?                */

#ifdef FLB_HAVE_TLS
    /* TLS: given configuration */
    int tls_verify;           /* Verify certs (default: true) */
    int tls_verify_hostname;  /* Verify hostname (default: false) */
    int tls_debug;            /* mbedtls debug level          */
    char *tls_ca_path;        /* Path to certificates         */
    char *tls_ca_file;        /* CA root cert                 */
    char *tls_crt_file;       /* Certificate                  */
    char *tls_key_file;       /* Cert Key                     */
    char *tls_key_passwd;     /* Cert Key Password            */
    char *tls_provider_query; /* OpenSSL Provider Query       */

    /* context with mbedTLS contexts and data */
    struct flb_tls *tls;
#else
    void *tls;
#endif

    /* Hash table to store custom config key/values for plugins */
    struct flb_hash_table *ht;

    /* Upstream context */
    struct flb_upstream *u;

    void *data;

    /* Link to upstream_ha or upstream */
    struct mk_list _head;
};


struct flb_upstream_node *flb_upstream_node_create(flb_sds_t name, flb_sds_t host,
                                                   flb_sds_t port,
                                                   int tls, int tls_verify,
                                                   int tls_verify_hostname,
                                                   int tls_debug,
                                                   const char *tls_vhost,
                                                   const char *tls_ca_path,
                                                   const char *tls_ca_file,
                                                   const char *tls_crt_file,
                                                   const char *tls_key_file,
                                                   const char *tls_key_passwd,
                                                   const char *tls_provider_query,
                                                   struct flb_hash_table *ht,
                                                   struct flb_config *config);
const char *flb_upstream_node_get_property(const char *prop,
                                           struct flb_upstream_node *node);

static inline void flb_upstream_node_set_data(void *data,
                                              struct flb_upstream_node *node)
{
    node->data = data;
}

static inline void *flb_upstream_node_get_data(struct flb_upstream_node *node)
{
    return node->data;
}

void flb_upstream_node_destroy(struct flb_upstream_node *node);

#endif
