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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_upstream_node.h>

/* Create a new Upstream Node context */
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
                                                   const char* tls_provider_query,
                                                   struct flb_hash_table *ht,
                                                   struct flb_config *config)
{
    int ret;
    int i_port;
    int io_flags;
    char tmp[255];
    struct flb_upstream_node *node;

    if (!host || !port) {
        return NULL;
    }

    /* port */
    i_port = atoi(port);

    /* Allocate node context */
    node = flb_calloc(1, sizeof(struct flb_upstream_node));
    if (!node) {
        flb_errno();
        return NULL;
    }

    /* Set node name */
    if (!name) {
        /* compose a name using given host and port */
        snprintf(tmp, sizeof(tmp) - 1, "%s:%s", host, port);
        node->name = flb_sds_create(tmp);
    }
    else {
        node->name = name;
    }

    /* host */
    node->host = host;
    if (!node->host) {
        flb_upstream_node_destroy(node);
        return NULL;
    }

    /* port */
    node->port = port;
    if (!node->port) {
        flb_upstream_node_destroy(node);
        return NULL;
    }

#ifdef FLB_HAVE_TLS

    /* tls: ca path */
    node->tls_ca_path = flb_sds_create(tls_ca_path);
    if (!node->tls_ca_path) {
        flb_upstream_node_destroy(node);
        return NULL;
    }

    /* tls: ca file */
    node->tls_ca_file = flb_sds_create(tls_ca_file);
    if (!node->tls_ca_file) {
        flb_upstream_node_destroy(node);
        return NULL;
    }

    /* tls: crt file */
    node->tls_crt_file = flb_sds_create(tls_crt_file);
    if (!node->tls_crt_file) {
        flb_upstream_node_destroy(node);
        return NULL;
    }

    /* tls: key file */
    node->tls_key_file = flb_sds_create(tls_key_file);
    if (!node->tls_key_file) {
        flb_upstream_node_destroy(node);
        return NULL;
    }

    /* tls: key passwd */
    node->tls_key_passwd = flb_sds_create(tls_key_passwd);
    if (!node->tls_key_passwd) {
        flb_upstream_node_destroy(node);
        return NULL;
    }

    node->tls_provider_query = flb_sds_create(tls_provider_query);
    if (!node->tls_provider_query) {
        flb_upstream_node_destroy(node);
        return NULL;
    }
#endif

    /* hash table */
    node->ht = ht;

#ifdef FLB_HAVE_TLS
    /* TLS setup */
    if (tls == FLB_TRUE) {
        node->tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                   tls_verify,
                                   tls_debug,
                                   tls_vhost,
                                   tls_ca_path,
                                   tls_ca_file,
                                   tls_crt_file,
                                   tls_key_file,
                                   tls_key_passwd, 
                                   tls_provider_query);
        if (!node->tls) {
            flb_error("[upstream_node] error initializing TLS context "
                      "on node '%s'", name);
            flb_upstream_node_destroy(node);
            return NULL;
        }
        node->tls_enabled = FLB_TRUE;
        if (tls_verify_hostname == FLB_TRUE) {
            ret = flb_tls_set_verify_hostname(node->tls, tls_verify_hostname);
            if (ret == -1) {
                flb_error("[upstream_node] error set up to verify hostname in TLS context "
                          "on node '%s'", name);
                flb_upstream_node_destroy(node);

                return NULL;
            }
        }
    }
#endif


    /* Upstream flags */
    if (tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

    /* upstream context */
    node->u = flb_upstream_create(config, node->host, i_port,
                                  io_flags, node->tls);
    if (!node->u) {
        flb_error("[upstream_node] error creating upstream context "
                  "for node '%s'", name);
        flb_upstream_node_destroy(node);
        return NULL;
    }

    return node;
}

const char *flb_upstream_node_get_property(const char *prop,
                                     struct flb_upstream_node *node)
{
    int ret;
    int len;
    void *value;
    size_t size;

    len = strlen(prop);

    ret = flb_hash_table_get(node->ht, prop, len, &value, &size);
    if (ret == -1) {
        return NULL;
    }

    return (char *) value;
}

void flb_upstream_node_destroy(struct flb_upstream_node *node)
{
    flb_sds_destroy(node->name);
    flb_sds_destroy(node->host);
    flb_sds_destroy(node->port);

    flb_hash_table_destroy(node->ht);
    if (node->u) {
        flb_upstream_destroy(node->u);
    }

#ifdef FLB_HAVE_TLS
    flb_sds_destroy(node->tls_ca_path);
    flb_sds_destroy(node->tls_ca_file);
    flb_sds_destroy(node->tls_crt_file);
    flb_sds_destroy(node->tls_key_file);
    flb_sds_destroy(node->tls_key_passwd);
    flb_sds_destroy(node->tls_provider_query);
    if (node->tls) {
        flb_tls_destroy(node->tls);
    }
#endif

    /* note: node link must be handled by the caller before this call */
    flb_free(node);
}
