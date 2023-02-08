/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <fluent-bit/flb_upstream_node.h>
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_kv.h>

#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Creates an Upstream HA Context */
struct flb_upstream_ha *flb_upstream_ha_create(const char *name)
{
    struct flb_upstream_ha *ctx;

    if (!name) {
        return NULL;
    }

    ctx = flb_calloc(1, sizeof(struct flb_upstream_ha));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    ctx->name = flb_sds_create(name);
    if (!ctx->name) {
        flb_free(ctx);
        return NULL;
    }

    mk_list_init(&ctx->nodes);
    ctx->last_used_node = NULL;

    return ctx;
}

void flb_upstream_ha_destroy(struct flb_upstream_ha *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_upstream_node *node;

    /* destroy nodes */
    mk_list_foreach_safe(head, tmp, &ctx->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);
        mk_list_del(&node->_head);
        flb_upstream_node_destroy(node);
    }

    flb_sds_destroy(ctx->name);
    flb_free(ctx);
}

/* Link a new node to the list handled by HA context */
void flb_upstream_ha_node_add(struct flb_upstream_ha *ctx,
                              struct flb_upstream_node *node)
{
    mk_list_add(&node->_head, &ctx->nodes);
}

/* Return a target node to be used for I/O */
struct flb_upstream_node *flb_upstream_ha_node_get(struct flb_upstream_ha *ctx)
{
    struct flb_upstream_node *cur_node;
    struct flb_upstream_node *node;

    if (mk_list_is_empty(&ctx->nodes) == 0) {
        return NULL;
    }

    if (!ctx->last_used_node) {
        node = mk_list_entry_first(&ctx->nodes, struct flb_upstream_node,
                                   _head);
        ctx->last_used_node = node;
        return node;
    }

    cur_node = (struct flb_upstream_node *) ctx->last_used_node;

    node = mk_list_entry_next(&cur_node->_head, struct flb_upstream_node,
                              _head, &ctx->nodes);
    ctx->last_used_node = node;
    return node;
}

static struct flb_upstream_node *create_node(int id,
                                             struct flb_cf *cf,
                                             struct flb_cf_section *s,
                                             struct flb_config *config)
{
    int i;
    int ret;
    int skip;
    int klen;
    int vlen;
    int tls = FLB_FALSE;
    int tls_verify = FLB_TRUE;
    int tls_debug = 1;
    char key[32];
    char *tmp;
    char *name = NULL;
    char *host = NULL;
    char *port = NULL;
    char *tls_vhost = NULL;
    char *tls_ca_path = NULL;
    char *tls_ca_file = NULL;
    char *tls_crt_file = NULL;
    char *tls_key_file = NULL;
    char *tls_key_passwd = NULL;
    struct cfl_list *head;
    struct cfl_kvpair *entry;
    struct flb_hash_table *ht;
    const char *known_keys[] = {"name", "host", "port",
                                "tls", "tls.vhost", "tls.verify", "tls.debug",
                                "tls.ca_path", "tls.ca_file", "tls.crt_file",
                                "tls.key_file", "tls.key_passwd", NULL};

    struct flb_upstream_node *node;

    /* name */
    name = flb_cf_section_property_get_string(cf, s, "name");
    if (!name) {
        flb_error("[upstream_ha] no 'name' has been set on node #%i",
                  id + 1);
        return NULL;
    }

    /* host */
    host = flb_cf_section_property_get_string(cf, s, "host");
    if (!host) {
        flb_error("[upstream_ha] no 'host' has been set on node #%i",
                  id + 1);
        return NULL;
    }

    /* port */
    port = flb_cf_section_property_get_string(cf, s, "port");
    if (!port) {
        flb_error("[upstream_ha] no 'port' has been set on node #%i",
                  id + 1);
        return NULL;
    }

    /* tls */
    tmp = flb_cf_section_property_get_string(cf, s, "tls");
    if (tmp) {
        tls = flb_utils_bool(tmp);
        flb_sds_destroy(tmp);
    }

    /* tls.verify */
    tmp = flb_cf_section_property_get_string(cf, s, "tls.verify");
    if (tmp) {
        tls_verify = flb_utils_bool(tmp);
        flb_sds_destroy(tmp);
    }

    /* tls.debug */
    tmp = flb_cf_section_property_get_string(cf, s, "tls.debug");
    if (tmp) {
        tls_debug = atoi(tmp);
        flb_sds_destroy(tmp);
    }

    /* tls.vhost */
    tls_vhost = flb_cf_section_property_get_string(cf, s, "tls.vhost");

    /* tls.ca_path */
    tls_ca_path = flb_cf_section_property_get_string(cf, s, "tls.ca_path");

    /* tls.ca_file */
    tls_ca_file = flb_cf_section_property_get_string(cf, s, "tls.ca_file");

    /* tls.crt_file */
    tls_crt_file = flb_cf_section_property_get_string(cf, s, "tls.crt_file");

    /* tls.key_file */
    tls_key_file = flb_cf_section_property_get_string(cf, s, "tls.key_file");

    /* tls.key_file */
    tls_key_passwd = flb_cf_section_property_get_string(cf, s, "tls.key_passwd");

    /*
     * Create hash table to store unknown key/values that might be used
     * by the caller plugin.
     */
    ht = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 32, 256);
    if (!ht) {
        flb_error("[upstream_ha] error creating hash table");
        return NULL;
    }

    /*
     * Iterate mk_rconf section internals, find all unknown keys and add
     * them to the hash table associated to the node.
     */
    cfl_list_foreach(head, &s->properties->list) {
        entry = cfl_list_entry(head, struct cfl_kvpair, _head);

        /* If this is a known entry, just skip it */
        skip = FLB_FALSE;
        for (i = 0; known_keys[i] != NULL; i++) {
            if (strcasecmp(entry->key, known_keys[i]) == 0) {
                skip = FLB_TRUE;
                break;
            }
        }
        if (skip == FLB_TRUE) {
            continue;
        }

        klen = flb_sds_len(entry->key);
        vlen = flb_sds_len(entry->val->data.as_string);

        /* Always store keys in lowercase */
        for (i = 0; i < klen; i++) {
            key[i] = tolower(entry->key[i]);
        }
        key[klen] = '\0';

        /* Add the key and value to the hash table */
        ret = flb_hash_table_add(ht, key, klen, entry->val->data.as_string, vlen);
        if (ret == -1) {
            flb_error("[upstream_ha] cannot add key %s to hash table",
                      entry->key);
        }
    }

    node = flb_upstream_node_create(name, host, port, tls, tls_verify,
                                    tls_debug, tls_vhost, tls_ca_path, tls_ca_file,
                                    tls_crt_file, tls_key_file,
                                    tls_key_passwd, ht, config);
    return node;
}

/* Read an upstream file and generate the context */
struct flb_upstream_ha *flb_upstream_ha_from_file(const char *file,
                                                  struct flb_config *config)
{
    int c = 0;
    int ret;
    const char *cfg = NULL;
    char *tmp;
    char path[PATH_MAX + 1];
    struct stat st;
    struct mk_list *head;
    struct flb_upstream_ha *ups;
    struct flb_upstream_node *node;
    struct flb_cf *cf = NULL;
    struct flb_cf_section *section;

#ifndef FLB_HAVE_STATIC_CONF
    ret = stat(file, &st);
    if (ret == -1 && errno == ENOENT) {
        /* Try to resolve the real path (if exists) */
        if (file[0] == '/') {
            return NULL;
        }

        if (config->conf_path) {
            snprintf(path, PATH_MAX, "%s%s", config->conf_path, file);
            cfg = path;
        }
    }
    else {
        cfg = file;
    }
    flb_debug("[upstream_ha] opening file %s", cfg);
    cf = flb_cf_create_from_file(NULL, (char *) cfg);
#else
    //DISABLED/FIXME fconf = flb_config_static_open(file);
#endif

    if (!cf) {
        return NULL;
    }

    /* 'upstream' sections are under enum section_type FLB_CF_OTHER */
    section = flb_cf_section_get_by_name(cf, "upstream");
    if (!section) {
        flb_error("[upstream_ha] section name 'upstream' could not be found");
        flb_cf_destroy(cf);
        return NULL;
    }

    /* upstream name */
    tmp = flb_cf_section_property_get_string(cf, section, "name");
    if (!tmp) {
        flb_error("[upstream_ha] missing name for upstream at %s", cfg);
        flb_cf_destroy(cf);
        return NULL;
    }

    ups = flb_upstream_ha_create(tmp);
    flb_sds_destroy(tmp);
    if (!ups) {
        flb_error("[upstream_ha] cannot create context");
        flb_cf_destroy(cf);
        return NULL;
    }

    /* 'node' sections */
    mk_list_foreach(head, &cf->sections) {
        section = mk_list_entry(head, struct flb_cf_section, _head);
        if (strcasecmp(section->name, "node") != 0) {
            continue;
        }

        /* Read section info and create a Node context */
        node = create_node(c, cf, section, config);
        if (!node) {
            flb_error("[upstream_ha] cannot register node on upstream '%s'",
                      tmp);
            flb_upstream_ha_destroy(ups);
            flb_cf_destroy(cf);
            return NULL;
        }

        flb_upstream_ha_node_add(ups, node);
        c++;
    }

    if (c == 0) {
        flb_error("[upstream_ha] no nodes defined");
        flb_upstream_ha_destroy(ups);
        flb_cf_destroy(cf);
        return NULL;
    }

    flb_cf_destroy(cf);
    return ups;
}
