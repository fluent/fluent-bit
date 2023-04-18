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
#include <ctype.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_config_format.h>

#include <cfl/cfl.h>
#include <cfl/cfl_sds.h>
#include <cfl/cfl_variant.h>
#include <cfl/cfl_kvlist.h>

int flb_cf_file_read()
{
    return 0;
}

struct flb_cf *flb_cf_create()
{
    struct flb_cf *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_cf));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* env vars */
    mk_list_init(&ctx->env);

    /* meta commands */
    mk_list_init(&ctx->metas);

    /* parsers */
    mk_list_init(&ctx->parsers);
    mk_list_init(&ctx->multiline_parsers);

    /* custom plugins */
    mk_list_init(&ctx->customs);

    /* pipeline */
    mk_list_init(&ctx->inputs);
    mk_list_init(&ctx->filters);
    mk_list_init(&ctx->outputs);

    /* other sections */
    mk_list_init(&ctx->others);

    /* general list for sections */
    mk_list_init(&ctx->sections);

    return ctx;
}

void flb_cf_destroy(struct flb_cf *cf)
{
    flb_kv_release(&cf->env);
    flb_kv_release(&cf->metas);
    flb_cf_section_destroy_all(cf);
    flb_free(cf);
}

static enum section_type get_section_type(char *name, int len)
{
    if (strncasecmp(name, "SERVICE", len) == 0) {
        return FLB_CF_SERVICE;
    }
    else if (strncasecmp(name, "PARSER", len) == 0) {
        return FLB_CF_PARSER;
    }
    else if (strncasecmp(name, "MULTILINE_PARSER", len) == 0) {
        return FLB_CF_MULTILINE_PARSER;
    }
    else if (strncasecmp(name, "CUSTOM", len) == 0 ||
             strncasecmp(name, "CUSTOMS", len) == 0) {
        return FLB_CF_CUSTOM;
    }
    else if (strncasecmp(name, "INPUT", len) == 0 ||
             strncasecmp(name, "INPUTS", len) == 0) {
        return FLB_CF_INPUT;
    }
    else if (strncasecmp(name, "FILTER", len) == 0 ||
             strncasecmp(name, "FILTERS", len) == 0) {
        return FLB_CF_FILTER;
    }
    else if (strncasecmp(name, "OUTPUT", len) == 0 ||
             strncasecmp(name, "OUTPUTS", len) == 0) {
        return FLB_CF_OUTPUT;
    }

    return FLB_CF_OTHER;
}

int flb_cf_plugin_property_add(struct flb_cf *cf,
                               struct cfl_kvlist *kv_list,
                               char *k_buf, size_t k_len,
                               char *v_buf, size_t v_len)
{
    int ret;
    flb_sds_t key;
    flb_sds_t val;

    if (k_len == 0) {
        k_len = strlen(k_buf);
    }
    if (v_len == 0) {
        v_len = strlen(v_buf);
    }

    key = flb_sds_create_len(k_buf, k_len);
    if (key == NULL) {
        return -1;
    }

    val = flb_sds_create_len(v_buf, v_len);
    if (val == NULL) {
        flb_sds_destroy(key);
        return -1;
    }

    /* sanitize key and value by removing empty spaces */
    ret = flb_sds_trim(key);
    if (ret == -1) {
        flb_cf_error_set(cf, FLB_CF_ERROR_KV_INVALID_KEY);
        flb_sds_destroy(key);
        flb_sds_destroy(val);
        return -1;
    }

    ret = flb_sds_trim(val);
    if (ret == -1) {
        flb_cf_error_set(cf, FLB_CF_ERROR_KV_INVALID_VAL);
        flb_sds_destroy(key);
        flb_sds_destroy(val);
        return ret;
    }

    ret = cfl_kvlist_insert_string(kv_list, key, val);
    flb_sds_destroy(key);
    flb_sds_destroy(val);
    return ret;
}

struct cfl_variant *flb_cf_section_property_add(struct flb_cf *cf,
                                              struct cfl_kvlist *kv_list,
                                              char *k_buf, size_t k_len,
                                              char *v_buf, size_t v_len)
{
    int i;
    int rc;
    flb_sds_t key;
    flb_sds_t val;
    struct cfl_variant *var;


    if (k_len == 0) {
        k_len = strlen(k_buf);
    }
    key = flb_sds_create_len(k_buf, k_len);
    if (key == NULL) {
        goto key_error;
    }

    /* sanitize key and value by removing empty spaces */
    rc = flb_sds_trim(key);
    if (rc == -1) {
        flb_cf_error_set(cf, FLB_CF_ERROR_KV_INVALID_KEY);
        goto val_error;
    }

    for (i = 0; i < flb_sds_len(key); i++) {
        key[i] = tolower(key[i]);
    }

    if (v_len == 0) {
        v_len = strlen(v_buf);
    }
    val = flb_sds_create_len(v_buf, v_len);
    if (val == NULL) {
        goto val_error;
    }
    /* sanitize key and value by removing empty spaces */
    rc = flb_sds_trim(val);
    if (rc == -1) {
        flb_cf_error_set(cf, FLB_CF_ERROR_KV_INVALID_VAL);
        goto var_error;
    }

    var = cfl_variant_create_from_string(val);
    if (var == NULL) {
        goto var_error;
    }

    rc = cfl_kvlist_insert(kv_list, key, var);
    if (rc < 0) {
        goto insert_error;
    }

    flb_sds_destroy(val);
    flb_sds_destroy(key);
    return var;

insert_error:
    cfl_variant_destroy(var);
var_error:
    flb_sds_destroy(val);
val_error:
    flb_sds_destroy(key);
key_error:
    return NULL;
}

struct cfl_array *flb_cf_section_property_add_list(struct flb_cf *cf,
                                                   struct cfl_kvlist *kv_list,
                                                   char *k_buf, size_t k_len)
{
    int rc;
    flb_sds_t key;
    struct cfl_array *arr;


    if (k_len == 0) {
        k_len = strlen(k_buf);
    }
    key = flb_sds_create_len(k_buf, k_len);
    if (key == NULL) {
        goto key_error;
    }

    arr = cfl_array_create(10);
    if (arr == NULL) {
        goto array_error;
    }
    cfl_array_resizable(arr, 1);

    /* sanitize key and value by removing empty spaces */
    rc = flb_sds_trim(key);
    if (rc == -1) {
        flb_cf_error_set(cf, FLB_CF_ERROR_KV_INVALID_KEY);
        goto cfg_error;
    }

    rc = cfl_kvlist_insert_array(kv_list, key, arr);
    if (rc < 0) {
        goto cfg_error;
    }

    flb_sds_destroy(key);
    return arr;

cfg_error:
    cfl_array_destroy(arr);
array_error:
    flb_sds_destroy(key);
key_error:
    return NULL;
}

flb_sds_t flb_cf_section_property_get_string(struct flb_cf *cf, struct flb_cf_section *s,
                                             char *key)
{
    (void) cf;
    flb_sds_t tkey;
    struct cfl_variant *val;
    flb_sds_t ret = NULL;
    struct cfl_variant *entry;
    int i;


    tkey = flb_sds_create(key);
    for (i = 0; i < strlen(key); i++) {
        tkey[i] = tolower(key[i]);
    }

    val = cfl_kvlist_fetch(s->properties, key);
    flb_sds_destroy(tkey);
    if (val == NULL) {
        return NULL;
    }

    if (val->type == CFL_VARIANT_STRING) {
        ret = flb_sds_create(val->data.as_string);
    }
    if (val->type == CFL_VARIANT_ARRAY) {
        // recreate the format SLISTS are expecting...
        ret = flb_sds_create("  ");
        for (i = 0; i < val->data.as_array->entry_count; i++) {
            entry = val->data.as_array->entries[i];
            if (entry->type != CFL_VARIANT_STRING) {
                flb_sds_destroy(ret);
                return NULL;
            }
            if ((i+1) < val->data.as_array->entry_count) {
                flb_sds_printf(&ret, "%s ", entry->data.as_string);
            } else {
                flb_sds_printf(&ret, "%s", entry->data.as_string);
            }
        }
    }
    return ret;
}

struct cfl_variant * flb_cf_section_property_get(struct flb_cf *cf, struct flb_cf_section *s,
                                                 char *key)
{
    (void) cf;
    return cfl_kvlist_fetch(s->properties, key);
}

struct flb_kv *flb_cf_env_property_add(struct flb_cf *cf,
                                       char *k_buf, size_t k_len,
                                       char *v_buf, size_t v_len)
{
    int ret;
    struct flb_kv *kv;

    if (k_len == 0) {
        k_len = strlen(k_buf);
    }
    if (v_len == 0) {
        v_len = strlen(v_buf);
    }

    kv = flb_kv_item_create_len(&cf->env, k_buf, k_len, v_buf, v_len);
    if (!kv) {
        return NULL;
    }

    /* sanitize key and value by removing empty spaces */
    ret = flb_sds_trim(kv->key);
    if (ret == -1) {
        flb_cf_error_set(cf, FLB_CF_ERROR_KV_INVALID_KEY);
        flb_kv_item_destroy(kv);
        return NULL;
    }

    ret = flb_sds_trim(kv->val);
    if (ret == -1) {
        flb_cf_error_set(cf, FLB_CF_ERROR_KV_INVALID_VAL);
        flb_kv_item_destroy(kv);
        return NULL;
    }

    return kv;
}

static struct flb_kv *meta_property_add(struct flb_cf *cf,
                                        char *k_buf, size_t k_len,
                                        char *v_buf, size_t v_len)
{
    int ret;
    struct flb_kv *kv;

    if (k_len == 0) {
        k_len = strlen(k_buf);
    }
    if (v_len == 0) {
        v_len = strlen(v_buf);
    }

    kv = flb_kv_item_create_len(&cf->metas, k_buf, k_len, v_buf, v_len);
    if (!kv) {
        return NULL;
    }

    /* sanitize key and value by removing empty spaces */
    ret = flb_sds_trim(kv->key);
    if (ret == -1) {
        flb_cf_error_set(cf, FLB_CF_ERROR_KV_INVALID_KEY);
        flb_kv_item_destroy(kv);
        return NULL;
    }

    ret = flb_sds_trim(kv->val);
    if (ret == -1) {
        flb_cf_error_set(cf, FLB_CF_ERROR_KV_INVALID_VAL);
        flb_kv_item_destroy(kv);
        return NULL;
    }

    return kv;
}

struct flb_kv *flb_cf_meta_property_add(struct flb_cf *cf, char *meta, int len)
{
    int xlen;
    char *p;
    char *tmp;

    if (len <= 0) {
        len = strlen(meta);
        if (len == 0) {
            return NULL;
        }
    }

    if (meta[0] != '@') {
        flb_cf_error_set(cf, FLB_CF_ERROR_META_CHAR);
        return NULL;
    }

    p = meta;
    tmp = strchr(p, ' ');
    xlen = (tmp - p);

    /* create k/v pair */
    return meta_property_add(cf,
                             meta + 1, xlen - 1,
                             meta + xlen + 1, len - xlen - 1);
}

struct flb_cf_group *flb_cf_group_create(struct flb_cf *cf, struct flb_cf_section *s,
                                         char *name, int len)
{
    struct flb_cf_group *g;

    if (!name || strlen(name) == 0 || len < 1) {
        return NULL;
    }

    /* section context */
    g = flb_malloc(sizeof(struct flb_cf_group));
    if (!g) {
        flb_errno();
        return NULL;
    }

    /* initialize lists */
    g->properties = cfl_kvlist_create();

    /* determinate type by name */
    if (len <= 0) {
        len = strlen(name);
    }

    /* create a NULL terminated name */
    g->name = flb_sds_create_len(name, len);
    if (!g->name) {
        flb_free(g);
        return NULL;
    }

    /* link to global section */
    mk_list_add(&g->_head, &s->groups);

    return g;
}

struct flb_cf_group *flb_cf_group_get(struct flb_cf *cf, struct flb_cf_section *s, char *name)
{
    struct mk_list *head;
    struct flb_cf_group *g;

    mk_list_foreach(head, &s->groups) {
        g = mk_list_entry(head, struct flb_cf_group, _head);
        if (strcasecmp(g->name, name) == 0){
            return g;
        }
    }

    return NULL;
}

void flb_cf_group_print(struct flb_cf_group *g)
{
    cfl_kvlist_print(stdout, g->properties);
}

void flb_cf_group_destroy(struct flb_cf_group *g)
{
    if (g->name) {
        flb_sds_destroy(g->name);
    }

    cfl_kvlist_destroy(g->properties);
    mk_list_del(&g->_head);
    flb_free(g);
}

struct flb_cf_section *flb_cf_section_create(struct flb_cf *cf, char *name, int len)
{
    int type;
    struct flb_cf_section *s;

    if (!name) {
        return NULL;
    }

    /* determinate type by name */
    if (len <= 0) {
        len = strlen(name);
    }

    /* get the section type */
    type = get_section_type(name, len);

    /* check if 'service' already exists */
    if (type == FLB_CF_SERVICE && cf->service) {
        return cf->service;
    }

    /* section context */
    s = flb_malloc(sizeof(struct flb_cf_section));
    if (!s) {
        flb_errno();
        return NULL;
    }

    /* initialize lists */
    s->properties = cfl_kvlist_create();
    mk_list_init(&s->groups);

    /* create a NULL terminated name */
    s->name = flb_sds_create_len(name, len);
    if (!s->name) {
        flb_free(s->properties);
        flb_free(s);
        return NULL;
    }
    s->type = type;

    if (type == FLB_CF_SERVICE && !cf->service) {
        cf->service = s;
    }

    /* link to global section */
    mk_list_add(&s->_head, &cf->sections);

    /* link to list per type */
    if (type == FLB_CF_PARSER) {
        mk_list_add(&s->_head_section, &cf->parsers);
    }
    else if (type == FLB_CF_MULTILINE_PARSER) {
        mk_list_add(&s->_head_section, &cf->multiline_parsers);
    }
    else if (type == FLB_CF_CUSTOM) {
        mk_list_add(&s->_head_section, &cf->customs);
    }
    else if (type == FLB_CF_INPUT) {
        mk_list_add(&s->_head_section, &cf->inputs);
    }
    else if (type == FLB_CF_FILTER) {
        mk_list_add(&s->_head_section, &cf->filters);
    }
    else if (type == FLB_CF_OUTPUT) {
        mk_list_add(&s->_head_section, &cf->outputs);
    }
    else if (type == FLB_CF_OTHER) {
        mk_list_add(&s->_head_section, &cf->others);
    }

    return s;
}

/* returns the first match of a section that it name matches 'name' parameter */
struct flb_cf_section *flb_cf_section_get_by_name(struct flb_cf *cf, char *name)
{
    struct mk_list *head;
    struct flb_cf_section *s;

    mk_list_foreach(head, &cf->sections) {
        s = mk_list_entry(head, struct flb_cf_section, _head);
        if (strcasecmp(s->name, name) == 0) {
            return s;
        }
    }

    return NULL;
}

void flb_cf_section_destroy(struct flb_cf *cf, struct flb_cf_section *s)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_cf_group *g;

    if (s->name) {
        flb_sds_destroy(s->name);
        s->name = NULL;
    }
    cfl_kvlist_destroy(s->properties);

    /* groups */
    mk_list_foreach_safe(head, tmp, &s->groups) {
        g = mk_list_entry(head, struct flb_cf_group, _head);
        flb_cf_group_destroy(g);
    }

    /* unlink */
    mk_list_del(&s->_head);

    if (s->type != FLB_CF_SERVICE) {
        mk_list_del(&s->_head_section);
    }

    flb_free(s);
}

static void section_destroy_list(struct flb_cf *cf, struct mk_list *list)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_cf_section *s;

    mk_list_foreach_safe(head, tmp, list) {
        s = mk_list_entry(head, struct flb_cf_section, _head);
        flb_cf_section_destroy(cf, s);
    }
}

void flb_cf_section_destroy_all(struct flb_cf *cf)
{
    section_destroy_list(cf, &cf->sections);
}

/*
 * Helpers
 * -------
 */

static char *section_type_str(int type)
{
    switch (type) {
    case FLB_CF_SERVICE:
        return "SERVICE";
    case FLB_CF_PARSER:
        return "PARSER";
    case FLB_CF_MULTILINE_PARSER:
        return "MULTILINE_PARSER";
    case FLB_CF_CUSTOM:
        return "CUSTOM";
    case FLB_CF_INPUT:
        return "INPUT";
    case FLB_CF_FILTER:
        return "FILTER";
    case FLB_CF_OUTPUT:
        return "OUTPUT";
    case FLB_CF_OTHER:
        return "OTHER";
    default:
        return "error / unknown";
    }

    return NULL;
}

static void dump_section(struct flb_cf_section *s)
{
    struct mk_list *head;
    struct cfl_list *p_head;
    struct cfl_kvpair *kv;
    struct flb_cf_group *g;

    printf("> section:\n  name: %s\n  type: %s\n",
           s->name, section_type_str(s->type));

    if (cfl_list_size(&s->properties->list) > 0) {
        printf("  properties:\n");
        cfl_list_foreach(p_head, &s->properties->list) {
            kv = cfl_list_entry(p_head, struct cfl_kvpair, _head);
            printf("    - %-15s: %s\n", kv->key, kv->val->data.as_string);
        }
    }
    else {
        printf("  properties: NONE\n");
    }

    if (mk_list_size(&s->groups) <= 0) {
        printf("  groups    : NONE\n");
        return;
    }

    mk_list_foreach(head, &s->groups) {
        g = mk_list_entry(head, struct flb_cf_group, _head);
        printf("    > group:\n      name: %s\n", g->name);

        if (cfl_list_size(&g->properties->list) > 0) {
            printf("      properties:\n");
            cfl_list_foreach(p_head, &g->properties->list) {
                kv = cfl_list_entry(p_head, struct cfl_kvpair, _head);
                printf("        - %-11s: %s\n", kv->key, kv->val->data.as_string);
            }
        }
        else {
            printf("      properties: NONE\n");
        }
    }
}

static void dump_env(struct mk_list *list)
{
    struct mk_list *head;
    struct flb_kv *kv;

    if (mk_list_size(list) == 0) {
        return;
    }

    printf("> env:\n");

    mk_list_foreach(head, list) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        printf("    - %-15s: %s\n", kv->key, kv->val);
    }
}

static void dump_metas(struct mk_list *list)
{
    struct mk_list *head;
    struct flb_kv *kv;

    if (mk_list_size(list) == 0) {
        return;
    }

    printf("> metas:\n");

    mk_list_foreach(head, list) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        printf("    - %-15s: %s\n", kv->key, kv->val);
    }
}

static void dump_section_list(struct mk_list *list)
{
    struct mk_list *head;
    struct flb_cf_section *s;

    mk_list_foreach(head, list) {
        s = mk_list_entry(head, struct flb_cf_section, _head);
        dump_section(s);
    }
}

void flb_cf_dump(struct flb_cf *cf)
{
    dump_metas(&cf->metas);
    dump_env(&cf->env);
    dump_section_list(&cf->sections);
}

struct flb_cf *flb_cf_create_from_file(struct flb_cf *cf, char *file)
{
    int format = FLB_CF_FLUENTBIT;
    char *ptr;

    if (!file) {
        return NULL;
    }

    ptr = strrchr(file, '.');
    if (!ptr) {
        format = FLB_CF_FLUENTBIT;
    }
    else {
        if (strcasecmp(ptr, ".conf") == 0) {
            format = FLB_CF_FLUENTBIT;
        }
#ifdef FLB_HAVE_LIBYAML
        else if (strcasecmp(ptr, ".yaml") == 0 || strcasecmp(ptr, ".yml") == 0) {
            format = FLB_CF_YAML;
        }
#endif
    }

    if (format == FLB_CF_FLUENTBIT) {
        cf = flb_cf_fluentbit_create(cf, file, NULL, 0);
    }
#ifdef FLB_HAVE_LIBYAML
    else if (format == FLB_CF_YAML) {
        cf = flb_cf_yaml_create(cf, file, NULL, 0);
    }
#endif

    return cf;
 }

