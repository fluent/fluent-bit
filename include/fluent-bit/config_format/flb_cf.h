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

#ifndef FLB_CONFIG_FORMAT_MAIN_H
#define FLB_CONFIG_FORMAT_MAIN_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <monkey/mk_core.h>

#include <cfl/cfl.h>
#include <cfl/cfl_sds.h>
#include <cfl/cfl_array.h>
#include <cfl/cfl_list.h>
#include <cfl/cfl_variant.h>

#define FLB_CF_ERROR_SERVICE_EXISTS "SERVICE definition already exists"
#define FLB_CF_ERROR_META_CHAR      "invalid first meta character: '@' expected"
#define FLB_CF_ERROR_KV_INVALID_KEY "invalid key content"
#define FLB_CF_ERROR_KV_INVALID_VAL "invalid value content"

/* manipulate error state for the context */
#define flb_cf_error_set(cf, err)  cf->error_str = err
#define flb_cf_error_get(cf)       cf->error_str
#define flb_cr_error_reset(cf)     cf->error_str = ""

/* meta commands: handled as key value pairs */
#define flb_cf_meta flb_kv

enum cf_file_format {
    FLB_CF_FLUENTBIT,
#ifdef FLB_HAVE_LIBYAML
    FLB_CF_YAML
#endif
};

#define FLB_CF_CLASSIC FLB_CF_FLUENTBIT

enum section_type {
    FLB_CF_SERVICE = 0,           /* [SERVICE]           */
    FLB_CF_PARSER,                /* [PARSER]            */
    FLB_CF_MULTILINE_PARSER,      /* multiline_parser    */
    FLB_CF_STREAM_PROCESSOR,      /* stream_processor    */
    FLB_CF_PLUGINS,               /* plugins             */
    FLB_CF_UPSTREAM_SERVERS,      /* upstream_servers    */
    FLB_CF_CUSTOM,                /* [CUSTOM]            */
    FLB_CF_INPUT,                 /* [INPUT]             */
    FLB_CF_FILTER,                /* [FILTER]            */
    FLB_CF_OUTPUT,                /* [OUTPUT]            */
    FLB_CF_OTHER,                 /* any other section.. */
};

struct flb_cf_group {
    flb_sds_t name;                /* group name */
    struct cfl_kvlist *properties; /* key value properties */
    struct mk_list _head;          /* link to struct flb_cf_section->groups */
};

struct flb_cf_section {
    int type;
    flb_sds_t name;                /* name (used for FLB_CF_OTHER type) */
    struct cfl_kvlist *properties; /* key value properties              */

    struct mk_list groups;         /* list of groups */

    struct mk_list _head;          /* link to struct flb_cf->sections */
    struct mk_list _head_section;  /* link to section type, e.g: inputs, filters.. */
};

struct flb_cf {
    /* origin format */
    int format;

    /* global service */
    struct flb_cf_section *service;

    /* config environment variables (env section, availble on YAML) */
    struct mk_list env;

    /* meta commands (used by fluentbit classic mode) */
    struct mk_list metas;

    /* parsers */
    struct mk_list parsers;
    struct mk_list multiline_parsers;

    /* stream processor: every entry is added as a task */
    struct mk_list stream_processors;

    /* external plugins (.so) */
    struct mk_list plugins;

    /* upstream servers */
    struct mk_list upstream_servers;

    /* 'custom' type plugins */
    struct mk_list customs;

    /* pipeline */
    struct mk_list inputs;
    struct mk_list filters;
    struct mk_list outputs;

    /* others */
    struct mk_list others;

    /* list head for all sections */
    struct mk_list sections;

    /* set the last error found */
    char *error_str;


    /* a list head entry in case the caller want's to link contexts */
    struct mk_list _head;
};


struct flb_cf *flb_cf_create();
struct flb_cf *flb_cf_create_from_file(struct flb_cf *cf, char *file);
flb_sds_t flb_cf_key_translate(struct flb_cf *cf, char *key, int len);

void flb_cf_destroy(struct flb_cf *cf);

int flb_cf_set_origin_format(struct flb_cf *cf, int format);
void flb_cf_dump(struct flb_cf *cf);

struct flb_kv *flb_cf_env_property_add(struct flb_cf *cf,
                                       char *k_buf, size_t k_len,
                                       char *v_buf, size_t v_len);

/* metas */
struct flb_kv *flb_cf_meta_property_add(struct flb_cf *cf, char *meta, int len);

#define flb_cf_foreach_meta(cf) \


void flb_cf_meta_destroy(struct flb_cf *cf, struct flb_cf_meta *meta);
void flb_cf_meta_destroy_all(struct flb_cf *cf);

/* groups */
struct flb_cf_group *flb_cf_group_create(struct flb_cf *cf, struct flb_cf_section *s,
                                         char *name, int len);
struct flb_cf_group *flb_cf_group_get(struct flb_cf *cf, struct flb_cf_section *s, char *name);
void flb_cf_group_print(struct flb_cf_group *g);

void flb_cf_group_destroy(struct flb_cf_group *g);

/* sections */
struct flb_cf_section *flb_cf_section_create(struct flb_cf *cf, char *name, int len);
struct flb_cf_section *flb_cf_section_get_by_name(struct flb_cf *cf, char *name);
void flb_cf_section_destroy(struct flb_cf *cf, struct flb_cf_section *s);
void flb_cf_section_destroy_all(struct flb_cf *cf);

/* properties */
struct cfl_variant *flb_cf_section_property_add(struct flb_cf *cf,
                                              struct cfl_kvlist *kv_list,
                                              char *k_buf, size_t k_len,
                                              char *v_buf, size_t v_len);

struct cfl_variant *flb_cf_section_property_add_variant(struct flb_cf *cf,
                                                        struct cfl_kvlist *kv_list,
                                                        char *k_buf, size_t k_len,
                                                        struct cfl_variant *variant);

struct cfl_array *flb_cf_section_property_add_list(struct flb_cf *cf,
                                                   struct cfl_kvlist *kv_list,
                                                   char *k_buf, size_t k_len);

struct cfl_variant *flb_cf_section_property_get(struct flb_cf *cf,
                                      struct flb_cf_section *s,
                                      char *key);

char *flb_cf_section_property_get_string(struct flb_cf *cf,
                                         struct flb_cf_section *s,
                                         char *key);

#endif
