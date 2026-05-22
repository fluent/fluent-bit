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

#ifndef FLB_REWRITE_TAG_H
#define FLB_REWRITE_TAG_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_metrics.h>

#define FLB_RTAG_METRIC_EMITTED    200
#define FLB_RTAG_MEM_BUF_LIMIT_DEFAULT  "10M"

/* Rewrite rule  */
struct rewrite_rule {
    int keep_record;                       /* keep original record ? */
    struct flb_regex *regex;               /* matching regex */
    struct flb_record_accessor *ra_key;    /* key record accessor */
    struct flb_record_accessor *ra_tag;    /* tag record accessor */
    struct mk_list _head;                  /* link to flb_rewrite_tag->rules */
};

enum recursion_action {
    REWRITE_ACTION_NONE = 0,
    REWRITE_ACTION_DROP,
    REWRITE_ACTION_DROP_AND_LOG,
    REWRITE_ACTION_EXIT,
};

/* Plugin context */
struct flb_rewrite_tag {
    int recursion_action;                   /* action when recursion occurs */
    flb_sds_t emitter_name;                 /* emitter input plugin name */
    flb_sds_t emitter_storage_type;         /* emitter storage type */
    size_t emitter_mem_buf_limit;           /* Emitter buffer limit */
    struct mk_list rules;                   /* processed rules */
    struct mk_list *cm_rules;               /* config_map rules (only strings) */
    struct flb_input_instance *ins_emitter; /* emitter input plugin instance */
    struct flb_filter_instance *ins;        /* self-filter instance */
    struct flb_config *config;              /* Fluent Bit context */

#ifdef FLB_HAVE_METRICS
    struct cmt_counter *cmt_emitted;
#endif
};

/* Register external function to emit records, check 'plugins/in_emitter' */
int in_emitter_add_record(const char *tag, int tag_len,
                          const char *buf_data, size_t buf_size,
                          struct flb_input_instance *in,
                          struct flb_input_instance *i_ins);
int in_emitter_get_collector_id(struct flb_input_instance *in);


#endif
