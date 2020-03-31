/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *  Copyright (C) 2020 Nick Fischer
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

#ifndef FLB_DUPLICATE_H
#define FLB_DUPLICATE_H

#include <fluent-bit/flb_input.h>

#define FLB_DUP_METRIC_EMITTED 300

/* Plugin context */
struct flb_duplicate {
    flb_sds_t new_tag;                      /* tag to apply to duplicate records */
    flb_sds_t emitter_name;                 /* emitter input plugin name */
    struct mk_list *cm_rules;               /* config_map rules (only strings) */
    struct flb_input_instance *ins_emitter; /* emitter input plugin instance */
    struct flb_filter_instance *ins;        /* self-filter instance */
    struct flb_config *config;              /* Fluent Bit context */
};

/* Register external function to emit records, check 'plugins/in_emitter' */
int in_emitter_add_record(const char *tag, int tag_len,
                          const char *buf_data, size_t buf_size,
                          struct flb_input_instance *in);
int in_emitter_get_collector_id(struct flb_input_instance *in);


#endif
