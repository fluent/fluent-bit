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

#ifndef FLB_PROCESSOR_SELECTOR_H
#define FLB_PROCESSOR_SELECTOR_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_record_accessor.h>

/* rule types */
#define SELECTOR_NO_RULE  0
#define SELECTOR_INCLUDE  1
#define SELECTOR_EXCLUDE  2

/* actions */
#define SELECTOR_RET_KEEP     0
#define SELECTOR_RET_EXCLUDE  1

#define SELECTOR_SUCCESS   0
#define SELECTOR_NOTOUCH   1
#define SELECTOR_FAILURE   2

#define SELECTOR_OPERATION_REGEX          0
#define SELECTOR_OPERATION_PREFIX         1
#define SELECTOR_OPERATION_SUBSTRING      2
#define SELECTOR_OPERATION_LABEL_DELETION 3

/* context */
#define SELECTOR_CONTEXT_FQNAME             0
#define SELECTOR_CONTEXT_LABELS             1
#define SELECTOR_CONTEXT_DESC               2
#define SELECTOR_CONTEXT_DELETE_LABEL_VALUE 3

struct selector_ctx {
    struct mk_list metrics_rules;
    flb_sds_t action;
    int action_type;
    int op_type;
    int context_type;
    char *selector_pattern;
    flb_sds_t label_key;
    flb_sds_t label_value;
    struct flb_regex *name_regex;
    struct flb_processor_instance *ins;
    struct flb_config *config;
};

#endif
