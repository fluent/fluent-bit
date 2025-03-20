/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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

#ifndef FLB_SAMPLING_COND_ATTRIBUTE_H

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_regex.h>
#include "sampling.h"

enum attribute_type {
    ATTRIBUTE_TYPE_STRING = 0,
    ATTRIBUTE_TYPE_NUMERIC,
    ATTRIBUTE_TYPE_BOOLEAN,
};

enum match_type {
    MATCH_TYPE_STRICT = 0,
    MATCH_TYPE_EXISTS,
    MATCH_TYPE_REGEX,
};

struct attribute_value {
    cfl_sds_t value;
    struct flb_regex *regex_value;
    struct cfl_list _head;
};

struct cond_attribute {
    int attribute_type;     /* string_attribute, numeric_attribute or boolean_attribute */

    /* config options */
    cfl_sds_t key;
    int match_type;

    /* numeric_attribute config options */
    int invert_match;
    int64_t min_value;
    int64_t max_value;

    /* boolean_attribute */
    bool boolean_value;

    struct cfl_list list_values;
};

int cond_attr_check(struct sampling_condition *sampling_condition, struct ctrace_span *span, int attribute_type);
void cond_attr_destroy(struct sampling_condition *sampling_condition);

#endif