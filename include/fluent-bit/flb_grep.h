/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#ifndef FLB_GREP_H
#define FLB_GREP_H

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_record_accessor.h>

/* rule types */
enum flb_grep_rule_type {
    FLB_GREP_NO_RULE,
    FLB_GREP_REGEX,
    FLB_GREP_EXCLUDE
};

/* actions */
enum flb_grep_action {
    FLB_GREP_RET_KEEP,
    FLB_GREP_RET_EXCLUDE
};

enum flb_grep_logical_op {
    FLB_GREP_LOGICAL_OP_LEGACY,
    FLB_GREP_LOGICAL_OP_OR,
    FLB_GREP_LOGICAL_OP_AND
};

struct flb_grep_rule {
    int type;
    flb_sds_t field;
    char *regex_pattern;
    struct flb_regex *regex;
    struct flb_record_accessor *ra;
    struct mk_list _head;
};


struct flb_grep {
    enum flb_grep_rule_type first_rule;
    enum flb_grep_logical_op op;
    struct mk_list rules; /* flb_grep_rule list */
};


int flb_grep_filter(msgpack_object map, struct flb_grep *grep_ctx);
int flb_grep_set_rule_str(struct flb_grep *ctx, enum flb_grep_rule_type type, char *rule_str);
struct flb_grep *flb_grep_create(enum flb_grep_logical_op op);
int flb_grep_destroy(struct flb_grep *grep_ctx);

#endif /* FLB_GREP_H */
