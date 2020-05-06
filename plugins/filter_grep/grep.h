/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#ifndef FLB_FILTER_GREP_H
#define FLB_FILTER_GREP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_record_accessor.h>

/* rule types */
#define GREP_REGEX    1
#define GREP_EXCLUDE  2

/* actions */
#define GREP_RET_KEEP     0
#define GREP_RET_EXCLUDE  1

struct grep_ctx {
    struct mk_list rules;
    struct flb_filter_instance *ins;
};

struct grep_rule {
    int type;
    flb_sds_t field;
    char *regex_pattern;
    struct flb_regex *regex;
    struct flb_record_accessor *ra;
    struct mk_list _head;
};

#endif
