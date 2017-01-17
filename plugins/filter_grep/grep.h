/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#include <regex.h>

/* rule types */
#define GREP_REGEX    1
#define GREP_EXCLUDE  2

/* actions */
#define GREP_RET_KEEP     0
#define GREP_RET_EXCLUDE  1

struct grep_ctx {
    struct mk_list rules;
};

struct grep_rule {
    int type;
    char *field;
    char *regex;
    regex_t match;
    struct mk_list _head;
};

#endif
