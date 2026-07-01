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

#ifndef FLB_FILTER_NEST_H
#define FLB_FILTER_NEST_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>

enum FILTER_NEST_OPERATION {
  NEST,
  LIFT
};

struct filter_nest_ctx
{
    enum FILTER_NEST_OPERATION operation;
    char *key;
    int key_len;
    char *prefix;
    int prefix_len;
    // nest
    struct mk_list wildcards;
    int wildcards_cnt;
    bool remove_prefix;
    // lift
    bool add_prefix;
    struct flb_filter_instance *ins;
};

struct filter_nest_wildcard
{
    char *key;
    int key_len;
    bool key_is_dynamic;
    struct mk_list _head;
};

#endif
