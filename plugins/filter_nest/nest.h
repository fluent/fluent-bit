/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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

#ifndef FLB_FILTER_NEST_H
#define FLB_FILTER_NEST_H

enum FILTER_NEST_OPERATION {
  NEST,
  LIFT
};

struct filter_nest_ctx
{
    enum FILTER_NEST_OPERATION operation;
    // nest
    char *nesting_key;
    int nesting_key_len;
    char *wildcard;
    int wildcard_len;
    bool wildcard_is_dynamic;
    // lift
    char *nested_under;
    int nested_under_len;
    char *prefix_with;
    int prefix_with_len;
    bool use_prefix;
};

#endif
