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

#ifndef FLB_FILTER_EXPECT_H
#define FLB_FILTER_EXPECT_H

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_record_accessor.h>

#define FLB_EXP_WARN              0
#define FLB_EXP_EXIT              1
#define FLB_EXP_RESULT_KEY        2

/* Rule types */
#define FLB_EXP_KEY_EXISTS        0   /* key exists */
#define FLB_EXP_KEY_NOT_EXISTS    1   /* key not exists */
#define FLB_EXP_KEY_VAL_NULL      2   /* key value has a NULL value */
#define FLB_EXP_KEY_VAL_NOT_NULL  3   /* key value has a NULL value */
#define FLB_EXP_KEY_VAL_EQ        4   /* key value is equal some given value */

struct flb_expect_rule {
    int type;
    flb_sds_t value;              /* original value given in the config       */
    flb_sds_t expect;             /* specific value match (FLB_EXP_KEY_VAL_EQ */
    struct flb_record_accessor *ra;
    struct mk_list _head;
};

struct flb_expect {
    int action;
    flb_sds_t result_key;
    struct mk_list rules;
    struct flb_filter_instance *ins;
};

#endif
