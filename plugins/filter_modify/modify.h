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

#ifndef FLB_FILTER_MODIFY_H
#define FLB_FILTER_MODIFY_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>

/* 
 * Speed up Key_Value_Type_Matches condition check,
 * use `switch` + `hash()` instead of `if ... else` + `strncmp()`.
 *
 * Note, it's arch sensitive, little-endian (LE) ONLY due to the implementation
 * of hash function, see `gen_hash()` in `flb_hash.c`.
 */
#define FLB_FILTER_MODIFY_HASH_NIL    976956422U
#define FLB_FILTER_MODIFY_HASH_BOOL   4022539617U
#define FLB_FILTER_MODIFY_HASH_NUMBER 4188039317U
#define FLB_FILTER_MODIFY_HASH_INT    3831089057U
#define FLB_FILTER_MODIFY_HASH_FLOAT  1075678673U
#define FLB_FILTER_MODIFY_HASH_STR    3331274845U
#define FLB_FILTER_MODIFY_HASH_ARRAY  968645473U
#define FLB_FILTER_MODIFY_HASH_MAP    671111262U
#define FLB_FILTER_MODIFY_HASH_BIN    3587806299U
#define FLB_FILTER_MODIFY_HASH_EXT    1459784193U

enum FLB_FILTER_MODIFY_RULETYPE {
  RENAME,
  HARD_RENAME,
  ADD,
  SET,
  REMOVE,
  REMOVE_WILDCARD,
  REMOVE_REGEX,
  COPY,
  HARD_COPY
};

enum FLB_FILTER_MODIFY_CONDITIONTYPE {
  KEY_EXISTS,
  KEY_DOES_NOT_EXIST,
  A_KEY_MATCHES,
  NO_KEY_MATCHES,
  KEY_VALUE_EQUALS,
  KEY_VALUE_DOES_NOT_EQUAL,
  KEY_VALUE_MATCHES,
  KEY_VALUE_DOES_NOT_MATCH,
  KEY_VALUE_TYPE_MATCHES,
  KEY_VALUE_TYPE_DOES_NOT_MATCH,
  MATCHING_KEYS_HAVE_MATCHING_VALUES,
  MATCHING_KEYS_DO_NOT_HAVE_MATCHING_VALUES,
  MATCHING_KEY
};

struct filter_modify_ctx
{
    int rules_cnt;
    struct mk_list rules;
    int conditions_cnt;
    struct mk_list conditions;
    struct flb_filter_instance *ins;
};

struct modify_rule
{
    enum FLB_FILTER_MODIFY_RULETYPE ruletype;
    int key_len;
    int val_len;
    char *key;
    char *val;
    bool key_is_regex;
    bool val_is_regex;
    struct flb_regex *key_regex;
    struct flb_regex *val_regex;
    char *raw_k;
    char *raw_v;
    struct mk_list _head;
};

struct modify_condition
{
    enum FLB_FILTER_MODIFY_CONDITIONTYPE conditiontype;
    int a_len;
    int b_len;
    char *a;
    char *b;
    bool a_is_regex;
    bool b_is_regex;
    struct flb_regex *a_regex;
    struct flb_regex *b_regex;
    char *raw_k;
    char *raw_v;
    struct mk_list _head;
};
#endif
