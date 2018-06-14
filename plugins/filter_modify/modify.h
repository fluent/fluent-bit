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

#ifndef FLB_FILTER_MODIFY_H
#define FLB_FILTER_MODIFY_H

enum FLB_FILTER_MODIFY_RULETYPE {
  RENAME,
  HARD_RENAME,
  ADD,
  SET,
  REMOVE,
  REMOVE_WILDCARD,
  COPY,
  HARD_COPY
};

enum FLB_FILTER_MODIFY_CONDITIONTYPE {
  KEY_EXISTS,
  KEY_DOES_NOT_EXIST,
  KEY_VALUE_EQUALS,
  KEY_VALUE_DOES_NOT_EQUAL
};

struct filter_modify_ctx
{
  int rules_cnt;
  struct mk_list rules;
  int conditions_cnt;
  struct mk_list conditions;
};

struct modify_rule
{
  enum FLB_FILTER_MODIFY_RULETYPE ruletype;
  int key_len;
  int val_len;
  char *key;
  char *val;
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
  char *raw_k;
  char *raw_v;
  struct mk_list _head;
};
#endif
