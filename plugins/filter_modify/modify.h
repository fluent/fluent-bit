/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
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

struct filter_modify_ctx
{
    int add_key_rules_cnt;
    int rename_key_rules_cnt;
    struct mk_list add_key_rules;
    struct mk_list rename_key_rules;
};

struct modify_rule
{
    int key_len;
    int val_len;
    char *key;
    char *val;
    struct mk_list _head;
};
#endif
