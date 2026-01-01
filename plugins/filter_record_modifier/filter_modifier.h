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

#ifndef FLB_FILTER_RECORD_MODIFIER_H
#define FLB_FILTER_RECORD_MODIFIER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_filter.h>

struct modifier_record {
    char *key;
    char *val;
    int  key_len;
    int  val_len;
    struct mk_list _head;
};

struct modifier_key {
    char *key;
    int   key_len;
    int   dynamic_key;
    struct mk_list _head;
};

struct record_modifier_ctx {
    int records_num;
    int remove_keys_num;
    int allowlist_keys_num;

    flb_sds_t uuid_key;

    /* config map */
    struct mk_list *records_map;
    struct mk_list *remove_keys_map;
    struct mk_list *allowlist_keys_map;
    struct mk_list *whitelist_keys_map;

    struct mk_list records;
    struct mk_list remove_keys;
    struct mk_list allowlist_keys;
    struct flb_filter_instance *ins;
};

typedef enum {
    TO_BE_REMOVED = 0,
    TO_BE_REMAINED = 1,
    TAIL_OF_ARRAY = 2
} bool_map_t;


#endif /* FLB_FILTER_RECORD_MODIFIER_H */
