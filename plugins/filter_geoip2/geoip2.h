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

#include <maxminddb.h>

#ifndef FLB_FILTER_GEOIP2_H
#define FLB_FILTER_GEOIP2_H

struct geoip2_record {
    char *lookup_key;
    char *key;
    char *val;
    int lookup_key_len;
    int key_len;
    int val_len;
    struct mk_list _head;
};

struct geoip2_ctx {
    flb_sds_t database;
    MMDB_s *mmdb;
    int lookup_keys_num;
    int records_num;
    struct mk_list *lookup_keys;
    struct mk_list *record_keys;
    struct mk_list records;
    struct flb_filter_instance *ins;
};

#endif
