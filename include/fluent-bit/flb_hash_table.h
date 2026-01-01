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

#ifndef FLB_HASH_TABLE_H
#define FLB_HASH_TABLE_H

#include <fluent-bit/flb_info.h>
#include <cfl/cfl.h>

#include <monkey/mk_core.h>

#include <stdio.h>
#include <stdlib.h>

/* Eviction modes when the table reach full capacity (if any) */
#define FLB_HASH_TABLE_EVICT_NONE       0
#define FLB_HASH_TABLE_EVICT_OLDER      1
#define FLB_HASH_TABLE_EVICT_LESS_USED  2
#define FLB_HASH_TABLE_EVICT_RANDOM     3

struct flb_hash_table_entry {
    time_t created;
    uint64_t hits;
    uint64_t hash;
    char *key;
    size_t key_len;
    void *val;
    ssize_t val_size;
    struct flb_hash_table_chain *table; /* link to parent flb_hash_table */
    struct mk_list _head;               /* link to flb_hash_table->chains */
    struct mk_list _head_parent;        /* link to flb_hash->entries */
};

struct flb_hash_table_chain {
    int count;
    struct mk_list chains;
};

struct flb_hash_table {
    int evict_mode;
    int max_entries;
    int total_count;
    int cache_ttl;
    int case_sensitivity;
    size_t size;
    struct mk_list entries;
    struct flb_hash_table_chain *table;
};

struct flb_hash_table *flb_hash_table_create(int evict_mode, size_t size, int max_entries);
struct flb_hash_table *flb_hash_table_create_with_ttl(int cache_ttl, int evict_mode,
                                                      size_t size, int max_entries);
void flb_hash_table_destroy(struct flb_hash_table *ht);

void flb_hash_table_set_case_sensitivity(struct flb_hash_table *ht, int status);

int flb_hash_table_add(struct flb_hash_table *ht,
                       const char *key, int key_len,
                       void *val, ssize_t val_size);
int flb_hash_table_get(struct flb_hash_table *ht,
                       const char *key, int key_len,
                       void **out_buf, size_t *out_size);

int flb_hash_table_exists(struct flb_hash_table *ht, uint64_t hash);
int flb_hash_table_get_by_id(struct flb_hash_table *ht, int id,
                             const char *key,
                             const char **out_buf, size_t *out_size);

void *flb_hash_table_get_ptr(struct flb_hash_table *ht, const char *key, int key_len);

int flb_hash_table_del(struct flb_hash_table *ht, const char *key);

int flb_hash_table_del_ptr(struct flb_hash_table *ht, const char *key, int key_len,
                           void *ptr);

#endif
