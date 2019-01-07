/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_HASH_H
#define FLB_HASH_H

#include <fluent-bit/flb_info.h>
#include <monkey/mk_core.h>

#include <stdio.h>
#include <stdlib.h>

/* Eviction modes when the table reach full capacity (if any) */
#define FLB_HASH_EVICT_NONE       0
#define FLB_HASH_EVICT_OLDER      1
#define FLB_HASH_EVICT_LESS_USED  2
#define FLB_HASH_EVICT_RANDOM     3

struct flb_hash_entry {
    time_t created;
    uint64_t hits;
    char *key;
    size_t key_len;
    char *val;
    size_t val_size;
    struct flb_hash_table *table; /* link to parent flb_hash_table */
    struct mk_list _head;         /* link to flb_hash_table->chains */
    struct mk_list _head_parent;  /* link to flb_hash->entries */
};

struct flb_hash_table {
    int count;
    struct mk_list chains;
};

struct flb_hash {
    int evict_mode;
    int max_entries;
    int total_count;
    size_t size;
    struct mk_list entries;
    struct flb_hash_table *table;
};

struct flb_hash *flb_hash_create(int evict_mode, size_t size, int max_entries);
void flb_hash_destroy(struct flb_hash *ht);

int flb_hash_add(struct flb_hash *ht, char *key, int key_len,
                 char *val, size_t val_size);
int flb_hash_get(struct flb_hash *ht, char *key, int key_len,
                 char **out_buf, size_t *out_size);
int flb_hash_get_by_id(struct flb_hash *ht, int id, char *key, char **out_buf,
                       size_t *out_size);
int flb_hash_del(struct flb_hash *ht, char *key);

#endif
