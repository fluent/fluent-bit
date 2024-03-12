/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <stdio.h>
#include <sys/types.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>
#include <pthread.h>

#include "window_tag.h"

/* This function create a new tag throttling window named @name with @size number of panes.
 * The total amount of entries is 0 with timestamp set according to the current system time.
 * The name of the window is null terminated.
 */
struct throttle_tag_window *tag_window_create(const char *name,
                                                int name_length,
                                                unsigned int size)
{
    struct throttle_tag_window *stw;
    struct flb_time ftm;
    int i;

    if (size <= 0) {
        return NULL;
    }

    stw = flb_malloc(sizeof(struct throttle_tag_window));
    if (!stw) {
        flb_errno();
        return NULL;
    }

    stw->size = size;
    stw->total = 0;
    stw->dropped = 0;
    stw->head = size - 1;
    stw->tail = 0;
    stw->table = flb_calloc(size, sizeof(struct throttle_tag_pane));
    if (!stw->table) {
        flb_errno();
        flb_free(stw);
        return NULL;
    }

    stw->name = flb_strndup(name, name_length);

    if (!stw->name) {
        flb_errno();
        flb_free(stw->table);
        flb_free(stw);
        return NULL;
    }

    flb_time_get(&ftm);
    stw->timestamp = flb_time_to_double(&ftm);

    for (i = 0; i < size; i++) {
        stw->table[i].timestamp = stw->timestamp;
        stw->table[i].size = 0;
    }
    flb_debug
        ("[filter_throttle_tag] New throttling window named \"%s\" was created.",
         stw->name);
    return stw;
}

static inline void *create_lock()
{
    pthread_mutex_t *lock = flb_malloc(sizeof(pthread_mutex_t));
    if (!lock) {
        return NULL;
    }
    if (pthread_mutex_init(lock, NULL) != 0) {
        flb_errno();
        return NULL;
    }
    return lock;
}

static inline void destroy_throttle_tag_table_lock(struct throttle_tag_table *ht)
{
    pthread_mutex_destroy(ht->lock);
    flb_free(ht->lock);
}

struct throttle_tag_table *create_throttle_tag_table(size_t size)
{
    struct throttle_tag_table *table;
    table = flb_malloc(sizeof(struct throttle_tag_table));
    if (!table) {
        return NULL;
    }
    table->windows =
        flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, size,
                              FLB_WINDOW_TAG_HASH_MAX_ENTRIES);
    if (!table->windows) {
        flb_errno();
        flb_free(table);
        return NULL;
    }
    table->lock = create_lock();
    if (!table->lock) {
        flb_free(table);
        return NULL;
    }
    return table;
}

void destroy_throttle_tag_table(struct throttle_tag_table *ht)
{
    int i;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hash_table_entry *entry;
    struct flb_hash_table_chain *table;

    for (i = 0; i < ht->windows->size; i++) {
        table = &ht->windows->table[i];
        mk_list_foreach_safe(head, tmp, &table->chains) {
            entry = mk_list_entry(head, struct flb_hash_table_entry, _head);
            free_stw_content((struct throttle_tag_window *) entry->val);
            mk_list_del(&entry->_head);
            mk_list_del(&entry->_head_parent);
            entry->table->count--;
            ht->windows->total_count--;
            flb_free(entry->key);
            flb_free(entry->val);
            flb_free(entry);
        }
    }
    destroy_throttle_tag_table_lock(ht);
    flb_free(ht->windows->table);
    flb_free(ht->windows);
    flb_free(ht);
}
