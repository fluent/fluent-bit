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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>
#include <xxhash.h>

static inline void flb_hash_entry_free(struct flb_hash *ht,
                                       struct flb_hash_entry *entry)
{
    mk_list_del(&entry->_head);
    mk_list_del(&entry->_head_parent);
    entry->table->count--;
    ht->total_count--;
    flb_free(entry->key);
    if (entry->val && entry->val_size > 0) {
        flb_free(entry->val);
    }
    flb_free(entry);
}

struct flb_hash *flb_hash_create(int evict_mode, size_t size, int max_entries)
{
    int i;
    struct flb_hash_table *tmp;
    struct flb_hash *ht;

    if (size <= 0) {
        return NULL;
    }

    ht = flb_malloc(sizeof(struct flb_hash));
    if (!ht) {
        flb_errno();
        return NULL;
    }

    mk_list_init(&ht->entries);
    ht->evict_mode = evict_mode;
    ht->max_entries = max_entries;
    ht->size = size;
    ht->total_count = 0;
    ht->table = flb_calloc(1, sizeof(struct flb_hash_table) * size);
    if (!ht->table) {
        flb_errno();
        flb_free(ht);
        return NULL;
    }

    /* Initialize chains list head */
    for (i = 0; i < size; i++) {
        tmp = &ht->table[i];
        tmp->count = 0;
        mk_list_init(&tmp->chains);
    }

    return ht;
}

int flb_hash_del_ptr(struct flb_hash *ht, const char *key, int key_len,
                     void *ptr)
{
    int id;
    uint64_t hash;
    struct mk_list *head;
    struct flb_hash_entry *entry = NULL;
    struct flb_hash_table *table;

    /* Generate hash number */
    hash = XXH3_64bits(key, key_len);
    id = (hash % ht->size);

    /* Link the new entry in our table at the end of the list */
    table = &ht->table[id];

    mk_list_foreach(head, &table->chains) {
        entry = mk_list_entry(head, struct flb_hash_entry, _head);
        if (strncmp(entry->key, key, key_len) == 0 && entry->val == ptr) {
            break;
        }
        entry = NULL;
    }

    if (!entry) {
        return -1;
    }

    /* delete the entry */
    flb_hash_entry_free(ht, entry);
    return 0;
}


void flb_hash_destroy(struct flb_hash *ht)
{
    int i;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hash_entry *entry;
    struct flb_hash_table *table;

    for (i = 0; i < ht->size; i++) {
        table = &ht->table[i];
        mk_list_foreach_safe(head, tmp, &table->chains) {
            entry = mk_list_entry(head, struct flb_hash_entry, _head);
            flb_hash_entry_free(ht, entry);
        }
    }

    flb_free(ht->table);
    flb_free(ht);
}

static void flb_hash_evict_random(struct flb_hash *ht)
{
    int id;
    int count = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hash_entry *entry;

    id = random() % ht->total_count;
    mk_list_foreach_safe(head, tmp, &ht->entries) {
        if (id == count) {
            entry = mk_list_entry(head, struct flb_hash_entry, _head_parent);
            flb_hash_entry_free(ht, entry);
            break;
        }
        count++;
    }
}

static void flb_hash_evict_less_used(struct flb_hash *ht)
{
    struct mk_list *head;
    struct flb_hash_entry *entry;
    struct flb_hash_entry *entry_less_used = NULL;

    mk_list_foreach(head, &ht->entries) {
        entry = mk_list_entry(head, struct flb_hash_entry, _head_parent);
        if (!entry_less_used) {
            entry_less_used = entry;
        }
        else if (entry->hits < entry_less_used->hits) {
            entry_less_used = entry;
        }
    }

    flb_hash_entry_free(ht, entry_less_used);
}

static void flb_hash_evict_older(struct flb_hash *ht)
{
    struct flb_hash_entry *entry;

    entry = mk_list_entry_first(&ht->entries, struct flb_hash_entry, _head_parent);
    flb_hash_entry_free(ht, entry);
}

static struct flb_hash_entry *hash_get_entry(struct flb_hash *ht,
                                             const char *key, int key_len, int *out_id)
{
    int id;
    unsigned int hash;
    struct mk_list *head;
    struct flb_hash_table *table;
    struct flb_hash_entry *entry;

    if (!key || key_len <= 0) {
        return NULL;
    }

    hash = XXH3_64bits(key, key_len);
    id = (hash % ht->size);

    table = &ht->table[id];
    if (table->count == 0) {
        return NULL;
    }

    if (table->count == 1) {
        entry = mk_list_entry_first(&table->chains,
                                    struct flb_hash_entry, _head);

        if (entry->key_len != key_len
            || strncmp(entry->key, key, key_len) != 0) {
            entry = NULL;
        }
    }
    else {
        /* Iterate entries */
        mk_list_foreach(head, &table->chains) {
            entry = mk_list_entry(head, struct flb_hash_entry, _head);
            if (entry->key_len != key_len) {
                entry = NULL;
                continue;
            }

            if (strncmp(entry->key, key, key_len) == 0) {
                break;
            }

            entry = NULL;
        }
    }

    if (entry) {
        *out_id = id;
    }

    return entry;
}

static int entry_set_value(struct flb_hash_entry *entry, void *val, size_t val_size)
{
    char *ptr;

    /*
     * If the entry already contains a previous value in the heap, just remove
     * the previously assigned memory.
     */
    if (entry->val_size > 0) {
        flb_free(entry->val);
    }

    /*
     * Now set the new value. If val_size > 0, we create a new memory area, otherwise
     * it means the caller just wants to store a pointer address, no allocation
     * is required.
     */
    if (val_size > 0) {
        entry->val = flb_malloc(val_size + 1);
        if (!entry->val) {
            flb_errno();
            return -1;
        }

        /*
         * Copy the buffer and append a NULL byte in case the caller set and
         * expects a string.
         */
        memcpy(entry->val, val, val_size);
        ptr = (char *) entry->val;
        ptr[val_size] = '\0';
        entry->val_size = val_size;
    }
    else {
        /* just do a reference */
        entry->val = val;
        entry->val_size = -1;
    }

    return 0;
}

int flb_hash_add(struct flb_hash *ht,
                 const char *key, int key_len,
                 void *val, ssize_t val_size)
{
    int id;
    int ret;
    uint64_t hash;
    struct flb_hash_entry *entry;
    struct flb_hash_table *table;

    if (!key || key_len <= 0) {
        return -1;
    }

    /* Check capacity */
    if (ht->max_entries > 0 && ht->total_count >= ht->max_entries) {
        if (ht->evict_mode == FLB_HASH_EVICT_NONE) {
            /* Do nothing */
        }
        else if (ht->evict_mode == FLB_HASH_EVICT_OLDER) {
            flb_hash_evict_older(ht);
        }
        else if (ht->evict_mode == FLB_HASH_EVICT_LESS_USED) {
            flb_hash_evict_less_used(ht);
        }
        else if (ht->evict_mode == FLB_HASH_EVICT_RANDOM) {
            flb_hash_evict_random(ht);
        }
    }

    /* Check if this is a replacement */
    entry = hash_get_entry(ht, key, key_len, &id);
    if (entry) {
        /*
         * The key already exists, just perform a value replacement, check if the
         * value refers to our own previous allocation.
         */
        ret = entry_set_value(entry, val, val_size);
        if (ret == -1) {
            return -1;
        }

        return id;
    }

    /*
     * Below is just code to handle the creation of a new entry in the table
     */

    /* Generate hash number */
    hash = XXH3_64bits(key, key_len);
    id = (hash % ht->size);

    /* Allocate the entry */
    entry = flb_calloc(1, sizeof(struct flb_hash_entry));
    if (!entry) {
        flb_errno();
        return -1;
    }
    entry->created = time(NULL);
    entry->hits = 0;

    /* Store the key and value as a new memory region */
    entry->key = flb_strndup(key, key_len);
    entry->key_len = key_len;
    entry->val_size = 0;

    /* store or reference the value */
    ret = entry_set_value(entry, val, val_size);
    if (ret == -1) {
        flb_free(entry);
        return -1;
    }

    /* Link the new entry in our table at the end of the list */
    table = &ht->table[id];
    entry->table = table;

    /* Add the new entry */
    mk_list_add(&entry->_head, &table->chains);
    mk_list_add(&entry->_head_parent, &ht->entries);

    /* Update counters */
    table->count++;
    ht->total_count++;

    return id;
}

int flb_hash_get(struct flb_hash *ht,
                 const char *key, int key_len,
                 void **out_buf, size_t *out_size)
{
    int id;
    struct flb_hash_entry *entry;

    entry = hash_get_entry(ht, key, key_len, &id);
    if (!entry) {
        return -1;
    }

    entry->hits++;
    *out_buf = entry->val;
    *out_size = entry->val_size;

    return id;
}

/*
 * Get an entry based in the table id. Note that a table id might have multiple
 * entries so the 'key' parameter is required to get an exact match.
 */
int flb_hash_get_by_id(struct flb_hash *ht, int id,
                       const char *key,
                       const char **out_buf, size_t * out_size)
{
    struct mk_list *head;
    struct flb_hash_entry *entry = NULL;
    struct flb_hash_table *table;

    if (ht->size <= id) {
        return -1;
    }

    table = &ht->table[id];
    if (table->count == 0) {
        return -1;
    }

    if (table->count == 1) {
        entry = mk_list_entry_first(&table->chains,
                                    struct flb_hash_entry, _head);
    }
    else {
        mk_list_foreach(head, &table->chains) {
            entry = mk_list_entry(head, struct flb_hash_entry, _head);
            if (strcmp(entry->key, key) == 0) {
                break;
            }
            entry = NULL;
        }
    }

    if (!entry) {
        return -1;
    }

    *out_buf = entry->val;
    *out_size = entry->val_size;

    return 0;
}

int flb_hash_del(struct flb_hash *ht, const char *key)
{
    int id;
    int len;
    unsigned int hash;
    struct mk_list *head;
    struct flb_hash_entry *entry = NULL;
    struct flb_hash_table *table;

    if (!key) {
        return -1;
    }

    len = strlen(key);
    if (len == 0) {
        return -1;
    }

    hash = XXH3_64bits(key, len);
    id = (hash % ht->size);

    table = &ht->table[id];
    if (table->count == 1) {
        entry = mk_list_entry_first(&table->chains,
                                    struct flb_hash_entry,
                                    _head);
        if (strcmp(entry->key, key) != 0) {
            entry = NULL;
        }
    }
    else {
        mk_list_foreach(head, &table->chains) {
            entry = mk_list_entry(head, struct flb_hash_entry, _head);
            if (strcmp(entry->key, key) == 0) {
                break;
            }
            entry = NULL;
        }
    }

    if (!entry) {
        return -1;
    }

    flb_hash_entry_free(ht, entry);

    return 0;
}
