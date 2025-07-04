/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <stdint.h>
#include <ctype.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>

#include <cfl/cfl.h>

static inline char *convert_string_to_lowercase(char  *output_buffer, char *input_buffer, size_t length)
{
    size_t index;

    if (input_buffer == NULL) {
        return NULL;
    }

    if (output_buffer == NULL) {
        output_buffer = flb_calloc(1, length + 1);
        if (output_buffer == NULL) {
            flb_errno();
            return NULL;
        }
    }

    if (output_buffer != NULL) {
        for (index = 0 ; index < length ; index++) {
            output_buffer[index] = tolower(input_buffer[index]);
        }
    }

    return output_buffer;
}

static inline int flb_hash_table_compute_key_hash(uint64_t *hash, char *key, size_t key_len, int case_sensitivity)
{
    int converted_key_allocated = FLB_FALSE;
    char  local_caseless_key_buffer[64];
    char *converted_key = key;

    if (!case_sensitivity) {
        if (key_len >= (sizeof(local_caseless_key_buffer) - 1)) {
            converted_key = convert_string_to_lowercase(NULL, key, key_len);
            converted_key_allocated = FLB_TRUE;
        }
        else {
            converted_key = convert_string_to_lowercase(local_caseless_key_buffer,
                                                        key, key_len);
        }

        if (converted_key == NULL) {
            return -1;
        }
    }

    *hash = cfl_hash_64bits(converted_key, key_len);
    if (converted_key_allocated) {
        flb_free(converted_key);
    }

    return 0;
}

static inline void flb_hash_table_entry_free(struct flb_hash_table *ht,
                                             struct flb_hash_table_entry *entry)
{
    mk_list_del(&entry->_head);
    mk_list_del(&entry->_head_parent);
    entry->table->count--;
    ht->total_count--;
    flb_free(entry->key);
    if (entry->val && entry->val_size > 0) {
        flb_free(entry->val);
    } else if (ht->force_remove_pointer) {
        flb_free(entry->val);
    }
    flb_free(entry);
}

struct flb_hash_table *flb_hash_table_create(int evict_mode, size_t size, int max_entries)
{
    int i;
    struct flb_hash_table_chain *tmp;
    struct flb_hash_table *ht;

    if (size <= 0) {
        return NULL;
    }

    ht = flb_calloc(1, sizeof(struct flb_hash_table));
    if (!ht) {
        flb_errno();
        return NULL;
    }

    mk_list_init(&ht->entries);
    ht->evict_mode = evict_mode;
    ht->max_entries = max_entries;
    ht->size = size;
    ht->total_count = 0;
    ht->cache_ttl = 0;
    ht->case_sensitivity = FLB_TRUE;
    ht->force_remove_pointer = 0;
    ht->table = flb_calloc(1, sizeof(struct flb_hash_table_chain) * size);
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

struct flb_hash_table *flb_hash_table_create_with_ttl(int cache_ttl, int evict_mode,
                                                      size_t size, int max_entries)
{
    struct flb_hash_table *ht;

    ht = flb_hash_table_create(evict_mode, size, max_entries);
    if (!ht) {
        flb_errno();
        return NULL;
    }

    ht->cache_ttl = cache_ttl;
    return ht;
}

struct flb_hash_table *flb_hash_table_create_with_ttl_force_destroy(int cache_ttl, int evict_mode,
                                          size_t size, int max_entries)
{
    struct flb_hash_table *ht;

    ht = flb_hash_table_create_with_ttl(cache_ttl,evict_mode, size, max_entries);
    if (!ht) {
        flb_errno();
        return NULL;
    }

    ht->force_remove_pointer = 1;
    return ht;
}

int flb_hash_table_del_ptr(struct flb_hash_table *ht, const char *key, int key_len,
                           void *ptr)
{
    int id;
    int result;
    uint64_t hash;
    struct mk_list *head;
    struct flb_hash_table_entry *entry = NULL;
    struct flb_hash_table_chain *table;

    /* Generate hash number */
    result = flb_hash_table_compute_key_hash(
                        &hash,
                        (char *) key, key_len,
                        ht->case_sensitivity);

    if (result != 0) {
        return -1;
    }

    id = (hash % ht->size);

    /* Link the new entry in our table at the end of the list */
    table = &ht->table[id];

    mk_list_foreach(head, &table->chains) {
        entry = mk_list_entry(head, struct flb_hash_table_entry, _head);
        if (strncmp(entry->key, key, key_len) == 0 && entry->val == ptr) {
            break;
        }
        entry = NULL;
    }

    if (!entry) {
        return -1;
    }

    /* delete the entry */
    flb_hash_table_entry_free(ht, entry);
    return 0;
}


void flb_hash_table_destroy(struct flb_hash_table *ht)
{
    int i;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hash_table_entry *entry;
    struct flb_hash_table_chain *table;

    for (i = 0; i < ht->size; i++) {
        table = &ht->table[i];
        mk_list_foreach_safe(head, tmp, &table->chains) {
            entry = mk_list_entry(head, struct flb_hash_table_entry, _head);
            flb_hash_table_entry_free(ht, entry);
        }
    }

    flb_free(ht->table);
    flb_free(ht);
}

void flb_hash_table_set_case_sensitivity(struct flb_hash_table *ht, int status)
{
    if (status != FLB_TRUE) {
        status = FLB_FALSE;
    }

    ht->case_sensitivity = status;
}

static void flb_hash_table_evict_random(struct flb_hash_table *ht)
{
    int id;
    int count = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hash_table_entry *entry;

    id = random() % ht->total_count;
    mk_list_foreach_safe(head, tmp, &ht->entries) {
        if (id == count) {
            entry = mk_list_entry(head, struct flb_hash_table_entry, _head_parent);
            flb_hash_table_entry_free(ht, entry);
            break;
        }
        count++;
    }
}

static void flb_hash_table_evict_less_used(struct flb_hash_table *ht)
{
    struct mk_list *head;
    struct flb_hash_table_entry *entry;
    struct flb_hash_table_entry *entry_less_used = NULL;

    mk_list_foreach(head, &ht->entries) {
        entry = mk_list_entry(head, struct flb_hash_table_entry, _head_parent);
        if (!entry_less_used) {
            entry_less_used = entry;
        }
        else if (entry->hits < entry_less_used->hits) {
            entry_less_used = entry;
        }
    }

    flb_hash_table_entry_free(ht, entry_less_used);
}

static void flb_hash_table_evict_older(struct flb_hash_table *ht)
{
    struct flb_hash_table_entry *entry;

    entry = mk_list_entry_first(&ht->entries, struct flb_hash_table_entry, _head_parent);
    flb_hash_table_entry_free(ht, entry);
}

static struct flb_hash_table_entry *hash_get_entry(struct flb_hash_table *ht,
                                                   const char *key, int key_len, int *out_id)
{
    int id;
    int result;
    uint64_t hash;
    struct mk_list *head;
    struct flb_hash_table_chain *table;
    struct flb_hash_table_entry *entry;

    if (!key || key_len <= 0) {
        return NULL;
    }

    if (out_id == NULL) {
        return NULL;
    }

    result = flb_hash_table_compute_key_hash(
                        &hash,
                        (char *) key, key_len,
                        ht->case_sensitivity);

    if (result != 0) {
        return NULL;
    }

    id = (hash % ht->size);

    table = &ht->table[id];
    if (table->count == 0) {
        return NULL;
    }

    if (table->count == 1) {
        entry = mk_list_entry_first(&table->chains,
                                    struct flb_hash_table_entry, _head);

        if (entry->key_len != key_len) {
            entry = NULL;
        }
        else {
            if (ht->case_sensitivity) {
                if (strncmp(entry->key, key, key_len) != 0) {
                    entry = NULL;
                }
            }
            else {
                if (strncasecmp(entry->key, key, key_len) != 0) {
                    entry = NULL;
                }
            }
        }
    }
    else {
        /* Iterate entries */
        mk_list_foreach(head, &table->chains) {
            entry = mk_list_entry(head, struct flb_hash_table_entry, _head);
            if (entry->key_len != key_len) {
                entry = NULL;
                continue;
            }

            if (ht->case_sensitivity) {
                if (strncmp(entry->key, key, key_len) == 0) {
                    break;
                }
            }
            else {
                if (strncasecmp(entry->key, key, key_len) == 0) {
                    break;
                }
            }

            entry = NULL;
        }
    }

    if (entry) {
        *out_id = id;
    }

    return entry;
}

static int entry_set_value(struct flb_hash_table_entry *entry, void *val, size_t val_size)
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

    entry->created = time(NULL);

    return 0;
}

int flb_hash_table_add(struct flb_hash_table *ht, const char *key, int key_len,
                       void *val, ssize_t val_size)
{
    int id;
    int ret;
    uint64_t hash;
    struct flb_hash_table_entry *entry;
    struct flb_hash_table_chain *table;

    if (!key || key_len <= 0) {
        return -1;
    }

    /* Check capacity */
    if (ht->max_entries > 0 && ht->total_count >= ht->max_entries) {
        if (ht->evict_mode == FLB_HASH_TABLE_EVICT_NONE) {
            /* Do nothing */
        }
        else if (ht->evict_mode == FLB_HASH_TABLE_EVICT_OLDER) {
            flb_hash_table_evict_older(ht);
        }
        else if (ht->evict_mode == FLB_HASH_TABLE_EVICT_LESS_USED) {
            flb_hash_table_evict_less_used(ht);
        }
        else if (ht->evict_mode == FLB_HASH_TABLE_EVICT_RANDOM) {
            flb_hash_table_evict_random(ht);
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
    ret = flb_hash_table_compute_key_hash(
            &hash,
            (char *) key, key_len,
            ht->case_sensitivity);

    if (ret != 0) {
        return -1;
    }

    id = (hash % ht->size);

    /* Allocate the entry */
    entry = flb_calloc(1, sizeof(struct flb_hash_table_entry));
    if (!entry) {
        flb_errno();
        return -1;
    }
    entry->created = time(NULL);
    entry->hash = hash;
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

int flb_hash_table_get(struct flb_hash_table *ht,
                       const char *key, int key_len,
                       void **out_buf, size_t *out_size)
{
    int id;
    struct flb_hash_table_entry *entry;
    time_t expiration;

    entry = hash_get_entry(ht, key, key_len, &id);
    if (!entry) {
        return -1;
    }

    if (ht->cache_ttl > 0) {
        expiration = entry->created + ht->cache_ttl;
        if (time(NULL) > expiration) {
            flb_hash_table_entry_free(ht, entry);
            return -1;
        }
    }

    entry->hits++;
    *out_buf = entry->val;
    *out_size = entry->val_size;

    return id;
}

/* check if a hash exists */
int flb_hash_table_exists(struct flb_hash_table *ht, uint64_t hash)
{
    int id;
    struct mk_list *head;
    struct flb_hash_table_chain *table;
    struct flb_hash_table_entry *entry;

    id = (hash % ht->size);
    table = &ht->table[id];

    /* Iterate entries */
    mk_list_foreach(head, &table->chains) {
        entry = mk_list_entry(head, struct flb_hash_table_entry, _head);
        if (entry->hash == hash) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

/*
 * Get an entry based in the table id. Note that a table id might have multiple
 * entries so the 'key' parameter is required to get an exact match.
 */
int flb_hash_table_get_by_id(struct flb_hash_table *ht, int id,
                             const char *key,
                             const char **out_buf, size_t * out_size)
{
    struct mk_list *head;
    struct flb_hash_table_entry *entry = NULL;
    struct flb_hash_table_chain *table;

    if (ht->size <= id) {
        return -1;
    }

    table = &ht->table[id];
    if (table->count == 0) {
        return -1;
    }

    if (table->count == 1) {
        entry = mk_list_entry_first(&table->chains,
                                    struct flb_hash_table_entry, _head);
    }
    else {
        mk_list_foreach(head, &table->chains) {
            entry = mk_list_entry(head, struct flb_hash_table_entry, _head);
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

void *flb_hash_table_get_ptr(struct flb_hash_table *ht, const char *key, int key_len)
{
    int id;
    struct flb_hash_table_entry *entry;

    entry = hash_get_entry(ht, key, key_len, &id);
    if (!entry) {
        return NULL;
    }

    entry->hits++;
    return entry->val;
}

int flb_hash_table_del(struct flb_hash_table *ht, const char *key)
{
    int id;
    int len;
    int result;
    uint64_t hash;
    struct mk_list *head;
    struct flb_hash_table_entry *entry = NULL;
    struct flb_hash_table_chain *table;

    if (!key) {
        return -1;
    }

    len = strlen(key);
    if (len == 0) {
        return -1;
    }

    result = flb_hash_table_compute_key_hash(
                &hash,
                (char *) key, len,
                ht->case_sensitivity);

    if (result != 0) {
        return -1;
    }

    id = (hash % ht->size);

    table = &ht->table[id];
    if (table->count == 1) {
        entry = mk_list_entry_first(&table->chains,
                                    struct flb_hash_table_entry,
                                    _head);
        if (ht->case_sensitivity) {
            if (entry->key_len != len || strncmp(entry->key, key, len) != 0) {
                entry = NULL;
            }
        }
        else {
            if (entry->key_len != len || strncasecmp(entry->key, key, len) != 0) {
                entry = NULL;
            }
        }
    }
    else {
        mk_list_foreach(head, &table->chains) {
            entry = mk_list_entry(head, struct flb_hash_table_entry, _head);
            if (ht->case_sensitivity) {
                if (entry->key_len == len && strncmp(entry->key, key, len) == 0) {
                    break;
                }
            }
            else {
                if (entry->key_len == len && strncasecmp(entry->key, key, len) == 0) {
                    break;
                }
            }
            entry = NULL;
        }
    }

    if (!entry) {
        return -1;
    }

    flb_hash_table_entry_free(ht, entry);
    return 0;
}
