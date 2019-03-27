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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>

/*
 * This hash generation function is taken originally from Redis source code:
 *
 *  https://github.com/antirez/redis/blob/unstable/src/dict.c#L109
 *
 * ----
 * MurmurHash2, by Austin Appleby
 * Note - This code makes a few assumptions about how your machine behaves -
 * 1. We can read a 4-byte value from any address without crashing
 * 2. sizeof(int) == 4
 *
 * And it has a few limitations -
 *
 * 1. It will not work incrementally.
 * 2. It will not produce the same results on little-endian and big-endian
 *    machines.
 */
static unsigned int gen_hash(const void *key, int len)
{
    /* 'm' and 'r' are mixing constants generated offline.
       They're not really 'magic', they just happen to work well.  */
    uint32_t seed = 5381;
    const uint32_t m = 0x5bd1e995;
    const int r = 24;

    /* Initialize the hash to a 'random' value */
    uint32_t h = seed ^ len;

    /* Mix 4 bytes at a time into the hash */
    const unsigned char *data = (const unsigned char *) key;

    while (len >= 4) {
        uint32_t k = *(uint32_t *) data;

        k *= m;
        k ^= k >> r;
        k *= m;

        h *= m;
        h ^= k;

        data += 4;
        len -= 4;
    }

    /* Handle the last few bytes of the input array  */
    switch (len) {
    case 3:
        h ^= data[2] << 16;
    case 2:
        h ^= data[1] << 8;
    case 1:
        h ^= data[0];
        h *= m;
    };

    /* Do a few final mixes of the hash to ensure the last few
     * bytes are well-incorporated. */
    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return (unsigned int) h;
}

static inline void flb_hash_entry_free(struct flb_hash *ht,
                                       struct flb_hash_entry *entry)
{
    mk_list_del(&entry->_head);
    mk_list_del(&entry->_head_parent);
    entry->table->count--;
    ht->total_count--;
    flb_free(entry->key);
    flb_free(entry->val);
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
    ht->total_count = 0;
    ht->size = size;
    ht->total_count = 0;
    ht->max_hash_table_length = 1;
    ht->resize_count = 0;
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

/* flb_hash_add_to_table_ add @entry to the @table. If such entry exists it replace the old one and return pointer to it
   so the caller can free this old entry. The table->count is incremented if old entry does not exist.*/
static struct flb_hash_entry *flb_hash_add_entry_to_table_(struct
                                                           flb_hash_table
                                                           *table,
                                                           struct
                                                           flb_hash_entry
                                                           *entry)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hash_entry *old = NULL;
    /* Link the new entry in our table at the end of the list */
    entry->table = table;
    /* Check if the new key already exists */
    if (table->count > 0) {
        mk_list_foreach_safe(head, tmp, &table->chains) {
            old = mk_list_entry(head, struct flb_hash_entry, _head);
            if (old->key_len == entry->key_len
                && strcmp(old->key, entry->key) == 0) {
                break;
            }
            old = NULL;
        }
    }
    mk_list_add(&entry->_head, &table->chains);
    table->count++;
    return old;
}

static int flb_hash_add_entry_(struct flb_hash *ht,
                               struct flb_hash_entry *entry)
{
    int id;
    unsigned int hash;
    struct flb_hash_entry *old_entry;

    /* Generate hash number */
    hash = gen_hash(entry->key, entry->key_len);
    id = (hash % ht->size);

    old_entry = flb_hash_add_entry_to_table_(&ht->table[id], entry);
    if (old_entry) {
        flb_hash_entry_free(ht, old_entry);
    }

    mk_list_add(&entry->_head_parent, &ht->entries);
    ht->total_count++;

    return id;
}

static void flb_hash_update_max_hash_table_length(struct flb_hash *ht)
{
    ht->max_hash_table_length =
        (ht->total_count / ht->size) + (ht->total_count % ht->size ? 1 : 0) +
        1;
}

static void flb_hash_resize(struct flb_hash *ht)
{
    struct flb_hash_table *new_tables = NULL;
    struct flb_hash_table *current_old_table;
    struct flb_hash_table *old_tables;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_hash_entry *entry;
    int table_index;
    size_t new_size;
    size_t old_size;

    old_size = ht->size;
    new_size = ht->size << 1;
    old_tables = ht->table;

    //allocate new array of tables with double size
    new_tables = flb_calloc(1, sizeof(struct flb_hash_table) * new_size);
    if (!new_tables) {
        flb_errno();
        return;
    }
    // init each of the new tables
    for (table_index = 0; table_index < new_size; table_index++) {
        new_tables[table_index].count = 0;
        mk_list_init(&new_tables[table_index].chains);
    }
    //clear the entries chain
    mk_list_init(&ht->entries);
    ht->total_count = 0;
    //attach new_tables to the hash_map
    ht->table = new_tables;
    ht->size = new_size;

    for (table_index = 0; table_index < old_size; table_index++) {
        current_old_table = &old_tables[table_index];
        if (current_old_table->count == 1) {
            entry = mk_list_entry_first(&current_old_table->chains,
                                        struct flb_hash_entry, _head);
            flb_hash_add_entry_(ht, entry);
        }
        else {
            mk_list_foreach_safe(head, tmp, &current_old_table->chains) {
                entry = mk_list_entry(head, struct flb_hash_entry, _head);
                flb_hash_add_entry_(ht, entry);
            }
        }
    }
    flb_hash_update_max_hash_table_length(ht);
    flb_free(old_tables);
    ht->resize_count++;
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

int flb_hash_add(struct flb_hash *ht, char *key, int key_len,
                 char *val, size_t val_size)
{
    int id;
    struct flb_hash_entry *entry;

    if (!key || key_len <= 0 || !val || val_size <= 0) {
        return -1;
    }

    /* Check capacity */
    if (ht->max_entries > 0 && ht->total_count >= ht->max_entries) {
        /* FIXME: handle eviction mode */
        if (ht->evict_mode == FLB_HASH_EVICT_NONE) {

        }
        else if (ht->evict_mode == FLB_HASH_EVICT_OLDER) {

        }
        else if (ht->evict_mode == FLB_HASH_EVICT_LESS_USED) {

        }
        else if (ht->evict_mode == FLB_HASH_EVICT_RANDOM) {
            flb_hash_evict_random(ht);
        }
    }

    /* Allocate the entry */
    entry = flb_malloc(sizeof(struct flb_hash_entry));
    if (!entry) {
        flb_errno();
        return -1;
    }
    entry->created = time(NULL);
    entry->hits = 0;

    /* Store the key and value as a new memory region */
    entry->key = flb_strdup(key);
    entry->key_len = key_len;
    entry->val = flb_malloc(val_size + 1);
    if (!entry->val) {
        flb_errno();
        flb_free(entry->key);
        flb_free(entry);
        return -1;
    }

    /*
     * Copy the buffer and append a NULL byte in case the caller set and
     * expects a string.
     */
    memcpy(entry->val, val, val_size);
    entry->val[val_size] = '\0';
    entry->val_size = val_size;

    id = flb_hash_add_entry_(ht, entry);

    //check if resizing is needed
    if (ht->table[id].count > ht->max_hash_table_length
        && ht->resize_count < FLB_HASH_MAX_RESIZING_COUNTS) {
        //make the resize
        flb_hash_resize(ht);
        //find the new if of the table where the new entry is added after the resizeing
        id = gen_hash(entry->key, entry->key_len) % ht->size;
    }

    return id;
}

int flb_hash_get(struct flb_hash *ht, char *key, int key_len,
                 char **out_buf, size_t * out_size)
{
    int id;
    unsigned int hash;
    struct mk_list *head;
    struct flb_hash_table *table;
    struct flb_hash_entry *entry;

    if (!key || key_len <= 0) {
        return -1;
    }

    hash = gen_hash(key, key_len);
    id = (hash % ht->size);

    table = &ht->table[id];
    if (table->count == 0) {
        return -1;
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

    if (!entry) {
        return -1;
    }

    if (!entry->val) {
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
int flb_hash_get_by_id(struct flb_hash *ht, int id, char *key, char **out_buf,
                       size_t * out_size)
{
    struct mk_list *head;
    struct flb_hash_entry *entry = NULL;
    struct flb_hash_table *table;

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

int flb_hash_del(struct flb_hash *ht, char *key)
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

    hash = gen_hash(key, len);
    id = (hash % ht->size);

    table = &ht->table[id];
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

    flb_hash_entry_free(ht, entry);

    return 0;
}
