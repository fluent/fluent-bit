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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_str.h>

/*
 * This file implements a very basic hash table implementation, it originally
 * goal is to serve as a storage for environment variables.
 *
 * Likely we should switch to Murmur3.. pending.
 */

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
    const unsigned char *data = (const unsigned char *)key;

    while(len >= 4) {
        uint32_t k = *(uint32_t*) data;

        k *= m;
        k ^= k >> r;
        k *= m;

        h *= m;
        h ^= k;

        data += 4;
        len -= 4;
    }

    /* Handle the last few bytes of the input array  */
    switch(len) {
    case 3: h ^= data[2] << 16;
    case 2: h ^= data[1] << 8;
    case 1: h ^= data[0]; h *= m;
    };

    /* Do a few final mixes of the hash to ensure the last few
     * bytes are well-incorporated. */
    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return (unsigned int) h;
}

static inline void flb_hash_entry_free(struct flb_hash *ht, int id)
{
    struct flb_hash_entry *entry;

    entry = &ht->table[id];
    if (!entry->key) {
        return;
    }

    flb_free(entry->key);
    flb_free(entry->val);
    entry->key = NULL;
    entry->val = NULL;
}

struct flb_hash *flb_hash_create(size_t size)
{
    struct flb_hash *ht;

    ht = flb_malloc(sizeof(struct flb_hash));
    if (!ht) {
        flb_errno();
        return NULL;
    }

    ht->size = size;
    ht->table = flb_calloc(1, sizeof(struct flb_hash_entry) * size);
    if (!ht->table) {
        flb_errno();
        flb_free(ht);
        return NULL;
    }

    return ht;
}

void flb_hash_destroy(struct flb_hash *ht)
{
    int i;

    for (i = 0; i < ht->size; i++) {
        flb_hash_entry_free(ht, i);
    }

    flb_free(ht->table);
    flb_free(ht);
}

int flb_hash_add(struct flb_hash *ht, char *key, int key_len,
                 void *val, size_t val_size)
{
    int id;
    unsigned int hash;
    struct flb_hash_entry *entry;

    if (!key || key_len <= 0 || !val || val_size <= 0) {
        return -1;
    }

    hash = gen_hash(key, key_len);
    id = (hash % ht->size);

    entry = &ht->table[id];
    entry->key = flb_strdup(key);
    entry->key_len = key_len;

    /* Store the value as a new memory region */
    entry->val = flb_malloc(val_size);
    if (!entry->val) {
        flb_errno();
        flb_free(entry->key);
        return -1;
    }
    memcpy(entry->val, val, val_size);
    entry->val_size = val_size;

    return 0;
}

char *flb_hash_get(struct flb_hash *ht, char *key, int key_len)
{
    int id;
    unsigned int hash;
    struct flb_hash_entry *entry;

    if (!key || key_len <= 0) {
        return NULL;
    }

    hash = gen_hash(key, key_len);
    id = (hash % ht->size);

    entry = &ht->table[id];
    return entry->val;
}

int flb_hash_del(struct flb_hash *ht, char *key)
{
    int id;
    int len;
    unsigned int hash;

    if (!key) {
        return -1;
    }

    len = strlen(key);
    if (len == 0) {
        return -1;
    }

    hash = gen_hash(key, len);
    id = (hash % ht->size);

    flb_hash_entry_free(ht, id);
    return 0;
}
