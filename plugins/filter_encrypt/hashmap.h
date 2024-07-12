#ifndef FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_HASHMAP_HASHMAP_H_
#define FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_HASHMAP_HASHMAP_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fluent-bit/flb_log.h>

#define MAX_KV_SIZE 1024

struct HashMapEntry {
    char *data;
    char *key;
};

void initHashMap();
void freeHashMap();
struct HashMapEntry *get(const char *key);
void insert(const char *key, const void *data);
struct HashMapEntry* delete(const char *key);
void dumpHashMap();

#endif //FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_HASHMAP_HASHMAP_H_
