#include "hashmap.h"

//#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>

#define INITIAL_SIZE 512

static struct HashMapEntry** hashTable;
static size_t currentSize;

static unsigned char hash(const char *key) {
    unsigned int hash = 0;
    while (*key) {
        hash = (hash * 31) ^ (unsigned char) *key++;
    }
    return hash % currentSize;
}

static void resize_if_needed() {
    // Add logic to resize and rehash the table if necessary
    // This can include conditions for load factor thresholds
}

struct HashMapEntry *get(const char *key) {
    int hashIndex = hash(key);

    while (hashTable[hashIndex] != NULL) {
        if (strcmp(hashTable[hashIndex]->key, key) == 0) {
            return hashTable[hashIndex];
        }
        hashIndex = (hashIndex + 1) % currentSize;
    }

    return NULL;
}

void insert(const char *key, const void *data) {
    resize_if_needed();

    struct HashMapEntry *item = flb_malloc(sizeof(struct HashMapEntry));
    if (!item) {
        flb_debug("Could not allocate memory for HashMapEntry struct. Exiting program.\n");
        exit(1);
    }

    item->data = flb_malloc(MAX_KV_SIZE);
    if (!item->data) {
        flb_debug("Could not allocate memory for data. Exiting program.\n");
        exit(1);
    }
    strncpy(item->data, data, MAX_KV_SIZE - 1);
    item->data[MAX_KV_SIZE - 1] = '\0';

    item->key = flb_malloc(MAX_KV_SIZE);
    if (!item->key) {
        flb_debug("Could not allocate memory for key. Exiting program.\n");
        exit(1);
    }
    strncpy(item->key, key, MAX_KV_SIZE - 1);
    item->key[MAX_KV_SIZE - 1] = '\0';

    int hashIndex = hash(key);
    while (hashTable[hashIndex] != NULL && hashTable[hashIndex]->key != (char *)-1) {
        hashIndex = (hashIndex + 1) % currentSize;
    }
    hashTable[hashIndex] = item;
}

struct HashMapEntry* delete(const char *key) {
    int hashIndex = hash(key);

    while (hashTable[hashIndex] != NULL) {
        if (strcmp(hashTable[hashIndex]->key, key) == 0) {
            struct HashMapEntry* temp = hashTable[hashIndex];
            hashTable[hashIndex] = (struct HashMapEntry *)-1;
            return temp;
        }
        hashIndex = (hashIndex + 1) % currentSize;
    }

    return NULL;
}

void dumpHashMap() {
    for (size_t i = 0; i < currentSize; i++) {
        if (hashTable[i] != NULL && hashTable[i] != (struct HashMapEntry *)-1)
            printf("[%zu] (%s, %s)\n", i, hashTable[i]->key, hashTable[i]->data);
        else
            printf("[%zu] (Empty, Empty)\n", i);
    }
    printf("\n");
}

void initHashMap() {
    currentSize = INITIAL_SIZE;
    hashTable = flb_malloc(currentSize * sizeof(struct HashMapEntry *));
    if (!hashTable) {
        //flb_error("Could not allocate memory for hash table. Exiting program.\n");
        printf("Error: Could not allocate memory for hash table. Exiting program.\n");
        exit(1);
    }
    for (size_t i = 0; i < currentSize; i++) {
        hashTable[i] = NULL;
    }
}

void freeHashMap() {
    for (size_t i = 0; i < currentSize; i++) {
        if (hashTable[i] != NULL && hashTable[i] != (struct HashMapEntry *)-1) {
            flb_free(hashTable[i]->data);
            flb_free(hashTable[i]->key);
            flb_free(hashTable[i]);
        }
    }
    flb_free(hashTable);
}
