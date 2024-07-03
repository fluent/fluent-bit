#include "hashmap.h"

#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>

struct HashMapEntry* hashTable[SIZE];
struct HashMapEntry* anItem;
struct HashMapEntry* element;

struct HashMapEntry *get(char *key) {
    //get the hash
    int hashIndex = hash(key);
    //printf("searching key=%s, hashIndex = %d\n", key, hashIndex);

    //move in array until an empty
    while(hashTable[hashIndex] != NULL) {

        //printf("comparing %s with %s\n", hashTable[hashIndex]->key, key);
        if(strcmp(hashTable[hashIndex]->key, key) == 0) {
            //printf("Item found!\n");
            return hashTable[hashIndex];
        }

        //go to next cell
        ++hashIndex;

        //wrap around the table
        hashIndex %= SIZE;
    }

    //printf("Item not found!\n");
    return NULL;
}

unsigned char hash(const char *key) {
    unsigned int hash = -1;
    while (*key) {
        hash *= 31;
        hash ^= (unsigned char) *key;
        key += 1;
    }
    return hash;
}

/**
 * Inserts key-value in the hash-table.
 * Note: Max length for key/value is defined in MAX_KV_SIZE
 * @param key key of the new entry
 * @param data value of the new entry
 */
void insert(char *key, void* data) {
    struct HashMapEntry *item = flb_malloc(sizeof(struct HashMapEntry));
    if( !item ) {
        flb_debug("Could not allocate memory for HashMapEntry struct. \n");
        flb_error("Could not allocate memory for HashMapEntry struct. Exiting program.\n");
        exit( 1 );
    }
    item->data = flb_malloc(MAX_KV_SIZE);
    memset(item->data,0,MAX_KV_SIZE);
    memcpy(item->data, data, strlen(data));

    item->key = flb_malloc(MAX_KV_SIZE);
    memset(item->key,0,MAX_KV_SIZE);
    memcpy(item->key, key, strlen(key));
    //get the hash
    int hashIndex = hash(key);
    //move in array until an empty or deleted cell
    while(hashTable[hashIndex] != NULL && hashTable[hashIndex]->key != -1) {
        //go to next cell
        ++hashIndex;

        //wrap around the table
        hashIndex %= SIZE;
    }
    hashTable[hashIndex] = item;
}

struct HashMapEntry* delete(struct HashMapEntry* item) {
    char *key = item->key;
    //get the hash
    int hashIndex = hash(key);

    //move in array until an empty
    while(hashTable[hashIndex] != NULL) {

        if(hashTable[hashIndex]->key == key) {
            struct HashMapEntry* temp = hashTable[hashIndex];

            //assign a dummy item at deleted position
            hashTable[hashIndex] = anItem;
            return temp;
        }

        //go to next cell
        ++hashIndex;

        //wrap around the table
        hashIndex %= SIZE;
    }

    return NULL;
}

void dumpHashMap() {
    int i = 0;
    for(i = 0; i<SIZE; i++) {
        if(hashTable[i] != NULL)
            printf("[%d] (%s,%s)\n",i, hashTable[i]->key,hashTable[i]->data);
        else
            printf("[%d] (Empty, Empty)\n");
    }
    printf("\n");
}
