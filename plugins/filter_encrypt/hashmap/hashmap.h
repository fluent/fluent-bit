//
// Created by alisrasic on 4/12/22.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define SIZE 512
#define MAX_KV_SIZE 1024

#ifndef FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_HASHMAP_HASHMAP_H_
#define FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_HASHMAP_HASHMAP_H_

struct HashMapEntry {
    char *data;
    char *key;
};

unsigned char hash(const char *key);

struct HashMapEntry *get(char *key);

void insert(char *key, void* data);

struct HashMapEntry* delete(struct HashMapEntry* item);

void display();


#endif //FLUENT_BIT_PLUGINS_FILTER_ENCRYPT_HASHMAP_HASHMAP_H_
