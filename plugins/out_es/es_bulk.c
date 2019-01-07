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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fluent-bit.h>
#include "es_bulk.h"

struct es_bulk *es_bulk_create()
{
    struct es_bulk *b;

    b = flb_malloc(sizeof(struct es_bulk));
    if (!b) {
        perror("calloc");
        return NULL;
    }

    b->ptr = flb_malloc(ES_BULK_CHUNK);
    if (!b->ptr) {
        perror("malloc");
        flb_free(b);
        return NULL;
    }

    b->size = ES_BULK_CHUNK;
    b->len  = 0;

    return b;
}

void es_bulk_destroy(struct es_bulk *bulk)
{
    if (bulk->size > 0) {
        flb_free(bulk->ptr);
    }
    flb_free(bulk);
}

int es_bulk_append(struct es_bulk *bulk, char *index, int i_len,
                   char *json, size_t j_len)
{
    int available;
    int new_size;
    int required;
    char *ptr;

    required = j_len + ES_BULK_HEADER + 1;
    available = (bulk->size - bulk->len);

    if (available < required) {
        new_size = bulk->size + available + required + ES_BULK_CHUNK;
        ptr = flb_realloc(bulk->ptr, new_size);
        if (!ptr) {
            perror("realloc");
            return -1;
        }
        bulk->ptr  = ptr;
        bulk->size = new_size;
    }

    memcpy(bulk->ptr + bulk->len, index, i_len);
    bulk->len += i_len;

    memcpy(bulk->ptr + bulk->len, json, j_len);
    bulk->len += j_len;
    bulk->ptr[bulk->len] = '\n';
    bulk->len++;

    return 0;
};
