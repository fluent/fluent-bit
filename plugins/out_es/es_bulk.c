/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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
#include <math.h>

#include <fluent-bit.h>
#include "es_bulk.h"

struct es_bulk *es_bulk_create(size_t estimated_size)
{
    struct es_bulk *b;

    if (estimated_size < ES_BULK_CHUNK) {
        estimated_size = ES_BULK_CHUNK;
    }

    b = flb_malloc(sizeof(struct es_bulk));
    if (!b) {
        perror("calloc");
        return NULL;
    }
    b->ptr = flb_malloc(estimated_size);
    if (b->ptr == NULL) {
        perror("malloc");
        flb_free(b);
        return NULL;
    }

    b->size = estimated_size;
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
                   char *json, size_t j_len,
                   size_t whole_size, size_t converted_size)
{
    int available;
    int append_size;
    int required;
    int remaining_size;
    char *ptr;

    required = i_len + j_len + ES_BULK_HEADER + 1;
    available = (bulk->size - bulk->len);

    if (available < required) {
        /*
         *  estimate a converted size of json
         *  calculate
         *    1. rest of msgpack data size
         *    2. ratio from bulk json size and processed msgpack size.
         */
        append_size = required - available;
        if (converted_size == 0) {
            /* converted_size = 0 causes div/0 */
            flb_debug("[out_es] converted_size is 0");
        } else {
            remaining_size = ceil((whole_size - converted_size) /* rest of size to convert */
                * ((double)bulk->size / converted_size));       /* = json size / msgpack size */
            append_size = fmax(append_size, remaining_size);
        }
        if (append_size < ES_BULK_CHUNK) {
            /* append at least ES_BULK_CHUNK size */
            append_size = ES_BULK_CHUNK;
        }
        ptr = flb_realloc(bulk->ptr, bulk->size + append_size);
        if (!ptr) {
            flb_errno();
            return -1;
        }
        bulk->ptr  = ptr;
        bulk->size += append_size;
    }

    memcpy(bulk->ptr + bulk->len, index, i_len);
    bulk->len += i_len;

    memcpy(bulk->ptr + bulk->len, json, j_len);
    bulk->len += j_len;
    bulk->ptr[bulk->len] = '\n';
    bulk->len++;

    return 0;
};
