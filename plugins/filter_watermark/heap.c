/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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
#include <sys/types.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <stddef.h>

#include "heap.h"
#include "watermark.h"

enum reheap_direction { DIR_UP, DIR_DOWN };

static void reheap(struct c_heap_t *h, size_t root, enum reheap_direction dir) 
{
    size_t left;
    size_t right;
    size_t min;
    int status;

    /* Calculate the positions of the children */
    left = (2 * root) + 1;
    if (left >= h->array_len)
        left = 0;

    right = (2 * root) + 2;
    if (right >= h->array_len)
        right = 0;

    /* Check which one of the children is smaller. */
    if ((left == 0) && (right == 0))
        return;
    else if (left == 0)
        min = right;
    else if (right == 0)
        min = left;
    else {
        status = h->compare(h->array[left], h->array[right]);
        if (status > 0) {
            min = right;
        } else {
            min = left;
        }
    }

    status = h->compare(h->array[root], h->array[min]);
    if (status <= 0) {
        /* We didn't need to change anything, so the rest of the tree should be okay now. */
        return;
    } else {
        /* if (status > 0) */
        void *tmp;
        tmp = h->array[root];
        h->array[root] = h->array[min];
        h->array[min] = tmp;
    }

    if ((dir == DIR_UP) && (root == 0)) {
        return;
    }

    if (dir == DIR_UP) {
        reheap(h, (root - 1) / 2, dir);
    } else if (dir == DIR_DOWN) {
        reheap(h, min, dir);
    }
}



struct c_heap_t *c_heap_create(int (*compare)(void *, void *), int (*deconstructor)(void *)) 
{
    struct c_heap_t *h;

    if (compare == NULL)
        return NULL;

    if (deconstructor == NULL)
        return NULL;

    h = calloc(1, sizeof(*h));
    if (h == NULL)
        return NULL;

    pthread_mutex_init(&h->lock, /* attr = */ NULL);
    h->compare = compare;
    h->deconstructor = deconstructor;
    h->array = NULL;
    h->array_len = 0;
    h->array_size = 0;

    return h;
}

void c_heap_destroy(struct c_heap_t *h) 
{
    int i;
    if (h == NULL)
        return;

    for(i=0; i< h->array_len; i++) {
        h->deconstructor(h->array[i]);
    }

    h->array_len = 0;
    h->array_size = 0;
    free(h->array);
    h->array = NULL;

    pthread_mutex_destroy(&h->lock);

    free(h);
}

int c_heap_insert(struct c_heap_t *h, void *ptr) 
{
    size_t index;

    if ((h == NULL) || (ptr == NULL))
        return -EINVAL;

    pthread_mutex_lock(&h->lock);

    assert(h->array_len <= h->array_size);
    if (h->array_len == h->array_size) {
        void **tmp;

        tmp = realloc(h->array, (h->array_size + 16) * sizeof(*h->array));
        if (tmp == NULL) {
            pthread_mutex_unlock(&h->lock);
            return -ENOMEM;
        }

        h->array = tmp;
        h->array_size += 16;
    }

    /* Insert the new node as a leaf. */
    index = h->array_len;
    h->array[index] = ptr;
    h->array_len++;

    /* Reorganize the heap from bottom up. */
    reheap(h, /* parent of this node */ (index - 1) / 2, DIR_UP);

    pthread_mutex_unlock(&h->lock);
    return 0;
}

void *c_heap_get_root(struct c_heap_t *h) 
{
    void *ret = NULL;

    if (h == NULL)
        return NULL;

    pthread_mutex_lock(&h->lock);

    if (h->array_len == 0) {
        pthread_mutex_unlock(&h->lock);
        return NULL;
    } else if (h->array_len == 1) {
        ret = h->array[0];
        h->array[0] = NULL;
        h->array_len = 0;
    } else {
        /* if (h->array_len > 1) */
        ret = h->array[0];
        h->array[0] = h->array[h->array_len - 1];
        h->array[h->array_len - 1] = NULL;
        h->array_len--;

        reheap(h, /* root = */ 0, DIR_DOWN);
    }

    /* free some memory */
    if ((h->array_len + 32) < h->array_size) {
        void **tmp;

        tmp = realloc(h->array, (h->array_len + 16) * sizeof(*h->array));
        if (tmp != NULL) {
            h->array = tmp;
            h->array_size = h->array_len + 16;
        }
    }

    pthread_mutex_unlock(&h->lock);

    return ret;
}

void *c_heap_read_root(struct c_heap_t *h) 
{
    void *ret = NULL;

    if (h == NULL)
        return NULL;

    if (h->array_len == 0) {
        return NULL;
    } else {
        /* if (h->array_len > 1) */
        ret = h->array[0];
    }
    return ret;
}
