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

/*
 * Note: This implementation can handle priority item removal via
 * flb_bucket_queue_delete_min(bucket_queue) and direct item removal
 * via mk_list_del(&item)
 */

#ifndef   	FLB_BUCKET_QUEUE_H_
#define   	FLB_BUCKET_QUEUE_H_

#include <stddef.h>
#include <fluent-bit/flb_mem.h>
#include <monkey/mk_core/mk_list.h>


struct flb_bucket_queue
{
    struct mk_list *buckets;
    size_t n_buckets;
    struct mk_list *top;
    size_t n_items;
};

static inline struct flb_bucket_queue *flb_bucket_queue_create(size_t priorities)
{
    size_t i;
    struct flb_bucket_queue *bucket_queue;

    bucket_queue = (struct flb_bucket_queue *)
                   flb_malloc(sizeof(struct flb_bucket_queue));
    if (!bucket_queue) {
        return NULL;
    }
    bucket_queue->buckets = (struct mk_list *)
                            flb_malloc(sizeof(struct mk_list) *priorities);
    if (!bucket_queue->buckets) {
        flb_free(bucket_queue);
        return NULL;
    }
    for (i = 0; i < priorities; ++i) {
        mk_list_init(&bucket_queue->buckets[i]);
    }
    bucket_queue->n_buckets = priorities;
    bucket_queue->top = (bucket_queue->buckets + bucket_queue->n_buckets); /* one past the last element */
    bucket_queue->n_items = 0;
    return bucket_queue;
}

static inline int flb_bucket_queue_is_empty(struct flb_bucket_queue *bucket_queue)
{
    return bucket_queue->top == (bucket_queue->buckets + bucket_queue->n_buckets);
}

static inline void flb_bucket_queue_seek(struct flb_bucket_queue *bucket_queue) {
    while (!flb_bucket_queue_is_empty(bucket_queue)
          && (mk_list_is_empty(bucket_queue->top) == 0)) {
        ++bucket_queue->top;
    }
}

static inline int flb_bucket_queue_add(struct flb_bucket_queue *bucket_queue,
                                      struct mk_list *item, size_t priority)
{
    if (priority >= bucket_queue->n_buckets) {
        /* flb_error("Error: attempting to add item of priority %zu to bucket_queue out "
               "of priority range", priority); */
        return -1;
    }
    flb_bucket_queue_seek(bucket_queue);
    mk_list_add(item, &bucket_queue->buckets[priority]);
    if (&bucket_queue->buckets[priority] < bucket_queue->top) {
        bucket_queue->top = &bucket_queue->buckets[priority];
    }
    ++bucket_queue->n_items;
    return 0;
}

/* fifo based on priority */
static inline struct mk_list *flb_bucket_queue_find_min(struct flb_bucket_queue *bucket_queue)
{
    flb_bucket_queue_seek(bucket_queue);
    if (flb_bucket_queue_is_empty(bucket_queue)) {
        return NULL;
    }
    return bucket_queue->top->next;
}

static inline void flb_bucket_queue_delete_min(struct flb_bucket_queue *bucket_queue)
{
    flb_bucket_queue_seek(bucket_queue);
    if (flb_bucket_queue_is_empty(bucket_queue)) {
        return;
    }
    mk_list_del(bucket_queue->top->next);
    flb_bucket_queue_seek(bucket_queue); /* this line can be removed. Debugging is harder */
    --bucket_queue->n_items;
}

static inline struct mk_list *flb_bucket_queue_pop_min(struct flb_bucket_queue *bucket_queue)
{
    struct mk_list *item;
    item = flb_bucket_queue_find_min(bucket_queue);
    flb_bucket_queue_delete_min(bucket_queue);
    return item;
}

static inline int flb_bucket_queue_destroy(
                                     struct flb_bucket_queue *bucket_queue)
{
    flb_bucket_queue_seek(bucket_queue);
    if (!flb_bucket_queue_is_empty(bucket_queue)) {
        /* flb_error("Error: attempting to destroy non empty bucket_queue. Remove all "
                  "items first."); */
        return -1;
    }
    flb_free(bucket_queue->buckets);
    flb_free(bucket_queue);
    return 0;
}

#endif /* !FLB_BUCKET_QUEUE_H_ */
