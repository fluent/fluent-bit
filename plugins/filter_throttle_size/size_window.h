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

#ifndef FLB_SIZE_WINDOW_H
#define FLB_SIZE_WINDOW_H

#include <fluent-bit/flb_hash_table.h>

#define FLB_SIZE_WINDOW_HASH_MAX_ENTRIES 100000

struct throttle_size_pane
{
    long timestamp;
    unsigned long size;
};

struct throttle_size_window
{
    char *name;
    unsigned size;
    unsigned long total;
    long timestamp;
    int head;
    int tail;
    struct throttle_size_pane *table;
};

struct throttle_size_table
{
    struct flb_hash_table *windows;
    void *lock;
};

struct throttle_size_table *create_throttle_size_table();

struct throttle_size_window *size_window_create(const char *name,
                                                unsigned name_length,
                                                unsigned int size);

/*This function adds new pane on top of the pane stack by overwriting the oldes one
  which @timestamp and load size of 0 bytes. The oldes pane's amount of load size
  is subtracted of the total amount.*/
inline static void add_new_pane(struct throttle_size_window *stw,
                                long timestamp)
{
    unsigned long tail_size = 0;
    tail_size = stw->table[stw->tail].size;
    if (stw->size - 1 == stw->head) {
        /* the head will exceed the end of the inner array end must be put at the begging.  */
        stw->head = -1;
    }
    stw->head += 1;
    stw->table[stw->head].timestamp = timestamp;
    stw->table[stw->head].size = 0;
    stw->total -= tail_size;
    if (stw->size - 1 == stw->tail) {
        /* the tail will exceed the end of the inner array end must be put at the begging. */
        stw->tail = -1;
    }
    stw->tail += 1;
}

/*This function adds @load to the latest pane which is on top of the pane stack.
  @load is added to the total amount of the size throttling window.
  If @load is not 0 then the size throttling window's timestamp will be updated to the
  one which is on top of the pane stack(latest)*/
inline static void add_load(struct throttle_size_window *stw,
                            unsigned long load)
{
    stw->table[stw->head].size += load;
    stw->total += load;
    if (load) {
        stw->timestamp = stw->table[stw->head].timestamp;
    }
}

inline static void free_stw_content(struct throttle_size_window *stw)
{
    flb_free(stw->name);
    flb_free(stw->table);
}

inline static void free_stw(struct throttle_size_window *stw)
{
    free_stw_content(stw);
    flb_free(stw);
}

inline static struct throttle_size_window *find_throttle_size_window(struct
                                                                     throttle_size_table
                                                                     *table,
                                                                     char
                                                                     *name,
                                                                     unsigned
                                                                     name_length)
{
    char *window = NULL;
    size_t out_size;
    if (flb_hash_table_get(table->windows, name, name_length,
                           (const char **)&window, &out_size) >= 0) {
        if (out_size < sizeof(struct throttle_size_window)) {
            flb_error("Malformed data in size window hashtable");
            return NULL;
        }
        return (struct throttle_size_window *) window;
    }
    return NULL;
}

inline static void add_throttle_size_window(struct throttle_size_table
                                            *table,
                                            struct throttle_size_window
                                            *window)
{
    flb_hash_table_add(table->windows, window->name, strlen(window->name),
                       (char *) window, sizeof(struct throttle_size_window));
}

void destroy_throttle_size_table(struct throttle_size_table *table);

void lock_throttle_size_table(struct throttle_size_table *ht);
void unlock_throttle_size_table(struct throttle_size_table *ht);

#endif
