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

struct c_heap_t {
    pthread_mutex_t lock;
    int (*compare)(void *, void *);
    int (*deconstructor)(void *);

    void **array;
    /* # entries used */
    size_t array_len;  
    /* # entries allocated */
    size_t array_size; 
};

//typedef struct c_heap_s c_heap_t;

struct c_heap_t *c_heap_create(int (*compare)(void *, void *), int (*deconstructor)(void *));
void c_heap_destroy(struct c_heap_t *h);
int c_heap_insert(struct c_heap_t *h, void *ptr);
void *c_heap_get_root(struct c_heap_t *h);
void *c_heap_read_root(struct c_heap_t *h);
