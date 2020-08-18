/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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

#ifndef FLB_AVRO_H
#define FLB_AVRO_H

#include <msgpack.h>
#include <avro.h>

// /*
//  * some memory pooling code because i'm paranoid about avro leaking
//  */
// typedef struct pool
// {
//   char * next;
//   char * end;
// } AVRO_POOL;

#include <stdlib.h>

#define MEMORY_POOL_SUCCESS 1
#define MEMORY_POOL_ERROR 0
#define MEMORY_POOL_MINIMUM_SIZE sizeof(void *)

typedef struct {
    void **head;
    void *memory;
} Memory_Pool;

//size must be greater than or equal to MEMORY_POOL_MINIMUM_SIZE
int mp_init(Memory_Pool *mp, size_t size, size_t slots);
void mp_destroy(Memory_Pool *mp);

void *mp_get(Memory_Pool *mp);
void mp_release(Memory_Pool *mp, void *mem);

void *flb_avro_allocator(void *ud, void *ptr, size_t osize, size_t nsize);
avro_value_iface_t *flb_avro_init(avro_value_t *aobject, char *json, size_t json_len, avro_schema_t *aschema);
int flb_msgpack_to_avro(avro_value_t *val, msgpack_object *o);

// AVRO_POOL * avro_pool_create( size_t size );
// void avro_pool_destroy( AVRO_POOL *p );
// size_t avro_pool_available( AVRO_POOL *p );
// void * avro_pool_alloc( AVRO_POOL *p, size_t size );
void *flb_avro_allocatorqqq(void *ud, void *ptr, size_t osize, size_t nsize);


#endif