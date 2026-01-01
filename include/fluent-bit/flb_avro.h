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

#ifndef FLB_AVRO_H
#define FLB_AVRO_H

#include <fluent-bit/flb_sds.h>
#include <msgpack.h>
#include <avro.h>

#include <stdlib.h>

#define MEMORY_POOL_SUCCESS 1
#define MEMORY_POOL_ERROR 0
#define MEMORY_POOL_MINIMUM_SIZE sizeof(void *)

struct flb_avro_fields {
    flb_sds_t schema_id;
    flb_sds_t schema_str;
};

void *flb_avro_allocator(void *ud, void *ptr, size_t osize, size_t nsize);
avro_value_iface_t *flb_avro_init(avro_value_t *aobject, char *json, size_t json_len, avro_schema_t *aschema);
int flb_msgpack_to_avro(avro_value_t *val, msgpack_object *o);
bool flb_msgpack_raw_to_avro_sds(const void *in_buf, size_t in_size, struct flb_avro_fields *ctx, char *out_buff, size_t *out_size);
int msgpack2avro(avro_value_t *val, msgpack_object *o);

#endif
