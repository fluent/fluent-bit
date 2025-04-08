/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#ifndef CTR_DECODE_OPENTELEMETRY_H
#define CTR_DECODE_OPENTELEMETRY_H

#define CTR_DECODE_OPENTELEMETRY_SUCCESS                 0
#define CTR_DECODE_OPENTELEMETRY_INSUFFICIENT_DATA      -1
#define CTR_DECODE_OPENTELEMETRY_INVALID_ARGUMENT       -2
#define CTR_DECODE_OPENTELEMETRY_CORRUPTED_DATA         -3
#define CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD        -4
#define CTR_DECODE_OPENTELEMETRY_ALLOCATION_ERROR       -5


typedef enum {
    CTR_OPENTELEMETRY_TYPE_ATTRIBUTE = 0,
    CTR_OPENTELEMETRY_TYPE_ARRAY = 1,
    CTR_OPENTELEMETRY_TYPE_KVLIST = 2,
} opentelemetry_decode_value_type;

struct opentelemetry_decode_value {
    opentelemetry_decode_value_type type;
    union {
        struct ctrace_attributes *ctr_attr;
        struct cfl_array *cfl_arr;
        struct cfl_kvlist *cfl_kvlist;
    };
};

int ctr_decode_opentelemetry_create(struct ctrace **out_ctr, char *in_buf, size_t in_size,
                                    size_t *offset);
void ctr_decode_opentelemetry_destroy(struct ctrace *ctr);

#endif