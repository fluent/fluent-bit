/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#ifndef FLB_COMPRESSION_H
#define FLB_COMPRESSION_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_gzip.h>
#include <stdio.h>

#define FLB_COMPRESSION_ALGORITHM_NONE                    0
#define FLB_COMPRESSION_ALGORITHM_GZIP                    1
#define FLB_COMPRESSION_ALGORITHM_ZSTD                    2

#define FLB_DECOMPRESSOR_STATE_FAILED                    -1
#define FLB_DECOMPRESSOR_STATE_EXPECTING_HEADER           0
#define FLB_DECOMPRESSOR_STATE_EXPECTING_OPTIONAL_HEADERS 1
#define FLB_DECOMPRESSOR_STATE_EXPECTING_BODY             2
#define FLB_DECOMPRESSOR_STATE_EXPECTING_FOOTER           3

#define FLB_DECOMPRESSOR_FAILURE                         -1
#define FLB_DECOMPRESSOR_CORRUPTED_HEADER                -2
#define FLB_DECOMPRESSOR_INVALID_STATE                   -3
#define FLB_DECOMPRESSOR_SUCCESS                          0
#define FLB_DECOMPRESSOR_INSUFFICIENT_DATA                0

#define FLB_DECOMPRESSION_BUFFER_SIZE                     (1024 * 1000)

struct flb_decompression_context {
    size_t     input_buffer_length;
    size_t     input_buffer_size;
    uint8_t   *input_buffer;
    uint8_t   *read_buffer;
    int        algorithm;
    int        state;

    /* Compression backend specific context (opaque) */
    void      *inner_context;
};

uint8_t *flb_decompression_context_get_append_buffer(
            struct flb_decompression_context *context);

size_t flb_decompression_context_get_available_space(
            struct flb_decompression_context *context);

int flb_decompression_context_resize_buffer(
        struct flb_decompression_context *context, size_t new_size);

struct flb_decompression_context *flb_decompression_context_create(
                                    int algorithm,
                                    size_t input_buffer_size);

void flb_decompression_context_destroy(
        struct flb_decompression_context *context);

int flb_decompress(struct flb_decompression_context *context,
                   void *output_buffer,
                   size_t *output_length);

#endif
