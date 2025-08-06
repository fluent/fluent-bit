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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_zstd.h>
#include <fluent-bit/flb_compression.h>

static size_t flb_decompression_context_get_read_buffer_offset(
                struct flb_decompression_context *context)
{
    uintptr_t input_buffer_offset;

    if (context == NULL) {
        return 0;
    }

    input_buffer_offset  = (uintptr_t) context->read_buffer;
    input_buffer_offset -= (uintptr_t) context->input_buffer;

    return input_buffer_offset;
}

static void flb_decompression_context_adjust_buffer(
            struct flb_decompression_context *context)
{
    uintptr_t input_buffer_offset;

    if (context != NULL) {
        input_buffer_offset = \
            flb_decompression_context_get_read_buffer_offset(context);

        if (input_buffer_offset >= (context->input_buffer_size / 2)) {
            memmove(context->input_buffer,
                    context->read_buffer,
                    context->input_buffer_length);

            context->read_buffer = context->input_buffer;
        }
    }
}

uint8_t *flb_decompression_context_get_append_buffer(
            struct flb_decompression_context *context)
{
    if (context != NULL) {
        flb_decompression_context_adjust_buffer(context);

        return &context->read_buffer[context->input_buffer_length];
    }

    return NULL;
}

size_t flb_decompression_context_get_available_space(
            struct flb_decompression_context *context)
{
    uintptr_t available_buffer_space;
    uintptr_t input_buffer_offset;

    if (context == NULL) {
        return 0;
    }

    flb_decompression_context_adjust_buffer(context);

    input_buffer_offset = \
        flb_decompression_context_get_read_buffer_offset(context);

    available_buffer_space  = context->input_buffer_size;
    available_buffer_space -= input_buffer_offset;
    available_buffer_space -= context->input_buffer_length;

    return available_buffer_space;
}

int flb_decompression_context_resize_buffer(
        struct flb_decompression_context *context, size_t new_size)
{
    void *new_buffer_address;

    if (new_size > context->input_buffer_length) {
        new_buffer_address = flb_realloc(context->input_buffer,
                                         new_size);

        if (new_buffer_address == NULL) {
            return FLB_DECOMPRESSOR_FAILURE;
        }

        if (new_buffer_address != context->input_buffer) {
            context->read_buffer =  (uint8_t *) \
                                        (((uintptr_t) context->read_buffer -
                                          (uintptr_t) context->input_buffer) +
                                         (uintptr_t) new_buffer_address);
            context->input_buffer = (uint8_t *) new_buffer_address;
            context->input_buffer_size = new_size;
        }
    }
    else if (new_size < context->input_buffer_length) {
        return FLB_DECOMPRESSOR_FAILURE;
    }

    return FLB_DECOMPRESSOR_SUCCESS;
}


void flb_decompression_context_destroy(struct flb_decompression_context *context)
{
    if (context != NULL) {
        if (context->input_buffer != NULL) {
            flb_free(context->input_buffer);

            context->input_buffer = NULL;
        }

        if (context->inner_context != NULL) {
            if (context->algorithm == FLB_COMPRESSION_ALGORITHM_GZIP) {
                flb_gzip_decompression_context_destroy(context->inner_context);
            }
            else if (context->algorithm == FLB_COMPRESSION_ALGORITHM_ZSTD) {
                flb_zstd_decompression_context_destroy(context->inner_context);
            }

            context->inner_context = NULL;
        }

        context->read_buffer = NULL;

        flb_free(context);
    }
}

struct flb_decompression_context *flb_decompression_context_create(int algorithm,
                                                                   size_t input_buffer_size)
{
    struct flb_decompression_context *context;

    if (input_buffer_size == 0) {
        input_buffer_size = FLB_DECOMPRESSION_BUFFER_SIZE;
    }

    context =
        flb_calloc(1, sizeof(struct flb_decompression_context));

    if (context == NULL) {
        flb_errno();

        flb_error("error allocating decompression context");

        return NULL;
    }

    context->input_buffer =
        flb_calloc(input_buffer_size, sizeof(uint8_t));

    if (context->input_buffer == NULL) {
        flb_errno();

        flb_error("error allocating decompression buffer");

        flb_decompression_context_destroy(context);

        return NULL;
    }

    if (algorithm == FLB_COMPRESSION_ALGORITHM_GZIP) {
        context->inner_context = flb_gzip_decompression_context_create();
    }
    else if (algorithm == FLB_COMPRESSION_ALGORITHM_ZSTD) {
        context->inner_context = flb_zstd_decompression_context_create();
    }
    else {
        flb_error("invalid compression algorithm : %d", algorithm);

        flb_decompression_context_destroy(context);

        return NULL;
    }

    if (context->inner_context == NULL) {
        flb_errno();

        flb_error("error allocating internal decompression context");

        flb_decompression_context_destroy(context);

        return NULL;
    }

    context->input_buffer_size = input_buffer_size;
    context->read_buffer = context->input_buffer;
    context->algorithm = algorithm;
    if (algorithm == FLB_COMPRESSION_ALGORITHM_GZIP) {
        context->state = FLB_DECOMPRESSOR_STATE_EXPECTING_HEADER;
    }
    else if (algorithm == FLB_COMPRESSION_ALGORITHM_ZSTD) {
        context->state = FLB_DECOMPRESSOR_STATE_EXPECTING_BODY;
    }

    return context;
}

int flb_decompress(struct flb_decompression_context *context,
                   void *output_buffer,
                   size_t *output_length)
{
    if (context != NULL) {
        if (context->algorithm == FLB_COMPRESSION_ALGORITHM_GZIP) {
            return flb_gzip_decompressor_dispatch(context,
                                                  output_buffer,
                                                  output_length);

        }
        else if (context->algorithm == FLB_COMPRESSION_ALGORITHM_ZSTD) {
            return flb_zstd_decompressor_dispatch(context,
                                                  output_buffer,
                                                  output_length);

        }
    }

    return FLB_DECOMPRESSOR_FAILURE;
}
