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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_zstd.h>
#include <fluent-bit/flb_compression.h>
#include <fluent-bit/flb_snappy.h>
#include <snappy.h>
#include <cfl/cfl_checksum.h>

struct flb_snappy_decompression_context {
    char *buffer;
    size_t length;
    size_t offset;
};

static int decompress_snappy_dispatch(struct flb_decompression_context *context,
                                       void *output_buffer, size_t *output_size);

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

            if (context->algorithm == FLB_COMPRESSION_ALGORITHM_SNAPPY) {
                flb_free(((struct flb_snappy_decompression_context *) context->inner_context)->buffer);
                flb_free(context->inner_context);
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
    else if (algorithm == FLB_COMPRESSION_ALGORITHM_SNAPPY) {
        context->inner_context = flb_calloc(1, sizeof(struct flb_snappy_decompression_context));
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

    context->output_limit = SIZE_MAX;
    context->input_buffer_size = input_buffer_size;
    context->read_buffer = context->input_buffer;
    context->algorithm = algorithm;
    if (algorithm == FLB_COMPRESSION_ALGORITHM_GZIP) {
        context->state = FLB_DECOMPRESSOR_STATE_EXPECTING_HEADER;
    }
    else {
        context->state = FLB_DECOMPRESSOR_STATE_EXPECTING_BODY;
    }

    return context;
}

int flb_decompress(struct flb_decompression_context *context,
                   void *output_buffer, size_t *output_length)
{
    size_t remaining;
    size_t produced;
    unsigned char probe;
    uint8_t *trailer;
    uint32_t declared_size;
    int ret;

    if (context == NULL || output_length == NULL || output_buffer == NULL) {
        return FLB_DECOMPRESSOR_FAILURE;
    }
    if (context->output_size > context->output_limit) {
        *output_length = 0;
        return FLB_DECOMPRESSOR_LIMIT_EXCEEDED;
    }
    remaining = context->output_limit - context->output_size;
    produced = *output_length;
    *output_length = 0;
    if (produced == 0) {
        return FLB_DECOMPRESSOR_SUCCESS;
    }
    if (context->input_complete && context->algorithm == FLB_COMPRESSION_ALGORITHM_GZIP &&
        context->state == FLB_DECOMPRESSOR_STATE_EXPECTING_HEADER && context->output_size == 0) {
        if (context->input_buffer_length < 18) {
            return FLB_DECOMPRESSOR_FAILURE;
        }
        trailer = context->read_buffer + context->input_buffer_length - 4;
        declared_size = ((uint32_t) trailer[0]) | ((uint32_t) trailer[1] << 8) |
                        ((uint32_t) trailer[2] << 16) | ((uint32_t) trailer[3] << 24);
        if (declared_size > remaining) {
            return FLB_DECOMPRESSOR_LIMIT_EXCEEDED;
        }
    }
    if (produced > remaining) {
        produced = remaining;
    }
    if (remaining == 0) {
        output_buffer = &probe;
        produced = 1;
    }
    switch (context->algorithm) {
    case FLB_COMPRESSION_ALGORITHM_GZIP:
        ret = flb_gzip_decompressor_dispatch(context, output_buffer, &produced);
        break;
    case FLB_COMPRESSION_ALGORITHM_ZSTD:
        ret = flb_zstd_decompressor_dispatch(context, output_buffer, &produced);
        break;
    case FLB_COMPRESSION_ALGORITHM_SNAPPY:
        ret = decompress_snappy_dispatch(context, output_buffer, &produced);
        break;
    default:
        return FLB_DECOMPRESSOR_FAILURE;
    }
    if (ret != FLB_DECOMPRESSOR_SUCCESS) {
        return ret;
    }
    if (produced > remaining) {
        context->state = FLB_DECOMPRESSOR_STATE_FAILED;
        return FLB_DECOMPRESSOR_LIMIT_EXCEEDED;
    }
    context->output_size += produced;
    *output_length = produced;
    return FLB_DECOMPRESSOR_SUCCESS;
}

static uint32_t decompression_read_le32(const unsigned char *buffer)
{
    return ((uint32_t) buffer[0]) | ((uint32_t) buffer[1] << 8) |
           ((uint32_t) buffer[2] << 16) | ((uint32_t) buffer[3] << 24);
}

static int decompress_snappy_bounded(char **output_buffer, size_t *output_size,
                                    char *input_buffer, size_t input_size, size_t limit)
{
    size_t offset;
    size_t length;
    size_t expanded;
    size_t total = 0;
    size_t output_offset = 0;
    int pass;
    unsigned char type;
    unsigned char *frame;
    uint32_t checksum;
    char *buffer = NULL;

    if (input_size == 0) {
        return FLB_DECOMPRESSOR_FAILURE;
    }
    if (input_size < 10 ||
        (unsigned char) input_buffer[0] != FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER ||
        input_buffer[1] != 6 || input_buffer[2] != 0 || input_buffer[3] != 0 ||
        memcmp(input_buffer + 4, FLB_SNAPPY_STREAM_IDENTIFIER_STRING, 6) != 0) {
        if (!snappy_uncompressed_length(input_buffer, input_size, &expanded)) {
            return FLB_DECOMPRESSOR_FAILURE;
        }
        if (expanded > limit) {
            return FLB_DECOMPRESSOR_LIMIT_EXCEEDED;
        }
        return flb_snappy_uncompress(input_buffer, input_size, output_buffer, output_size) == 0 ?
               0 : FLB_DECOMPRESSOR_FAILURE;
    }

    /* Inspect every framed chunk before allocating a single bounded output. */
    for (pass = 0; pass < 2; pass++) {
        offset = 0;
        while (offset < input_size) {
            if (input_size - offset < 4) {
                goto invalid;
            }
            frame = (unsigned char *) input_buffer + offset;
            type = frame[0];
            length = ((size_t) frame[1]) | ((size_t) frame[2] << 8) |
                     ((size_t) frame[3] << 16);
            if (length > input_size - offset - 4) {
                goto invalid;
            }
            frame += 4;
            if (type == FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER) {
                if (length != 6 || memcmp(frame, FLB_SNAPPY_STREAM_IDENTIFIER_STRING, 6) != 0) {
                    goto invalid;
                }
            }
            else if (type == FLB_SNAPPY_FRAME_TYPE_COMPRESSED_DATA ||
                     type == FLB_SNAPPY_FRAME_TYPE_UNCOMPRESSED_DATA) {
                if (length < 4 || length > FLB_SNAPPY_FRAME_SIZE_LIMIT) {
                    goto invalid;
                }
                expanded = length - 4;
                if (type == FLB_SNAPPY_FRAME_TYPE_COMPRESSED_DATA &&
                    !snappy_uncompressed_length((char *) frame + 4, length - 4, &expanded)) {
                    goto invalid;
                }
                if (pass == 0) {
                    if (expanded > limit - total) {
                        return FLB_DECOMPRESSOR_LIMIT_EXCEEDED;
                    }
                    total += expanded;
                }
                else {
                    if (type == FLB_SNAPPY_FRAME_TYPE_COMPRESSED_DATA) {
                        if (snappy_uncompress((char *) frame + 4, length - 4,
                                              buffer + output_offset) != 0) {
                            goto invalid;
                        }
                    }
                    else {
                        memcpy(buffer + output_offset, frame + 4, expanded);
                    }
                    checksum = cfl_checksum_crc32c((unsigned char *) buffer + output_offset,
                                                   expanded);
                    checksum = ((checksum >> 15) | (checksum << 17)) + 0xa282ead8;
                    if (checksum != decompression_read_le32(frame)) {
                        goto invalid;
                    }
                    output_offset += expanded;
                }
            }
            else if (type < FLB_SNAPPY_FRAME_TYPE_RESERVED_SKIPPABLE_BASE) {
                goto invalid;
            }
            offset += 4 + length;
        }
        if (pass == 0) {
            buffer = flb_malloc(total == 0 ? 1 : total);
            if (buffer == NULL) {
                return FLB_DECOMPRESSOR_FAILURE;
            }
        }
    }
    *output_buffer = buffer;
    *output_size = total;
    return 0;

invalid:
    flb_free(buffer);
    return FLB_DECOMPRESSOR_FAILURE;
}

static int decompress_snappy_dispatch(struct flb_decompression_context *context,
                                       void *output_buffer, size_t *output_size)
{
    struct flb_snappy_decompression_context *snappy = context->inner_context;
    size_t length = *output_size;
    int ret;

    *output_size = 0;
    if (snappy->buffer == NULL) {
        ret = decompress_snappy_bounded(&snappy->buffer, &snappy->length,
                                          (char *) context->read_buffer,
                                          context->input_buffer_length,
                                          context->output_limit - context->output_size);
        if (ret != FLB_DECOMPRESSOR_SUCCESS) {
            return ret;
        }
    }
    if (length > snappy->length - snappy->offset) {
        length = snappy->length - snappy->offset;
    }
    memcpy(output_buffer, snappy->buffer + snappy->offset, length);
    snappy->offset += length;
    *output_size = length;
    if (snappy->offset == snappy->length) {
        context->read_buffer += context->input_buffer_length;
        context->input_buffer_length = 0;
        flb_free(snappy->buffer);
        snappy->buffer = NULL;
        snappy->length = 0;
        snappy->offset = 0;
    }
    return FLB_DECOMPRESSOR_SUCCESS;
}

/* Collect bounded chunks only for the protobuf decoder's contiguous input. */
int flb_decompress_buffer(int algorithm, void *input, size_t input_size,
                          size_t limit, void **payload, size_t *payload_size)
{
    struct flb_decompression_context *decoder;
    size_t chunk_size = FLB_DECOMPRESSION_BUFFER_SIZE;
    size_t produced;
    size_t previous_input;
    size_t total = 0;
    int previous_state;
    char *chunk;
    char *buffer = NULL;
    char *resized;
    int ret;

    if (payload == NULL || payload_size == NULL) {
        return FLB_DECOMPRESSOR_FAILURE;
    }
    *payload = NULL;
    *payload_size = 0;
    if (input == NULL || input_size == 0) {
        return FLB_DECOMPRESSOR_FAILURE;
    }
    if (chunk_size > limit) {
        chunk_size = limit;
    }
    if (chunk_size == 0) {
        chunk_size = 1;
    }
    decoder = flb_decompression_context_create(algorithm, input_size);
    if (decoder == NULL) {
        return FLB_DECOMPRESSOR_FAILURE;
    }
    decoder->output_limit = limit;
    decoder->input_complete = FLB_TRUE;
    memcpy(flb_decompression_context_get_append_buffer(decoder), input, input_size);
    decoder->input_buffer_length = input_size;
    chunk = flb_malloc(chunk_size);
    if (chunk == NULL) {
        flb_decompression_context_destroy(decoder);
        return FLB_DECOMPRESSOR_FAILURE;
    }
    while (decoder->input_buffer_length > 0) {
        previous_input = decoder->input_buffer_length;
        previous_state = decoder->state;
        produced = chunk_size;
        ret = flb_decompress(decoder, chunk, &produced);
        if (ret != FLB_DECOMPRESSOR_SUCCESS) {
            goto error;
        }
        if (produced > 0) {
            resized = flb_realloc(buffer, total + produced);
            if (resized == NULL) {
                ret = FLB_DECOMPRESSOR_FAILURE;
                goto error;
            }
            buffer = resized;
            memcpy(buffer + total, chunk, produced);
            total += produced;
        }
        if (produced == 0 && previous_input == decoder->input_buffer_length &&
            previous_state == decoder->state) {
            ret = FLB_DECOMPRESSOR_FAILURE;
            goto error;
        }
    }
    if (algorithm == FLB_COMPRESSION_ALGORITHM_GZIP &&
        decoder->state != FLB_DECOMPRESSOR_STATE_EXPECTING_HEADER) {
        ret = FLB_DECOMPRESSOR_FAILURE;
        goto error;
    }
    flb_free(chunk);
    flb_decompression_context_destroy(decoder);
    *payload = buffer;
    *payload_size = total;
    return FLB_DECOMPRESSOR_SUCCESS;

error:
    flb_free(buffer);
    flb_free(chunk);
    flb_decompression_context_destroy(decoder);
    return ret;
}
