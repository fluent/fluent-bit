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

struct flb_snappy_decompression_context {
    char *buffer;
    size_t length;
    size_t offset;
    /* Input bytes consumed by the decode that produced buffer/length. The
     * decoded span and the currently resident span diverge as soon as a caller
     * appends while we are still draining, so they must not be conflated. */
    size_t consumed;
    /* A framed stream identifier has been seen, so later spans arriving on this
     * context are continuations of that stream rather than new payloads. */
    int stream_started;
};

/* Framed Snappy stream identifier chunk: type, 24-bit little-endian length and
 * the magic name. It is also the only marker flb_snappy_uncompress_bounded()
 * accepts as "this is framing". */
static const unsigned char snappy_stream_identifier[] = {
    FLB_SNAPPY_FRAME_TYPE_STREAM_IDENTIFIER, 6, 0, 0, 's', 'N', 'a', 'P', 'p', 'Y'
};

static int snappy_has_stream_identifier(const unsigned char *data, size_t size)
{
    if (size < sizeof(snappy_stream_identifier)) {
        return FLB_FALSE;
    }

    return memcmp(data, snappy_stream_identifier,
                  sizeof(snappy_stream_identifier)) == 0;
}

/* Byte offset just past the last framed chunk wholly present in size bytes, or 0
 * when even the first header is incomplete. Chunk semantics stay with the
 * decoder: this only answers where a partial stream can safely be cut. */
static size_t snappy_complete_chunk_span(const unsigned char *data, size_t size)
{
    size_t offset;
    size_t length;

    offset = 0;
    while (size - offset >= 4) {
        length = ((size_t) data[offset + 1]) | ((size_t) data[offset + 2] << 8) |
                 ((size_t) data[offset + 3] << 16);

        if (length > size - offset - 4) {
            break;
        }
        offset += 4 + length;
    }

    return offset;
}

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
    size_t minimum_size;
    size_t input_buffer_offset;

    if (context == NULL) {
        return FLB_DECOMPRESSOR_FAILURE;
    }

    /* Keep the allocation when an empty context is resized to zero. */
    if (new_size == 0 && context->input_buffer_length == 0) {
        return FLB_DECOMPRESSOR_SUCCESS;
    }

    /*
     * Resident bytes start at read_buffer, not at input_buffer, so a resize is
     * only safe while the allocation still covers offset + length. Sizing from
     * the length alone could shrink the buffer below data that is still live.
     */
    input_buffer_offset = flb_decompression_context_get_read_buffer_offset(context);

    if (context->input_buffer_length > SIZE_MAX - input_buffer_offset) {
        return FLB_DECOMPRESSOR_FAILURE;
    }

    minimum_size = input_buffer_offset + context->input_buffer_length;

    if (new_size < minimum_size) {
        return FLB_DECOMPRESSOR_FAILURE;
    }

    if (new_size == context->input_buffer_size) {
        return FLB_DECOMPRESSOR_SUCCESS;
    }

    new_buffer_address = flb_realloc(context->input_buffer, new_size);

    if (new_buffer_address == NULL) {
        return FLB_DECOMPRESSOR_ALLOCATION_FAILURE;
    }

    context->input_buffer = new_buffer_address;
    context->read_buffer = context->input_buffer + input_buffer_offset;
    context->input_buffer_size = new_size;

    return FLB_DECOMPRESSOR_SUCCESS;
}


int flb_decompression_context_at_payload_boundary(
        struct flb_decompression_context *context)
{
    struct flb_snappy_decompression_context *snappy;

    if (context == NULL || context->inner_context == NULL) {
        return FLB_FALSE;
    }

    /* Undecoded bytes are still held, so the position after them is not a start. */
    if (context->input_buffer_length > 0) {
        return FLB_FALSE;
    }

    if (context->algorithm == FLB_COMPRESSION_ALGORITHM_GZIP) {
        /* The gzip state machine lives in this context: back to expecting a header
         * with nothing pending means the next byte opens a new member. */
        return context->state == FLB_DECOMPRESSOR_STATE_EXPECTING_HEADER ?
               FLB_TRUE : FLB_FALSE;
    }

    if (context->algorithm == FLB_COMPRESSION_ALGORITHM_ZSTD) {
        return flb_zstd_decompression_context_at_boundary(context->inner_context);
    }

    if (context->algorithm == FLB_COMPRESSION_ALGORITHM_SNAPPY) {
        snappy = context->inner_context;

        /* Output still being drained, or a span not yet retired, both mean the
         * decode is unfinished. */
        if (snappy->buffer != NULL || snappy->consumed > 0) {
            return FLB_FALSE;
        }

        /* Framing is only recognised through the leading identifier chunk, so a
         * fresh decoder can resume at the start of a stream and nowhere later. */
        return snappy->stream_started ? FLB_FALSE : FLB_TRUE;
    }

    return FLB_FALSE;
}

int flb_decompression_context_reserve(struct flb_decompression_context *context,
                                      size_t needed, size_t maximum_size)
{
    size_t minimum_size;
    size_t input_buffer_offset;

    if (context == NULL) {
        return FLB_DECOMPRESSOR_FAILURE;
    }

    input_buffer_offset = flb_decompression_context_get_read_buffer_offset(context);

    if (context->input_buffer_length > SIZE_MAX - input_buffer_offset) {
        return FLB_DECOMPRESSOR_FAILURE;
    }

    if (needed > SIZE_MAX - input_buffer_offset - context->input_buffer_length) {
        return FLB_DECOMPRESSOR_FAILURE;
    }

    /* The append cursor sits past the consumed prefix, so that prefix has to be
     * part of any size computed for a grow. */
    minimum_size = input_buffer_offset + context->input_buffer_length + needed;

    if (maximum_size > 0 &&
        (context->input_buffer_size > maximum_size || minimum_size > maximum_size)) {
        return FLB_DECOMPRESSOR_LIMIT_EXCEEDED;
    }

    if (minimum_size <= context->input_buffer_size) {
        return FLB_DECOMPRESSOR_SUCCESS;
    }

    return flb_decompression_context_resize_buffer(context, minimum_size);
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
    if (context->state == FLB_DECOMPRESSOR_STATE_FAILED) {
        *output_length = 0;
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
    if (ret != FLB_DECOMPRESSOR_SUCCESS &&
        ret != FLB_DECOMPRESSOR_INSUFFICIENT_DATA) {
        return ret;
    }
    if (produced > remaining) {
        context->state = FLB_DECOMPRESSOR_STATE_FAILED;
        return FLB_DECOMPRESSOR_LIMIT_EXCEEDED;
    }
    /* A backend can emit bytes and only then report that it needs more input, so
     * a wait still has to be credited against the output budget. */
    context->output_size += produced;
    *output_length = produced;

    /* Propagate the wait: SUCCESS here would tell a streaming caller the payload
     * was finished when the decoder only ran out of input. */
    return ret;
}

static int decompress_snappy_dispatch(struct flb_decompression_context *context,
                                       void *output_buffer, size_t *output_size)
{
    struct flb_snappy_decompression_context *snappy = context->inner_context;
    size_t input_size;
    size_t decode_size;
    size_t span;
    size_t length = *output_size;
    unsigned char *decode_buffer;
    int framed;
    int decode_owned;
    int ret;

    *output_size = 0;
    if (snappy == NULL) {
        return FLB_DECOMPRESSOR_FAILURE;
    }
    if (snappy->consumed > context->input_buffer_length) {
        context->state = FLB_DECOMPRESSOR_STATE_FAILED;
        return FLB_DECOMPRESSOR_FAILURE;
    }
    if (snappy->buffer == NULL) {
        input_size = context->input_buffer_length;
        decode_buffer = context->read_buffer;
        decode_owned = FLB_FALSE;
        framed = (snappy->stream_started ||
                  snappy_has_stream_identifier(context->read_buffer, input_size));

        if (!framed) {
            /* A raw block carries no framing, so its end is not self-delimiting.
             * Bytes that could still grow into a stream identifier wait instead
             * of being misrouted here as an incomplete framed prefix. */
            if (!context->input_complete &&
                input_size < sizeof(snappy_stream_identifier) &&
                memcmp(context->read_buffer, snappy_stream_identifier, input_size) == 0) {
                return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
            }

            span = input_size;
        }
        else {
            span = snappy_complete_chunk_span(context->read_buffer, input_size);

            if (context->input_complete) {
                /* A complete payload keeps the one-shot contract: a short tail is
                 * corruption, not a chunk boundary we are free to ignore. */
                span = input_size;
            }
            else if (span == 0) {
                return FLB_DECOMPRESSOR_INSUFFICIENT_DATA;
            }

            if (snappy->stream_started) {
                /* A continuation span no longer starts with the identifier, and
                 * anything without it is routed to the raw block path. Hand the
                 * decoder a synthesised identifier so the framing logic stays
                 * single-sourced; those bytes are not input we own, so they stay
                 * out of the consumed span below. */
                decode_buffer = flb_malloc(sizeof(snappy_stream_identifier) + span);

                if (decode_buffer == NULL) {
                    return FLB_DECOMPRESSOR_ALLOCATION_FAILURE;
                }
                memcpy(decode_buffer, snappy_stream_identifier,
                       sizeof(snappy_stream_identifier));
                memcpy(decode_buffer + sizeof(snappy_stream_identifier),
                       context->read_buffer, span);
                decode_owned = FLB_TRUE;
            }
        }

        decode_size = (decode_owned ? sizeof(snappy_stream_identifier) : 0) + span;

        ret = flb_snappy_uncompress_bounded(&snappy->buffer, &snappy->length,
                                          (char *) decode_buffer, decode_size,
                                          context->output_limit - context->output_size);
        if (decode_owned) {
            flb_free(decode_buffer);
        }
        if (ret != FLB_DECOMPRESSOR_SUCCESS) {
            return ret;
        }

        if (framed) {
            snappy->stream_started = FLB_TRUE;
        }

        /* Pin the span this decode actually read. */
        snappy->consumed = span;
    }
    if (length > snappy->length - snappy->offset) {
        length = snappy->length - snappy->offset;
    }
    memcpy(output_buffer, snappy->buffer + snappy->offset, length);
    snappy->offset += length;
    *output_size = length;
    if (snappy->offset == snappy->length) {
        /* Retire only what the decode consumed: bytes a caller appended while
         * this output was being drained stay resident for the next decode. */
        context->read_buffer += snappy->consumed;
        context->input_buffer_length -= snappy->consumed;
        flb_free(snappy->buffer);
        snappy->buffer = NULL;
        snappy->length = 0;
        snappy->offset = 0;
        snappy->consumed = 0;
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
    if (algorithm != FLB_COMPRESSION_ALGORITHM_GZIP &&
        algorithm != FLB_COMPRESSION_ALGORITHM_ZSTD &&
        algorithm != FLB_COMPRESSION_ALGORITHM_SNAPPY) {
        return FLB_DECOMPRESSOR_FAILURE;
    }
    decoder = flb_decompression_context_create(algorithm, input_size);
    if (decoder == NULL) {
        return FLB_DECOMPRESSOR_ALLOCATION_FAILURE;
    }
    decoder->output_limit = limit;
    decoder->input_complete = FLB_TRUE;
    memcpy(flb_decompression_context_get_append_buffer(decoder), input, input_size);
    decoder->input_buffer_length = input_size;
    chunk = flb_malloc(chunk_size);
    if (chunk == NULL) {
        flb_decompression_context_destroy(decoder);
        return FLB_DECOMPRESSOR_ALLOCATION_FAILURE;
    }
    while (decoder->input_buffer_length > 0) {
        previous_input = decoder->input_buffer_length;
        previous_state = decoder->state;
        produced = chunk_size;
        ret = flb_decompress(decoder, chunk, &produced);
        if (ret == FLB_DECOMPRESSOR_INSUFFICIENT_DATA) {
            /* Every byte this API will ever supply is already resident, so a
             * decoder that cannot advance has run out of stream. */
            ret = FLB_DECOMPRESSOR_FAILURE;
            goto error;
        }
        if (ret != FLB_DECOMPRESSOR_SUCCESS) {
            goto error;
        }
        if (produced > 0) {
            resized = flb_realloc(buffer, total + produced);
            if (resized == NULL) {
                ret = FLB_DECOMPRESSOR_ALLOCATION_FAILURE;
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
