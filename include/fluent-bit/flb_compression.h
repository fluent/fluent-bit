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

#ifndef FLB_COMPRESSION_H
#define FLB_COMPRESSION_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_gzip.h>
#include <stdio.h>

#define FLB_COMPRESSION_ALGORITHM_NONE                    0
#define FLB_COMPRESSION_ALGORITHM_GZIP                    1
#define FLB_COMPRESSION_ALGORITHM_ZSTD                    2
#define FLB_COMPRESSION_ALGORITHM_SNAPPY                  3

#define FLB_DECOMPRESSOR_STATE_FAILED                    -1
#define FLB_DECOMPRESSOR_STATE_EXPECTING_HEADER           0
#define FLB_DECOMPRESSOR_STATE_EXPECTING_OPTIONAL_HEADERS 1
#define FLB_DECOMPRESSOR_STATE_EXPECTING_BODY             2
#define FLB_DECOMPRESSOR_STATE_EXPECTING_FOOTER           3

#define FLB_DECOMPRESSOR_ALLOCATION_FAILURE              -5
#define FLB_DECOMPRESSOR_LIMIT_EXCEEDED                  -4
#define FLB_DECOMPRESSOR_INVALID_STATE                   -3
#define FLB_DECOMPRESSOR_CORRUPTED_HEADER                -2
#define FLB_DECOMPRESSOR_FAILURE                         -1
#define FLB_DECOMPRESSOR_SUCCESS                          0
/*
 * The decoder cannot advance yet but is still able to: it needs more input, or,
 * for a streaming caller, more room to write. This is not success and not an
 * error. Negative values stay errors and zero stays "the decode advanced".
 *
 * It used to alias FLB_DECOMPRESSOR_SUCCESS, which made every `ret != SUCCESS`
 * check silently swallow a wait (that is how the gzip header-boundary defect was
 * written). Consumers therefore fall into two groups:
 *   - streaming callers must consume any reported output (it will not be returned
 *     again), retain the decoder state, and supply more input when available;
 *   - one-shot callers, which already declared the input complete, must translate
 *     it into FLB_DECOMPRESSOR_FAILURE because a decoder that cannot advance over
 *     complete input has run out of stream.
 * Third-party code compiled against the previous header must be rebuilt: only
 * this constant changed value (0 -> 1); every error code keeps its number.
 */
#define FLB_DECOMPRESSOR_INSUFFICIENT_DATA                1

#define FLB_DECOMPRESSION_BUFFER_SIZE                     (1024 * 1000)

struct flb_decompression_context {
    size_t     input_buffer_length;
    size_t     input_buffer_size;
    uint8_t   *input_buffer;
    uint8_t   *read_buffer;
    int        algorithm;
    int        state;
    /* Expanded output budget, SIZE_MAX by default, and bytes produced so far. */
    size_t     output_limit;
    size_t     output_size;
    /* The caller has supplied all compressed bytes for this payload. */
    int        input_complete;

    /* Compression backend specific context (opaque) */
    void      *inner_context;
};

uint8_t *flb_decompression_context_get_append_buffer(
            struct flb_decompression_context *context);

/*
 * Space left for appending at the current read cursor. This already subtracts
 * the consumed prefix (read_buffer - input_buffer), so a caller that grows the
 * buffer must add that prefix back: use flb_decompression_context_reserve()
 * instead of sizing from input_buffer_length alone.
 */
size_t flb_decompression_context_get_available_space(
            struct flb_decompression_context *context);

int flb_decompression_context_resize_buffer(
        struct flb_decompression_context *context, size_t new_size);

/*
 * Make room to append `needed` bytes at the current read cursor, growing the
 * allocation as required. This is the only safe way for a caller to size a grow:
 * the target covers the consumed prefix plus the resident span plus `needed`, so
 * the following get_append_buffer()/memcpy() pair cannot run past the new block.
 * `maximum_size` caps the resulting allocation (0 means uncapped) and is the
 * caller's policy, not the decoder's. Returns FLB_DECOMPRESSOR_SUCCESS when the
 * space is available afterwards, FLB_DECOMPRESSOR_LIMIT_EXCEEDED when honouring
 * the cap would be required, and another negative code on a real failure.
 */
int flb_decompression_context_reserve(struct flb_decompression_context *context,
                                      size_t needed, size_t maximum_size);

/*
 * True when the decoder holds no undecoded bytes and can decode the next byte
 * from scratch with no memory of what came before. This is the only kind of
 * position a caller may persist as a resume point: anywhere else it would need
 * decoder state that cannot be reconstructed, so resuming there makes the rest
 * of the stream undecodable.
 *
 * Backends differ on what "from scratch" means. A gzip context is resumable at a
 * member boundary; zstd at a frame boundary; framed Snappy only at the start of
 * the stream, because this decoder recognises framing through the leading
 * identifier chunk and a continuation span carries none.
 */
int flb_decompression_context_at_payload_boundary(struct flb_decompression_context *context);

struct flb_decompression_context *flb_decompression_context_create(
                                    int algorithm,
                                    size_t input_buffer_size);

void flb_decompression_context_destroy(
        struct flb_decompression_context *context);

int flb_decompress(struct flb_decompression_context *context,
                   void *output_buffer,
                   size_t *output_length);

/*
 * Decode one complete payload using bounded output chunks. The returned buffer
 * preserves the full payload for protocols with grouped records. The caller
 * owns the buffer and must flb_free it. On failure output is NULL/0; an expanded
 * size rejection returns FLB_DECOMPRESSOR_LIMIT_EXCEEDED. Codec workspace is
 * separate from the expanded-output budget.
 */
int flb_decompress_buffer(int algorithm, void *input, size_t input_size,
                          size_t limit, void **payload, size_t *payload_size);

#endif
