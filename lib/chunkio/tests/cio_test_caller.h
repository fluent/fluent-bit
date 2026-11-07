/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2026 The Fluent Bit Authors
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

/* Test-only filesystem caller model, shared by the tests and benchmark. */
#ifndef CIO_TEST_CALLER_H
#define CIO_TEST_CALLER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_meta.h>

#define CALLER_METADATA_SIZE 64
#define CALLER_FIXED_HINT 0
#define CALLER_APPEND_HINT 1

struct caller_chunk {
    struct cio_chunk *chunk;
    size_t key;
    size_t offset;
    size_t length;
    size_t appends;
    size_t hint;
    size_t initial_capacity;
    int busy;
    char name[40];
    char metadata[CALLER_METADATA_SIZE];
};

struct caller {
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct caller_chunk *chunks;
    struct caller_chunk **active;
    size_t *written;
    size_t key_count;
    size_t chunk_count;
    size_t chunk_limit;
    size_t content_threshold;
    int policy;
};

static int caller_hint(size_t append, size_t metadata, int policy, size_t *hint)
{
    if (metadata > UINT16_MAX ||
        append > (size_t) PTRDIFF_MAX - CIO_FILE_HEADER_MIN - metadata) {
        return CIO_ERROR;
    }

    if (policy == CALLER_FIXED_HINT) {
        *hint = 256 * 1024;
    }
    else {
        /* Filesystem capacity includes the header, opaque metadata and data. */
        *hint = CIO_FILE_HEADER_MIN + metadata + append;
    }

    return CIO_OK;
}

static int caller_init(struct caller *caller, struct cio_ctx *ctx,
                       struct cio_stream *stream, size_t keys, size_t chunks,
                       size_t content_threshold, int policy)
{
    memset(caller, 0, sizeof(*caller));
    caller->ctx = ctx;
    caller->stream = stream;
    caller->key_count = keys;
    caller->chunk_limit = chunks;
    caller->content_threshold = content_threshold;
    caller->policy = policy;
    caller->chunks = calloc(chunks, sizeof(*caller->chunks));
    caller->active = calloc(keys, sizeof(*caller->active));
    caller->written = calloc(keys, sizeof(*caller->written));

    if (!caller->chunks || !caller->active || !caller->written) {
        free(caller->chunks);
        free(caller->active);
        free(caller->written);

        return CIO_ERROR;
    }

    return CIO_OK;
}

/* Each key represents one (tag, event type) pair; never a physical capacity. */
static int caller_append(struct caller *caller, size_t key,
                         const void *data, size_t length)
{
    int err;
    int created_down = CIO_FALSE;
    int set_down = CIO_FALSE;
    size_t hint;
    size_t i;
    struct caller_chunk *entry;
    struct cio_file *file;

    if (key >= caller->key_count || length == 0) {
        return CIO_ERROR;
    }

    entry = caller->active[key];
    /* flb_input_chunk.c: input_chunk_get() rejects busy/locked chunks. */
    if (entry && (entry->busy || cio_chunk_is_locked(entry->chunk))) {
        entry = NULL;
    }

    if (!entry) {
        if (caller_hint(length, CALLER_METADATA_SIZE,
                        caller->policy, &hint) != CIO_OK) {
            return CIO_ERROR;
        }

        if (caller->chunk_count == caller->chunk_limit) {
            return CIO_ERROR;
        }

        entry = &caller->chunks[caller->chunk_count];
        memset(entry, 0, sizeof(*entry));
        entry->key = key;
        /* This offset is for verification only, not allocation prediction. */
        entry->offset = caller->written[key];
        entry->hint = hint;
        snprintf(entry->name, sizeof(entry->name), "chunk-%zu", caller->chunk_count);
        for (i = 0; i < sizeof(entry->metadata); i++) {
            entry->metadata[i] = (char) (key + i);
        }

        entry->chunk = cio_chunk_open(caller->ctx, caller->stream, entry->name,
                                      CIO_OPEN, hint, &err);
        if (!entry->chunk) {
            return CIO_ERROR;
        }

        if (!cio_chunk_is_up(entry->chunk)) {
            created_down = CIO_TRUE;
            if (cio_chunk_up_force(entry->chunk) != CIO_OK) {
                cio_chunk_close(entry->chunk, CIO_TRUE);

                return CIO_ERROR;
            }
        }

        file = entry->chunk->backend;
        entry->initial_capacity = file->alloc_size;
        if (cio_meta_write(entry->chunk, entry->metadata,
                           sizeof(entry->metadata)) != CIO_OK) {
            cio_chunk_close(entry->chunk, CIO_TRUE);

            return CIO_ERROR;
        }

        caller->chunk_count++;
        caller->active[key] = entry;
        if (created_down && cio_chunk_down(entry->chunk) != CIO_OK) {
            return CIO_ERROR;
        }
    }

    if (!cio_chunk_is_up(entry->chunk)) {
        set_down = CIO_TRUE;
        if (cio_chunk_up_force(entry->chunk) != CIO_OK) {
            return CIO_ERROR;
        }
    }

    if (cio_chunk_write(entry->chunk, data, length) != CIO_OK) {
        return CIO_ERROR;
    }

    entry->length += length;
    entry->appends++;
    caller->written[key] += length;

    /* input_chunk_append_raw(): append whole, then lock above the soft limit. */
    if (entry->length > caller->content_threshold &&
        cio_chunk_lock(entry->chunk) != CIO_OK) {
        return CIO_ERROR;
    }

    if (set_down && cio_chunk_down(entry->chunk) != CIO_OK) {
        return CIO_ERROR;
    }

    return CIO_OK;
}

static void caller_destroy(struct caller *caller)
{
    size_t i;

    for (i = 0; i < caller->chunk_count; i++) {
        cio_chunk_close(caller->chunks[i].chunk, CIO_TRUE);
    }

    free(caller->chunks);
    free(caller->active);
    free(caller->written);
}

#endif
