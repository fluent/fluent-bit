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

/* Linux benchmark of planned caller semantics, not a Fluent Bit executable. */
#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "cio_test_caller.h"

#ifdef NDEBUG
#error "The benchmark requires assertions; compile without -DNDEBUG"
#endif

#define MAX_CHUNKS 4096
#define RECORD_SIZE 256

static size_t remaps;
static size_t resize_calls;
static size_t growth_calls;

int __real_cio_file_native_remap(struct cio_file *file, size_t size);
int __real_cio_file_native_resize(struct cio_file *file, size_t size);

int __wrap_cio_file_native_remap(struct cio_file *file, size_t size)
{
    remaps++;

    return __real_cio_file_native_remap(file, size);
}

int __wrap_cio_file_native_resize(struct cio_file *file, size_t size)
{
    int ret;
    size_t before;

    resize_calls++;
    before = file->fs_size;
    ret = __real_cio_file_native_resize(file, size);
    if (ret == CIO_OK && before > 0 && size > before) {
        growth_calls++;
    }

    return ret;
}

struct source {
    char *data;
    size_t length;
    size_t batch;
    size_t offset;
};

struct allocation {
    size_t *chunks;
    size_t current;
    size_t peak;
};

static double seconds(clockid_t clock)
{
    struct timespec value;

    assert(clock_gettime(clock, &value) == 0);

    return value.tv_sec + value.tv_nsec / 1000000000.0;
}

static size_t capacity(struct caller_chunk *entry)
{
    struct cio_file *file;

    file = entry->chunk->backend;

    return cio_chunk_is_up(entry->chunk) ? file->alloc_size : file->fs_size;
}

static void sample(struct caller *caller, struct allocation *allocation, size_t index)
{
    struct stat status;
    struct cio_file *file;
    size_t allocated;

    file = caller->chunks[index].chunk->backend;
    assert(stat(file->path, &status) == 0);
    allocated = (size_t) status.st_blocks * 512;
    allocation->current -= allocation->chunks[index];
    allocation->current += allocated;
    allocation->chunks[index] = allocated;
    if (allocation->current > allocation->peak) {
        allocation->peak = allocation->current;
    }
}

static void verify(struct caller_chunk *entry, struct source *source)
{
    char *content;
    size_t size;

    assert(cio_chunk_get_content(entry->chunk, &content, &size) == CIO_OK);
    assert(size == entry->length);
    assert(entry->offset + size <= source->length);
    assert(memcmp(content, source->data + entry->offset, size) == 0);
    assert(cio_meta_cmp(entry->chunk, entry->metadata,
                        sizeof(entry->metadata)) == 0);
}

static void reopen(struct caller *caller, struct caller_chunk *entry,
                   struct source *source)
{
    int err;
    size_t before;
    size_t hint;

    before = capacity(entry);
    assert(cio_chunk_down(entry->chunk) == CIO_OK);
    assert(cio_chunk_up(entry->chunk) == CIO_OK);
    assert(capacity(entry) == before);
    verify(entry, source);
    assert(cio_chunk_sync(entry->chunk) == CIO_OK);
    cio_chunk_close(entry->chunk, CIO_FALSE);
    hint = (entry - caller->chunks) % 2 ? 1 : 8 * 1024 * 1024;
    entry->chunk = cio_chunk_open(caller->ctx, caller->stream, entry->name,
                                  CIO_OPEN, hint, &err);
    assert(entry->chunk != NULL && err == CIO_OK);
    assert(capacity(entry) == before);
    verify(entry, source);
}

int main(int argc, char **argv)
{
    int policy;
    int checksum;
    int diagnostic;
    int reopen_case;
    int more;
    size_t keys;
    size_t i;
    size_t j;
    size_t count;
    size_t length;
    size_t prior_chunks;
    size_t prior_remaps;
    size_t first_remaps = 0;
    size_t appends = 0;
    size_t reopens = 0;
    size_t logical = 0;
    size_t initial = 0;
    size_t final = 0;
    size_t initial_min = SIZE_MAX;
    size_t initial_max = 0;
    size_t final_min = SIZE_MAX;
    size_t final_max = 0;
    uint64_t identity;
    double cpu_start;
    double wall_start;
    double ingest_cpu;
    double ingest_wall;
    double cpu;
    double wall;
    char root[PATH_MAX];
    char directory[PATH_MAX];
    const char *temporary;
    struct cio_options options;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct caller caller;
    struct caller_chunk *entry;
    struct source *sources;
    struct allocation allocation;

    if (argc != 5) {
        fprintf(stderr, "Usage: %s sparse|sparse_fragmented|busy|mixed|large|reopen fixed|append "
                        "checksum diagnostic\n", argv[0]);
        return 1;
    }

    assert(strcmp(argv[2], "fixed") == 0 || strcmp(argv[2], "append") == 0);
    policy = strcmp(argv[2], "append") == 0 ? CALLER_APPEND_HINT : CALLER_FIXED_HINT;
    checksum = atoi(argv[3]);
    diagnostic = atoi(argv[4]);
    reopen_case = strcmp(argv[1], "reopen") == 0;
    keys = 1;
    if (strcmp(argv[1], "sparse") == 0 ||
        strcmp(argv[1], "sparse_fragmented") == 0) {
        keys = 1000;
    }
    else if (strcmp(argv[1], "mixed") == 0) {
        keys = 1008;
    }
    else if (strcmp(argv[1], "large") == 0) {
        keys = 64;
    }
    else {
        assert(strcmp(argv[1], "busy") == 0 || reopen_case);
    }

    sources = calloc(keys, sizeof(*sources));
    allocation.chunks = calloc(MAX_CHUNKS, sizeof(*allocation.chunks));
    allocation.current = 0;
    allocation.peak = 0;
    assert(sources != NULL && allocation.chunks != NULL);
    for (i = 0; i < keys; i++) {
        sources[i].length = 16 * 1024;
        sources[i].batch = 16 * 1024;
        if (strcmp(argv[1], "sparse_fragmented") == 0) {
            sources[i].batch = RECORD_SIZE;
        }
        if (strcmp(argv[1], "busy") == 0 || reopen_case) {
            sources[i].length = reopen_case ? 8 * 1024 * 1024 : 64 * 1024 * 1024;
            sources[i].batch = 1024;
        }
        else if (strcmp(argv[1], "mixed") == 0 && i >= 1000) {
            sources[i].length = 8 * 1024 * 1024;
            sources[i].batch = 1024;
        }
        else if (strcmp(argv[1], "large") == 0) {
            sources[i].length = 1024 * 1024;
            sources[i].batch = sources[i].length;
        }

        sources[i].data = malloc(sources[i].length);
        assert(sources[i].data != NULL);
        /* Prebuild deterministic synthetic encoded records, outside timers. */
        for (j = 0; j < sources[i].length; j += RECORD_SIZE) {
            identity = ((uint64_t) i << 32) | (j / RECORD_SIZE);
            memset(sources[i].data + j, (int) (identity % 251), RECORD_SIZE);
            memcpy(sources[i].data + j, &identity, sizeof(identity));
        }
        logical += sources[i].length;
    }

    temporary = getenv("TMPDIR");
    if (!temporary) {
        temporary = "/tmp";
    }
    assert(snprintf(root, sizeof(root), "%s/cio-caller-XXXXXX", temporary) < (int) sizeof(root));
    assert(mkdtemp(root) != NULL);
    cio_options_init(&options);
    options.root_path = root;
    options.flags = CIO_OPEN | (checksum ? CIO_CHECKSUM : 0);
    ctx = cio_create(&options);
    assert(ctx != NULL);
    assert(cio_set_max_chunks_up(ctx, MAX_CHUNKS) == CIO_OK);
    stream = cio_stream_create(ctx, "input", CIO_STORE_FS);
    assert(stream != NULL);
    assert(caller_init(&caller, ctx, stream, keys, MAX_CHUNKS,
                       2048000, policy) == CIO_OK);

    cpu_start = seconds(CLOCK_PROCESS_CPUTIME_ID);
    wall_start = seconds(CLOCK_MONOTONIC);
    do {
        more = 0;
        for (i = 0; i < keys; i++) {
            if (sources[i].offset == sources[i].length) {
                continue;
            }
            more = 1;
            length = sources[i].length - sources[i].offset;
            count = length < sources[i].batch ? length : sources[i].batch;
            prior_chunks = caller.chunk_count;
            prior_remaps = remaps;
            assert(caller_append(&caller, i, sources[i].data + sources[i].offset,
                                  count) == CIO_OK);
            entry = caller.active[i];
            if (caller.chunk_count != prior_chunks) {
                first_remaps += remaps - prior_remaps;
            }
            sources[i].offset += count;
            appends++;
            if (reopen_case && entry->appends == 8) {
                reopen(&caller, entry, &sources[i]);
                reopens++;
            }
            if (diagnostic) {
                sample(&caller, &allocation, (size_t) (entry - caller.chunks));
            }
        }
    } while (more);
    ingest_cpu = seconds(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    ingest_wall = seconds(CLOCK_MONOTONIC) - wall_start;

    /* Hold every chunk until this drain; each record is compared before/after up. */
    for (i = 0; i < caller.chunk_count; i++) {
        entry = &caller.chunks[i];
        verify(entry, &sources[entry->key]);
        if (!cio_chunk_is_locked(entry->chunk)) {
            assert(cio_chunk_lock(entry->chunk) == CIO_OK);
        }
        assert(cio_chunk_down(entry->chunk) == CIO_OK);
        assert(cio_chunk_up(entry->chunk) == CIO_OK);
        verify(entry, &sources[entry->key]);
        sample(&caller, &allocation, i);
        initial += entry->initial_capacity;
        final += capacity(entry);
        if (entry->initial_capacity < initial_min) {
            initial_min = entry->initial_capacity;
        }
        if (entry->initial_capacity > initial_max) {
            initial_max = entry->initial_capacity;
        }
        if (capacity(entry) < final_min) {
            final_min = capacity(entry);
        }
        if (capacity(entry) > final_max) {
            final_max = capacity(entry);
        }
    }
    for (i = 0; i < keys; i++) {
        assert(caller.written[i] == sources[i].length);
    }
    if (diagnostic) {
        printf("{\"chunks\":[");
        for (i = 0; i < caller.chunk_count; i++) {
            entry = &caller.chunks[i];
            printf("%s{\"key\":%zu,\"initial\":%zu,\"final\":%zu,"
                   "\"allocated\":%zu,\"logical\":%zu,\"appends\":%zu}",
                   i ? "," : "", entry->key, entry->initial_capacity,
                   capacity(entry), allocation.chunks[i], entry->length, entry->appends);
        }
        printf("],");
    }
    else {
        printf("{");
    }
    caller_destroy(&caller);
    cpu = seconds(CLOCK_PROCESS_CPUTIME_ID) - cpu_start;
    wall = seconds(CLOCK_MONOTONIC) - wall_start;
    printf("\"cpu_ms\":%.6f,\"elapsed_ms\":%.6f,"
           "\"ingest_cpu_ms\":%.6f,\"ingest_elapsed_ms\":%.6f,"
           "\"remaps\":%zu,\"first_append_remaps\":%zu,"
           "\"resize_calls\":%zu,\"growth_calls\":%zu,"
           "\"chunk_count\":%zu,\"appends\":%zu,\"reopens\":%zu,"
           "\"initial_capacity_total\":%zu,\"final_capacity_total\":%zu,"
           "\"initial_capacity_min\":%zu,\"initial_capacity_max\":%zu,"
           "\"final_capacity_min\":%zu,\"final_capacity_max\":%zu,"
           "\"peak_allocated_bytes\":%zu,\"final_allocated_bytes\":%zu,"
           "\"logical_bytes\":%zu,\"metadata_bytes\":%zu,"
           "\"amplification\":%.9f,\"records\":%zu,\"correct\":true}\n",
           cpu * 1000, wall * 1000, ingest_cpu * 1000, ingest_wall * 1000,
           remaps, first_remaps, resize_calls, growth_calls, caller.chunk_count,
           appends, reopens, initial, final, initial_min, initial_max, final_min,
           final_max, allocation.peak, allocation.current, logical,
           caller.chunk_count * CALLER_METADATA_SIZE,
           (double) allocation.current / logical, logical / RECORD_SIZE);
    cio_destroy(ctx);
    assert(snprintf(directory, sizeof(directory), "%s/input", root) < (int) sizeof(directory));
    assert(rmdir(directory) == 0);
    assert(rmdir(root) == 0);
    for (i = 0; i < keys; i++) {
        free(sources[i].data);
    }
    free(sources);
    free(allocation.chunks);

    return 0;
}
