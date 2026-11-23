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

/* Allocation benchmark. Build instructions: docs/allocation.md. */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_memfs.h>
#include <chunkio/cio_meta.h>

static size_t remaps;
static size_t reallocations;
int __real_cio_file_native_remap(struct cio_file *cf, size_t size);
void *__real_realloc(void *ptr, size_t size);

int __wrap_cio_file_native_remap(struct cio_file *cf, size_t size)
{
    remaps++;
    return __real_cio_file_native_remap(cf, size);
}

void *__wrap_realloc(void *ptr, size_t size)
{
    reallocations++;
    return __real_realloc(ptr, size);
}

static double seconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    return now.tv_sec + now.tv_nsec / 1e9;
}

static size_t capacity(struct cio_chunk *ch)
{
    struct cio_file *cf;
    struct cio_memfs *mf;

    if (ch->st->type == CIO_STORE_FS) {
        cf = ch->backend;
        return cf->alloc_size;
    }

    mf = ch->backend;

    return mf->buf_size;
}

int main(int argc, char **argv)
{
    struct cio_options opts;
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *ch;
    char root[] = "/tmp/cio-allocation-bench-XXXXXX";
    char directory[128];
    char *payload;
    char *content;
    char metadata[64];
    size_t chunks;
    size_t length;
    size_t batch;
    size_t hint;
    size_t written;
    size_t count;
    size_t verified;
    size_t i;
    size_t initial = 0;
    size_t final = 0;
    double start;
    double elapsed;
    int backend;
    int err;

    if (argc != 8) {
        fprintf(stderr,
                "Usage: %s fs|mem chunks bytes batch opening_hint "
                "adaptive checksum\n", argv[0]);
        return 1;
    }

    backend = strcmp(argv[1], "mem") == 0 ? CIO_STORE_MEM : CIO_STORE_FS;
    chunks = strtoull(argv[2], NULL, 10);
    length = strtoull(argv[3], NULL, 10);
    batch = strtoull(argv[4], NULL, 10);
    hint = strtoull(argv[5], NULL, 10);
    assert(chunks > 0 && length > 0 && batch > 0);
    payload = malloc(length);
    assert(payload != NULL);
    memset(payload, 'x', length);
    memset(metadata, 'm', sizeof(metadata));
    assert(mkdtemp(root) != NULL);
    cio_options_init(&opts);
    opts.root_path = root;
    if (!atoi(argv[6])) {
        opts.flags |= CIO_FIXED_GROWTH;
    }

    if (atoi(argv[7])) {
        opts.flags |= CIO_CHECKSUM;
    }

    ctx = cio_create(&opts);
    assert(ctx != NULL);
    st = cio_stream_create(ctx, "bench", backend);
    assert(st != NULL);
    start = seconds();
    for (i = 0; i < chunks; i++) {
        ch = cio_chunk_open(ctx, st, "chunk", CIO_OPEN, hint, &err);
        assert(ch != NULL && err == CIO_OK);
        initial = capacity(ch);
        assert(cio_meta_write(ch, metadata, sizeof(metadata)) == CIO_OK);
        for (written = 0; written < length; written += count) {
            count = length - written < batch ? length - written : batch;
            assert(cio_chunk_write(ch, payload + written, count) == CIO_OK);
        }

        final = capacity(ch);
        assert(cio_chunk_lock(ch) == CIO_OK);
        assert(cio_chunk_down(ch) == CIO_OK);
        assert(cio_chunk_up(ch) == CIO_OK);
        assert(cio_chunk_get_content(ch, &content, &verified) == CIO_OK);
        assert(verified == length && memcmp(content, payload, length) == 0);
        assert(cio_meta_cmp(ch, metadata, sizeof(metadata)) == 0);
        cio_chunk_close(ch, CIO_TRUE);
    }

    elapsed = seconds() - start;
    printf("ms=%.3f remaps=%zu reallocations=%zu initial=%zu final=%zu\n",
           elapsed * 1000, remaps, reallocations, initial, final);
    cio_destroy(ctx);
    if (backend == CIO_STORE_FS) {
        snprintf(directory, sizeof(directory), "%s/bench", root);
        assert(rmdir(directory) == 0);
    }

    assert(rmdir(root) == 0);
    free(payload);
    return 0;
}
