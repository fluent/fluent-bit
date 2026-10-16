/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *
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

/*  File-slot pool tests: bounded chunk file names, recycle-on-delete,
 *  recovery, backlog fallback and concurrency.
 */

#ifndef _WIN32
#include <sys/mman.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#endif
#include <fcntl.h>
#include <stdint.h>
#ifdef _WIN32
#include <io.h>
#else
#include <dirent.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_scan.h>
#include <chunkio/cio_file.h>
#include <chunkio/cio_meta.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_utils.h>
#include <chunkio/cio_error.h>
#include <chunkio/cio_file_native.h>

#include "cio_tests_internal.h"

#ifdef _WIN32
/*
 * chunkio_compat.h (via cio_chunk.h) already includes winsock2.h and
 * windows.h in the right order; include it explicitly after the chunkio
 * headers for the CreateThread-based concurrency test.
 */
#include <windows.h>
#endif

#define CIO_POOL_ENV  "/tmp/cio-fs-pool-test/"
#define CIO_POOL_NAME "pool-test"

#define POOL_SIZE 4

/* Logging callback, once called it just turn on the log_check flag */
static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    (void) ctx;
    (void) level;

    printf("[cio-test-pool] %-60s => %s:%i\n", str, file, line);
    return 0;
}

/* Count regular files inside a stream directory */
#ifdef _WIN32
static int count_stream_files(const char *stream)
{
    int n = 0;
    char pattern[512];
    struct _finddata_t fd;
    intptr_t handle;

    snprintf(pattern, sizeof(pattern), "%s%s\\*", CIO_POOL_ENV, stream);
    handle = _findfirst(pattern, &fd);
    if (handle == -1) {
        return -1;
    }

    do {
        if ((fd.attrib & _A_SUBDIR) == 0) {
            n++;
        }
    } while (_findnext(handle, &fd) == 0);

    _findclose(handle);
    return n;
}
#else
static int count_stream_files(const char *stream)
{
    int n = 0;
    char path[512];
    DIR *dir;
    struct dirent *ent;

    snprintf(path, sizeof(path), "%s%s", CIO_POOL_ENV, stream);
    dir = opendir(path);
    if (!dir) {
        return -1;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        if (ent->d_type != DT_REG) {
            continue;
        }
        n++;
    }
    closedir(dir);

    return n;
}
#endif

static struct cio_ctx *pool_ctx_create(int pool_size, int extra_flags)
{
    struct cio_options opts;
    struct cio_ctx *ctx;

    cio_options_init(&opts);
    opts.root_path = CIO_POOL_ENV;
    opts.log_cb = log_cb;
    opts.flags = CIO_CHECKSUM | extra_flags;
    opts.file_pool_size = pool_size;

    ctx = cio_create(&opts);
    return ctx;
}

static int write_and_close(struct cio_ctx *ctx, struct cio_stream *st,
                           const char *name, const char *payload,
                           int delete_chunk)
{
    int err;
    int ret = CIO_OK;
    void *out_buf = NULL;
    size_t out_size = 0;
    struct cio_chunk *chunk;

    chunk = cio_chunk_open(ctx, st, name, CIO_OPEN, 4096, &err);
    if (!chunk) {
        return -1;
    }

    if (payload) {
        ret = cio_chunk_write(chunk, payload, strlen(payload));
        if (ret != CIO_OK) {
            cio_chunk_close(chunk, CIO_TRUE);
            return -1;
        }

        /* read back while the chunk is up: catches stale slot content */
        ret = cio_chunk_get_content_copy(chunk, &out_buf, &out_size);
        if (ret != CIO_OK || out_size != strlen(payload) ||
            memcmp(out_buf, payload, out_size) != 0) {
            if (out_buf) {
                free(out_buf);
            }
            cio_chunk_close(chunk, CIO_TRUE);
            return -1;
        }
        free(out_buf);
    }

    cio_chunk_close(chunk, delete_chunk ? CIO_TRUE : CIO_FALSE);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* 1. name parsing helpers                                                    */
/* ------------------------------------------------------------------------- */
static void test_pool_slot_name_parse()
{
    char name[64];

    printf("\n");

    TEST_CHECK(cio_stream_pool_slot_from_name("slot-000000.flb") == 0);
    TEST_CHECK(cio_stream_pool_slot_from_name("slot-000123.flb") == 123);
    TEST_CHECK(cio_stream_pool_slot_from_name("slot-999999.flb") == 999999);
    TEST_CHECK(cio_stream_pool_slot_from_name("other-000001.flb") == -1);
    TEST_CHECK(cio_stream_pool_slot_from_name("slot-.flb") == -1);

    /* only the canonical slot-<6 digits>.flb form is a slot */
    TEST_CHECK(cio_stream_pool_slot_from_name("slot-5.flb") == -1);
    TEST_CHECK(cio_stream_pool_slot_from_name("slot-5") == -1);
    TEST_CHECK(cio_stream_pool_slot_from_name("slot-000005") == -1);
    TEST_CHECK(cio_stream_pool_slot_from_name("slot-000005.flb.orig") == -1);
    TEST_CHECK(cio_stream_pool_slot_from_name("slot-0000005.flb") == -1);
    TEST_CHECK(cio_stream_pool_slot_from_name("slot-1000000.flb") == -1);
    TEST_CHECK(cio_stream_pool_slot_from_name("slot-00000a.flb") == -1);
    TEST_CHECK(cio_stream_pool_slot_from_name(NULL) == -1);

    cio_stream_pool_slot_name(7, name, sizeof(name));
    TEST_CHECK(strcmp(name, "slot-000007.flb") == 0);
    TEST_CHECK(cio_stream_pool_slot_from_name(name) == 7);
}

/* ------------------------------------------------------------------------- */
/* 2. pool disabled: legacy behaviour (unlink on delete)                      */
/* ------------------------------------------------------------------------- */
static void test_pool_disabled_legacy()
{
    int i;
    int n;
    int err;
    char name[64];
    char payload[64];
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(0, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);

    for (i = 0; i < 10; i++) {
        snprintf(name, sizeof(name), "chunk-%04d.flb", i);
        snprintf(payload, sizeof(payload), "payload-%d", i);
        err = write_and_close(ctx, st, name, payload, CIO_TRUE);
        TEST_CHECK(err == 0);
    }

    /* legacy: every deleted chunk is unlinked */
    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n == 0);

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 5b. legacy (non-slot) chunk files are recovered in place, not redirected   */
/* ------------------------------------------------------------------------- */
static void test_pool_recovery_legacy_name()
{
    int err;
    int n;
    int found;
    size_t size;
    char *buf = NULL;
    struct mk_list *head;
    struct cio_chunk *chunk;
    struct cio_chunk *legacy = NULL;
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    /* phase 1: write a chunk with the pool disabled (legacy unique name) */
    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(0, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);
    TEST_CHECK(st->pool_size == 0);

    err = write_and_close(ctx, st, "legacy-0001.flb", "legacy-payload",
                          CIO_FALSE);
    TEST_CHECK(err == 0);
    cio_destroy(ctx);

    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n == 1);

    /*
     * phase 2: enable the pool and rescan. The legacy file must be recovered
     * in place under its own name; no slot file may be created for it.
     */
    ctx = pool_ctx_create(4, 0);
    TEST_CHECK(ctx != NULL);
    TEST_CHECK(cio_load(ctx, ".flb") == 0);
    st = cio_stream_get(ctx, CIO_POOL_NAME);
    TEST_CHECK(st != NULL);
    TEST_CHECK(st->pool_size == 4);

    TEST_CHECK(mk_list_size(&st->chunks) == 1);
    TEST_CHECK(count_stream_files(CIO_POOL_NAME) == 1);

    found = 0;
    mk_list_foreach(head, &st->chunks) {
        chunk = mk_list_entry(head, struct cio_chunk, _head);
        TEST_CHECK(strcmp(chunk->name, "legacy-0001.flb") == 0);

        err = cio_chunk_get_content_copy(chunk, (void **) &buf, &size);
        TEST_CHECK(err == CIO_OK);
        if (err == CIO_OK) {
            TEST_CHECK(size == strlen("legacy-payload"));
            TEST_CHECK(memcmp(buf, "legacy-payload", size) == 0);
            found = 1;
            free(buf);
        }
    }
    TEST_CHECK(found == 1);

    /*
     * phase 3: new chunks use slots; the recovered legacy chunk is still
     * unlinked (not truncated) when it is deleted.
     */
    err = write_and_close(ctx, st, "new-0001.flb", "new-payload", CIO_TRUE);
    TEST_CHECK(err == 0);
    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n == 2);

    mk_list_foreach(head, &st->chunks) {
        chunk = mk_list_entry(head, struct cio_chunk, _head);
        if (strcmp(chunk->name, "legacy-0001.flb") == 0) {
            legacy = chunk;
            break;
        }
    }
    TEST_CHECK(legacy != NULL);
    if (legacy) {
        cio_chunk_close(legacy, CIO_TRUE);
    }

    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n == 1);

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 3. pool enabled: file count stays bounded, content always correct          */
/* ------------------------------------------------------------------------- */
static void test_pool_reuse_bounds_files()
{
    int i;
    int n;
    char name[64];
    char payload[64];
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_options opts;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    cio_options_init(&opts);
    opts.root_path = CIO_POOL_ENV;
    opts.log_cb = log_cb;
    opts.file_pool_size = 4;
    ctx = cio_create(&opts);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);
    TEST_CHECK(st->pool_size == 4);
    TEST_CHECK(st->pool_busy != NULL);

    for (i = 0; i < 50; i++) {
        snprintf(name, sizeof(name), "logical-%04d.flb", i);
        snprintf(payload, sizeof(payload), "iteration-%d-payload", i);

        n = write_and_close(ctx, st, name, payload, CIO_TRUE);
        TEST_CHECK(n == 0);

        n = count_stream_files(CIO_POOL_NAME);
        TEST_CHECK(n >= 0 && n <= POOL_SIZE);
    }

    /* all slots ever used remain (truncated) after the loop; the exact count
     * depends on the allocation policy (lowest free slot first) */
    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n >= 1 && n <= POOL_SIZE);

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 4. backlog: more live chunks than slots -> unique fallback names           */
/* ------------------------------------------------------------------------- */
static void test_pool_backlog_fallback()
{
    int i;
    int n;
    int err;
    char name[64];
    char payload[64];
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *chunks[5];

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(2, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);
    TEST_CHECK(st->pool_size == 2);

    /* hold 5 live chunks: 2 pooled + 3 fallback */
    for (i = 0; i < 5; i++) {
        snprintf(name, sizeof(name), "backlog-%d.flb", i);
        snprintf(payload, sizeof(payload), "backlog-%d", i);
        chunks[i] = cio_chunk_open(ctx, st, name, CIO_OPEN, 4096, &err);
        TEST_CHECK(chunks[i] != NULL);
        err = cio_chunk_write(chunks[i], payload, strlen(payload));
        TEST_CHECK(err == CIO_OK);
    }

    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n == 5);

    for (i = 0; i < 5; i++) {
        cio_chunk_close(chunks[i], CIO_TRUE);
    }

    /* pooled files remain (truncated), fallback files are unlinked */
    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n == 2);

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 5. recovery: scan keeps live chunks, frees empty slots, no collision       */
/* ------------------------------------------------------------------------- */
static void test_pool_recovery()
{
    int i;
    int n;
    int err;
    int found;
    size_t size;
    char *buf = NULL;
    char name[64];
    struct mk_list *head;
    struct cio_chunk *chunk;
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    /* phase 1: one live chunk (no delete) + one deleted */
    ctx = pool_ctx_create(4, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);

    err = write_and_close(ctx, st, "keep.flb", "keep-payload", CIO_FALSE);
    TEST_CHECK(err == 0);
    err = write_and_close(ctx, st, "drop.flb", "drop-payload", CIO_TRUE);
    TEST_CHECK(err == 0);
    cio_destroy(ctx);

    /* phase 2: rescan the same root */
    ctx = pool_ctx_create(4, 0);
    TEST_CHECK(ctx != NULL);
    TEST_CHECK(cio_load(ctx, ".flb") == 0);
    st = cio_stream_get(ctx, CIO_POOL_NAME);
    TEST_CHECK(st != NULL);
    TEST_CHECK(st->pool_size == 4);

    TEST_CHECK(mk_list_size(&st->chunks) == 1);

    found = 0;
    mk_list_foreach(head, &st->chunks) {
        chunk = mk_list_entry(head, struct cio_chunk, _head);
        err = cio_chunk_get_content_copy(chunk, (void **) &buf, &size);
        TEST_CHECK(err == CIO_OK);
        if (err == CIO_OK) {
            TEST_CHECK(size == strlen("keep-payload"));
            TEST_CHECK(memcmp(buf, "keep-payload", size) == 0);
            found = 1;
            free(buf);
        }
    }
    TEST_CHECK(found == 1);

    /* phase 3: new chunks must not clobber the recovered one */
    for (i = 0; i < 10; i++) {
        snprintf(name, sizeof(name), "after-%d.flb", i);
        err = write_and_close(ctx, st, name, "new-payload", CIO_TRUE);
        TEST_CHECK(err == 0);
    }

    found = 0;
    mk_list_foreach(head, &st->chunks) {
        chunk = mk_list_entry(head, struct cio_chunk, _head);
        err = cio_chunk_get_content_copy(chunk, (void **) &buf, &size);
        TEST_CHECK(err == CIO_OK);
        if (err == CIO_OK) {
            TEST_CHECK(memcmp(buf, "keep-payload", size) == 0);
            found = 1;
            free(buf);
        }
    }
    TEST_CHECK(found == 1);

    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n >= 1 && n <= POOL_SIZE);

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 6. corrupt slot file is truncated during scan and becomes reusable         */
/* ------------------------------------------------------------------------- */
static void test_pool_corrupt_slot()
{
    int fd;
    int err;
    int n;
    char path[512];
    char garbage[256];
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(2, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);
    err = write_and_close(ctx, st, "corrupt-me.flb", "x", CIO_FALSE);
    TEST_CHECK(err == 0);
    cio_destroy(ctx);

    /* find the slot file and overwrite it with garbage */
    snprintf(path, sizeof(path), "%s%s/slot-000000.flb",
             CIO_POOL_ENV, CIO_POOL_NAME);
    fd = open(path, O_WRONLY | O_TRUNC);
    TEST_CHECK(fd != -1);
    if (fd != -1) {
        memset(garbage, 0x5a, sizeof(garbage));
        TEST_CHECK(write(fd, garbage, sizeof(garbage)) ==
                   (ssize_t) sizeof(garbage));
        close(fd);
    }

    /* rescan with delete-irrecoverable: the corrupt slot is truncated */
    ctx = pool_ctx_create(2, CIO_DELETE_IRRECOVERABLE);
    TEST_CHECK(ctx != NULL);
    TEST_CHECK(cio_load(ctx, ".flb") == 0);
    st = cio_stream_get(ctx, CIO_POOL_NAME);
    TEST_CHECK(st != NULL);

    /* the slot file remains but must be empty (reusable) */
    {
        struct stat sb;
        TEST_CHECK(stat(path, &sb) == 0);
        TEST_CHECK(sb.st_size == 0);
    }

    /* and a new chunk can use it again */
    err = write_and_close(ctx, st, "reuse.flb", "reuse-payload", CIO_TRUE);
    TEST_CHECK(err == 0);
    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n >= 1 && n <= 2);

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 7. pool allocator lock: no double allocation under threads                 */
/* ------------------------------------------------------------------------- */
#ifndef _WIN32
struct lock_thread {
    struct cio_stream *st;
    int iterations;
    int errors;
};

static volatile int held[POOL_SIZE];

static void *lock_worker(void *arg)
{
    int i;
    int slot;
    struct lock_thread *t = arg;

    for (i = 0; i < t->iterations; i++) {
        slot = cio_stream_pool_acquire(t->st);
        if (slot < 0 || slot >= POOL_SIZE) {
            t->errors++;
            continue;
        }

        /* if the slot was already held, the lock is broken */
        if (__sync_fetch_and_add(&held[slot], 1) != 0) {
            t->errors++;
        }
        sched_yield();
        __sync_fetch_and_sub(&held[slot], 1);

        cio_stream_pool_release(t->st, slot);
    }

    return NULL;
}

static void test_pool_lock_threads()
{
    int i;
    pthread_t threads[4];
    struct lock_thread args[4];
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(4, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);

    memset((void *) held, 0, sizeof(held));

    for (i = 0; i < 4; i++) {
        args[i].st = st;
        args[i].iterations = 5000;
        args[i].errors = 0;
        TEST_CHECK(pthread_create(&threads[i], NULL, lock_worker,
                                  &args[i]) == 0);
    }
    for (i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
        TEST_CHECK(args[i].errors == 0);
    }

    /* pool must be fully free again */
    for (i = 0; i < POOL_SIZE; i++) {
        TEST_CHECK(held[i] == 0);
    }

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 8. threaded chunk create/write/delete over the pool                       */
/* ------------------------------------------------------------------------- */
struct chunk_thread {
    struct cio_ctx *ctx;
    struct cio_stream *st;
    int tid;
    int iterations;
    int errors;
};

static void *chunk_worker(void *arg)
{
    int i;
    int err;
    char name[64];
    char payload[96];
    char *buf = NULL;
    size_t size = 0;
    struct cio_chunk *chunk;
    struct chunk_thread *t = arg;

    for (i = 0; i < t->iterations; i++) {
        snprintf(name, sizeof(name), "t%d-chunk-%d.flb", t->tid, i);
        snprintf(payload, sizeof(payload), "thread-%d-iteration-%d", t->tid, i);

        chunk = cio_chunk_open(t->ctx, t->st, name, CIO_OPEN, 4096, &err);
        if (!chunk) {
            t->errors++;
            continue;
        }
        if (cio_chunk_write(chunk, payload, strlen(payload)) != CIO_OK) {
            t->errors++;
            cio_chunk_close(chunk, CIO_TRUE);
            continue;
        }
        if (cio_chunk_get_content_copy(chunk, (void **) &buf, &size) != CIO_OK ||
            size != strlen(payload) || memcmp(buf, payload, size) != 0) {
            t->errors++;
        }
        if (buf) {
            free(buf);
            buf = NULL;
        }
        cio_chunk_close(chunk, CIO_TRUE);
    }

    return NULL;
}

static void test_pool_threaded_chunks()
{
    int i;
    int n;
    pthread_t threads[2];
    struct chunk_thread args[2];
    struct cio_ctx *ctx;
    struct cio_stream *streams[2];

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(8, 0);
    TEST_CHECK(ctx != NULL);
    /* avoid the global up-chunk counter becoming the bottleneck in this test */
    cio_set_max_chunks_up(ctx, 1024);

    /*
     * Fluent Bit gives each input its own stream, so concurrent input threads
     * never share a stream object; model that here.
     */
    for (i = 0; i < 2; i++) {
        char sname[64];
        snprintf(sname, sizeof(sname), "pool-t%d", i);
        streams[i] = cio_stream_create(ctx, sname, CIO_STORE_FS);
        TEST_CHECK(streams[i] != NULL);
        TEST_CHECK(streams[i]->pool_size == 8);
    }

    for (i = 0; i < 2; i++) {
        args[i].ctx = ctx;
        args[i].st = streams[i];
        args[i].tid = i;
        args[i].iterations = 30;
        args[i].errors = 0;
        TEST_CHECK(pthread_create(&threads[i], NULL, chunk_worker,
                                  &args[i]) == 0);
    }
    for (i = 0; i < 2; i++) {
        pthread_join(threads[i], NULL);
        TEST_CHECK(args[i].errors == 0);
    }

    for (i = 0; i < 2; i++) {
        char sname[64];
        snprintf(sname, sizeof(sname), "pool-t%d", i);
        n = count_stream_files(sname);
        TEST_CHECK(n >= 0 && n <= 8);
    }

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 10b. the max_chunks_up reservation under concurrent opens                  */
/* ------------------------------------------------------------------------- */
struct limit_thread {
    struct cio_ctx *ctx;
    struct cio_stream *st;
    pthread_barrier_t *barrier;
    struct cio_chunk *chunk;
    int tid;
    int errors;
};

static void *limit_worker(void *arg)
{
    struct limit_thread *t = arg;
    char name[64];
    int err = 0;

    snprintf(name, sizeof(name), "limit-%d.flb", t->tid);

    pthread_barrier_wait(t->barrier);

    t->chunk = cio_chunk_open(t->ctx, t->st, name, CIO_OPEN_RW, 4096, &err);
    if (!t->chunk) {
        t->errors++;
    }

    return NULL;
}

static void test_pool_threaded_max_chunks()
{
    int i;
    int round;
    int ups;
    pthread_t threads[8];
    pthread_barrier_t barrier;
    struct limit_thread args[8];
    struct cio_ctx *ctx;
    struct cio_stream *streams[8];

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(16, 0);
    TEST_CHECK(ctx != NULL);
    cio_set_max_chunks_up(ctx, 4);
    TEST_CHECK(pthread_barrier_init(&barrier, NULL, 8) == 0);

    /*
     * Fluent Bit gives each input its own stream; the up-chunk counter and the
     * limit are context-wide, so that is what the threads race on.
     */
    for (i = 0; i < 8; i++) {
        char sname[64];
        snprintf(sname, sizeof(sname), "limit-t%d", i);
        streams[i] = cio_stream_create(ctx, sname, CIO_STORE_FS);
        TEST_CHECK(streams[i] != NULL);

        args[i].ctx = ctx;
        args[i].st = streams[i];
        args[i].barrier = &barrier;
        args[i].chunk = NULL;
        args[i].tid = i;
        args[i].errors = 0;
    }

    for (round = 0; round < 20; round++) {
        ups = 0;

        for (i = 0; i < 8; i++) {
            args[i].chunk = NULL;
            args[i].errors = 0;
            TEST_CHECK(pthread_create(&threads[i], NULL, limit_worker,
                                      &args[i]) == 0);
        }
        for (i = 0; i < 8; i++) {
            pthread_join(threads[i], NULL);
            TEST_CHECK(args[i].errors == 0);
            if (args[i].chunk != NULL &&
                cio_chunk_is_up(args[i].chunk) == CIO_TRUE) {
                ups++;
            }
        }

        /* exactly max_chunks_up opens must have succeeded, never more */
        TEST_CHECK(ups == 4);
        TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 4);

        for (i = 0; i < 8; i++) {
            if (args[i].chunk) {
                cio_chunk_close(args[i].chunk, CIO_TRUE);
            }
        }
        TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 0);
    }

    pthread_barrier_destroy(&barrier);
    cio_destroy(ctx);
}
#endif

#ifdef _WIN32
/* ------------------------------------------------------------------------- */
/* 10c. the same max_chunks_up race on the win32 thread/atomic path           */
/* ------------------------------------------------------------------------- */
struct limit_thread_win {
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_chunk *chunk;
    int tid;
    int errors;
};

static DWORD WINAPI limit_worker_win(LPVOID arg)
{
    struct limit_thread_win *t = arg;
    char name[64];
    int err = 0;

    snprintf(name, sizeof(name), "limit-%d.flb", t->tid);

    t->chunk = cio_chunk_open(t->ctx, t->st, name, CIO_OPEN_RW, 4096, &err);
    if (!t->chunk) {
        t->errors++;
    }

    return 0;
}

static void test_pool_threaded_max_chunks_win()
{
    int i;
    int round;
    int ups;
    HANDLE threads[8];
    struct limit_thread_win args[8];
    struct cio_ctx *ctx;
    struct cio_stream *streams[8];

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(16, 0);
    TEST_CHECK(ctx != NULL);
    cio_set_max_chunks_up(ctx, 4);

    for (i = 0; i < 8; i++) {
        char sname[64];
        snprintf(sname, sizeof(sname), "limit-t%d", i);
        streams[i] = cio_stream_create(ctx, sname, CIO_STORE_FS);
        TEST_CHECK(streams[i] != NULL);

        args[i].ctx = ctx;
        args[i].st = streams[i];
        args[i].chunk = NULL;
        args[i].tid = i;
        args[i].errors = 0;
    }

    for (round = 0; round < 20; round++) {
        ups = 0;

        /* create every thread suspended so they all race from ResumeThread */
        for (i = 0; i < 8; i++) {
            args[i].chunk = NULL;
            args[i].errors = 0;
            threads[i] = CreateThread(NULL, 0, limit_worker_win, &args[i],
                                      CREATE_SUSPENDED, NULL);
            TEST_CHECK(threads[i] != NULL);
        }
        for (i = 0; i < 8; i++) {
            ResumeThread(threads[i]);
        }
        WaitForMultipleObjects(8, threads, TRUE, INFINITE);

        for (i = 0; i < 8; i++) {
            CloseHandle(threads[i]);
            TEST_CHECK(args[i].errors == 0);
            if (args[i].chunk != NULL &&
                cio_chunk_is_up(args[i].chunk) == CIO_TRUE) {
                ups++;
            }
        }

        TEST_CHECK(ups == 4);
        TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 4);

        for (i = 0; i < 8; i++) {
            if (args[i].chunk) {
                cio_chunk_close(args[i].chunk, CIO_TRUE);
            }
        }
        TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 0);
    }

    cio_destroy(ctx);
}
#endif

/* ------------------------------------------------------------------------- */
/* 10. pool size option is clamped to the supported maximum                   */
/* ------------------------------------------------------------------------- */
static void test_pool_option_clamp()
{
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(100000, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);
    TEST_CHECK(st->pool_size == 4096);

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 11. invalid pool sizes fall back to disabled                               */
/* ------------------------------------------------------------------------- */
static void test_pool_option_invalid()
{
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(-5, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);
    TEST_CHECK(st->pool_size == 0);
    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 12. a single slot still recycles correctly                                 */
/* ------------------------------------------------------------------------- */
static void test_pool_single_slot()
{
    int i;
    int n;
    char name[64];
    char payload[64];
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(1, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);
    TEST_CHECK(st->pool_size == 1);

    for (i = 0; i < 10; i++) {
        snprintf(name, sizeof(name), "one-%04d.flb", i);
        snprintf(payload, sizeof(payload), "one-%d", i);
        n = write_and_close(ctx, st, name, payload, CIO_TRUE);
        TEST_CHECK(n == 0);
        n = count_stream_files(CIO_POOL_NAME);
        TEST_CHECK(n == 1);
    }

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 13. memory streams ignore the option and keep valid pool state             */
/* ------------------------------------------------------------------------- */
static void test_pool_mem_stream_ignores_option()
{
    int err;
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(8, 0);
    TEST_CHECK(ctx != NULL);

    st = cio_stream_create(ctx, "mem-pool-test", CIO_STORE_MEM);
    TEST_CHECK(st != NULL);
    TEST_CHECK(st->pool_size == 0);
    TEST_CHECK(st->pool_busy == NULL);

    err = write_and_close(ctx, st, "mem-chunk.flb", "mem-payload", CIO_TRUE);
    TEST_CHECK(err == 0);

    /* destroy exercises pool_destroy() for the memory stream */
    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 14. delete by logical name resolves the real slot file and frees the slot  */
/* ------------------------------------------------------------------------- */
static void test_pool_delete_by_name()
{
    int err;
    int n;
    struct cio_chunk *chunk;
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(4, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);

    /* keep the chunk loaded, then delete it by its logical name */
    chunk = cio_chunk_open(ctx, st, "by-name.flb", CIO_OPEN, 4096, &err);
    TEST_CHECK(chunk != NULL);
    TEST_CHECK(cio_chunk_write(chunk, "by-name-payload", 15) == CIO_OK);
    TEST_CHECK(cio_chunk_delete(ctx, st, "by-name.flb") == CIO_OK);

    /* exactly one (empty) slot file remains, no stale content */
    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n == 1);

    /* the slot is reusable and the new chunk has no stale data */
    err = write_and_close(ctx, st, "next.flb", "next-payload", CIO_TRUE);
    TEST_CHECK(err == 0);
    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n == 1);

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 14b. up-chunk counter balance: limit, failed maps and failed opens         */
/* ------------------------------------------------------------------------- */
static void test_pool_counter_balance()
{
    int err;
    int fd;
    size_t size;
    char *buf = NULL;
    char path[512];
    struct cio_chunk *a;
    struct cio_chunk *b;
    struct cio_chunk *loaded;
    struct cio_ctx *ctx;
    struct cio_stream *st;
    struct cio_options opts;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(4, 0);
    TEST_CHECK(ctx != NULL);
    cio_set_max_chunks_up(ctx, 1);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);

    /* A is up, B hits the limit and stays down */
    a = cio_chunk_open(ctx, st, "counter-a.flb", CIO_OPEN_RW, 4096, &err);
    TEST_CHECK(a != NULL && cio_chunk_is_up(a) == CIO_TRUE);
    TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 1);

    b = cio_chunk_open(ctx, st, "counter-b.flb", CIO_OPEN_RW, 4096, &err);
    TEST_CHECK(b != NULL && cio_chunk_is_up(b) == CIO_FALSE);
    TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 1);

    /* a read on a down chunk fails and must not touch the counter */
    TEST_CHECK(cio_meta_size(b) == -1);
    TEST_CHECK(cio_chunk_get_content(b, &buf, &size) != CIO_OK);
    TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 1);

    /* the non-enforced up/down pair stays balanced */
    TEST_CHECK(cio_chunk_up_force(b) == CIO_OK);
    TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 2);
    TEST_CHECK(cio_chunk_down(b) == CIO_OK);
    TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 1);

    cio_chunk_close(b, CIO_TRUE);
    cio_chunk_close(a, CIO_TRUE);
    TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 0);

    /* a failed open of a corrupt slot must not consume an up-slot */
    snprintf(path, sizeof(path), "%s%s/slot-000000.flb",
             CIO_POOL_ENV, CIO_POOL_NAME);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    TEST_CHECK(fd != -1);
    if (fd != -1) {
        TEST_CHECK(write(fd, "garbage-payload", 15) == 15);
        close(fd);
    }
    a = cio_chunk_open(ctx, st, "slot-000000.flb", CIO_OPEN_RD, 0, &err);
    TEST_CHECK(a == NULL);
    TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 0);

    cio_destroy(ctx);
    cio_utils_recursive_delete(CIO_POOL_ENV);

    /* pool disabled: delete-by-name keeps stock semantics (chunk untouched) */
    cio_options_init(&opts);
    opts.root_path = CIO_POOL_ENV;
    opts.log_cb = log_cb;
    opts.flags = CIO_CHECKSUM;
    ctx = cio_create(&opts);
    TEST_CHECK(ctx != NULL);
    TEST_CHECK(cio_load(ctx, ".flb") == 0);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);
    cio_set_max_chunks_up(ctx, 8);

    loaded = cio_chunk_open(ctx, st, "loaded.flb", CIO_OPEN_RW, 4096, &err);
    TEST_CHECK(loaded != NULL && cio_chunk_is_up(loaded) == CIO_TRUE);
    TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 1);

    /*
     * Delete-by-name must not close/free a loaded chunk when the pool is
     * disabled (stock semantics); Windows cannot unlink an open file, so only
     * the chunk state is asserted here, not the delete return value.
     */
    cio_chunk_delete(ctx, st, "loaded.flb");
    TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 1);
    TEST_CHECK(mk_list_size(&st->chunks) == 1);
    TEST_CHECK(cio_chunk_is_up(loaded) == CIO_TRUE);

    cio_chunk_close(loaded, CIO_FALSE);
    TEST_CHECK(cio_chunk_counter_total_up_get(ctx) == 0);

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 15. a failed truncate keeps the slot busy (no stale data reuse)            */
/* ------------------------------------------------------------------------- */
#ifndef _WIN32
static void test_pool_truncate_failure_keeps_slot()
{
    int err;
    char path[512];
    struct cio_chunk *chunk;
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    ctx = pool_ctx_create(1, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);

    chunk = cio_chunk_open(ctx, st, "keep-slot.flb", CIO_OPEN, 4096, &err);
    TEST_CHECK(chunk != NULL);
    TEST_CHECK(cio_chunk_write(chunk, "data", 4) == CIO_OK);

    /* replace the slot file with a directory so truncation fails */
    snprintf(path, sizeof(path), "%s%s/slot-000000.flb",
             CIO_POOL_ENV, CIO_POOL_NAME);
    TEST_CHECK(unlink(path) == 0);
    TEST_CHECK(mkdir(path, 0755) == 0);

    /* delete path: truncate fails, so the slot must stay busy */
    cio_chunk_close(chunk, CIO_TRUE);
    TEST_CHECK((st->pool_busy[0] & 0x01) != 0);

    TEST_CHECK(rmdir(path) == 0);
    cio_destroy(ctx);
}
#endif

/* ------------------------------------------------------------------------- */
/* 16. shrinking the pool: stale slots are cleaned, live ones stay usable     */
/* ------------------------------------------------------------------------- */
static void test_pool_shrunk_pool_cleanup()
{
    int i;
    int n;
    int err;
    int fd;
    char name[64];
    char path[512];
    struct stat sb;
    struct mk_list *head;
    struct mk_list *tmp;
    struct cio_chunk *ch;
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    /* phase 1: pool of 8 leaves 8 live slot files behind */
    ctx = pool_ctx_create(8, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);
    for (i = 0; i < 8; i++) {
        snprintf(name, sizeof(name), "live-%d.flb", i);
        err = write_and_close(ctx, st, name, "shrunk-payload", CIO_FALSE);
        TEST_CHECK(err == 0);
    }
    /* plus one empty slot from an even larger pool */
    snprintf(path, sizeof(path), "%s%s/slot-000099.flb",
             CIO_POOL_ENV, CIO_POOL_NAME);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    TEST_CHECK(fd != -1);
    if (fd != -1) {
        close(fd);
    }
    cio_destroy(ctx);
    TEST_CHECK(count_stream_files(CIO_POOL_NAME) == 9);

    /* phase 2: pool shrunk to 2 */
    ctx = pool_ctx_create(2, 0);
    TEST_CHECK(ctx != NULL);
    TEST_CHECK(cio_load(ctx, ".flb") == 0);
    st = cio_stream_get(ctx, CIO_POOL_NAME);
    TEST_CHECK(st != NULL);

    /* the empty out-of-range slot was unlinked during the scan */
    TEST_CHECK(stat(path, &sb) != 0);

    /* delete all recovered chunks: in-range slots stay, others are unlinked */
    mk_list_foreach_safe(head, tmp, &st->chunks) {
        ch = mk_list_entry(head, struct cio_chunk, _head);
        cio_chunk_close(ch, CIO_TRUE);
    }
    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n == 2);

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 17. empty slot left by a crash after truncate is reused                    */
/* ------------------------------------------------------------------------- */
static void test_pool_crash_after_truncate()
{
    int err;
    int n;
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    /* phase 1: a delivered chunk leaves an empty slot file behind */
    ctx = pool_ctx_create(2, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);
    err = write_and_close(ctx, st, "delivered.flb", "delivered", CIO_TRUE);
    TEST_CHECK(err == 0);
    cio_destroy(ctx);
    TEST_CHECK(count_stream_files(CIO_POOL_NAME) == 1);

    /* phase 2: scan must treat it as a free slot and reuse it */
    ctx = pool_ctx_create(2, 0);
    TEST_CHECK(ctx != NULL);
    TEST_CHECK(cio_load(ctx, ".flb") == 0);
    st = cio_stream_get(ctx, CIO_POOL_NAME);
    TEST_CHECK(st != NULL);
    TEST_CHECK(mk_list_size(&st->chunks) == 0);

    err = write_and_close(ctx, st, "reuse.flb", "reuse-payload", CIO_TRUE);
    TEST_CHECK(err == 0);
    n = count_stream_files(CIO_POOL_NAME);
    TEST_CHECK(n == 1);

    cio_destroy(ctx);
}

/* ------------------------------------------------------------------------- */
/* 18. partial chunk from a crash mid-write is discarded, pool stays usable   */
/* ------------------------------------------------------------------------- */
static void test_pool_crash_mid_write()
{
    int err;
    int fd;
    char path[512];
    struct stat sb;
    struct cio_ctx *ctx;
    struct cio_stream *st;

    printf("\n");

    cio_utils_recursive_delete(CIO_POOL_ENV);

    /* phase 1: write a valid chunk with the pool disabled */
    ctx = pool_ctx_create(0, 0);
    TEST_CHECK(ctx != NULL);
    st = cio_stream_create(ctx, CIO_POOL_NAME, CIO_STORE_FS);
    TEST_CHECK(st != NULL);
    err = write_and_close(ctx, st, "partial.flb", "partial-payload", CIO_FALSE);
    TEST_CHECK(err == 0);
    cio_destroy(ctx);

    snprintf(path, sizeof(path), "%s%s/partial.flb",
             CIO_POOL_ENV, CIO_POOL_NAME);
    TEST_CHECK(stat(path, &sb) == 0);
    fd = open(path, O_WRONLY);
    TEST_CHECK(fd != -1);
    if (fd != -1) {
#ifdef _WIN32
        TEST_CHECK(_chsize(fd, 5) == 0);
#else
        TEST_CHECK(ftruncate(fd, 5) == 0);
#endif
        close(fd);
    }

    /* phase 2: the partial chunk is dropped, the stream keeps working */
    ctx = pool_ctx_create(2, CIO_DELETE_IRRECOVERABLE);
    TEST_CHECK(ctx != NULL);
    TEST_CHECK(cio_load(ctx, ".flb") == 0);
    st = cio_stream_get(ctx, CIO_POOL_NAME);
    TEST_CHECK(st != NULL);
    TEST_CHECK(mk_list_size(&st->chunks) == 0);
    TEST_CHECK(stat(path, &sb) != 0);   /* irrecoverable file removed */

    err = write_and_close(ctx, st, "after.flb", "after-payload", CIO_TRUE);
    TEST_CHECK(err == 0);

    cio_destroy(ctx);
}

TEST_LIST = {
    {"pool_slot_name_parse", test_pool_slot_name_parse},
    {"pool_disabled_legacy", test_pool_disabled_legacy},
    {"pool_reuse_bounds_files", test_pool_reuse_bounds_files},
    {"pool_backlog_fallback", test_pool_backlog_fallback},
    {"pool_recovery", test_pool_recovery},
    {"pool_recovery_legacy_name", test_pool_recovery_legacy_name},
    {"pool_corrupt_slot", test_pool_corrupt_slot},
    {"pool_option_clamp", test_pool_option_clamp},
    {"pool_option_invalid", test_pool_option_invalid},
    {"pool_single_slot", test_pool_single_slot},
    {"pool_mem_stream_ignores_option", test_pool_mem_stream_ignores_option},
    {"pool_delete_by_name", test_pool_delete_by_name},
    {"pool_counter_balance", test_pool_counter_balance},
#ifndef _WIN32
    {"pool_truncate_failure_keeps_slot", test_pool_truncate_failure_keeps_slot},
#endif
    {"pool_shrunk_pool_cleanup", test_pool_shrunk_pool_cleanup},
    {"pool_crash_after_truncate", test_pool_crash_after_truncate},
    {"pool_crash_mid_write", test_pool_crash_mid_write},
#ifndef _WIN32
    {"pool_lock_threads", test_pool_lock_threads},
    {"pool_threaded_chunks", test_pool_threaded_chunks},
    {"pool_threaded_max_chunks", test_pool_threaded_max_chunks},
#endif
#ifdef _WIN32
    {"pool_threaded_max_chunks_win", test_pool_threaded_max_chunks_win},
#endif
    { 0 }
};
