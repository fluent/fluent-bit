/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Chunk I/O
 *  =========
 *  Copyright 2018 Eduardo Silva <eduardo@monkey.io>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chunkio/chunkio_compat.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_os.h>
#include <chunkio/cio_log.h>
#include <chunkio/cio_chunk.h>
#include <chunkio/cio_stream.h>
#include <chunkio/cio_utils.h>

#include <monkey/mk_core/mk_list.h>

#ifdef _WIN32
#include <windows.h>
typedef CRITICAL_SECTION cio_pool_lock_t;
#else
#include <pthread.h>
typedef pthread_mutex_t cio_pool_lock_t;
#endif

#define CIO_FILE_POOL_MAX_SLOTS 4096
#define CIO_FILE_POOL_PREFIX    "slot-"

static int pool_lock_create(cio_pool_lock_t **out)
{
    *out = calloc(1, sizeof(cio_pool_lock_t));
    if (!*out) {
        return -1;
    }
#ifdef _WIN32
    InitializeCriticalSection(*out);
#else
    if (pthread_mutex_init(*out, NULL) != 0) {
        free(*out);
        *out = NULL;
        return -1;
    }
#endif
    return 0;
}

static void pool_lock_destroy(cio_pool_lock_t *lock)
{
    if (!lock) {
        return;
    }
#ifdef _WIN32
    DeleteCriticalSection(lock);
#else
    pthread_mutex_destroy(lock);
#endif
    free(lock);
}

static void pool_lock(cio_pool_lock_t *lock)
{
    if (!lock) {
        return;
    }
#ifdef _WIN32
    EnterCriticalSection(lock);
#else
    pthread_mutex_lock(lock);
#endif
}

static void pool_unlock(cio_pool_lock_t *lock)
{
    if (!lock) {
        return;
    }
#ifdef _WIN32
    LeaveCriticalSection(lock);
#else
    pthread_mutex_unlock(lock);
#endif
}

static int pool_option_size(struct cio_ctx *ctx)
{
    long val;

    if (!ctx) {
        return 0;
    }

    val = ctx->options.file_pool_size;
    if (val <= 0) {
        return 0;
    }
    if (val > CIO_FILE_POOL_MAX_SLOTS) {
        val = CIO_FILE_POOL_MAX_SLOTS;
    }

    return (int) val;
}

static void pool_init(struct cio_stream *st)
{
    cio_pool_lock_t *lock;
    int size;

    st->pool_size = 0;
    st->pool_busy = NULL;
    st->pool_warned = 0;
    st->pool_lock = NULL;

    size = pool_option_size((struct cio_ctx *) st->parent);
    if (size <= 0) {
        return;
    }

    st->pool_busy = calloc(1, (size + 7) / 8);
    if (!st->pool_busy) {
        cio_log_error((struct cio_ctx *) st->parent,
                      "[cio stream] could not allocate file pool bitmap");
        return;
    }

    if (pool_lock_create(&lock) != 0) {
        free(st->pool_busy);
        st->pool_busy = NULL;
        cio_log_error((struct cio_ctx *) st->parent,
                      "[cio stream] could not allocate file pool lock");
        return;
    }

    st->pool_lock = lock;
    st->pool_size = size;
}

static void pool_destroy(struct cio_stream *st)
{
    if (!st) {
        return;
    }
    if (st->pool_busy) {
        free(st->pool_busy);
        st->pool_busy = NULL;
    }
    if (st->pool_lock) {
        pool_lock_destroy((cio_pool_lock_t *) st->pool_lock);
        st->pool_lock = NULL;
    }
    st->pool_size = 0;
}

int cio_stream_pool_acquire(struct cio_stream *st)
{
    int i;
    int byte;
    int bit;

    if (!st || st->pool_size <= 0 || !st->pool_busy) {
        return -1;
    }

    pool_lock((cio_pool_lock_t *) st->pool_lock);
    for (i = 0; i < st->pool_size; i++) {
        byte = i / 8;
        bit = i % 8;
        if (!(st->pool_busy[byte] & (1 << bit))) {
            st->pool_busy[byte] |= (1 << bit);
            pool_unlock((cio_pool_lock_t *) st->pool_lock);
            return i;
        }
    }
    pool_unlock((cio_pool_lock_t *) st->pool_lock);

    return -1;
}

void cio_stream_pool_release(struct cio_stream *st, int slot)
{
    int byte;
    int bit;

    if (!st || slot < 0 || slot >= st->pool_size || !st->pool_busy) {
        return;
    }

    byte = slot / 8;
    bit = slot % 8;
    pool_lock((cio_pool_lock_t *) st->pool_lock);
    st->pool_busy[byte] &= (unsigned char) ~(1 << bit);
    pool_unlock((cio_pool_lock_t *) st->pool_lock);
}

void cio_stream_pool_mark_busy(struct cio_stream *st, int slot)
{
    int byte;
    int bit;

    if (!st || slot < 0 || slot >= st->pool_size || !st->pool_busy) {
        return;
    }

    byte = slot / 8;
    bit = slot % 8;
    pool_lock((cio_pool_lock_t *) st->pool_lock);
    st->pool_busy[byte] |= (1 << bit);
    pool_unlock((cio_pool_lock_t *) st->pool_lock);
}

int cio_stream_pool_slot_from_name(const char *name)
{
    int i;
    int slot;
    const char *p;
    size_t prefix_len;

    if (!name) {
        return -1;
    }

    prefix_len = strlen(CIO_FILE_POOL_PREFIX);
    if (strncmp(name, CIO_FILE_POOL_PREFIX, prefix_len) != 0) {
        return -1;
    }

    /*
     * Only the canonical form is a slot: slot-<6 digits>.flb
     * (reject slot-5.flb, slot-000005.flb.orig, etc.).
     */
    p = name + prefix_len;
    for (i = 0; i < 6; i++) {
        if (p[i] < '0' || p[i] > '9') {
            return -1;
        }
    }
    if (strcmp(p + 6, ".flb") != 0) {
        return -1;
    }

    slot = 0;
    for (i = 0; i < 6; i++) {
        slot = slot * 10 + (p[i] - '0');
    }

    return slot;
}

void cio_stream_pool_slot_name(int slot, char *buf, size_t len)
{
    if (!buf || len == 0) {
        return;
    }
    if (slot < 0 || slot > 999999) {
        buf[0] = '\0';
        return;
    }
    snprintf(buf, len, CIO_FILE_POOL_PREFIX "%06d.flb", slot);
}

int cio_stream_pool_slot_valid(struct cio_stream *st, int slot)
{
    if (!st || slot < 0 || slot >= st->pool_size) {
        return CIO_FALSE;
    }

    return CIO_TRUE;
}

int cio_stream_pool_exhausted_warned(struct cio_stream *st)
{
    int warned;

    if (!st) {
        return 1;
    }
    pool_lock((cio_pool_lock_t *) st->pool_lock);
    warned = st->pool_warned;
    st->pool_warned = 1;
    pool_unlock((cio_pool_lock_t *) st->pool_lock);

    return warned;
}

static char *get_stream_path(struct cio_ctx *ctx, struct cio_stream *st)
{
    int ret;
    int len;
    char *p;

    /* Compose final path */
    len = strlen(ctx->options.root_path) + strlen(st->name) + 2;
    p = malloc(len + 1);
    if (!p) {
        cio_errno();
        return NULL;
    }

    ret = snprintf(p, len, "%s/%s", ctx->options.root_path, st->name);
    if (ret == -1) {
        cio_errno();
        free(p);
        return NULL;
    }

    return p;
}

static int check_stream_path(struct cio_ctx *ctx, const char *path)
{
    int ret;
    int len;
    char *p;

    /* Compose final path */
    len = strlen(ctx->options.root_path) + strlen(path) + 2;
    p = malloc(len + 1);
    if (!p) {
        cio_errno();
        return -1;
    }
    ret = snprintf(p, len, "%s/%s", ctx->options.root_path, path);
    if (ret == -1) {
        cio_errno();
        free(p);
        return -1;
    }

    ret = cio_os_isdir(p);
    if (ret == -1) {
        /* Try to create the path */
        ret = cio_os_mkpath(p, 0755);
        if (ret == -1) {
            cio_log_error(ctx, "cannot create stream path %s", p);
            free(p);
            return -1;
        }
        cio_log_debug(ctx, "created stream path %s", p);
        free(p);
        return 0;
    }

    /* Check write access and release*/
    ret = access(p, W_OK);
    free(p);
    return ret;
}

struct cio_stream *cio_stream_get(struct cio_ctx *ctx, const char *name)
{
    struct mk_list *head;
    struct cio_stream *st;

    mk_list_foreach(head, &ctx->streams) {
        st = mk_list_entry(head, struct cio_stream, _head);
        if (strcmp(st->name, name) == 0) {
            return st;
        }
    }

    return NULL;
}

struct cio_stream *cio_stream_create(struct cio_ctx *ctx, const char *name,
                                     int type)
{
    int ret;
    int len;
    struct cio_stream *st;

    if (!name) {
        cio_log_error(ctx, "[stream create] stream name not set");
        return NULL;
    }

    len = strlen(name);
    if (len == 0) {
        cio_log_error(ctx, "[stream create] invalid stream name");
        return NULL;
    }

    if (len == 1 && (name[0] == '.' || name[0] == '/')) {
        cio_log_error(ctx, "[stream create] invalid stream name");
        return NULL;
    }
#ifndef CIO_HAVE_BACKEND_FILESYSTEM
    if (type == CIO_STORE_FS) {
        cio_log_error(ctx, "[stream create] file system backend not supported");
        return NULL;
    }
#endif

    /* Find duplicated */
    st = cio_stream_get(ctx, name);
    if (st) {
        cio_log_error(ctx, "[cio stream] stream already registered: %s", name);
        return NULL;
    }

    /* If backend is the file system, validate the stream path */
    if (type == CIO_STORE_FS) {
        ret = check_stream_path(ctx, name);
        if (ret == -1) {
            return NULL;
        }
    }

    st = malloc(sizeof(struct cio_stream));
    if (!st) {
        cio_errno();
        return NULL;
    }
    st->type = type;
    st->name = strdup(name);
    if (!st->name) {
        cio_errno();
        free(st);
        return NULL;
    }

    st->parent = ctx;
    mk_list_init(&st->chunks);
    mk_list_init(&st->chunks_up);
    mk_list_init(&st->chunks_down);
    mk_list_add(&st->_head, &ctx->streams);

    /* pool state must be valid for every stream type (destroy frees it) */
    st->pool_size = 0;
    st->pool_busy = NULL;
    st->pool_warned = 0;
    st->pool_lock = NULL;
    st->scanning = CIO_FALSE;

    if (type == CIO_STORE_FS) {
        pool_init(st);
    }

    cio_log_debug(ctx, "[cio stream] new stream registered: %s", name);
    return st;
}

void cio_stream_destroy(struct cio_stream *st)
{
    if (!st) {
        return;
    }
    /* close all files */
    cio_chunk_close_stream(st);

    pool_destroy(st);

    /* destroy stream */
    mk_list_del(&st->_head);
    free(st->name);
    free(st);
}

/* Deletes a complete stream, this include all chunks available */
int cio_stream_delete(struct cio_stream *st)
{
    int ret;
    char *path;
    struct mk_list *tmp;
    struct mk_list *head;
    struct cio_chunk *ch;
    struct cio_ctx *ctx;

    ctx = st->parent;

    /* delete all chunks */
    mk_list_foreach_safe(head, tmp, &st->chunks) {
        ch = mk_list_entry(head, struct cio_chunk, _head);
        cio_chunk_close(ch, CIO_TRUE);
    }

    /* the stream directory is wiped below: all slots become free */
    if (st->pool_busy) {
        memset(st->pool_busy, 0, (st->pool_size + 7) / 8);
    }

#ifdef CIO_HAVE_BACKEND_FILESYSTEM
    /* If the stream is filesystem based, destroy the real directory */
    if (st->type == CIO_STORE_FS) {
        path = get_stream_path(ctx, st);
        if (!path) {
            cio_log_error(ctx,
                          "content from stream '%s' has been deleted, but the "
                          "directory might still exists.", path);
            return -1;
        }

        cio_log_debug(ctx, "[cio stream] delete stream path: %s", path);

        /* Recursive deletion */
        ret = cio_utils_recursive_delete(path);
        if (ret == -1) {
            cio_log_error(ctx, "error in recursive deletion of path %s", path);
            free(path);
            return -1;
        }
        free(path);

        return ret;
    }
#endif

    return 0;
}

void cio_stream_destroy_all(struct cio_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct cio_stream *st;

    if (!ctx) {
        return;
    }

    mk_list_foreach_safe(head, tmp, &ctx->streams) {
        st = mk_list_entry(head, struct cio_stream, _head);
        cio_stream_destroy(st);
    }
}

/* Return the total number of bytes being used by Chunks up in memory */
size_t cio_stream_size_chunks_up(struct cio_stream *st)
{
    ssize_t bytes;
    size_t total = 0;
    struct cio_chunk *ch;
    struct mk_list *head;

    mk_list_foreach(head, &st->chunks_up) {
        ch = mk_list_entry(head, struct cio_chunk, _state_head);

        bytes = cio_chunk_get_content_size(ch);
        if (bytes <= 0) {
            continue;
        }
        total += bytes;
    }

    return total;
}
