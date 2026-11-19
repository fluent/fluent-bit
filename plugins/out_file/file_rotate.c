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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_lock.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_random.h>
#include <fluent-bit/flb_sds.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifdef FLB_SYSTEM_WINDOWS
#include <shlwapi.h>
#include <windows.h>
#else
#include <dirent.h>
#include <libgen.h>
#include <unistd.h>
#endif

#include "file_rotate.h"

/*
 * Fluent Bit has no core path separator macro; upstream's file.c defines its
 * own the same way. Each translation unit needs its own copy, and adding a
 * shared one would mean modifying file.h and file.c, which this patch keeps
 * untouched.
 */
#ifdef FLB_SYSTEM_WINDOWS
#define FLB_PATH_SEPARATOR "\\"
#else
#define FLB_PATH_SEPARATOR "/"
#endif

#define FILE_ROTATE_GZIP_CHUNK_SIZE  (4 * 1024 * 1024)
#define FILE_ROTATE_INDEX_BUCKETS    128
#define FILE_ROTATE_SUFFIX_SIZE      32

struct file_rotate_entry {
    flb_sds_t path;
    size_t size;
    int seeded;
    flb_lock_t lock;
    struct file_rotate_ctx *rot;
    struct mk_list _head;
};

struct file_rotate_ctx {
    struct flb_output_instance *ins;
    int enabled;
    size_t max_size;
    int max_files;
    int gzip;
    struct mk_list entries;
    struct flb_hash_table *index;
    flb_lock_t index_lock;
};

struct file_rotate_ctx *file_rotate_create(struct flb_output_instance *ins,
                                           int enabled, size_t max_size,
                                           int max_files, int gzip)
{
    struct file_rotate_ctx *rot;

    if (enabled == FLB_TRUE) {
        if (max_size == 0) {
            flb_plg_error(ins, "rotate_max_size must be greater than zero");
            return NULL;
        }
        if (max_files < 1) {
            flb_plg_error(ins, "invalid rotate_max_files=%d; must be >= 1",
                          max_files);
            return NULL;
        }
    }

    rot = flb_calloc(1, sizeof(struct file_rotate_ctx));
    if (rot == NULL) {
        flb_errno();
        return NULL;
    }

    rot->ins = ins;
    rot->enabled = enabled;
    rot->max_size = max_size;
    rot->max_files = max_files;
    rot->gzip = gzip;
    mk_list_init(&rot->entries);

    if (enabled == FLB_FALSE) {
        return rot;
    }

    if (flb_lock_init(&rot->index_lock) != 0) {
        flb_plg_error(ins, "could not initialize rotation index lock");
        flb_free(rot);
        return NULL;
    }

    rot->index = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE,
                                       FILE_ROTATE_INDEX_BUCKETS, 0);
    if (rot->index == NULL) {
        flb_plg_error(ins, "could not create rotation index");
        flb_lock_destroy(&rot->index_lock);
        flb_free(rot);
        return NULL;
    }

    flb_plg_info(ins, "file rotation enabled: rotate_max_size=%zu, "
                 "rotate_max_files=%d, rotate_gzip=%s",
                 max_size, max_files, gzip == FLB_TRUE ? "true" : "false");

    return rot;
}

void file_rotate_destroy(struct file_rotate_ctx *rot)
{
    struct mk_list *head;
    struct mk_list *tmp;
    struct file_rotate_entry *entry;

    if (rot == NULL) {
        return;
    }

    mk_list_foreach_safe(head, tmp, &rot->entries) {
        entry = mk_list_entry(head, struct file_rotate_entry, _head);
        mk_list_del(&entry->_head);
        flb_lock_destroy(&entry->lock);
        flb_sds_destroy(entry->path);
        flb_free(entry);
    }

    if (rot->enabled == FLB_TRUE) {
        flb_hash_table_destroy(rot->index);
        flb_lock_destroy(&rot->index_lock);
    }

    flb_free(rot);
}

/*
 * Build a rotated-file suffix: YYYYMMDD_HHMMSS_xxxxxxxx (8 hex chars from
 * random bytes). Avoids collisions when multiple rotations occur in the same
 * wall-clock second.
 */
static void generate_rotation_suffix(char *suffix, size_t size)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char rnd[4];
    time_t now;
    struct tm tm_info;
    char date_part[16];
    int ok;
    uint32_t v;

    now = time(NULL);
    if (localtime_r(&now, &tm_info) == NULL ||
        strftime(date_part, sizeof(date_part), "%Y%m%d_%H%M%S", &tm_info) == 0) {
        snprintf(date_part, sizeof(date_part), "19700101_000000");
    }

    ok = (flb_random_bytes(rnd, sizeof(rnd)) == 0);
    if (!ok) {
        v = (uint32_t)now ^ (uint32_t)(uintptr_t)suffix;
        rnd[0] = (unsigned char)(v & 0xffU);
        rnd[1] = (unsigned char)((v >> 8) & 0xffU);
        rnd[2] = (unsigned char)((v >> 16) & 0xffU);
        rnd[3] = (unsigned char)((v >> 24) & 0xffU);
    }

    snprintf(suffix, size, "%s_%c%c%c%c%c%c%c%c", date_part,
             hex[(rnd[0] >> 4) & 0xf], hex[rnd[0] & 0xf],
             hex[(rnd[1] >> 4) & 0xf], hex[rnd[1] & 0xf],
             hex[(rnd[2] >> 4) & 0xf], hex[rnd[2] & 0xf],
             hex[(rnd[3] >> 4) & 0xf], hex[rnd[3] & 0xf]);
}

static int rotation_suffix_char_is_hex(unsigned char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

/*
 * Function to validate if a filename matches the rotation pattern format.
 * Valid suffixes after pattern:
 *   - Legacy: YYYYMMDD_HHMMSS (15) or YYYYMMDD_HHMMSS.gz (18)
 *   - Current: YYYYMMDD_HHMMSS_xxxxxxxx (24) or same + .gz (27)
 */
static int is_valid_rotation_filename(const char *filename, const char *pattern)
{
    size_t pattern_len = strlen(pattern);
    size_t filename_len = strlen(filename);
    const char *suffix;
    size_t suffix_len;
    const char *body;
    int i;

    /* Check that filename starts with pattern */
    if (strncmp(filename, pattern, pattern_len) != 0) {
        return 0;
    }

    /* Get the suffix after the pattern */
    suffix = filename + pattern_len;
    suffix_len = filename_len - pattern_len;

    body = suffix;

    if (suffix_len != 15 && suffix_len != 18 && suffix_len != 24 &&
        suffix_len != 27) {
        return 0;
    }

    /* Variants ending in .gz */
    if (suffix_len == 18) {
        if (strcmp(suffix + 15, ".gz") != 0) {
            return 0;
        }
    }
    else if (suffix_len == 27) {
        if (strcmp(suffix + 24, ".gz") != 0) {
            return 0;
        }
    }

    /* Validate timestamp format: YYYYMMDD_HHMMSS (first 15 chars of body) */
    for (i = 0; i < 8; i++) {
        if (body[i] < '0' || body[i] > '9') {
            return 0;
        }
    }
    if (body[8] != '_') {
        return 0;
    }
    for (i = 9; i < 15; i++) {
        if (body[i] < '0' || body[i] > '9') {
            return 0;
        }
    }

    /* New format: extra _ + 8 hex digits after the timestamp */
    if (suffix_len == 24 || suffix_len == 27) {
        if (body[15] != '_') {
            return 0;
        }
        for (i = 16; i < 24; i++) {
            if (!rotation_suffix_char_is_hex((unsigned char)body[i])) {
                return 0;
            }
        }
    }

    return 1;
}

/*
 * Compress 'src_path' into 'dst_path' as gzip. The input is read in fixed
 * chunks and each chunk is emitted as an independent gzip member, which keeps
 * memory bounded regardless of file size. Concatenated members are valid gzip
 * and are decompressed transparently by gzip(1) and by
 * flb_gzip_uncompress_multi().
 */
static int file_rotate_compress(struct file_rotate_ctx *rot,
                                const char *src_path, const char *dst_path)
{
    int ret = -1;
    size_t in_len;
    size_t out_len;
    size_t total_in = 0;
    char *in_buf = NULL;
    void *out_buf = NULL;
    FILE *src = NULL;
    FILE *dst = NULL;

    src = fopen(src_path, "rb");
    if (src == NULL) {
        flb_errno();
        flb_plg_error(rot->ins, "could not open %s for compression", src_path);
        return -1;
    }

    dst = fopen(dst_path, "wb");
    if (dst == NULL) {
        flb_errno();
        flb_plg_error(rot->ins, "could not create %s", dst_path);
        fclose(src);
        return -1;
    }

    in_buf = flb_malloc(FILE_ROTATE_GZIP_CHUNK_SIZE);
    if (in_buf == NULL) {
        flb_errno();
        goto cleanup;
    }

    while ((in_len = fread(in_buf, 1, FILE_ROTATE_GZIP_CHUNK_SIZE, src)) > 0) {
        total_in += in_len;
        if (flb_gzip_compress(in_buf, in_len, &out_buf, &out_len) != 0) {
            flb_plg_error(rot->ins, "compression failed for %s", src_path);
            goto cleanup;
        }
        if (fwrite(out_buf, 1, out_len, dst) != out_len) {
            flb_errno();
            flb_free(out_buf);
            goto cleanup;
        }
        flb_free(out_buf);
    }

    if (ferror(src) != 0) {
        flb_plg_error(rot->ins, "read error on %s", src_path);
        goto cleanup;
    }

    /*
     * An empty source would otherwise produce a zero byte file, which is not
     * valid gzip. Emit a single empty member instead.
     */
    if (total_in == 0) {
        if (flb_gzip_compress(in_buf, 0, &out_buf, &out_len) != 0) {
            goto cleanup;
        }
        if (fwrite(out_buf, 1, out_len, dst) != out_len) {
            flb_errno();
            flb_free(out_buf);
            goto cleanup;
        }
        flb_free(out_buf);
    }

    ret = 0;

cleanup:
    flb_free(in_buf);

    if (dst != NULL) {
        if (fclose(dst) != 0) {
            flb_errno();
            flb_plg_error(rot->ins, "could not close %s", dst_path);
            ret = -1;
        }
    }
    fclose(src);

    if (ret != 0) {
        remove(dst_path);
    }

    return ret;
}

struct file_rotate_candidate {
    flb_sds_t path;
    time_t mtime;
};

static int file_rotate_candidate_cmp(const void *a, const void *b)
{
    const struct file_rotate_candidate *ca = a;
    const struct file_rotate_candidate *cb = b;

    if (ca->mtime < cb->mtime) {
        return -1;
    }
    if (ca->mtime > cb->mtime) {
        return 1;
    }

    return strcmp(ca->path, cb->path);
}

static int file_rotate_candidate_add(struct file_rotate_candidate **list,
                                     int *count, int *capacity,
                                     const char *path)
{
    int new_capacity;
    struct stat st;
    struct file_rotate_candidate *tmp;

    if (stat(path, &st) != 0) {
        /* Vanished between listing and stat; nothing to retain. */
        return 0;
    }

    /* Only regular files are rotation candidates; skip directories etc. */
    if (!S_ISREG(st.st_mode)) {
        return 0;
    }

    if (*count == *capacity) {
        new_capacity = (*capacity == 0) ? 16 : (*capacity * 2);
        tmp = flb_realloc(*list,
                          new_capacity * sizeof(struct file_rotate_candidate));
        if (tmp == NULL) {
            flb_errno();
            return -1;
        }
        *list = tmp;
        *capacity = new_capacity;
    }

    (*list)[*count].path = flb_sds_create(path);
    if ((*list)[*count].path == NULL) {
        flb_errno();
        return -1;
    }

    (*list)[*count].mtime = st.st_mtime;
    (*count)++;

    return 0;
}

/* Keep at most rot->max_files rotated files for 'base_filename'. */
static int file_rotate_trim(struct file_rotate_ctx *rot, const char *directory,
                            const char *base_filename)
{
    int i;
    int ret = 0;
    int count = 0;
    int capacity = 0;
    char pattern[PATH_MAX];
    char full_path[PATH_MAX];
    struct file_rotate_candidate *candidates = NULL;
#ifdef FLB_SYSTEM_WINDOWS
    char search_path[PATH_MAX];
    HANDLE find_handle;
    WIN32_FIND_DATAA find_data;
#else
    DIR *dir;
    struct dirent *entry;
#endif

    snprintf(pattern, sizeof(pattern), "%s.", base_filename);

#ifdef FLB_SYSTEM_WINDOWS
    snprintf(search_path, sizeof(search_path), "%s" FLB_PATH_SEPARATOR "*",
             directory);

    find_handle = FindFirstFileA(search_path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return 0;
    }

    do {
        if (is_valid_rotation_filename(find_data.cFileName, pattern) == 0) {
            continue;
        }
        snprintf(full_path, sizeof(full_path), "%s" FLB_PATH_SEPARATOR "%s",
                 directory, find_data.cFileName);
        if (file_rotate_candidate_add(&candidates, &count, &capacity,
                                      full_path) != 0) {
            ret = -1;
            break;
        }
    } while (FindNextFileA(find_handle, &find_data) != 0);

    FindClose(find_handle);
#else
    dir = opendir(directory);
    if (dir == NULL) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (is_valid_rotation_filename(entry->d_name, pattern) == 0) {
            continue;
        }
        snprintf(full_path, sizeof(full_path), "%s" FLB_PATH_SEPARATOR "%s",
                 directory, entry->d_name);
        if (file_rotate_candidate_add(&candidates, &count, &capacity,
                                      full_path) != 0) {
            ret = -1;
            break;
        }
    }

    closedir(dir);
#endif

    if (ret != 0 || count <= rot->max_files) {
        goto cleanup;
    }

    qsort(candidates, count, sizeof(struct file_rotate_candidate),
          file_rotate_candidate_cmp);

    flb_plg_info(rot->ins,
                 "cleaning up old rotated files: removing %d files "
                 "(keeping %d)", count - rot->max_files, rot->max_files);

    for (i = 0; i < count - rot->max_files; i++) {
#ifdef FLB_SYSTEM_WINDOWS
        if (DeleteFileA(candidates[i].path) != 0) {
#else
        if (unlink(candidates[i].path) == 0) {
#endif
            flb_plg_debug(rot->ins, "removed old rotated file: %s",
                          candidates[i].path);
        }
        else {
            flb_plg_warn(rot->ins, "could not remove old rotated file: %s",
                         candidates[i].path);
        }
    }

cleanup:
    for (i = 0; i < count; i++) {
        flb_sds_destroy(candidates[i].path);
    }
    flb_free(candidates);

    return ret;
}

/*
 * Rotate the file tracked by 'entry'. Called with the entry lock held. A
 * failure here is never fatal: the caller keeps writing to the existing file
 * and the attempt repeats on the next flush.
 */
static void file_rotate_do(struct file_rotate_entry *entry)
{
    int ret;
    char suffix[FILE_ROTATE_SUFFIX_SIZE];
    char *rotated = NULL;
    char *compressed = NULL;
    char *directory = NULL;
    char *base = NULL;
    char *path_copy = NULL;
    char *last_sep;
    size_t len;
    struct file_rotate_ctx *rot = entry->rot;

    generate_rotation_suffix(suffix, sizeof(suffix));

    len = flb_sds_len(entry->path) + sizeof(suffix) + 8;
    rotated = flb_malloc(len);
    if (rotated == NULL) {
        flb_errno();
        return;
    }

    snprintf(rotated, len, "%s.%s", entry->path, suffix);

#ifdef FLB_SYSTEM_WINDOWS
    if (MoveFileExA(entry->path, rotated, MOVEFILE_REPLACE_EXISTING) == 0) {
        flb_plg_warn(rot->ins, "could not rotate %s", entry->path);
        flb_free(rotated);
        return;
    }
#else
    if (rename(entry->path, rotated) != 0) {
        flb_errno();
        flb_plg_warn(rot->ins, "could not rotate %s", entry->path);
        flb_free(rotated);
        return;
    }
#endif

    flb_plg_info(rot->ins, "rotated %s to %s", entry->path, rotated);
    entry->size = 0;

    if (rot->gzip == FLB_TRUE) {
        compressed = flb_malloc(len + 4);
        if (compressed != NULL) {
            snprintf(compressed, len + 4, "%s.gz", rotated);
            ret = file_rotate_compress(rot, rotated, compressed);
            if (ret == 0) {
                remove(rotated);
            }
            else {
                flb_plg_warn(rot->ins,
                             "keeping uncompressed rotated file %s", rotated);
            }
            flb_free(compressed);
        }
        else {
            flb_errno();
            flb_plg_warn(rot->ins,
                         "keeping uncompressed rotated file %s", rotated);
        }
    }

    path_copy = flb_strdup(entry->path);
    if (path_copy == NULL) {
        flb_errno();
        flb_free(rotated);
        return;
    }

    directory = flb_malloc(PATH_MAX);
    base = flb_malloc(PATH_MAX);
    if (directory == NULL || base == NULL) {
        flb_errno();
        flb_free(directory);
        flb_free(base);
        flb_free(path_copy);
        flb_free(rotated);
        return;
    }

#ifdef FLB_SYSTEM_WINDOWS
    PathRemoveFileSpecA(path_copy);
    snprintf(directory, PATH_MAX, "%s", path_copy);
#else
    snprintf(directory, PATH_MAX, "%s", dirname(path_copy));
#endif

    last_sep = strrchr(entry->path, FLB_PATH_SEPARATOR[0]);
    if (last_sep != NULL) {
        snprintf(base, PATH_MAX, "%s", last_sep + 1);
    }
    else {
        snprintf(base, PATH_MAX, "%s", entry->path);
    }

    /*
     * A trim failure is non-fatal: retention just is not enforced this
     * round and the attempt is retried on the next rotation.
     */
    file_rotate_trim(rot, directory, base);

    flb_free(base);
    flb_free(directory);
    flb_free(path_copy);
    flb_free(rotated);
}

/* Caller must hold rot->index_lock. */
static struct file_rotate_entry *file_rotate_entry_create(
    struct file_rotate_ctx *rot, const char *path)
{
    int ret;
    struct file_rotate_entry *entry;

    entry = flb_calloc(1, sizeof(struct file_rotate_entry));
    if (entry == NULL) {
        flb_errno();
        return NULL;
    }

    entry->path = flb_sds_create(path);
    if (entry->path == NULL) {
        flb_errno();
        flb_free(entry);
        return NULL;
    }

    if (flb_lock_init(&entry->lock) != 0) {
        flb_plg_error(rot->ins, "could not initialize lock for %s", path);
        flb_sds_destroy(entry->path);
        flb_free(entry);
        return NULL;
    }

    entry->rot = rot;

    ret = flb_hash_table_add(rot->index, path, strlen(path), entry, 0);
    if (ret < 0) {
        flb_lock_destroy(&entry->lock);
        flb_sds_destroy(entry->path);
        flb_free(entry);
        return NULL;
    }

    mk_list_add(&entry->_head, &rot->entries);

    return entry;
}

int file_rotate_acquire(struct file_rotate_ctx *rot, const char *path,
                        struct file_rotate_entry **entry)
{
    struct file_rotate_entry *tmp;
    struct stat st;

    *entry = NULL;

    if (rot == NULL || rot->enabled == FLB_FALSE) {
        return 0;
    }

    if (flb_lock_acquire(&rot->index_lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                         FLB_LOCK_DEFAULT_RETRY_DELAY) != 0) {
        flb_plg_error(rot->ins, "could not acquire rotation index lock");
        return -1;
    }

    tmp = (struct file_rotate_entry *)
          flb_hash_table_get_ptr(rot->index, path, strlen(path));
    if (tmp == NULL) {
        tmp = file_rotate_entry_create(rot, path);
        if (tmp == NULL) {
            flb_lock_release(&rot->index_lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                             FLB_LOCK_DEFAULT_RETRY_DELAY);
            return -1;
        }
    }

    if (flb_lock_acquire(&tmp->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                         FLB_LOCK_DEFAULT_RETRY_DELAY) != 0) {
        flb_plg_error(rot->ins, "could not acquire rotation lock for %s", path);
        flb_lock_release(&rot->index_lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                         FLB_LOCK_DEFAULT_RETRY_DELAY);
        return -1;
    }

    flb_lock_release(&rot->index_lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                     FLB_LOCK_DEFAULT_RETRY_DELAY);

    /*
     * Seed the size from disk the first time this destination is seen so a
     * file that was already oversized at startup rotates immediately.
     */
    if (tmp->seeded == FLB_FALSE) {
        tmp->seeded = FLB_TRUE;
        if (stat(path, &st) == 0) {
            tmp->size = (size_t) st.st_size;
        }
    }

    if (tmp->size >= rot->max_size) {
        file_rotate_do(tmp);
    }

    *entry = tmp;

    return 0;
}

void file_rotate_update(struct file_rotate_entry *entry, FILE *fp)
{
    struct stat st;

    if (entry == NULL) {
        return;
    }

    if (fp != NULL && fflush(fp) != 0) {
        flb_errno();
        flb_plg_warn(entry->rot->ins, "could not flush %s", entry->path);
        return;
    }

    if (stat(entry->path, &st) == 0) {
        entry->size = (size_t) st.st_size;
    }
}

void file_rotate_release(struct file_rotate_entry *entry)
{
    if (entry == NULL) {
        return;
    }

    flb_lock_release(&entry->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                     FLB_LOCK_DEFAULT_RETRY_DELAY);
}
