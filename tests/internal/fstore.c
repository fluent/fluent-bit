/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
#include <fluent-bit/flb_fstore.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_compat.h>

#include <chunkio/chunkio.h>
#include <chunkio/cio_utils.h>

#include "flb_tests_internal.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef FLB_SYSTEM_WINDOWS
/* Not yet implemented! */
#else
#define FSF_STORE_PATH "/tmp/flb-fstore"
#endif

void cb_all()
{
    int ret;
    void *out_buf;
    size_t out_size;
    struct stat st_data;
    struct flb_fstore *fs;
    struct flb_fstore_stream *st;
    struct flb_fstore_file *fsf;

    cio_utils_recursive_delete(FSF_STORE_PATH);

    fs = flb_fstore_create(FSF_STORE_PATH, FLB_FSTORE_FS);
    TEST_CHECK(fs != NULL);

    st = flb_fstore_stream_create(fs, "abc");
    TEST_CHECK(st != NULL);

    fsf = flb_fstore_file_create(fs, st, "example.txt", 100);
    TEST_CHECK(fsf != NULL);
    if (!fsf) {
        return;
    }

    ret = stat(FSF_STORE_PATH "/abc/example.txt", &st_data);
    TEST_CHECK(ret == 0);

    ret = flb_fstore_file_append(fsf, "fluent-bit\n", 11);
    TEST_CHECK(ret == 0);

    ret = flb_fstore_file_content_copy(fs, fsf, &out_buf, &out_size);
    TEST_CHECK(ret == 0);

    TEST_CHECK(memcmp(out_buf, "fluent-bit\n", 11) == 0);
    TEST_CHECK(out_size == 11);
    flb_free(out_buf);

    flb_fstore_dump(fs);
    flb_fstore_destroy(fs);
}

void cb_delete_after_external_close()
{
    int ret;
    struct stat st_data;
    struct flb_fstore *fs;
    struct flb_fstore_stream *st;
    struct flb_fstore_file *fsf;
    struct cio_chunk *chunk;

    cio_utils_recursive_delete(FSF_STORE_PATH);

    fs = flb_fstore_create(FSF_STORE_PATH, FLB_FSTORE_FS);
    TEST_CHECK(fs != NULL);
    if (!fs) {
        return;
    }

    st = flb_fstore_stream_create(fs, "abc");
    TEST_CHECK(st != NULL);
    if (!st) {
        flb_fstore_destroy(fs);
        return;
    }

    fsf = flb_fstore_file_create(fs, st, "example.txt", 100);
    TEST_CHECK(fsf != NULL);
    if (!fsf) {
        flb_fstore_destroy(fs);
        return;
    }

    chunk = fsf->chunk;
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        flb_fstore_destroy(fs);
        return;
    }

    cio_chunk_close(chunk, CIO_TRUE);

    ret = stat(FSF_STORE_PATH "/abc/example.txt", &st_data);
    TEST_CHECK(ret == -1 && errno == ENOENT);

    ret = flb_fstore_file_delete(fs, fsf);
    TEST_CHECK(ret == 0);

    flb_fstore_destroy(fs);
}

static const char retained_metadata[] = "buffered.logs";
static const char retained_payload[] = "record retained until delivery\n";

static struct flb_fstore *create_store(char *path, int type)
{
    struct flb_fstore *fs;

    TEST_ASSERT(mkdtemp(path) != NULL);
    fs = flb_fstore_create(path, type);
    TEST_ASSERT(fs != NULL);
    return fs;
}

static struct flb_fstore_file *create_file(struct flb_fstore *fs,
                                         struct flb_fstore_stream *stream,
                                         char *name)
{
    struct flb_fstore_file *file;

    file = flb_fstore_file_create(fs, stream, name, sizeof(retained_payload) - 1);
    TEST_ASSERT(file != NULL);
    TEST_ASSERT(flb_fstore_file_meta_set(fs, file, (void *) retained_metadata,
                                      sizeof(retained_metadata) - 1) == 0);
    TEST_ASSERT(flb_fstore_file_append(file, (void *) retained_payload,
                                    sizeof(retained_payload) - 1) == 0);
    return file;
}

static void check_file(struct flb_fstore *fs, struct flb_fstore_stream *stream,
                       char *name)
{
    int ret;
    void *data = NULL;
    size_t size;
    struct flb_fstore_file *file;

    file = flb_fstore_file_get(fs, stream, name, strlen(name));
    if (!TEST_CHECK(file != NULL)) {
        return;
    }

    TEST_CHECK(file->meta_size == sizeof(retained_metadata) - 1 &&
               file->meta_buf != NULL &&
               memcmp(file->meta_buf, retained_metadata,
                      sizeof(retained_metadata) - 1) == 0);

    ret = flb_fstore_file_content_copy(fs, file, &data, &size);
    if (TEST_CHECK(ret == 0)) {
        TEST_CHECK(size == sizeof(retained_payload) - 1 &&
                   memcmp(data, retained_payload, sizeof(retained_payload) - 1) == 0);
        flb_free(data);
    }
}

static void check_shutdown_retention(int inactive, int delete_acknowledged)
{
    int ret;
    char path[] = "/tmp/flb-fstore-retention-XXXXXX";
    char acknowledged_path[sizeof(path) + sizeof("/records/acknowledged")];
    struct stat file_stat;
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream;
    struct flb_fstore_file *file;

    fs = create_store(path, FLB_FSTORE_FS);
    stream = flb_fstore_stream_create(fs, "records");
    TEST_ASSERT(stream != NULL);
    file = create_file(fs, stream, "retained");
    if (inactive) {
        TEST_ASSERT(flb_fstore_file_inactive(fs, file) == 0);
    }

    if (delete_acknowledged) {
        file = create_file(fs, stream, "acknowledged");
        TEST_ASSERT(flb_fstore_file_delete(fs, file) == 0);
        snprintf(acknowledged_path, sizeof(acknowledged_path),
                 "%s/records/acknowledged", path);
        ret = stat(acknowledged_path, &file_stat);
        TEST_CHECK(ret == -1 && errno == ENOENT);
    }

    TEST_CHECK(flb_fstore_destroy(fs) == 0);

    fs = flb_fstore_create(path, FLB_FSTORE_FS);
    TEST_ASSERT(fs != NULL);
    stream = flb_fstore_stream_create(fs, "records");
    TEST_ASSERT(stream != NULL);
    check_file(fs, stream, "retained");
    if (delete_acknowledged) {
        TEST_CHECK(flb_fstore_file_get(fs, stream, "acknowledged", 12) == NULL);
        ret = stat(acknowledged_path, &file_stat);
        TEST_CHECK(ret == -1 && errno == ENOENT);
    }

    TEST_CHECK(flb_fstore_destroy(fs) == 0);
    TEST_CHECK(cio_utils_recursive_delete(path) == 0);
}

void cb_destroy_active_file()
{
    check_shutdown_retention(FLB_FALSE, FLB_FALSE);
}

void cb_destroy_inactive_file()
{
    check_shutdown_retention(FLB_TRUE, FLB_FALSE);
}

void cb_destroy_after_acknowledged_file_delete()
{
    check_shutdown_retention(FLB_TRUE, FLB_TRUE);
}

void cb_destroy_empty_stream()
{
    int ret;
    char path[] = "/tmp/flb-fstore-empty-XXXXXX";
    char stream_path[sizeof(path) + sizeof("/records")];
    struct stat stream_stat;
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream;

    fs = create_store(path, FLB_FSTORE_FS);
    stream = flb_fstore_stream_create(fs, "records");
    TEST_ASSERT(stream != NULL);
    snprintf(stream_path, sizeof(stream_path), "%s/records", path);
    TEST_CHECK(stat(stream_path, &stream_stat) == 0);

    TEST_CHECK(flb_fstore_destroy(fs) == 0);
    ret = stat(stream_path, &stream_stat);
    TEST_CHECK(ret == -1 && errno == ENOENT);
    TEST_CHECK(cio_utils_recursive_delete(path) == 0);
}

static void write_unreferenced_file(char *path)
{
    FILE *file;

    file = fopen(path, "wb");
    TEST_ASSERT(file != NULL);
    TEST_CHECK(fwrite(retained_payload, 1, sizeof(retained_payload), file) ==
               sizeof(retained_payload));
    TEST_CHECK(fclose(file) == 0);
}

static void check_unreferenced_file(char *path)
{
    size_t size;
    char data[sizeof(retained_payload)];
    FILE *file;

    file = fopen(path, "rb");
    if (!TEST_CHECK(file != NULL)) {
        return;
    }
    size = fread(data, 1, sizeof(data), file);
    TEST_CHECK(size == sizeof(retained_payload) &&
               memcmp(data, retained_payload, sizeof(retained_payload)) == 0);
    TEST_CHECK(fgetc(file) == EOF && !ferror(file));
    TEST_CHECK(fclose(file) == 0);
}

void cb_destroy_unreferenced_files()
{
    char path[] = "/tmp/flb-fstore-unreferenced-XXXXXX";
    char nested_path[sizeof(path) + sizeof("/records/nested")];
    char direct_file[sizeof(path) + sizeof("/records/unreferenced")];
    char nested_file[sizeof(path) + sizeof("/records/nested/unreferenced")];
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream;

    fs = create_store(path, FLB_FSTORE_FS);
    stream = flb_fstore_stream_create(fs, "records");
    TEST_ASSERT(stream != NULL);
    snprintf(nested_path, sizeof(nested_path), "%s/records/nested", path);
    TEST_ASSERT(mkdir(nested_path, 0700) == 0);
    snprintf(direct_file, sizeof(direct_file), "%s/records/unreferenced", path);
    snprintf(nested_file, sizeof(nested_file), "%s/records/nested/unreferenced", path);
    write_unreferenced_file(direct_file);
    write_unreferenced_file(nested_file);

    TEST_CHECK(flb_fstore_destroy(fs) == 0);
    check_unreferenced_file(direct_file);
    check_unreferenced_file(nested_file);
    TEST_CHECK(cio_utils_recursive_delete(path) == 0);
}

void cb_destroy_memory_stream()
{
    char path[] = "/tmp/flb-fstore-memory-XXXXXX";
    char stream_path[sizeof(path) + sizeof("/records")];
    struct stat stream_stat;
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream;

    fs = create_store(path, FLB_FSTORE_MEM);
    stream = flb_fstore_stream_create(fs, "records");
    TEST_ASSERT(stream != NULL);
    create_file(fs, stream, "retained");
    check_file(fs, stream, "retained");

    /* This directory is not owned by the memory-backed stream. */
    snprintf(stream_path, sizeof(stream_path), "%s/records", path);
    TEST_ASSERT(mkdir(stream_path, 0700) == 0);
    TEST_CHECK(flb_fstore_destroy(fs) == 0);
    TEST_CHECK(stat(stream_path, &stream_stat) == 0);
    TEST_CHECK(cio_utils_recursive_delete(path) == 0);
}

TEST_LIST = {
    { "all" , cb_all},
    { "delete_after_external_close", cb_delete_after_external_close},
    { "destroy_active_file", cb_destroy_active_file},
    { "destroy_inactive_file", cb_destroy_inactive_file},
    { "destroy_after_acknowledged_file_delete",
      cb_destroy_after_acknowledged_file_delete},
    { "destroy_empty_stream", cb_destroy_empty_stream},
    { "destroy_unreferenced_files", cb_destroy_unreferenced_files},
    { "destroy_memory_stream", cb_destroy_memory_stream},
    { NULL }
};
