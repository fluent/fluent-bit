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

    ret = flb_fstore_file_append(fs, fsf, "fluent-bit\n", 11);
    TEST_CHECK(ret == 0);

    ret = flb_fstore_file_content_copy(fs, fsf, &out_buf, &out_size);
    TEST_CHECK(ret == 0);

    TEST_CHECK(memcmp(out_buf, "fluent-bit\n", 11) == 0);
    TEST_CHECK(out_size == 11);
    flb_free(out_buf);

    flb_fstore_dump(fs);
    flb_fstore_destroy(fs);
}

void test_add_n_files(const int n_files)
{
    int ret;
    void *out_buf;
    size_t out_size;
    char filepath[1000];
    char filename[1000];
    struct stat st_data;
    struct flb_fstore *fs;
    struct flb_fstore_stream *st;
    int i;

    cio_utils_recursive_delete(FSF_STORE_PATH);

    fs = flb_fstore_create(FSF_STORE_PATH, FLB_FSTORE_FS);
    TEST_CHECK(fs != NULL);

    st = flb_fstore_stream_create(fs, "abc");
    TEST_CHECK(st != NULL);

    /* first pass, write files */
    struct flb_fstore_file *files[n_files];
    for (i = 0; i < n_files; ++i) {
        sprintf(filepath, FSF_STORE_PATH "/abc/file-%d.txt", i);
        sprintf(filename, "file-%d.txt", i);

        files[i] = flb_fstore_file_create(fs, st, filename, 100);
        TEST_CHECK(files[i] != NULL);
        if (!files[i]) {
            return;
        }

        ret = stat(filepath, &st_data);
        TEST_CHECK(ret == 0);

        ret = flb_fstore_file_append(fs, files[i], "fluent-bit\n", 11);
        TEST_CHECK(ret == 0);

        ret = flb_fstore_file_content_copy(fs, files[i], &out_buf, &out_size);
        TEST_CHECK(ret == 0);

        TEST_CHECK(memcmp(out_buf, "fluent-bit\n", 11) == 0);
        TEST_CHECK(out_size == 11);
        flb_free(out_buf);
    }

    /* second pass, ref files, ensure cache is working */
    for (i = 0; i < n_files; ++i) {
        flb_fstore_file_append(fs, files[i], "fluent-bit-2\n", 13);

        ret = flb_fstore_file_content_copy(fs, files[i], &out_buf, &out_size);
        TEST_CHECK(ret == 0);

        TEST_CHECK(memcmp(out_buf, "fluent-bit\nfluent-bit-2\n", 11+13) == 0);
        TEST_CHECK(out_size == 11+13);
        flb_free(out_buf);
    }

    /* third pass, no append just content check */
    for (i = 0; i < n_files; ++i) {
        ret = flb_fstore_file_content_copy(fs, files[i], &out_buf, &out_size);
        TEST_CHECK(ret == 0);

        TEST_CHECK(memcmp(out_buf, "fluent-bit\nfluent-bit-2\n", 11+13) == 0);
        TEST_CHECK(out_size == 11+13);
        flb_free(out_buf);
    }
    
    /* test inactive and delete */
    for (i = 0; i < n_files / 4; ++i) {
        flb_fstore_file_inactive(fs, files[i]);
    }

    for (i = 0; i < n_files / 4; ++i) {
        flb_fstore_file_delete(fs, files[i + n_files / 4]);
    }

    /* test add more files */
    for (i = 0; i < n_files / 4 * 2; ++i) {
        sprintf(filepath, FSF_STORE_PATH "/abc/files-round_2-%d.txt", i);
        sprintf(filename, "files-round_2-%d.txt", i);

        files[i] = flb_fstore_file_create(fs, st, filename, 100);
        TEST_CHECK(files[i] != NULL);
        if (!files[i]) {
            return;
        }

        ret = stat(filepath, &st_data);
        TEST_CHECK(ret == 0);

        ret = flb_fstore_file_append(fs, files[i], "fluent-bit-3\n", 13);
        TEST_CHECK(ret == 0);

        ret = flb_fstore_file_content_copy(fs, files[i], &out_buf, &out_size);
        TEST_CHECK(ret == 0);

        TEST_CHECK(memcmp(out_buf, "fluent-bit-3\n", 13) == 0);
        TEST_CHECK(out_size == 13);
        flb_free(out_buf);
    }

    /* copy, delete, inactivate, and create */
    for (i = 0; i < n_files; ++i) {
        ret = flb_fstore_file_content_copy(fs, files[i], &out_buf, &out_size);
        TEST_CHECK(ret == 0);
        if (i < n_files / 4 * 2) {
            TEST_CHECK(memcmp(out_buf, "fluent-bit-3\n", 13) == 0);
            TEST_CHECK(out_size == 13);
            flb_free(out_buf);
        }
        else {
            TEST_CHECK(memcmp(out_buf, "fluent-bit\nfluent-bit-2\n", 11+13) == 0);
            TEST_CHECK(out_size == 11+13);
            flb_free(out_buf);
        }
       
        if (i % 2) {
            flb_fstore_file_delete(fs, files[i]);
        } else {
            flb_fstore_file_inactive(fs, files[i]);
        }

        sprintf(filepath, FSF_STORE_PATH "/abc/files-round_3-%d.txt", i);
        sprintf(filename, "files-round_3-%d.txt", i);

        files[i] = flb_fstore_file_create(fs, st, filename, 100);
    }

    flb_fstore_destroy(fs);
}

void test_add_1_file()
{
    test_add_n_files(1);
}

void test_add_10_files()
{
    test_add_n_files(10);
}

void test_add_64_files()
{
    test_add_n_files(64);
}

void test_add_65_files()
{
    test_add_n_files(65);
}

void test_add_256_files()
{
    test_add_n_files(256);
}

/* Logging callback, once called it just turn on the log_check flag */
static int log_cb(struct cio_ctx *ctx, int level, const char *file, int line,
                  char *str)
{
    (void) ctx;

    printf("[cio-test-fs] %-60s => %s:%i\n",  str, file, line);
    return 0;
}

void test_chunkio_up_down_up_append()
{
    int ret;
    int err;
    struct cio_ctx *ctx;
    struct cio_chunk *chunk;
    struct cio_stream *stream;

    void *out_buf;
    size_t out_size;

    cio_utils_recursive_delete(FSF_STORE_PATH);

    /* Create a temporal storage */
    ctx = cio_create(FSF_STORE_PATH, log_cb, CIO_LOG_DEBUG, CIO_CHECKSUM);
    stream = cio_stream_create(ctx, "cio", CIO_STORE_FS);
    chunk = cio_chunk_open(ctx, stream, "c", CIO_OPEN, 1000, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        printf("cannot open chunk\n");
        exit(1);
    }

    ret = cio_chunk_get_content_copy(chunk, &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(memcmp(out_buf, "", 1) == 0);
    TEST_CHECK(out_size == 0);
    flb_free(out_buf);

    ret = cio_chunk_write(chunk, "line 1\n", 7);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(memcmp(out_buf, "line 1\n", 7+1) == 0);
    TEST_CHECK(out_size == 7);
    flb_free(out_buf);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(memcmp(out_buf, "line 1\n", 7+1) == 0);
    TEST_CHECK(out_size == 7);
    flb_free(out_buf);

    /* append */
    ret = cio_chunk_write(chunk, "line 2\n", 7);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_down(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_up(chunk);
    TEST_CHECK(ret == CIO_OK);

    ret = cio_chunk_get_content_copy(chunk, &out_buf, &out_size);
    TEST_CHECK(ret == CIO_OK);
    TEST_CHECK(memcmp(out_buf, "line 1\nline 2\n", 7*2+1) == 0);
    TEST_CHECK(out_size == 7*2);
    flb_free(out_buf);

    cio_destroy(ctx);
}

TEST_LIST = {
    { "all" , cb_all},
    { "test_add_1_file", test_add_1_file},
    { "test_add_10_files", test_add_10_files},
    { "test_add_64_files", test_add_64_files},
    { "test_add_65_files", test_add_65_files},
    { "test_add_256_files", test_add_256_files},
    { "test_chunkio_up_down_up_append", test_chunkio_up_down_up_append},
    { NULL }
};
