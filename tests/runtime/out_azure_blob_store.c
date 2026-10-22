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

#include <fluent-bit.h>
#include "../../plugins/out_azure_blob/azure_blob_store.h"
#include "flb_tests_runtime.h"

static char payload[] = "{\"record_id\":\"retained-buffer\"}\n";
static char tag[] = "quota";

struct store_test {
    flb_ctx_t *engine;
    struct flb_azure_blob store;
    char directory[64];
    char root[80];
};

static void create_test(struct store_test *test, size_t limit)
{
    int output;

    memset(test, 0, sizeof(*test));
    strcpy(test->directory, "/tmp/flb-azq-XXXXXX");
    TEST_ASSERT(mkdtemp(test->directory) != NULL);
    snprintf(test->root, sizeof(test->root), "%s/quota", test->directory);
    test->engine = flb_create();
    TEST_ASSERT(test->engine != NULL);
    output = flb_output(test->engine, "azure_blob", NULL);
    TEST_ASSERT(output >= 0);
    test->store.ins = flb_output_get_instance(test->engine->config, output);
    TEST_ASSERT(test->store.ins != NULL);
    test->store.buffer_dir = flb_sds_create(test->directory);
    test->store.azure_blob_buffer_key = flb_sds_create("quota");
    TEST_ASSERT(test->store.buffer_dir != NULL);
    TEST_ASSERT(test->store.azure_blob_buffer_key != NULL);
    test->store.store_dir_limit_size = limit;
}

static void open_store(struct store_test *test)
{
    test->store.current_buffer_size = 0;
    TEST_ASSERT(azure_blob_store_init(&test->store) == 0);
}

static void close_store(struct store_test *test)
{
    TEST_ASSERT(azure_blob_store_exit(&test->store) == 0);
    test->store.fs = NULL;
    test->store.stream_active = NULL;
}

static void destroy_test(struct store_test *test)
{
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream;
    struct flb_fstore_file *file;
    struct mk_list *head;
    struct mk_list *file_head;
    struct mk_list *tmp;

    if (test->store.fs) {
        close_store(test);
    }
    fs = flb_fstore_create(test->root, FLB_FSTORE_FS);
    TEST_ASSERT(fs != NULL);
    mk_list_foreach(head, &fs->streams) {
        stream = mk_list_entry(head, struct flb_fstore_stream, _head);
        mk_list_foreach_safe(file_head, tmp, &stream->files) {
            file = mk_list_entry(file_head, struct flb_fstore_file, _head);
            TEST_CHECK(flb_fstore_file_delete(fs, file) == 0);
        }
    }
    TEST_CHECK(flb_fstore_destroy(fs) == 0);
    TEST_CHECK(rmdir(test->root) == 0);
    TEST_CHECK(rmdir(test->directory) == 0);
    flb_sds_destroy(test->store.buffer_dir);
    flb_sds_destroy(test->store.azure_blob_buffer_key);
    /* The output instance supplies logging context without starting a worker. */
    TEST_CHECK(flb_output_instance_destroy(test->store.ins) == 0);
    flb_init_env();
    flb_destroy(test->engine);
}

static void seed_file(struct flb_fstore *fs, struct flb_fstore_stream *stream,
                       char *name)
{
    struct flb_fstore_file *file;

    file = flb_fstore_file_create(fs, stream, name, sizeof(payload) - 1);
    TEST_ASSERT(file != NULL);
    TEST_ASSERT(flb_fstore_file_meta_set(fs, file, tag, sizeof(tag) - 1) == 0);
    TEST_ASSERT(flb_fstore_file_append(file, payload, sizeof(payload) - 1) == 0);
}

static void seed_files(struct store_test *test, int count)
{
    int index;
    char name[32];
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream;

    fs = flb_fstore_create(test->root, FLB_FSTORE_FS);
    TEST_ASSERT(fs != NULL);
    stream = flb_fstore_stream_create(fs, "retained");
    TEST_ASSERT(stream != NULL);
    for (index = 0; index < count; index++) {
        snprintf(name, sizeof(name), "file-%d", index);
        seed_file(fs, stream, name);
    }
    TEST_ASSERT(flb_fstore_destroy(fs) == 0);
}

static struct azure_blob_file *retained_file(struct store_test *test, int index)
{
    char name[32];
    struct flb_fstore_stream *stream;
    struct flb_fstore_file *file;

    stream = flb_fstore_stream_create(test->store.fs, "retained");
    TEST_ASSERT(stream != NULL);
    snprintf(name, sizeof(name), "file-%d", index);
    file = flb_fstore_file_get(test->store.fs, stream, name, strlen(name));
    TEST_ASSERT(file != NULL);
    TEST_ASSERT(file->data != NULL);
    return file->data;
}

static void check_payload(struct store_test *test, struct flb_fstore_file *file)
{
    void *data;
    size_t size;
    int was_up = cio_chunk_is_up(file->chunk);

    TEST_ASSERT(flb_fstore_file_content_copy(test->store.fs, file, &data, &size) == 0);
    TEST_CHECK(size == sizeof(payload) - 1);
    TEST_CHECK(size == sizeof(payload) - 1 && memcmp(data, payload, size) == 0);
    TEST_CHECK(cio_chunk_is_up(file->chunk) == was_up);
    flb_free(data);
}

static int put_payload(struct store_test *test, size_t size)
{
    return azure_blob_store_buffer_put(&test->store, NULL, tag, sizeof(tag) - 1,
                                        payload, size);
}

static void test_recovered_files_limit(void)
{
    int index;
    int down = 0;
    const int count = CIO_MAX_CHUNKS_UP + 2;
    struct store_test test;
    struct azure_blob_file *file;

    create_test(&test, (count + 1) * (sizeof(payload) - 1));
    seed_files(&test, count);
    open_store(&test);
    for (index = 0; index < count; index++) {
        file = retained_file(&test, index);
        if (cio_chunk_is_up(file->fsf->chunk) == CIO_FALSE) {
            down++;
        }
        check_payload(&test, file->fsf);
    }
    TEST_CHECK(down == 2);
    TEST_CHECK(put_payload(&test, sizeof(payload) - 1) == -1);
    TEST_CHECK(put_payload(&test, sizeof(payload) - 2) == 0);
    TEST_CHECK(put_payload(&test, 1) == -1);
    destroy_test(&test);
}

static void test_retired_files_limit(void)
{
    struct store_test test;

    create_test(&test, 4 * (sizeof(payload) - 1));
    seed_files(&test, 3);
    open_store(&test);
    TEST_ASSERT(azure_blob_store_file_inactive(&test.store,
                                               retained_file(&test, 0)) == 0);
    TEST_CHECK(put_payload(&test, sizeof(payload) - 1) == -1);
    TEST_ASSERT(azure_blob_store_file_delete(&test.store,
                                             retained_file(&test, 1)) == 0);
    TEST_CHECK(put_payload(&test, sizeof(payload) - 2) == 0);
    TEST_CHECK(put_payload(&test, sizeof(payload) - 1) == 0);
    TEST_CHECK(put_payload(&test, 1) == -1);

    close_store(&test);
    open_store(&test);
    check_payload(&test, retained_file(&test, 0)->fsf);
    check_payload(&test, retained_file(&test, 2)->fsf);
    TEST_CHECK(put_payload(&test, 1) == -1);
    destroy_test(&test);
}

static void test_recovered_files_above_limit(void)
{
    struct store_test test;

    create_test(&test, sizeof(payload) - 1);
    seed_files(&test, 2);
    open_store(&test);
    TEST_CHECK(put_payload(&test, 1) == -1);
    close_store(&test);
    open_store(&test);
    check_payload(&test, retained_file(&test, 0)->fsf);
    check_payload(&test, retained_file(&test, 1)->fsf);
    TEST_CHECK(put_payload(&test, 1) == -1);
    destroy_test(&test);
}

static void test_active_stream_recovery(void)
{
    int index;
    const int count = 60;
    time_t now = time(NULL);
    time_t timestamp;
    struct tm tm;
    char stream_name[64];
    struct store_test test;
    struct flb_fstore *fs;
    struct flb_fstore_stream *stream;
    struct flb_fstore_file *file;

    create_test(&test, (count + 1) * (sizeof(payload) - 1));
    fs = flb_fstore_create(test.root, FLB_FSTORE_FS);
    TEST_ASSERT(fs != NULL);
    /* Seed a minute of timestamps so recovery need not finish in one second. */
    for (index = 0; index < count; index++) {
        timestamp = now + index;
        TEST_ASSERT(localtime_r(&timestamp, &tm) != NULL);
        TEST_ASSERT(strftime(stream_name, sizeof(stream_name),
                              "%Y-%m-%dT%H:%M:%S", &tm) > 0);
        stream = flb_fstore_stream_create(fs, stream_name);
        TEST_ASSERT(stream != NULL);
        seed_file(fs, stream, "record");
    }
    TEST_ASSERT(flb_fstore_destroy(fs) == 0);
    open_store(&test);
    if (TEST_CHECK_(mk_list_size(&test.store.stream_active->files) == 1,
                     "active timestamp %s must be within the seeded minute ending %s",
                     test.store.stream_active->name, stream_name)) {
        file = mk_list_entry_first(&test.store.stream_active->files,
                                   struct flb_fstore_file, _head);
        TEST_CHECK(file->data != NULL);
        check_payload(&test, file);
        TEST_CHECK(put_payload(&test, sizeof(payload) - 1) == -1);
    }
    destroy_test(&test);
}

TEST_LIST = {
    {"recovered_files_limit", test_recovered_files_limit},
    {"retired_files_limit", test_retired_files_limit},
    {"recovered_files_above_limit", test_recovered_files_above_limit},
    {"active_stream_recovery", test_active_stream_recovery},
    {NULL, NULL}
};
