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
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/flb_time.h>

#include <chunkio/cio_utils.h>

#include <string.h>
#include <sys/stat.h>

#include "flb_tests_runtime.h"
#include "../include/flb_tests_tmpdir.h"

#define TEST_RECORD "[0, {\"message\":\"persisted\"}]"

static flb_ctx_t *start_context(const char *storage_path,
                                const char *input_tag,
                                const char *output_match,
                                const char *output_name,
                                int *input_id)
{
    int output_id;
    int ret;
    flb_ctx_t *ctx;

    ctx = flb_create();
    if (ctx == NULL) {
        return NULL;
    }

    if (flb_service_set(ctx,
                        "flush", "60",
                        "grace", "0",
                        "storage.path", storage_path,
                        NULL) != 0) {
        flb_destroy(ctx);
        return NULL;
    }

    *input_id = flb_input(ctx, (char *) "lib", NULL);
    if (*input_id < 0) {
        flb_destroy(ctx);
        return NULL;
    }

    if (flb_input_set(ctx, *input_id,
                      "tag", input_tag,
                      "storage.type", "filesystem",
                      NULL) != 0) {
        flb_destroy(ctx);
        return NULL;
    }

    output_id = flb_output(ctx, output_name, NULL);
    if (output_id < 0) {
        flb_destroy(ctx);
        return NULL;
    }

    if (strcmp(output_name, "http") == 0) {
        ret = flb_output_set(ctx, output_id,
                             "match", output_match,
                             "host", "127.0.0.1",
                             "port", "9",
                             "retry_limit", "no_limits",
                             NULL);
    }
    else {
        ret = flb_output_set(ctx, output_id, "match", output_match, NULL);
    }

    if (ret != 0) {
        flb_destroy(ctx);
        return NULL;
    }

    if (flb_start(ctx) != 0) {
        flb_destroy(ctx);
        return NULL;
    }

    return ctx;
}

static int wait_for_chunk_content(struct flb_input_instance *input_instance)
{
    int attempts;
    struct flb_input_chunk *input_chunk;

    for (attempts = 0; attempts < 50; attempts++) {
        if (mk_list_is_empty(&input_instance->chunks) != 0) {
            input_chunk = mk_list_entry_first(&input_instance->chunks,
                                              struct flb_input_chunk,
                                              _head);
            if (flb_input_chunk_get_size(input_chunk) > 0) {
                return 0;
            }
        }

        flb_time_msleep(100);
    }

    return -1;
}

static int wait_for_filesystem_chunk_count(flb_ctx_t *ctx, int expected)
{
    int attempts;
    int fs_chunks;
    int mem_chunks;

    for (attempts = 0; attempts < 50; attempts++) {
        flb_storage_chunk_count(ctx->config, &mem_chunks, &fs_chunks);
        if (fs_chunks == expected) {
            return 0;
        }

        flb_time_msleep(100);
    }

    return -1;
}

static void test_unroutable_chunk_is_detached_and_preserved(void)
{
    int input_id;
    int ret;
    struct stat file_status;
    struct flb_input_chunk *input_chunk;
    struct flb_input_instance *input_instance;
    struct flb_storage_input *storage_input;
    flb_ctx_t *ctx;
    char chunk_path[4096];
    char *storage_path;

    storage_path = flb_test_tmpdir_cat("/flb-storage-backlog-no-route-XXXXXX");
    TEST_ASSERT(storage_path != NULL);
    TEST_ASSERT(mkdtemp(storage_path) != NULL);

    /* Seed one routed filesystem chunk whose output cannot deliver it. */
    ctx = start_context(storage_path, "stale", "stale", "http", &input_id);
    TEST_ASSERT(ctx != NULL);

    ret = flb_lib_push(ctx, input_id, TEST_RECORD, sizeof(TEST_RECORD) - 1);
    TEST_ASSERT(ret >= 0);
    TEST_ASSERT(wait_for_filesystem_chunk_count(ctx, 1) == 0);

    input_instance = flb_input_get_instance(ctx->config, input_id);
    TEST_ASSERT(input_instance != NULL);
    TEST_ASSERT(wait_for_chunk_content(input_instance) == 0);
    TEST_ASSERT(mk_list_is_empty(&input_instance->chunks) != 0);

    input_chunk = mk_list_entry_first(&input_instance->chunks,
                                      struct flb_input_chunk,
                                      _head);
    storage_input = (struct flb_storage_input *) input_instance->storage;
    TEST_ASSERT(storage_input != NULL);

    ret = snprintf(chunk_path, sizeof(chunk_path), "%s/%s/%s",
                   storage_path, storage_input->stream->name,
                   ((struct cio_chunk *) input_chunk->chunk)->name);
    TEST_ASSERT(ret > 0 && (size_t) ret < sizeof(chunk_path));

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_ASSERT(stat(chunk_path, &file_status) == 0);

    /* Restore with a configuration whose only route does not match the chunk. */
    ctx = start_context(storage_path, "live", "live", "null", &input_id);
    TEST_ASSERT(ctx != NULL);

    TEST_CHECK_(wait_for_filesystem_chunk_count(ctx, 0) == 0,
                "unroutable restored chunk remained in active filesystem accounting");
    TEST_CHECK_(stat(chunk_path, &file_status) == 0,
                "unroutable restored chunk was deleted");

    flb_stop(ctx);
    flb_destroy(ctx);

    TEST_CHECK_(stat(chunk_path, &file_status) == 0,
                "unroutable restored chunk was not preserved across shutdown");

    cio_utils_recursive_delete(storage_path);
    flb_free(storage_path);
}

TEST_LIST = {
    {"unroutable_chunk_is_detached_and_preserved",
     test_unroutable_chunk_is_detached_and_preserved},
    {NULL, NULL}
};
