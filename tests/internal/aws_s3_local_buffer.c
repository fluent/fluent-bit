/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_s3_local_buffer.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_aws_util.h>

#include "flb_tests_internal.h"

#define BUFFER_DIRECTORY FLB_TESTS_DATA_PATH "data/s3_local_buffer/"
#define PLUGIN_NAME "s3_plugin"
#define TEST_DATA "I love Fluent Bit"
#define KEY_1 "key1"
#define KEY_2 "key2"

static void check_chunk(struct flb_local_chunk *chunk, char *tag, char *data)
{
    int ret;
    size_t buffer_size;
    char *buffered_data = NULL;
    
    /* Ensure data retreived is same as that which was stored. */
    TEST_CHECK(strcmp(chunk->tag, tag) == 0);
    ret = flb_read_file(chunk->file_path, &buffered_data, &buffer_size);
    TEST_CHECK(ret == 0);
    TEST_CHECK(strcmp(buffered_data, data) == 0);

    flb_free(buffered_data);
}

static void test_flb_buffer_put_valid_chunk()
{
    int ret;
    struct flb_local_chunk *chunk = NULL;
    struct flb_local_buffer *store = NULL;
    struct flb_output_instance *out = NULL;
    
    store = flb_calloc(1, sizeof(struct flb_local_buffer));
    TEST_CHECK(store != NULL);
    out = flb_calloc(1, sizeof(struct flb_output_instance));
    TEST_CHECK(out != NULL);
    
    store->dir = BUFFER_DIRECTORY;
    strcpy(out->name, PLUGIN_NAME);
    store->ins = out;
    mk_list_init(&store->chunks);
    TEST_CHECK(mk_list_size(&store->chunks) == 0);

    /* No local chunk suitable for this data has been created yet,
     * hence chunk should be NULL.
     */
    chunk = flb_chunk_get(store, KEY_1);
    TEST_CHECK(chunk == NULL);

    ret = flb_buffer_put(store, chunk, KEY_1, TEST_DATA, strlen(TEST_DATA));
    TEST_CHECK(ret == 0);
    TEST_CHECK(mk_list_size(&store->chunks) == 1);

    /* A new chunk associated with key2 was created in the above statement,
     * hence this time, chunk should not be NULL.
     */
    chunk = flb_chunk_get(store, KEY_1);
    TEST_CHECK(chunk != NULL);
    TEST_CHECK(mk_list_size(&store->chunks) == 1);

    chunk = flb_chunk_get(store, KEY_1);
    check_chunk(chunk, KEY_1, TEST_DATA);

    ret = flb_remove_chunk_files(chunk);
    TEST_CHECK(ret == 0);
    flb_chunk_destroy(chunk);
    flb_free(out);
    flb_free(store);
}

static void test_flb_init_local_buffer()
{
    int ret;
    struct flb_local_chunk *chunk;
    struct flb_local_buffer *store = NULL;
    struct flb_local_buffer *new_store = NULL; 
    struct flb_output_instance *out = NULL;
    
    store = flb_calloc(1, sizeof(struct flb_local_buffer));
    TEST_CHECK(store != NULL);
    new_store = flb_calloc(1, sizeof(struct flb_local_buffer));
    TEST_CHECK(new_store != NULL);
    out = flb_calloc(1, sizeof(struct flb_output_instance));
    TEST_CHECK(out != NULL);
    
    store->dir = BUFFER_DIRECTORY;
    strcpy(out->name, PLUGIN_NAME);
    store->ins = out;
    mk_list_init(&store->chunks);
    TEST_CHECK(mk_list_size(&store->chunks) == 0);

    new_store->dir = BUFFER_DIRECTORY;
    strcpy(out->name, PLUGIN_NAME);
    new_store->ins = out;
    mk_list_init(&new_store->chunks);
    TEST_CHECK(mk_list_size(&new_store->chunks) == 0);

    chunk = flb_chunk_get(store, KEY_2);
    TEST_CHECK(chunk == NULL);
    ret = flb_buffer_put(store, chunk, KEY_2, TEST_DATA, strlen(TEST_DATA));
    TEST_CHECK(ret == 0);
    TEST_CHECK(mk_list_size(&store->chunks) == 1);

    ret = flb_init_local_buffer(new_store);
    TEST_CHECK(ret == 0);

    chunk = flb_chunk_get(new_store, KEY_2);
    check_chunk(chunk, KEY_2, TEST_DATA);

    ret = flb_remove_chunk_files(chunk);
    TEST_CHECK(ret == 0);
    flb_chunk_destroy(chunk);
    flb_free(out);
    flb_free(store);
    flb_free(new_store);
}


TEST_LIST = {
    { "flb_buffer_put_valid_chunk" , test_flb_buffer_put_valid_chunk},
    {"flb_buffer_init_local_buffer", test_flb_init_local_buffer},
    { 0 }
};