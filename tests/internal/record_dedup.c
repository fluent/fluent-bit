/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_record_dedup.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <cfl/cfl.h>
#include <msgpack.h>

#include "flb_tests_internal.h"

struct test_record {
    msgpack_object *obj;
    msgpack_sbuffer sbuf;
    msgpack_zone zone;
    struct cfl_variant *variant;
    struct cfl_kvlist *kvlist;
    /* Stack objects */
    struct cfl_variant stack_variant;
    struct cfl_object stack_obj;
    struct flb_mp_chunk_record chunk;
};

static struct test_record *create_test_record(const char *key, const char *value)
{
    struct test_record *record;
    msgpack_packer pck;
    struct cfl_kvlist *kvlist = NULL;
    struct cfl_variant *variant = NULL;
    char *key_copy = NULL;
    char *value_copy = NULL;

    record = flb_calloc(1, sizeof(struct test_record));
    if (!record) {
        return NULL;
    }

    /* Initialize buffers */
    msgpack_sbuffer_init(&record->sbuf);
    msgpack_zone_init(&record->zone, 2048);
    msgpack_packer_init(&pck, &record->sbuf, msgpack_sbuffer_write);

    /* Pack key-value */
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, strlen(key));
    msgpack_pack_str_body(&pck, key, strlen(key));
    msgpack_pack_str(&pck, strlen(value));
    msgpack_pack_str_body(&pck, value, strlen(value));

    record->obj = msgpack_zone_malloc(&record->zone, sizeof(msgpack_object));
    if (!record->obj) {
        goto error;
    }

    msgpack_unpack(record->sbuf.data, record->sbuf.size, NULL,
                  &record->zone, record->obj);

    /* Create kvlist */
    kvlist = cfl_kvlist_create();
    if (!kvlist) {
        goto error;
    }

    /* Make copies of strings */
    key_copy = strdup(key);
    value_copy = strdup(value);
    if (!key_copy || !value_copy) {
        goto error;
    }

    /* Insert strings into kvlist */
    if (cfl_kvlist_insert_string(kvlist, key_copy, value_copy) != 0) {
        goto error;
    }

    /* Free our copies since kvlist has them */
    free(key_copy);
    free(value_copy);
    key_copy = value_copy = NULL;

    /* Create variant */
    variant = cfl_variant_create();
    if (!variant) {
        goto error;
    }

    /* Link structures */
    variant->type = CFL_VARIANT_KVLIST;
    variant->data.as_kvlist = kvlist;
    record->variant = variant;
    record->kvlist = kvlist;

    /* Set up stack objects */
    record->stack_variant.type = CFL_VARIANT_KVLIST;
    record->stack_variant.data.as_kvlist = kvlist;
    record->stack_obj.type = CFL_VARIANT_KVLIST;
    record->stack_obj.variant = &record->stack_variant;

    /* Set up chunk record */
    record->chunk.event.body = record->obj;
    record->chunk.cobj_record = &record->stack_obj;

    return record;

error:
    if (key_copy) free(key_copy);
    if (value_copy) free(value_copy);
    if (variant) cfl_variant_destroy(variant);
    if (kvlist) cfl_kvlist_destroy(kvlist);
    if (record) {
        msgpack_zone_destroy(&record->zone);
        msgpack_sbuffer_destroy(&record->sbuf);
        flb_free(record);
    }
    return NULL;
}

static void destroy_test_record(struct test_record *record)
{
    if (!record) {
        return;
    }
    if (record->variant) {
        cfl_variant_destroy(record->variant);
    }
    msgpack_zone_destroy(&record->zone);
    msgpack_sbuffer_destroy(&record->sbuf);
    flb_free(record);
}

static void test_dedup_create_destroy()
{
    struct flb_record_dedup_context *dedup;

    /* Test with default options (NULL) */
    dedup = flb_record_dedup_context_create("/tmp/test-dedup", NULL);
    TEST_CHECK(dedup != NULL);

    flb_record_dedup_destroy(dedup);
}

static void test_dedup_basic_operations()
{
    struct flb_record_dedup_context *dedup;
    struct flb_record_dedup_options opts;
    struct test_record *record;
    int ret;

    /* Create dedup instance with custom options */
    flb_record_dedup_options_default(&opts);
    opts.ttl = 30; /* 30 seconds default TTL */
    dedup = flb_record_dedup_context_create("/tmp/test-dedup-ops", &opts);
    TEST_CHECK(dedup != NULL);

    /* Create test record */
    record = create_test_record("key", "value");
    TEST_CHECK(record != NULL);

    /* First check - should not exist */
    ret = flb_record_dedup_exists(dedup, &record->chunk);
    TEST_CHECK(ret == FLB_FALSE);

    /* Store the record */
    ret = flb_record_dedup_add(dedup, &record->chunk);
    TEST_CHECK(ret == 0);

    /* Second check - should exist */
    ret = flb_record_dedup_exists(dedup, &record->chunk);
    TEST_CHECK(ret == FLB_TRUE);

    /* Cleanup */
    destroy_test_record(record);
    flb_record_dedup_destroy(dedup);
}

static void test_dedup_different_records()
{
    struct flb_record_dedup_context *dedup;
    struct test_record *record1, *record2;
    int ret;

    dedup = flb_record_dedup_context_create("/tmp/test-dedup-diff", NULL);
    TEST_CHECK(dedup != NULL);

    /* Create first record */
    record1 = create_test_record("key", "value1");
    TEST_CHECK(record1 != NULL);

    /* Create second record (different) */
    record2 = create_test_record("key", "value2");
    TEST_CHECK(record2 != NULL);

    /* Store first record */
    ret = flb_record_dedup_add(dedup, &record1->chunk);
    TEST_CHECK(ret == 0);

    /* Check first record exists */
    ret = flb_record_dedup_exists(dedup, &record1->chunk);
    TEST_CHECK(ret == FLB_TRUE);

    /* Check second record doesn't exist */
    ret = flb_record_dedup_exists(dedup, &record2->chunk);
    TEST_CHECK(ret == FLB_FALSE);

    /* Store second record */
    ret = flb_record_dedup_add(dedup, &record2->chunk);
    TEST_CHECK(ret == 0);

    /* Now both should exist */
    ret = flb_record_dedup_exists(dedup, &record1->chunk);
    TEST_CHECK(ret == FLB_TRUE);

    ret = flb_record_dedup_exists(dedup, &record2->chunk);
    TEST_CHECK(ret == FLB_TRUE);

    /* Cleanup */
    destroy_test_record(record1);
    destroy_test_record(record2);
    flb_record_dedup_destroy(dedup);
}

static void test_dedup_expiration()
{
    struct flb_record_dedup_context *dedup;
    struct flb_record_dedup_options opts;
    struct test_record *record;
    int ret;

    /* Create with 1 second TTL */
    flb_record_dedup_options_default(&opts);
    opts.ttl = 1; /* 1 second TTL */
    dedup = flb_record_dedup_context_create("/tmp/test-dedup-expire", &opts);
    TEST_CHECK(dedup != NULL);

    /* Create test record */
    record = create_test_record("key", "value");
    TEST_CHECK(record != NULL);

    /* Store the record */
    ret = flb_record_dedup_add(dedup, &record->chunk);
    TEST_CHECK(ret == 0);

    /* Should exist immediately */
    ret = flb_record_dedup_exists(dedup, &record->chunk);
    TEST_CHECK(ret == FLB_TRUE);

    /* Wait for expiration */
    sleep(2);

    /* Trigger compaction to clean up expired entries */
    ret = flb_record_dedup_compact(dedup);
    TEST_CHECK(ret == 0);

    /* Should not exist after expiration and compaction */
    ret = flb_record_dedup_exists(dedup, &record->chunk);
    TEST_CHECK(ret == FLB_FALSE);

    /* Cleanup */
    destroy_test_record(record);
    flb_record_dedup_destroy(dedup);
}

static void test_dedup_compact()
{
    struct flb_record_dedup_context *dedup;
    struct flb_record_dedup_options opts;
    struct test_record *record1, *record2, *record3;
    int ret;
    int pruned;

    /* Use short default TTL for test */
    flb_record_dedup_options_default(&opts);
    opts.ttl = 1; /* 1 second default TTL */
    dedup = flb_record_dedup_context_create("/tmp/test-dedup-compact", &opts);
    TEST_CHECK(dedup != NULL);

    /* Create test records */
    record1 = create_test_record("key1", "value1");
    TEST_CHECK(record1 != NULL);
    record2 = create_test_record("key2", "value2");
    TEST_CHECK(record2 != NULL);
    record3 = create_test_record("key3", "value3");
    TEST_CHECK(record3 != NULL);

    /* Store all records - they all use the context TTL */
    ret = flb_record_dedup_add(dedup, &record1->chunk);
    TEST_CHECK(ret == 0);
    ret = flb_record_dedup_add(dedup, &record2->chunk);
    TEST_CHECK(ret == 0);
    ret = flb_record_dedup_add(dedup, &record3->chunk);
    TEST_CHECK(ret == 0);

    /* All should exist immediately */
    TEST_CHECK(flb_record_dedup_exists(dedup, &record1->chunk) == FLB_TRUE);
    TEST_CHECK(flb_record_dedup_exists(dedup, &record2->chunk) == FLB_TRUE);
    TEST_CHECK(flb_record_dedup_exists(dedup, &record3->chunk) == FLB_TRUE);

    /* Compact before expiration - should succeed */
    pruned = flb_record_dedup_compact(dedup);
    TEST_CHECK(pruned == 0);

    /* Wait for all to expire */
    sleep(2);

    /* Compact triggers cleanup of expired entries */
    pruned = flb_record_dedup_compact(dedup);
    TEST_CHECK(pruned == 0);  /* Returns 0 on success */
    TEST_MSG("Triggered database compaction");

    /* All should have expired */
    TEST_CHECK(flb_record_dedup_exists(dedup, &record1->chunk) == FLB_FALSE);
    TEST_CHECK(flb_record_dedup_exists(dedup, &record2->chunk) == FLB_FALSE);
    TEST_CHECK(flb_record_dedup_exists(dedup, &record3->chunk) == FLB_FALSE);

    /* Cleanup */
    destroy_test_record(record1);
    destroy_test_record(record2);
    destroy_test_record(record3);
    flb_record_dedup_destroy(dedup);
}

static void test_dedup_custom_options()
{
    struct flb_record_dedup_context *dedup;
    struct flb_record_dedup_options opts;
    struct test_record *record;
    int ret;

    /* Test with custom options */
    flb_record_dedup_options_default(&opts);
    opts.ttl = 300; /* 5 minutes */
    opts.cache_size = 50 * 1024 * 1024; /* 50MB */
    opts.write_buffer_size = 32 * 1024 * 1024; /* 32MB */

    dedup = flb_record_dedup_context_create("/tmp/test-dedup-custom", &opts);
    TEST_CHECK(dedup != NULL);

    /* Verify options were set */
    TEST_CHECK(dedup->opts.ttl == 300);
    TEST_CHECK(dedup->opts.cache_size == 50 * 1024 * 1024);
    TEST_CHECK(dedup->opts.write_buffer_size == 32 * 1024 * 1024);

    /* Test basic operations work with custom options */
    record = create_test_record("key", "value");
    TEST_CHECK(record != NULL);

    ret = flb_record_dedup_add(dedup, &record->chunk);
    TEST_CHECK(ret == 0);

    ret = flb_record_dedup_exists(dedup, &record->chunk);
    TEST_CHECK(ret == FLB_TRUE);

    destroy_test_record(record);
    flb_record_dedup_destroy(dedup);
}

static void test_dedup_statistics()
{
    struct flb_record_dedup_context *dedup;
    struct flb_record_dedup_options opts;
    struct test_record *record1, *record2;
    int ret;

    /* Use default options */
    flb_record_dedup_options_default(&opts);

    dedup = flb_record_dedup_context_create("/tmp/test-dedup-stats", &opts);
    TEST_CHECK(dedup != NULL);

    /* Create test records */
    record1 = create_test_record("key1", "value1");
    TEST_CHECK(record1 != NULL);
    record2 = create_test_record("key2", "value2");
    TEST_CHECK(record2 != NULL);

    /* Check initial stats - should be zero */
    TEST_CHECK(dedup->records_added == 0);
    TEST_CHECK(dedup->records_checked == 0);
    TEST_CHECK(dedup->hits == 0);
    TEST_CHECK(dedup->misses == 0);

    /* Add first record */
    ret = flb_record_dedup_add(dedup, &record1->chunk);
    TEST_CHECK(ret == 0);

    /* Check for first record (hit) */
    ret = flb_record_dedup_exists(dedup, &record1->chunk);
    TEST_CHECK(ret == FLB_TRUE);

    /* Check for second record (miss) */
    ret = flb_record_dedup_exists(dedup, &record2->chunk);
    TEST_CHECK(ret == FLB_FALSE);

    /* Add second record */
    ret = flb_record_dedup_add(dedup, &record2->chunk);
    TEST_CHECK(ret == 0);

    /* Check both records again */
    ret = flb_record_dedup_exists(dedup, &record1->chunk);
    TEST_CHECK(ret == FLB_TRUE);
    ret = flb_record_dedup_exists(dedup, &record2->chunk);
    TEST_CHECK(ret == FLB_TRUE);

    /* Check final stats */
    TEST_CHECK(dedup->records_added == 2);     /* Added 2 records */
    TEST_CHECK(dedup->records_checked == 4);   /* 4 existence checks */
    TEST_CHECK(dedup->hits == 3);              /* 3 found */
    TEST_CHECK(dedup->misses == 1);            /* 1 not found */

    TEST_MSG("Stats - Added: %llu, Checked: %llu, Hits: %llu, Misses: %llu",
             (unsigned long long)dedup->records_added,
             (unsigned long long)dedup->records_checked,
             (unsigned long long)dedup->hits,
             (unsigned long long)dedup->misses);

    /* Cleanup */
    destroy_test_record(record1);
    destroy_test_record(record2);
    flb_record_dedup_destroy(dedup);
}

TEST_LIST = {
    {"dedup_create_destroy", test_dedup_create_destroy},
    {"dedup_basic_operations", test_dedup_basic_operations},
    {"dedup_different_records", test_dedup_different_records},
    {"dedup_expiration", test_dedup_expiration},
    {"dedup_compact", test_dedup_compact},
    {"dedup_custom_options", test_dedup_custom_options},
    {"dedup_statistics", test_dedup_statistics},
    {NULL, NULL}
};
