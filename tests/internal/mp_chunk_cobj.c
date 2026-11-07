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
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_conditionals.h>

#include <cfl/cfl_kvlist.h>
#include <cfl/cfl_arena.h>

#include <string.h>

#include "flb_tests_internal.h"

void decoder_groups_cobj()
{
    struct flb_log_event_encoder *builder = NULL;
    struct flb_log_event_encoder *chunk_encoder = NULL;
    struct flb_log_event_decoder decoder;
    struct flb_log_event_decoder verify_decoder;
    struct flb_mp_chunk_cobj *chunk = NULL;
    struct flb_mp_chunk_record *record = NULL;
    struct flb_log_event verify_event;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *variant;
    struct cfl_object *metadata_obj = NULL;
    struct cfl_object *body_obj = NULL;
    char *encoded_buf = NULL;
    struct flb_time ts;
    int decoder_ready = FLB_FALSE;
    int verify_decoder_ready = FLB_FALSE;
    int ret;
    int record_type;
    int group_index;
    size_t encoded_size = 0;

    memset(&verify_decoder, 0, sizeof(verify_decoder));
    memset(&verify_event, 0, sizeof(verify_event));

    builder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!TEST_CHECK(builder != NULL)) {
        return;
    }

    ret = flb_log_event_encoder_group_init(builder);
    if (!TEST_CHECK(ret == 0)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_append_metadata_values(builder,
                                                        FLB_LOG_EVENT_STRING_VALUE("group_id", 8),
                                                        FLB_LOG_EVENT_INT64_VALUE(42));
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_append_body_values(builder,
                                                   FLB_LOG_EVENT_STRING_VALUE("resource_type", 13),
                                                   FLB_LOG_EVENT_CSTRING_VALUE("demo"));
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_group_header_end(builder);
    if (!TEST_CHECK(ret == 0)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_begin_record(builder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    flb_time_set(&ts, 1700000000, 0);
    ret = flb_log_event_encoder_set_timestamp(builder, &ts);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_append_body_values(builder,
                                                   FLB_LOG_EVENT_STRING_VALUE("message", 7),
                                                   FLB_LOG_EVENT_CSTRING_VALUE("hello"));
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_commit_record(builder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_group_end(builder);
    if (!TEST_CHECK(ret == 0)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_group_init(builder);
    if (!TEST_CHECK(ret == 0)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_append_metadata_values(builder,
                                                        FLB_LOG_EVENT_STRING_VALUE("group_id", 8),
                                                        FLB_LOG_EVENT_INT64_VALUE(100));
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_append_body_values(builder,
                                                   FLB_LOG_EVENT_STRING_VALUE("resource_type", 13),
                                                   FLB_LOG_EVENT_CSTRING_VALUE("prod"));
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_group_header_end(builder);
    if (!TEST_CHECK(ret == 0)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_begin_record(builder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    flb_time_set(&ts, 1700000001, 0);
    ret = flb_log_event_encoder_set_timestamp(builder, &ts);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_append_body_values(builder,
                                                   FLB_LOG_EVENT_STRING_VALUE("message", 7),
                                                   FLB_LOG_EVENT_CSTRING_VALUE("world"));
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_commit_record(builder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        goto cleanup;
    }

    ret = flb_log_event_encoder_group_end(builder);
    if (!TEST_CHECK(ret == 0)) {
        goto cleanup;
    }

    ret = flb_log_event_decoder_init(&decoder,
                                     builder->output_buffer,
                                     builder->output_length);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        goto cleanup;
    }
    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);
    decoder_ready = FLB_TRUE;

    chunk_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!TEST_CHECK(chunk_encoder != NULL)) {
        goto cleanup;
    }

    chunk = flb_mp_chunk_cobj_create(chunk_encoder, &decoder);
    if (!TEST_CHECK(chunk != NULL)) {
        goto cleanup;
    }

    group_index = 0;
    while ((ret = flb_mp_chunk_cobj_record_next(chunk, &record)) == FLB_MP_CHUNK_RECORD_OK) {
        ret = flb_log_event_decoder_get_record_type(&record->event, &record_type);
        if (!TEST_CHECK(ret == 0)) {
            goto cleanup;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            group_index++;

            if (!TEST_CHECK(record->cobj_group_metadata != NULL &&
                            record->cobj_group_metadata->variant != NULL)) {
                goto cleanup;
            }

            kvlist = record->cobj_group_metadata->variant->data.as_kvlist;
            variant = cfl_kvlist_fetch(kvlist, "group_id");
            if (group_index == 1) {
                if (!TEST_CHECK(variant != NULL &&
                                ((variant->type == CFL_VARIANT_INT &&
                                  variant->data.as_int64 == 42) ||
                                 (variant->type == CFL_VARIANT_UINT &&
                                  variant->data.as_uint64 == 42)))) {
                    goto cleanup;
                }
            }
            else if (group_index == 2) {
                if (!TEST_CHECK(variant != NULL &&
                                ((variant->type == CFL_VARIANT_INT &&
                                  variant->data.as_int64 == 100) ||
                                 (variant->type == CFL_VARIANT_UINT &&
                                  variant->data.as_uint64 == 100)))) {
                    goto cleanup;
                }
            }

            if (!TEST_CHECK(record->cobj_group_attributes != NULL &&
                            record->cobj_group_attributes->variant != NULL)) {
                goto cleanup;
            }

            kvlist = record->cobj_group_attributes->variant->data.as_kvlist;
            variant = cfl_kvlist_fetch(kvlist, "resource_type");
            if (group_index == 1) {
                if (!TEST_CHECK(variant != NULL &&
                                variant->type == CFL_VARIANT_STRING &&
                                variant->size == 4 &&
                                strncmp(variant->data.as_string, "demo", 4) == 0)) {
                    goto cleanup;
                }
            }
            else if (group_index == 2) {
                if (!TEST_CHECK(variant != NULL &&
                                variant->type == CFL_VARIANT_STRING &&
                                variant->size == 4 &&
                                strncmp(variant->data.as_string, "prod", 4) == 0)) {
                    goto cleanup;
                }
            }
        }
        else if (record_type == FLB_LOG_EVENT_NORMAL) {
            if (!TEST_CHECK(record->cobj_group_metadata != NULL &&
                            record->cobj_group_metadata->variant != NULL)) {
                goto cleanup;
            }

            kvlist = record->cobj_group_metadata->variant->data.as_kvlist;
            variant = cfl_kvlist_fetch(kvlist, "group_id");
            if (!TEST_CHECK(variant != NULL)) {
                goto cleanup;
            }

            if (group_index == 1) {
                if (variant->type == CFL_VARIANT_INT) {
                    variant->data.as_int64 = 4242;
                }
                else if (variant->type == CFL_VARIANT_UINT) {
                    variant->data.as_uint64 = 4242;
                }
                else {
                    TEST_CHECK(0);
                    goto cleanup;
                }

                if (!TEST_CHECK(record->cobj_group_attributes != NULL &&
                                record->cobj_group_attributes->variant != NULL)) {
                    goto cleanup;
                }

                kvlist = record->cobj_group_attributes->variant->data.as_kvlist;
                ret = cfl_kvlist_insert_int64(kvlist, "new_attribute", 1);
                if (!TEST_CHECK(ret == 0)) {
                    goto cleanup;
                }
            }
            else if (group_index == 2) {
                if (!TEST_CHECK(((variant->type == CFL_VARIANT_INT &&
                                   variant->data.as_int64 == 100) ||
                                  (variant->type == CFL_VARIANT_UINT &&
                                   variant->data.as_uint64 == 100)))) {
                    goto cleanup;
                }
            }
        }
    }

    if (!TEST_CHECK(ret == FLB_MP_CHUNK_RECORD_EOF)) {
        goto cleanup;
    }

    ret = flb_mp_chunk_cobj_encode(chunk, &encoded_buf, &encoded_size);
    if (!TEST_CHECK(ret == 0)) {
        goto cleanup;
    }

    ret = flb_log_event_decoder_init(&verify_decoder, encoded_buf, encoded_size);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        goto cleanup;
    }
    flb_log_event_decoder_read_groups(&verify_decoder, FLB_TRUE);
    verify_decoder_ready = FLB_TRUE;

    group_index = 0;
    while ((ret = flb_log_event_decoder_next(&verify_decoder, &verify_event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_decoder_get_record_type(&verify_event, &record_type);
        if (!TEST_CHECK(ret == 0)) {
            goto cleanup;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            group_index++;
            if (!TEST_CHECK(verify_event.metadata != NULL &&
                            verify_event.metadata->type == MSGPACK_OBJECT_MAP)) {
                goto cleanup;
            }

            metadata_obj = flb_mp_object_to_cfl(verify_event.metadata);
            if (!TEST_CHECK(metadata_obj != NULL && metadata_obj->variant != NULL)) {
                goto cleanup;
            }

            kvlist = metadata_obj->variant->data.as_kvlist;
            variant = cfl_kvlist_fetch(kvlist, "group_id");
            if (!TEST_CHECK(variant != NULL)) {
                goto cleanup;
            }

            if (group_index == 1) {
                if (!TEST_CHECK(((variant->type == CFL_VARIANT_INT &&
                                  variant->data.as_int64 == 4242) ||
                                 (variant->type == CFL_VARIANT_UINT &&
                                  variant->data.as_uint64 == 4242)))) {
                    goto cleanup;
                }

                if (!TEST_CHECK(verify_event.body != NULL &&
                                verify_event.body->type == MSGPACK_OBJECT_MAP)) {
                    goto cleanup;
                }

                body_obj = flb_mp_object_to_cfl(verify_event.body);
                if (!TEST_CHECK(body_obj != NULL && body_obj->variant != NULL)) {
                    goto cleanup;
                }

                kvlist = body_obj->variant->data.as_kvlist;
                variant = cfl_kvlist_fetch(kvlist, "new_attribute");
                if (!TEST_CHECK(variant != NULL &&
                                (variant->type == CFL_VARIANT_INT || variant->type == CFL_VARIANT_UINT) &&
                                ((variant->type == CFL_VARIANT_INT && variant->data.as_int64 == 1) ||
                                 (variant->type == CFL_VARIANT_UINT && variant->data.as_uint64 == 1)))) {
                    goto cleanup;
                }
            }
            else if (group_index == 2) {
                if (!TEST_CHECK(((variant->type == CFL_VARIANT_INT &&
                                  variant->data.as_int64 == 100) ||
                                 (variant->type == CFL_VARIANT_UINT &&
                                  variant->data.as_uint64 == 100)))) {
                    goto cleanup;
                }
            }

            if (metadata_obj) {
                cfl_object_destroy(metadata_obj);
                metadata_obj = NULL;
            }
            if (body_obj) {
                cfl_object_destroy(body_obj);
                body_obj = NULL;
            }
        }
    }

    ret = flb_log_event_decoder_get_last_result(&verify_decoder);

    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        goto cleanup;
    }

cleanup:
    if (metadata_obj) {
        cfl_object_destroy(metadata_obj);
    }
    if (body_obj) {
        cfl_object_destroy(body_obj);
    }
    if (encoded_buf) {
        flb_free(encoded_buf);
    }
    if (chunk) {
        flb_mp_chunk_cobj_destroy(chunk);
    }
    if (chunk_encoder) {
        flb_log_event_encoder_destroy(chunk_encoder);
    }
    if (decoder_ready == FLB_TRUE) {
        flb_log_event_decoder_destroy(&decoder);
    }
    if (builder) {
        flb_log_event_encoder_destroy(builder);
    }

    if (verify_decoder_ready == FLB_TRUE) {
        flb_log_event_decoder_destroy(&verify_decoder);
    }
}


/*
 * Regression test for the condition-filtering path of
 * flb_mp_chunk_cobj_record_next().
 *
 * When a processor condition is attached to a chunk, records that do not match
 * the condition are skipped. This used to be implemented with tail recursion:
 * every non-matching record made the function call itself to advance to the
 * next one, so the recursion depth grew proportionally to the number of
 * records. A large run of non-matching records (a common case for a condition
 * that filters out most of a chunk) could therefore exhaust the stack.
 *
 * This test builds a chunk with many records where only a few match the
 * condition, including a long trailing run of non-matching records, and
 * verifies that exactly the matching records are returned and the iteration
 * terminates cleanly.
 */
void record_next_condition_filter()
{
    struct flb_log_event_encoder *builder = NULL;
    struct flb_log_event_encoder *chunk_encoder = NULL;
    struct flb_log_event_decoder decoder;
    struct flb_mp_chunk_cobj *chunk = NULL;
    struct flb_mp_chunk_record *record = NULL;
    struct flb_condition *cond = NULL;
    struct flb_time ts;
    int decoder_ready = FLB_FALSE;
    int ret;
    int i;
    int matched = 0;
    int expected = 0;
    const int total = 20000;
    const int stride = 5000;

    builder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!TEST_CHECK(builder != NULL)) {
        return;
    }

    flb_time_set(&ts, 1700000000, 0);

    /*
     * Records where (i % stride == 0) carry match="yes", the rest match="no".
     * With total=20000 and stride=5000 this yields matches at i = 0, 5000,
     * 10000, 15000, each separated by a long run of non-matching records and
     * followed by a long trailing run that does not match.
     */
    for (i = 0; i < total; i++) {
        const char *value = (i % stride == 0) ? "yes" : "no";

        if (i % stride == 0) {
            expected++;
        }

        ret = flb_log_event_encoder_begin_record(builder);
        if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
            goto cleanup;
        }

        ret = flb_log_event_encoder_set_timestamp(builder, &ts);
        if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
            goto cleanup;
        }

        ret = flb_log_event_encoder_append_body_values(
                builder,
                FLB_LOG_EVENT_CSTRING_VALUE("match"),
                FLB_LOG_EVENT_CSTRING_VALUE(value));
        if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
            goto cleanup;
        }

        ret = flb_log_event_encoder_commit_record(builder);
        if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
            goto cleanup;
        }
    }

    ret = flb_log_event_decoder_init(&decoder,
                                     builder->output_buffer,
                                     builder->output_length);
    if (!TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS)) {
        goto cleanup;
    }
    decoder_ready = FLB_TRUE;

    chunk_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!TEST_CHECK(chunk_encoder != NULL)) {
        goto cleanup;
    }

    chunk = flb_mp_chunk_cobj_create(chunk_encoder, &decoder);
    if (!TEST_CHECK(chunk != NULL)) {
        goto cleanup;
    }

    /* Only records whose body has match == "yes" should be returned */
    cond = flb_condition_create(FLB_COND_OP_AND);
    if (!TEST_CHECK(cond != NULL)) {
        goto cleanup;
    }

    if (!TEST_CHECK(flb_condition_add_rule(cond, "$match", FLB_RULE_OP_EQ,
                                           "yes", 0,
                                           RECORD_CONTEXT_BODY) == FLB_TRUE)) {
        goto cleanup;
    }

    /* The chunk borrows the condition; it does not take ownership of it */
    chunk->condition = cond;

    while ((ret = flb_mp_chunk_cobj_record_next(chunk, &record)) ==
           FLB_MP_CHUNK_RECORD_OK) {
        matched++;
    }

    TEST_CHECK(ret == FLB_MP_CHUNK_RECORD_EOF);
    TEST_MSG("expected FLB_MP_CHUNK_RECORD_EOF, got ret=%d", ret);

    TEST_CHECK(matched == expected);
    TEST_MSG("expected %d matching records, got %d", expected, matched);

cleanup:
    if (chunk) {
        flb_mp_chunk_cobj_destroy(chunk);
    }
    if (cond) {
        flb_condition_destroy(cond);
    }
    if (chunk_encoder) {
        flb_log_event_encoder_destroy(chunk_encoder);
    }
    if (decoder_ready == FLB_TRUE) {
        flb_log_event_decoder_destroy(&decoder);
    }
    if (builder) {
        flb_log_event_encoder_destroy(builder);
    }
}


static void bounded_record_pool_preserves_moved_records(void)
{
    struct flb_log_event_encoder *encoder;
    struct flb_log_event_decoder decoder = {0};
    struct flb_mp_chunk_cobj *source;
    struct flb_mp_chunk_cobj *destination;
    struct flb_mp_chunk_record *records[1024];
    int moved[] = {0, 511, 512, 1023};
    size_t index;
    size_t pooled = 0;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    source = flb_mp_chunk_cobj_create(encoder, &decoder);
    destination = flb_mp_chunk_cobj_create(encoder, &decoder);
    TEST_ASSERT(source != NULL && destination != NULL);
    source->record_pool_enabled = FLB_TRUE;
    for (index = 0; index < 1024; index++) {
        records[index] = flb_mp_chunk_record_create(source);
        TEST_ASSERT(records[index] != NULL);
        TEST_CHECK(records[index]->cobj_record == NULL);
        TEST_CHECK(records[index]->owns_group_attributes == FLB_FALSE);
        pooled += records[index]->storage_block != NULL;
        records[index]->modified = index;
        cfl_list_add(&records[index]->_head, &source->records);
    }
    TEST_CHECK(pooled == 512);
    TEST_CHECK(source->record_pool_blocks == 8);
    for (index = 0; index < sizeof(moved) / sizeof(moved[0]); index++) {
        cfl_list_del(&records[moved[index]]->_head);
        cfl_list_add(&records[moved[index]]->_head, &destination->records);
    }
    TEST_CHECK(flb_mp_chunk_cobj_destroy(source) == 0);
    for (index = 0; index < sizeof(moved) / sizeof(moved[0]); index++) {
        TEST_CHECK(records[moved[index]]->modified == moved[index]);
    }
    TEST_CHECK(flb_mp_chunk_cobj_destroy(destination) == 0);
    flb_log_event_encoder_destroy(encoder);
}

static void scratch_encode_preserves_field_boundaries(void)
{
    struct flb_log_event_encoder *builder;
    struct flb_log_event_encoder *encoder;
    struct flb_log_event_decoder decoder;
    struct flb_log_event_decoder verify;
    struct flb_log_event event;
    struct flb_mp_chunk_cobj *chunk;
    struct flb_mp_chunk_record *record;
    struct flb_time timestamp;
    char payload[9000];
    size_t lengths[] = {0, 1, sizeof(payload), 2};
    size_t length;
    size_t index;
    char *output;
    size_t output_size;
    int ret;

    memset(payload, 0xff, sizeof(payload));
    payload[1] = '\0';
    builder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(builder != NULL && encoder != NULL);
    flb_time_set(&timestamp, 1, 0);
    for (index = 0; index < 16; index++) {
        length = lengths[index % 4];
        TEST_ASSERT(flb_log_event_encoder_begin_record(builder) == 0);
        TEST_ASSERT(flb_log_event_encoder_set_timestamp(builder, &timestamp) == 0);
        if (index % 2) {
            ret = flb_log_event_encoder_append_metadata_values(builder,
                FLB_LOG_EVENT_CSTRING_VALUE("text"), FLB_LOG_EVENT_STRING_VALUE(payload, length));
            TEST_ASSERT(ret == 0);
        }
        ret = flb_log_event_encoder_append_body_values(builder,
            FLB_LOG_EVENT_CSTRING_VALUE("binary"), FLB_LOG_EVENT_BINARY_VALUE(payload, length));
        TEST_ASSERT(ret == 0);
        TEST_ASSERT(flb_log_event_encoder_commit_record(builder) == 0);
    }
    TEST_ASSERT(flb_log_event_decoder_init(&decoder, builder->output_buffer,
                                          builder->output_length) == 0);
    chunk = flb_mp_chunk_cobj_create(encoder, &decoder);
    TEST_ASSERT(chunk != NULL);
    flb_mp_chunk_cobj_value_pool_enable(chunk);
    TEST_ASSERT(chunk->value_pool != NULL);
    while ((ret = flb_mp_chunk_cobj_record_next(chunk, &record)) == FLB_MP_CHUNK_RECORD_OK) {
        TEST_CHECK(record->cobj_record->variant->arena == chunk->value_pool);
    }
    TEST_ASSERT(ret == FLB_MP_CHUNK_RECORD_EOF);
    TEST_ASSERT(flb_mp_chunk_cobj_encode(chunk, &output, &output_size) == 0);
    TEST_ASSERT(flb_log_event_decoder_init(&verify, output, output_size) == 0);
    index = 0;
    while (flb_log_event_decoder_next(&verify, &event) == FLB_EVENT_DECODER_SUCCESS) {
        length = lengths[index % 4];
        TEST_ASSERT(event.body->type == MSGPACK_OBJECT_MAP && event.body->via.map.size == 1);
        TEST_ASSERT(event.body->via.map.ptr[0].val.type == MSGPACK_OBJECT_BIN);
        TEST_CHECK(event.body->via.map.ptr[0].val.via.bin.size == length);
        TEST_CHECK(memcmp(event.body->via.map.ptr[0].val.via.bin.ptr, payload, length) == 0);
        TEST_ASSERT(event.metadata->type == MSGPACK_OBJECT_MAP);
        TEST_CHECK(event.metadata->via.map.size == index % 2);
        if (index % 2) {
            TEST_ASSERT(event.metadata->via.map.ptr[0].val.type == MSGPACK_OBJECT_STR);
            TEST_CHECK(event.metadata->via.map.ptr[0].val.via.str.size == length);
            TEST_CHECK(memcmp(event.metadata->via.map.ptr[0].val.via.str.ptr, payload, length) == 0);
        }
        index++;
    }
    TEST_CHECK(index == 16);
    flb_log_event_decoder_destroy(&verify);
    flb_mp_chunk_cobj_destroy(chunk);
    flb_log_event_decoder_destroy(&decoder);
    flb_log_event_encoder_destroy(builder);
    flb_log_event_encoder_destroy(encoder);
    flb_free(output);
}

static void scratch_encode_failure_releases_storage(void)
{
    struct flb_log_event_encoder *encoder;
    struct flb_log_event_decoder decoder = {0};
    struct flb_mp_chunk_cobj *chunk;
    struct flb_mp_chunk_record *record;
    char *output = NULL;
    size_t output_size = 0;

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(encoder != NULL);
    chunk = flb_mp_chunk_cobj_create(encoder, &decoder);
    TEST_ASSERT(chunk != NULL);
    record = flb_mp_chunk_record_create(chunk);
    TEST_ASSERT(record != NULL);
    record->cobj_record = cfl_object_create();
    TEST_ASSERT(record->cobj_record != NULL);
    cfl_list_add(&record->_head, &chunk->records);
    TEST_CHECK(flb_mp_chunk_cobj_encode(chunk, &output, &output_size) == -1);
    TEST_CHECK(output == NULL && output_size == 0);
    flb_mp_chunk_cobj_destroy(chunk);
    flb_log_event_encoder_destroy(encoder);
}

static void exhausted_value_pool_falls_back_to_heap(void)
{
    struct flb_log_event_encoder *builder;
    struct flb_log_event_encoder *encoder;
    struct flb_log_event_decoder decoder;
    struct flb_mp_chunk_cobj *chunk;
    struct flb_mp_chunk_record *record;
    struct flb_time timestamp;
    size_t blocks = 0;
    int ret;

    builder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    TEST_ASSERT(builder != NULL && encoder != NULL);
    flb_time_set(&timestamp, 1, 0);
    TEST_ASSERT(flb_log_event_encoder_begin_record(builder) == 0);
    TEST_ASSERT(flb_log_event_encoder_set_timestamp(builder, &timestamp) == 0);
    ret = flb_log_event_encoder_append_body_values(builder,
        FLB_LOG_EVENT_CSTRING_VALUE("message"), FLB_LOG_EVENT_CSTRING_VALUE("preserved"));
    TEST_ASSERT(ret == 0);
    TEST_ASSERT(flb_log_event_encoder_commit_record(builder) == 0);
    TEST_ASSERT(flb_log_event_decoder_init(&decoder, builder->output_buffer,
                                          builder->output_length) == 0);
    chunk = flb_mp_chunk_cobj_create(encoder, &decoder);
    TEST_ASSERT(chunk != NULL);
    flb_mp_chunk_cobj_value_pool_enable(chunk);
    TEST_ASSERT(chunk->value_pool != NULL);
    TEST_CHECK(flb_mp_chunk_cobj_value_pool_get(chunk, SIZE_MAX) == NULL);
    /* Trees already in the pool can grow past the budget; new trees cannot */
    while (blocks < 80 && cfl_arena_malloc(chunk->value_pool, 16384) != NULL) {
        blocks++;
    }
    TEST_CHECK(blocks == 80);
    TEST_CHECK(chunk->value_pool_bytes > 1024 * 1024);
    TEST_CHECK(flb_mp_chunk_cobj_value_pool_get(chunk, 512) == NULL);
    TEST_ASSERT(flb_mp_chunk_cobj_record_next(chunk, &record) == FLB_MP_CHUNK_RECORD_OK);
    TEST_CHECK(record->cobj_record->variant->arena == NULL);
    TEST_CHECK(record->cobj_metadata->variant->arena == NULL);
    TEST_CHECK(cfl_kvlist_contains(record->cobj_record->variant->data.as_kvlist, "message") == 1);
    flb_mp_chunk_cobj_destroy(chunk);
    flb_log_event_decoder_destroy(&decoder);
    flb_log_event_encoder_destroy(builder);
    flb_log_event_encoder_destroy(encoder);
}

TEST_LIST = {
    { "exhausted_value_pool_heap_fallback", exhausted_value_pool_falls_back_to_heap },
    { "bounded_record_pool_moved_lifetime", bounded_record_pool_preserves_moved_records },
    { "scratch_encode_field_boundaries", scratch_encode_preserves_field_boundaries },
    { "scratch_encode_failure_cleanup", scratch_encode_failure_releases_storage },
    { "decoder_groups_cobj", decoder_groups_cobj },
    { "record_next_condition_filter", record_next_condition_filter },
    { 0 }
};

