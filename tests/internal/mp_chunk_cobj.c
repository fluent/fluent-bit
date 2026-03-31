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

#include <cfl/cfl_kvlist.h>

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


TEST_LIST = {
    { "decoder_groups_cobj", decoder_groups_cobj },
    { 0 }
};

