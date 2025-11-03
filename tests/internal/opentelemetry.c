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

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

// #include "../../plugins/in_opentelemetry/opentelemetry.h"
#include <fluent-bit/flb_opentelemetry.h>
#include <ctraces/ctraces.h>
#include <msgpack.h>
#include <string.h>

#include "flb_tests_internal.h"

// Remove the error_map struct and otel_error_map array from here
// as they will be moved to flb_opentelemetry.h

/* --------------------------------------------------------------- */
/* Helpers                                                        */
/* --------------------------------------------------------------- */

/* Structure to hold a single record */
struct test_record {
    char *metadata;
    char *body;
};

/* Structure to hold a single group */
struct test_group {
    char *metadata;
    char *body;
    struct test_record *records;
    size_t record_count;
};

/* Structure to hold the complete test output */
struct test_output {
    struct test_group *groups;
    size_t group_count;
};

static void free_test_output(struct test_output *output)
{
    size_t i, j;

    if (!output) {
        return;
    }

    for (i = 0; i < output->group_count; i++) {
        if (output->groups[i].metadata) {
            flb_free(output->groups[i].metadata);
        }
        if (output->groups[i].body) {
            flb_free(output->groups[i].body);
        }
        for (j = 0; j < output->groups[i].record_count; j++) {
            if (output->groups[i].records[j].metadata) {
                flb_free(output->groups[i].records[j].metadata);
            }
            if (output->groups[i].records[j].body) {
                flb_free(output->groups[i].records[j].body);
            }
        }
        if (output->groups[i].records) {
            flb_free(output->groups[i].records);
        }
    }
    if (output->groups) {
        flb_free(output->groups);
    }

    flb_free(output);
}

static struct test_output *parse_test_output(void *chunk, size_t size)
{
    struct flb_log_event_decoder dec;
    struct flb_log_event event;
    struct test_output *output;
    int ret;
    int32_t record_type;
    size_t group_idx = 0;
    size_t record_idx = 0;
    int in_group = 0;
    size_t *record_counts = NULL;

    if (size <= 0) {
        return NULL;
    }

    output = flb_calloc(1, sizeof(struct test_output));
    if (!output) {
        return NULL;
    }

    ret = flb_log_event_decoder_init(&dec, chunk, size);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    flb_log_event_decoder_read_groups(&dec, FLB_TRUE);

    /* First pass: count groups and records */
    while ((ret = flb_log_event_decoder_next(&dec, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_decoder_get_record_type(&event, &record_type);
        if (ret != 0) {
            flb_log_event_decoder_destroy(&dec);
            flb_free(record_counts);
            free_test_output(output);
            return NULL;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            size_t *tmp;

            output->group_count++;
            tmp = flb_realloc(record_counts, sizeof(size_t) * output->group_count);
            if (!tmp) {
                flb_log_event_decoder_destroy(&dec);
                flb_free(record_counts);
                free_test_output(output);
                return NULL;
            }
            record_counts = tmp;
            record_counts[output->group_count - 1] = 0;
            in_group = 1;
        }
        else if (record_type == FLB_LOG_EVENT_NORMAL && in_group) {
            record_counts[output->group_count - 1]++;
        }
        else if (record_type == FLB_LOG_EVENT_GROUP_END) {
            in_group = 0;
        }
    }

    /* Allocate groups */
    if (output->group_count > 0) {
        size_t i;

        output->groups = flb_calloc(output->group_count, sizeof(struct test_group));
        if (!output->groups) {
            flb_log_event_decoder_destroy(&dec);
            flb_free(record_counts);
            free_test_output(output);
            return NULL;
        }

        for (i = 0; i < output->group_count; i++) {
            output->groups[i].record_count = record_counts[i];
        }
    }

    /* Reset decoder for second pass */
    flb_log_event_decoder_destroy(&dec);
    ret = flb_log_event_decoder_init(&dec, chunk, size);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);
    flb_log_event_decoder_read_groups(&dec, FLB_TRUE);

    /* Second pass: extract data */
    while ((ret = flb_log_event_decoder_next(&dec, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_decoder_get_record_type(&event, &record_type);
        if (ret != 0) {
            flb_log_event_decoder_destroy(&dec);
            free_test_output(output);
            return NULL;
        }

        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            /* Group header */
            if (group_idx < output->group_count) {
                output->groups[group_idx].metadata = flb_msgpack_to_json_str(1024, event.metadata, FLB_TRUE);
                output->groups[group_idx].body = flb_msgpack_to_json_str(1024, event.body, FLB_TRUE);

                /* Allocate records for this group */
                if (output->groups[group_idx].record_count > 0) {
                    output->groups[group_idx].records = flb_calloc(output->groups[group_idx].record_count,
                                                                  sizeof(struct test_record));
                    if (!output->groups[group_idx].records) {
                        flb_log_event_decoder_destroy(&dec);
                        flb_free(record_counts);
                        free_test_output(output);
                        return NULL;
                    }
                }
                record_idx = 0;
                in_group = 1;
            }
        }
        else if (record_type == FLB_LOG_EVENT_NORMAL && in_group) {
            /* Log record within a group */
            if (group_idx < output->group_count &&
                record_idx < output->groups[group_idx].record_count) {
                output->groups[group_idx].records[record_idx].metadata = flb_msgpack_to_json_str(1024, event.metadata, FLB_TRUE);
                output->groups[group_idx].records[record_idx].body = flb_msgpack_to_json_str(1024, event.body, FLB_TRUE);
                record_idx++;
            }
        }
        else if (record_type == FLB_LOG_EVENT_GROUP_END) {
            /* End of group */
            group_idx++;
            in_group = 0;
        }
    }

    flb_log_event_decoder_destroy(&dec);
    flb_free(record_counts);
    return output;
}

/* Legacy helper functions for backward compatibility */
static char *get_group_metadata(void *chunk, size_t size)
{
    struct test_output *output;
    char *result = NULL;

    output = parse_test_output(chunk, size);
    if (output && output->group_count > 0 && output->groups[0].metadata) {
        result = flb_strdup(output->groups[0].metadata);
    }
    free_test_output(output);
    return result;
}

static char *get_group_body(void *chunk, size_t size)
{
    struct test_output *output;
    char *result = NULL;

    output = parse_test_output(chunk, size);
    if (output && output->group_count > 0 && output->groups[0].body) {
        result = flb_strdup(output->groups[0].body);
    }
    free_test_output(output);
    return result;
}

static char *get_log_body(void *chunk, size_t size)
{
    struct test_output *output;
    char *result = NULL;

    output = parse_test_output(chunk, size);
    if (output && output->group_count > 0 &&
        output->groups[0].record_count > 0 &&
        output->groups[0].records[0].body) {
        result = flb_strdup(output->groups[0].records[0].body);
    }
    free_test_output(output);
    return result;
}

/* New function to validate extended output structure */
static int validate_extended_output(struct test_output *actual, msgpack_object *expected)
{
    msgpack_object *groups_array;
    size_t i, j;
    int ret;

    /* Check if expected has "groups" field (new format) */
    ret = flb_otel_utils_find_map_entry_by_key(&expected->via.map, "groups", 0, FLB_TRUE);
    if (ret < 0) {
        /* Old format - not extended */
        return -1;
    }

    groups_array = &expected->via.map.ptr[ret].val;
    if (groups_array->type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    /* Validate group count */
    if (groups_array->via.array.size != actual->group_count) {
        printf("Group count mismatch: expected %zu, got %zu\n",
               (size_t)groups_array->via.array.size, actual->group_count);
        return -1;
    }

    /* Validate each group */
    for (i = 0; i < groups_array->via.array.size; i++) {
        msgpack_object *group_obj = &groups_array->via.array.ptr[i];
        msgpack_object *records_array;
        char *expected_meta, *expected_body;

        if (group_obj->type != MSGPACK_OBJECT_MAP) {
            printf("Group %zu is not a map\n", i);
            return -1;
        }

        /* Validate group metadata */
        ret = flb_otel_utils_find_map_entry_by_key(&group_obj->via.map, "metadata", 0, FLB_TRUE);
        if (ret >= 0) {
            expected_meta = flb_msgpack_to_json_str(256, &group_obj->via.map.ptr[ret].val, FLB_TRUE);
            if (strcmp(expected_meta, actual->groups[i].metadata) != 0) {
                printf("Group %zu metadata mismatch:\nExpected: %s\nGot: %s\n",
                       i, expected_meta, actual->groups[i].metadata);
                flb_free(expected_meta);
                return -1;
            }
            flb_free(expected_meta);
        }

        /* Validate group body */
        ret = flb_otel_utils_find_map_entry_by_key(&group_obj->via.map, "body", 0, FLB_TRUE);
        if (ret >= 0) {
            expected_body = flb_msgpack_to_json_str(256, &group_obj->via.map.ptr[ret].val, FLB_TRUE);
            if (strcmp(expected_body, actual->groups[i].body) != 0) {
                printf("Group %zu body mismatch:\nExpected: %s\nGot: %s\n",
                       i, expected_body, actual->groups[i].body);
                flb_free(expected_body);
                return -1;
            }
            flb_free(expected_body);
        }

        /* Validate records */
        ret = flb_otel_utils_find_map_entry_by_key(&group_obj->via.map, "records", 0, FLB_TRUE);
        if (ret >= 0) {
            records_array = &group_obj->via.map.ptr[ret].val;
            if (records_array->type != MSGPACK_OBJECT_ARRAY) {
                printf("Group %zu records is not an array\n", i);
                return -1;
            }

            if (records_array->via.array.size != actual->groups[i].record_count) {
                printf("Group %zu record count mismatch: expected %u, got %zu\n",
                       i, (unsigned int)records_array->via.array.size, actual->groups[i].record_count);
                return -1;
            }

            /* Validate each record */
            for (j = 0; j < records_array->via.array.size; j++) {
                msgpack_object *record_obj = &records_array->via.array.ptr[j];
                char *expected_meta, *expected_body;

                if (record_obj->type != MSGPACK_OBJECT_MAP) {
                    printf("Group %zu record %zu is not a map\n", i, j);
                    return -1;
                }

                /* Validate record metadata */
                ret = flb_otel_utils_find_map_entry_by_key(&record_obj->via.map, "metadata", 0, FLB_TRUE);
                if (ret >= 0) {
                    expected_meta = flb_msgpack_to_json_str(256, &record_obj->via.map.ptr[ret].val, FLB_TRUE);
                    if (strcmp(expected_meta, actual->groups[i].records[j].metadata) != 0) {
                        printf("Group %zu record %zu metadata mismatch:\nExpected: %s\nGot: %s\n",
                               i, j, expected_meta, actual->groups[i].records[j].metadata);
                        flb_free(expected_meta);
                        return -1;
                    }
                    flb_free(expected_meta);
                }

                /* Validate record body */
                ret = flb_otel_utils_find_map_entry_by_key(&record_obj->via.map, "body", 0, FLB_TRUE);
                if (ret >= 0) {
                    expected_body = flb_msgpack_to_json_str(256, &record_obj->via.map.ptr[ret].val, FLB_TRUE);
                    if (strcmp(expected_body, actual->groups[i].records[j].body) != 0) {
                        printf("Group %zu record %zu body mismatch:\nExpected: %s\nGot: %s\n",
                               i, j, expected_body, actual->groups[i].records[j].body);
                        flb_free(expected_body);
                        return -1;
                    }
                    flb_free(expected_body);
                }
            }
        }
    }

    return 0;
}

/* --------------------------------------------------------------- */
/* Unit tests                                                     */
/* --------------------------------------------------------------- */

void test_hex_to_id()
{
    unsigned char out[16];
    int ret;
    const char *hex = "000102030405060708090a0b0c0d0e0f";
    unsigned char expect[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    ret = flb_otel_utils_hex_to_id((char *)hex, strlen(hex), out, sizeof(out));
    TEST_CHECK(ret == 0);
    TEST_CHECK(memcmp(out, expect, sizeof(expect)) == 0);
}

void test_hex_to_id_error_cases()
{
    unsigned char out[16];
    int ret;

    /* Test zero length string */
    ret = flb_otel_utils_hex_to_id("", 0, out, 16);
    TEST_CHECK(ret == 0); /* Zero length should succeed (empty output) */

    /* Test odd length string */
    ret = flb_otel_utils_hex_to_id("123", 3, out, 16);
    TEST_CHECK(ret == -1); /* Odd length should fail */

    /* Test invalid hex character */
    ret = flb_otel_utils_hex_to_id("0000000000000000000000000000000G", 32, out, 16);
    TEST_CHECK(ret == -1); /* Invalid hex character should fail */

    /* Test mixed valid/invalid hex */
    ret = flb_otel_utils_hex_to_id("0000000000000000000000000000000Z", 32, out, 16);
    TEST_CHECK(ret == -1); /* Invalid hex character should fail */

    /* Test valid hex with wrong output size */
    ret = flb_otel_utils_hex_to_id("00000000000000000000000000000001", 32, out, 8);
    TEST_CHECK(ret == 0); /* Should succeed even with larger output buffer */

    /* Test valid hex with correct size */
    ret = flb_otel_utils_hex_to_id("0000000000000001", 16, out, 8);
    TEST_CHECK(ret == 0); /* Should succeed */

    /* Test valid hex with uppercase */
    ret = flb_otel_utils_hex_to_id("0000000000000000000000000000000A", 32, out, 16);
    TEST_CHECK(ret == 0); /* Should succeed with uppercase hex */

    /* Test valid hex with lowercase */
    ret = flb_otel_utils_hex_to_id("0000000000000000000000000000000a", 32, out, 16);
    TEST_CHECK(ret == 0); /* Should succeed with lowercase hex */
}

void test_convert_string_number_to_u64()
{
    uint64_t val;

    val = flb_otel_utils_convert_string_number_to_u64("123456", 6);
    TEST_CHECK(val == 123456ULL);
}

void test_find_map_entry_by_key()
{
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked up;
    int index;
    msgpack_object_map *map;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&pck, 2);
    msgpack_pack_str(&pck, 3); msgpack_pack_str_body(&pck, "foo", 3);
    msgpack_pack_int(&pck, 1);
    msgpack_pack_str(&pck, 3); msgpack_pack_str_body(&pck, "Bar", 3);
    msgpack_pack_int(&pck, 2);

    msgpack_unpacked_init(&up);
    msgpack_unpack_next(&up, sbuf.data, sbuf.size, NULL);
    map = &up.data.via.map;

    index = flb_otel_utils_find_map_entry_by_key(map, "bar", 0, FLB_TRUE);
    TEST_CHECK(index == 1);

    index = flb_otel_utils_find_map_entry_by_key(map, "bar", 0, FLB_FALSE);
    TEST_CHECK(index == -1);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&up);
}

void test_json_payload_get_wrapped_value()
{
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked up;
    msgpack_object *val;
    int type;
    int ret;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 11);
    msgpack_pack_str_body(&pck, "stringValue", 11);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "abc", 3);

    msgpack_unpacked_init(&up);
    msgpack_unpack_next(&up, sbuf.data, sbuf.size, NULL);

    ret = flb_otel_utils_json_payload_get_wrapped_value(&up.data, &val, &type);
    TEST_CHECK(ret == 0);
    TEST_CHECK(type == MSGPACK_OBJECT_STR);
    TEST_CHECK(val->type == MSGPACK_OBJECT_STR);
    TEST_CHECK(val->via.str.size == 3);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&up);

    /* Test integer value provided as a string */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 8);
    msgpack_pack_str_body(&pck, "intValue", 8);
    msgpack_pack_str(&pck, 1);
    msgpack_pack_str_body(&pck, "1", 1);

    msgpack_unpacked_init(&up);
    msgpack_unpack_next(&up, sbuf.data, sbuf.size, NULL);

    ret = flb_otel_utils_json_payload_get_wrapped_value(&up.data, &val, &type);
    TEST_CHECK(ret == 0);
    TEST_CHECK(type == MSGPACK_OBJECT_POSITIVE_INTEGER);
    TEST_CHECK(val->type == MSGPACK_OBJECT_STR);

    msgpack_sbuffer_destroy(&sbuf);
    msgpack_unpacked_destroy(&up);
}

#define OTEL_TEST_CASES_PATH      FLB_TESTS_DATA_PATH "/data/opentelemetry/logs.json"
#define OTEL_TRACES_TEST_CASES_PATH FLB_TESTS_DATA_PATH "/data/opentelemetry/traces.json"

void test_opentelemetry_cases()
{
    int ret;
    char *cases_json;
    char *tmp_buf;
    size_t tmp_size;
    int type;
    msgpack_unpacked result;
    msgpack_object *root;
    size_t i;

    cases_json = mk_file_to_buffer(OTEL_TEST_CASES_PATH);
    TEST_CHECK(cases_json != NULL);
    if (cases_json == NULL) {
        flb_error("could not read test cases from '%s'", OTEL_TEST_CASES_PATH);
        return;
    }

    ret = flb_pack_json(cases_json, strlen(cases_json), &tmp_buf, &tmp_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_error("could not convert test cases to msgpack from file '%s'", OTEL_TEST_CASES_PATH);
        flb_free(cases_json);
        return;
    }

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, tmp_buf, tmp_size, NULL);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);

    root = &result.data;
    printf("\n");

    for (i = 0; i < root->via.map.size; i++) {
        msgpack_object *case_obj;
        char *input_json;
        int error_status = 0;
        int empty_payload = FLB_FALSE;
        struct flb_log_event_encoder enc;
        msgpack_object *expected;
        msgpack_object *exp_err;
        char *meta_json = NULL;
        char *body_json = NULL;
        char *log_json = NULL;
        char *expect_group_meta = NULL;
        char *expect_group_body = NULL;
        char *expect_log_meta = NULL;
        char *expect_log_body = NULL;
        int has_groups = FLB_FALSE;
        char *case_name = NULL;

        /* put the test name in a new buffer to avoid referencing msgpack object directly */
        case_name = flb_malloc(root->via.map.ptr[i].key.via.str.size + 1);
        if (!case_name) {
            flb_errno();
            flb_free(cases_json);
            msgpack_unpacked_destroy(&result);
            return;
        }

        memcpy(case_name, root->via.map.ptr[i].key.via.str.ptr, root->via.map.ptr[i].key.via.str.size);
        case_name[root->via.map.ptr[i].key.via.str.size] = '\0';
        printf(">> running test case '%s'\n", case_name);

        case_obj = &root->via.map.ptr[i].val;

        ret = flb_otel_utils_find_map_entry_by_key(&case_obj->via.map, "input", 0, FLB_TRUE);
        TEST_CHECK(ret >= 0);
        input_json = flb_msgpack_to_json_str(1024, &case_obj->via.map.ptr[ret].val, FLB_TRUE);
        TEST_CHECK(input_json != NULL);

        ret = flb_log_event_encoder_init(&enc, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
        TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);

        /* Successful case */
        ret = flb_otel_utils_find_map_entry_by_key(&case_obj->via.map, "expected", 0, FLB_TRUE);
        if (ret >= 0) {
            expected = &case_obj->via.map.ptr[ret].val;
            has_groups = (flb_otel_utils_find_map_entry_by_key(&expected->via.map, "groups", 0, FLB_TRUE) >= 0);

            /* check if we do expect an ok but an empty response (no ingestion) */
            ret = flb_otel_utils_find_map_entry_by_key(&expected->via.map, "empty_payload", 0, FLB_TRUE);
            if (ret >= 0) {
                if (expected->via.map.ptr[ret].val.type != MSGPACK_OBJECT_BOOLEAN) {
                    flb_error("expected 'empty_payload' to be a boolean");
                    flb_free(input_json);
                    flb_log_event_encoder_destroy(&enc);
                    flb_free(case_name);
                    msgpack_unpacked_destroy(&result);
                    flb_free(cases_json);
                    return;
                }
                empty_payload = expected->via.map.ptr[ret].val.via.boolean;
            }
            else {
                /* if 'empty_payload' is not specified, we assume it's false */
                empty_payload = FLB_FALSE;
            }

            if (empty_payload == FLB_FALSE && has_groups == FLB_FALSE) {
                ret = flb_otel_utils_find_map_entry_by_key(&expected->via.map, "group_metadata", 0, FLB_TRUE);
                TEST_CHECK(ret >= 0);
                expect_group_meta = flb_msgpack_to_json_str(256, &expected->via.map.ptr[ret].val, FLB_TRUE);
                TEST_CHECK(expect_group_meta != NULL);

                ret = flb_otel_utils_find_map_entry_by_key(&expected->via.map, "group_body", 0, FLB_TRUE);
                TEST_CHECK(ret >= 0);
                expect_group_body = flb_msgpack_to_json_str(256, &expected->via.map.ptr[ret].val, FLB_TRUE);
                TEST_CHECK(expect_group_body != NULL);

                ret = flb_otel_utils_find_map_entry_by_key(&expected->via.map, "log_metadata", 0, FLB_TRUE);
                TEST_CHECK(ret >= 0);
                expect_log_meta = flb_msgpack_to_json_str(256, &expected->via.map.ptr[ret].val, FLB_TRUE);
                TEST_CHECK(expect_log_meta != NULL);

                ret = flb_otel_utils_find_map_entry_by_key(&expected->via.map, "log_body", 0, FLB_TRUE);
                TEST_CHECK(ret >= 0);
                expect_log_body = flb_msgpack_to_json_str(256, &expected->via.map.ptr[ret].val, FLB_TRUE);
                TEST_CHECK(expect_log_body != NULL);
            }

            /* try to encode the OTLP JSON as messagepack */
            ret = flb_opentelemetry_logs_json_to_msgpack(&enc, input_json, strlen(input_json), NULL, &error_status);
            TEST_CHECK_(ret == 0, "case %s", case_name);

            if (empty_payload == FLB_FALSE) {
                /* Try extended format first */
                struct test_output *actual_output = parse_test_output(enc.output_buffer, enc.output_length);
                if (actual_output) {
                    int extended_result = validate_extended_output(actual_output, expected);
                    if (extended_result == 0) {
                        /* Extended format validation succeeded */
                        free_test_output(actual_output);
                        flb_free(meta_json);
                        flb_free(body_json);
                        flb_free(log_json);
                        flb_free(expect_group_meta);
                        flb_free(expect_group_body);
                        flb_free(expect_log_meta);
                        flb_free(expect_log_body);
                        flb_log_event_encoder_destroy(&enc);
                        flb_free(input_json);
                        flb_free(case_name);
                        continue;
                    }
                    free_test_output(actual_output);
                }
                if (has_groups == FLB_FALSE) {
                    /* Fall back to legacy format validation */
                    meta_json = get_group_metadata(enc.output_buffer, enc.output_length);
                    TEST_CHECK(strcmp(meta_json, expect_group_meta) == 0);
                    if (strcmp(meta_json, expect_group_meta) != 0) {
                        TEST_MSG("group metadata mismatch: expected '%s', got '%s'",
                                 expect_group_meta, meta_json);
                    }

                    body_json = get_group_body(enc.output_buffer, enc.output_length);
                    TEST_CHECK(strcmp(body_json, expect_group_body) == 0);
                    if (strcmp(body_json, expect_group_body) != 0) {
                        TEST_MSG("group body mismatch: expected '%s', got '%s'",
                                 expect_group_body, body_json);
                    }

                    log_json = get_log_body(enc.output_buffer, enc.output_length);
                    TEST_CHECK(strcmp(log_json, expect_log_body) == 0);
                    if (strcmp(log_json, expect_log_body) != 0) {
                        TEST_MSG("log body mismatch: expected '%s', got '%s'",
                                 expect_log_body, log_json);
                    }
                }
                else {
                    TEST_CHECK_(0, "extended format validation failed: %s", case_name);
                }
            }
            else {
                /* if we expect an empty payload, there should be no metadata, body or log */
                meta_json = get_group_metadata(enc.output_buffer, enc.output_length);
                TEST_CHECK(meta_json == NULL);

                body_json = get_group_body(enc.output_buffer, enc.output_length);
                TEST_CHECK(body_json == NULL);

                log_json = get_log_body(enc.output_buffer, enc.output_length);
                TEST_CHECK(log_json == NULL);

                /* check that the output buffer is empty */
                TEST_CHECK(enc.output_length == 0);

                /* check the output status */
                TEST_CHECK(error_status == FLB_OTEL_LOGS_ERR_EMPTY_PAYLOAD);
            }

            flb_free(meta_json);
            flb_free(body_json);
            flb_free(log_json);
            flb_free(expect_group_meta);
            flb_free(expect_group_body);
            flb_free(expect_log_meta);
            flb_free(expect_log_body);
        }
        else {
            int exp_code;
            char *error_str;
            char tmp[128];
            msgpack_object *code_obj;

            ret = flb_otel_utils_find_map_entry_by_key(&case_obj->via.map, "expected_error", 0, FLB_TRUE);
            TEST_CHECK(ret >= 0);

            exp_err = &case_obj->via.map.ptr[ret].val;
            ret = flb_otel_utils_find_map_entry_by_key(&exp_err->via.map, "code", 0, FLB_TRUE);
            TEST_CHECK(ret >= 0);
            code_obj = &exp_err->via.map.ptr[ret].val;

            TEST_CHECK(code_obj->type == MSGPACK_OBJECT_STR);
            TEST_CHECK(code_obj->via.str.size < sizeof(tmp));
            memcpy(tmp, code_obj->via.str.ptr, code_obj->via.str.size);
            tmp[code_obj->via.str.size] = '\0';
            exp_code = flb_opentelemetry_error_code(tmp);

            /* try to encode it */
            ret = flb_opentelemetry_logs_json_to_msgpack(&enc, input_json, strlen(input_json), NULL, &error_status);
            TEST_CHECK_(ret < 0, "test case '%s' should fail", case_name);
            TEST_CHECK_(error_status == exp_code,
                        "expected error code=%i, returned error_status=%i (%s)",
                        exp_code, error_status,
                        flb_opentelemetry_error_to_string(error_status));
            if (error_status != exp_code) {

                flb_log_event_encoder_destroy(&enc);
                flb_free(input_json);
                flb_free(case_name);
                break;
            }

            /*
             * check that 'error_status' matches the expected error code from the JSON
             * file, convert the numeric error code into it string representation name
             */
            error_str = (char *) flb_opentelemetry_error_to_string(error_status);
            TEST_CHECK(error_str != NULL);

            memcpy(tmp, code_obj->via.str.ptr, code_obj->via.str.size);
            tmp[code_obj->via.str.size] = '\0';

            TEST_CHECK(strcmp(tmp, error_str) == 0);
        }

        flb_log_event_encoder_destroy(&enc);
        flb_free(input_json);
        flb_free(case_name);
    }

    msgpack_unpacked_destroy(&result);
    flb_free(tmp_buf);
    flb_free(cases_json);
}

void test_opentelemetry_traces_cases()
{
    int ret;
    char *cases_json;
    char *tmp_buf = NULL;
    size_t tmp_size;
    int type;
    msgpack_unpacked result;
    msgpack_object *root;
    size_t i;

    cases_json = mk_file_to_buffer(OTEL_TRACES_TEST_CASES_PATH);
    TEST_CHECK(cases_json != NULL);
    if (cases_json == NULL) {
        flb_error("could not read trace test cases from '%s'", OTEL_TRACES_TEST_CASES_PATH);
        return;
    }

    ret = flb_pack_json(cases_json, strlen(cases_json), &tmp_buf, &tmp_size, &type, NULL);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        flb_error("could not convert trace test cases to msgpack from '%s'", OTEL_TRACES_TEST_CASES_PATH);
        flb_free(cases_json);
        return;
    }

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, tmp_buf, tmp_size, NULL);
    TEST_CHECK(ret == MSGPACK_UNPACK_SUCCESS);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        flb_free(tmp_buf);
        flb_free(cases_json);
        return;
    }

    root = &result.data;

    for (i = 0; i < root->via.map.size; i++) {
        msgpack_object *case_obj;
        char *case_name;
        char *input_json = NULL;
        struct ctrace *ctr = NULL;
        int error_status = 0;
        int expect_error = FLB_FALSE;
        int expected_code = 0;

        case_name = flb_malloc(root->via.map.ptr[i].key.via.str.size + 1);
        if (!case_name) {
            flb_errno();
            continue;
        }
        memcpy(case_name,
               root->via.map.ptr[i].key.via.str.ptr,
               root->via.map.ptr[i].key.via.str.size);
        case_name[root->via.map.ptr[i].key.via.str.size] = '\0';
        printf(">> running trace test case '%s'\n", case_name);

        case_obj = &root->via.map.ptr[i].val;

        ret = flb_otel_utils_find_map_entry_by_key(&case_obj->via.map, "input", 0, FLB_TRUE);
        TEST_CHECK(ret >= 0);
        if (ret < 0) {
            flb_free(case_name);
            continue;
        }

        input_json = flb_msgpack_to_json_str(512, &case_obj->via.map.ptr[ret].val, FLB_TRUE);
        TEST_CHECK(input_json != NULL);
        if (input_json == NULL) {
            flb_free(case_name);
            continue;
        }

        ret = flb_otel_utils_find_map_entry_by_key(&case_obj->via.map, "expected_error", 0, FLB_TRUE);
        if (ret >= 0) {
            msgpack_object *exp_obj;
            int code_idx;

            exp_obj = &case_obj->via.map.ptr[ret].val;
            code_idx = flb_otel_utils_find_map_entry_by_key(&exp_obj->via.map, "code", 0, FLB_TRUE);
            TEST_CHECK(code_idx >= 0);
            if (code_idx >= 0 && exp_obj->via.map.ptr[code_idx].val.type == MSGPACK_OBJECT_STR) {
                char *code_str;

                code_str = flb_malloc(exp_obj->via.map.ptr[code_idx].val.via.str.size + 1);
                if (code_str) {
                    memcpy(code_str,
                           exp_obj->via.map.ptr[code_idx].val.via.str.ptr,
                           exp_obj->via.map.ptr[code_idx].val.via.str.size);
                    code_str[exp_obj->via.map.ptr[code_idx].val.via.str.size] = '\0';
                    expected_code = flb_opentelemetry_error_code(code_str);
                    TEST_CHECK(expected_code != -1000);
                    flb_free(code_str);
                    expect_error = FLB_TRUE;
                }
            }
        }

        ctr = flb_opentelemetry_json_traces_to_ctrace(input_json, strlen(input_json), &error_status);

        if (expect_error == FLB_TRUE) {
            TEST_CHECK_(ctr == NULL, "trace case %s should fail", case_name);
            TEST_CHECK_(error_status == expected_code,
                       "trace case %s expected status %d got %d",
                       case_name, expected_code, error_status);
        }
        else {
            TEST_CHECK_(ctr != NULL, "trace case %s should succeed", case_name);
            TEST_CHECK_(error_status == 0,
                       "trace case %s expected success status 0 got %d",
                       case_name, error_status);
        }

        if (ctr) {
            ctr_destroy(ctr);
        }

        flb_free(input_json);
        flb_free(case_name);
    }

    msgpack_unpacked_destroy(&result);
    flb_free(tmp_buf);
    flb_free(cases_json);
}

void test_trace_span_binary_sizes()
{
    int ret;
    struct flb_log_event_encoder enc;
    struct flb_log_event_decoder dec;
    struct flb_log_event event;
    int32_t record_type;
    char *input_json;
    int error_status = 0;
    int found_trace_id = 0;
    int found_span_id = 0;
    size_t trace_id_size = 0;
    size_t span_id_size = 0;
    struct flb_record_accessor *ra_trace_id;
    struct flb_record_accessor *ra_span_id;
    struct flb_ra_value *val_trace_id;
    struct flb_ra_value *val_span_id;

    /* Test input with trace_id and span_id */
    input_json = "{\"resourceLogs\":[{\"scopeLogs\":[{\"logRecords\":[{\"timeUnixNano\":\"1640995200000000000\",\"traceId\":\"5B8EFFF798038103D269B633813FC60C\",\"spanId\":\"EEE19B7EC3C1B174\",\"body\":{\"stringValue\":\"test\"}}]}]}]}";

    ret = flb_log_event_encoder_init(&enc, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS);

    ret = flb_opentelemetry_logs_json_to_msgpack(&enc, input_json, strlen(input_json), NULL, &error_status);
    TEST_CHECK(ret == 0);

    /* Create record accessors for trace_id and span_id */
    ra_trace_id = flb_ra_create("$otlp['trace_id']", FLB_FALSE);
    TEST_CHECK(ra_trace_id != NULL);

    ra_span_id = flb_ra_create("$otlp['span_id']", FLB_FALSE);
    TEST_CHECK(ra_span_id != NULL);

    /* Decode the output to check binary sizes */
    ret = flb_log_event_decoder_init(&dec, enc.output_buffer, enc.output_length);
    TEST_CHECK(ret == FLB_EVENT_DECODER_SUCCESS);

    flb_log_event_decoder_read_groups(&dec, FLB_TRUE);

    while ((ret = flb_log_event_decoder_next(&dec, &event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_decoder_get_record_type(&event, &record_type);
        TEST_CHECK(ret == 0);

        if (record_type == FLB_LOG_EVENT_NORMAL) {
            /* Use record accessor to get trace_id */
            val_trace_id = flb_ra_get_value_object(ra_trace_id, *event.metadata);
            if (val_trace_id != NULL) {
                found_trace_id = 1;
                if (val_trace_id->type == FLB_RA_BINARY) {
                    trace_id_size = flb_sds_len(val_trace_id->val.binary);
                    printf("Found trace_id with binary size: %zu\n", trace_id_size);
                    /* trace_id should be 16 bytes (32 hex chars = 16 bytes) */
                    TEST_CHECK_(trace_id_size == 16, "trace_id binary size should be 16, got %zu", trace_id_size);
                }
                else if (val_trace_id->type == FLB_RA_STRING) {
                    printf("Found trace_id as string: %s\n", val_trace_id->val.string);
                }
                flb_ra_key_value_destroy(val_trace_id);
            }

            /* Use record accessor to get span_id */
            val_span_id = flb_ra_get_value_object(ra_span_id, *event.metadata);
            if (val_span_id != NULL) {
                found_span_id = 1;
                if (val_span_id->type == FLB_RA_BINARY) {
                    span_id_size = flb_sds_len(val_span_id->val.binary);
                    printf("Found span_id with binary size: %zu\n", span_id_size);
                    /* span_id should be 8 bytes (16 hex chars = 8 bytes) */
                    TEST_CHECK_(span_id_size == 8, "span_id binary size should be 8, got %zu", span_id_size);
                }
                else if (val_span_id->type == FLB_RA_STRING) {
                    printf("Found span_id as string: %s\n", val_span_id->val.string);
                }
                flb_ra_key_value_destroy(val_span_id);
            }
        }
    }

    flb_log_event_decoder_destroy(&dec);
    flb_log_event_encoder_destroy(&enc);
    flb_ra_destroy(ra_trace_id);
    flb_ra_destroy(ra_span_id);

    TEST_CHECK(found_trace_id == 1);
    TEST_CHECK(found_span_id == 1);
}

/* Test list */
TEST_LIST = {
    { "hex_to_id", test_hex_to_id },
    { "hex_to_id_error_cases", test_hex_to_id_error_cases },
    { "convert_string_number_to_u64", test_convert_string_number_to_u64 },
    { "find_map_entry_by_key", test_find_map_entry_by_key },
    { "json_payload_get_wrapped_value", test_json_payload_get_wrapped_value },
    { "opentelemetry_cases", test_opentelemetry_cases },
    { "opentelemetry_traces_cases", test_opentelemetry_traces_cases },
    { "trace_span_binary_sizes", test_trace_span_binary_sizes },
    { 0 }
};

