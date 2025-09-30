/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2023 The Fluent Bit Authors
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

#include <string.h>
#include <fluent-bit.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>
#include <float.h>
#include <math.h>
#include "flb_tests_internal.h"

static int msgpack_strncmp(char* str, size_t str_len, msgpack_object obj)
{
    int ret = -1;

    if (str == NULL) {
        flb_error("str is NULL");
        return -1;
    }

    switch (obj.type)  {
    case MSGPACK_OBJECT_STR:
        if (obj.via.str.size != str_len) {
            return -1;
        }
        ret = strncmp(str, obj.via.str.ptr, str_len);
        break;
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        {
            unsigned long val = strtoul(str, NULL, 10);
            if (val == (unsigned long)obj.via.u64) {
                ret = 0;
            }
        }
        break;
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        {
            long long val = strtoll(str, NULL, 10);
            if (val == (unsigned long)obj.via.i64) {
                ret = 0;
            }
        }
        break;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        {
            double val = strtod(str, NULL);
            if (fabs(val - obj.via.f64) < DBL_EPSILON) {
                ret = 0;
            }
        }
        break;
    case MSGPACK_OBJECT_BOOLEAN:
        if (obj.via.boolean) {
            if (str_len != 4 /*true*/) {
                return -1;
            }
            ret = strncasecmp(str, "true", 4);
        }
        else {
            if (str_len != 5 /*false*/) {
                return -1;
            }
            ret = strncasecmp(str, "false", 5);
        }
        break;
    default:
        flb_error("not supported");
    }

    return ret;
}

struct str_list {
    size_t size;
    char **lists;
};

static int compare_msgpack_map(msgpack_object *map, struct str_list *l)
{
    int map_size;
    int i_map;
    int i_list;
    int num = 0;

    if (!TEST_CHECK(map->type == MSGPACK_OBJECT_MAP)) {
        TEST_MSG("type is not map. type = %d", map->type);
        return -1;
    }

    map_size = map->via.map.size;
    for (i_map=0; i_map<map_size; i_map++) {
        if (!TEST_CHECK(map->via.map.ptr[i_map].key.type == MSGPACK_OBJECT_STR)) {
            TEST_MSG("key is not string. type =%d", map->via.map.ptr[i_map].key.type);
            continue;
        }
        for (i_list=0; i_list< l->size/2; i_list++)  {
            if (msgpack_strncmp(l->lists[i_list*2], strlen(l->lists[i_list*2]),
                                map->via.map.ptr[i_map].key) == 0 &&
                msgpack_strncmp(l->lists[i_list*2+1], strlen(l->lists[i_list*2+1]),
                                map->via.map.ptr[i_map].val) == 0) {
                num++;
            }
        }
    }
    if (!TEST_CHECK(num == l->size/2)) {
        msgpack_object_print(stdout, *map);
        putchar('\n');
        TEST_MSG("compare failed. matched_num=%d expect=%lu", num, l->size/2);
        return -1;
    }

    return 0;
}

static int compare_msgpack_format_fluentbit_v2(void *msgpack_data, size_t msgpack_size,
                                               struct str_list *metadata,
                                               struct str_list *body)
{
    msgpack_unpacked result;
    msgpack_object obj;
    msgpack_object root;
    size_t off = 0;
    int ret;

    if (!TEST_CHECK(msgpack_data != NULL)) {
        TEST_MSG("msgpack_data is NULL");
        return -1;
    }
    else if (!TEST_CHECK(msgpack_size > 0)) {
        TEST_MSG("msgpack_size is 0");
        return -1;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, msgpack_data, msgpack_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        /*
        msgpack_object_print(stdout, obj);
        */

        /* format v2: [[timestamp, {metadata}], {record}]*/

        if (!TEST_CHECK(root.type == MSGPACK_OBJECT_ARRAY)) {
            TEST_MSG("type is not array. type = %d", root.type);
            msgpack_unpacked_destroy(&result);
            return -1;
        }
        if (!TEST_CHECK(root.via.array.size == 2)) {
            TEST_MSG("array size error. size = %d", root.via.array.size);
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        obj = root.via.array.ptr[0]; /* [timestamp, {metadata}] */
        if (!TEST_CHECK(root.type == MSGPACK_OBJECT_ARRAY)) {
            TEST_MSG("type is not array. type = %d", root.type);
            msgpack_unpacked_destroy(&result);
            return -1;
        }
        if (!TEST_CHECK(root.via.array.size == 2)) {
            TEST_MSG("array size error. size = %d", root.via.array.size);
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        obj = root.via.array.ptr[0].via.array.ptr[0]; /* timestamp */
        if (!TEST_CHECK(obj.type == MSGPACK_OBJECT_EXT ||
                        obj.type == MSGPACK_OBJECT_POSITIVE_INTEGER)) {
            TEST_MSG("timestamp format error. type = %d", obj.type);
            msgpack_unpacked_destroy(&result);
            return -1;
        }
        obj = root.via.array.ptr[0].via.array.ptr[1]; /* metadata */
        if (!TEST_CHECK(obj.type == MSGPACK_OBJECT_MAP)) {
            TEST_MSG("type is not map. type = %d", obj.type);
            msgpack_unpacked_destroy(&result);
            return -1;
        }
        if (metadata != NULL) {
            ret = compare_msgpack_map(&obj, metadata);
            if (!TEST_CHECK(ret == 0)) {
                TEST_MSG("compare_msgpack_body failed");
                msgpack_unpacked_destroy(&result);
                return -1;
            }
        }
        else if (!TEST_CHECK(obj.via.map.size == 0)) {
            TEST_MSG("map size error. size = %d", root.via.map.size);
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        obj = root.via.array.ptr[1]; /* {record} */
        ret = compare_msgpack_map(&obj, body);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("compare_msgpack_body failed");
            msgpack_unpacked_destroy(&result);
            return -1;
        }

    }
    msgpack_unpacked_destroy(&result);

    return 0;
}

static int compare_msgpack_format_fluentbit_v1(void *msgpack_data, size_t msgpack_size,
                                               struct str_list *body)
{
    msgpack_unpacked result;
    msgpack_object obj;
    msgpack_object root;
    size_t off = 0;
    int ret;

    if (!TEST_CHECK(msgpack_data != NULL)) {
        TEST_MSG("msgpack_data is NULL");
        return -1;
    }
    else if (!TEST_CHECK(msgpack_size > 0)) {
        TEST_MSG("msgpack_size is 0");
        return -1;
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, msgpack_data, msgpack_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        /*
        msgpack_object_print(stdout, obj);
        */

        /* format v1: [timestamp, {record}]*/

        if (!TEST_CHECK(root.type == MSGPACK_OBJECT_ARRAY)) {
            TEST_MSG("type is not array. type = %d", root.type);
            msgpack_unpacked_destroy(&result);
            return -1;
        }
        if (!TEST_CHECK(root.via.array.size == 2)) {
            TEST_MSG("array size error. size = %d", root.via.array.size);
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        obj = root.via.array.ptr[0]; /* timestamp */
        if (!TEST_CHECK(obj.type == MSGPACK_OBJECT_EXT ||
                        obj.type == MSGPACK_OBJECT_POSITIVE_INTEGER)) {
            TEST_MSG("timestamp format error. type = %d", obj.type);
            msgpack_unpacked_destroy(&result);
            return -1;
        }

        obj = root.via.array.ptr[1]; /* {record} */
        ret = compare_msgpack_map(&obj, body);
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("compare_msgpack_body failed");
            msgpack_unpacked_destroy(&result);
            return -1;
        }
    }
    msgpack_unpacked_destroy(&result);

    return 0;
}


static void create_destroy()
{
    struct flb_log_event_encoder *encoder = NULL;
    int index;
    int formats[] = {
        FLB_LOG_EVENT_FORMAT_DEFAULT,
        FLB_LOG_EVENT_FORMAT_FORWARD,
        FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V1,
        FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2,
        -1,
    };

    for (index=0; formats[index] != -1; index++) {
        encoder = flb_log_event_encoder_create(formats[index]);
        if (!TEST_CHECK(encoder != NULL)) {
            TEST_MSG("%d: flb_log_event_encoder_create failed. format=%d", index, formats[index]);
        }
        flb_log_event_encoder_destroy(encoder);
    }
}

static void create_unsupported_format()
{
    struct flb_log_event_encoder *encoder = NULL;
    int index;
    int formats[] = {
        FLB_LOG_EVENT_FORMAT_UNKNOWN,
        FLB_LOG_EVENT_FORMAT_FORWARD_LEGACY,
        -1,
    };

    for (index=0; formats[index] != -1; index++) {
        encoder = flb_log_event_encoder_create(formats[index]);
        if (!TEST_CHECK(encoder == NULL)) {
            TEST_MSG("%d: flb_log_event_encoder_create should be failed. format=%d", index, formats[index]);
            flb_log_event_encoder_destroy(encoder);
        }
    }
}

static void init_destroy()
{
    struct flb_log_event_encoder encoder;
    int index;
    int ret;
    int formats[] = {
        FLB_LOG_EVENT_FORMAT_DEFAULT,
        FLB_LOG_EVENT_FORMAT_FORWARD,
        FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V1,
        FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2,
        -1,
    };

    for (index=0; formats[index] != -1; index++) {
        ret = flb_log_event_encoder_init(&encoder, formats[index]);
        if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
            TEST_MSG("%d: flb_log_event_encoder_init failed. format=%d", index, formats[index]);
        }
        flb_log_event_encoder_destroy(&encoder);
    }
}

static void init_unsupported_format()
{
    struct flb_log_event_encoder encoder;
    int index;
    int ret;
    int formats[] = {
        FLB_LOG_EVENT_FORMAT_UNKNOWN,
        FLB_LOG_EVENT_FORMAT_FORWARD_LEGACY,
        -1,
    };

    for (index=0; formats[index] != -1; index++) {
        ret = flb_log_event_encoder_init(&encoder, formats[index]);
        if (!TEST_CHECK(ret != FLB_EVENT_ENCODER_SUCCESS)) {
            TEST_MSG("%d: flb_log_event_encoder_init should be failed. format=%d", index, formats[index]);
        }
    }
}

static void basic_format_fluent_bit_v2()
{
    struct flb_log_event_encoder encoder;
    int ret;
    char *expected_strs[] = {"key1", "value1", "key2", "value2"};
    struct str_list expected_body = {
                     .size = sizeof(expected_strs)/sizeof(char*),
                     .lists = &expected_strs[0],
    };

    ret = flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_init failed");
        return;
    }

    ret = flb_log_event_encoder_begin_record(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_begin_record failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_set_current_timestamp(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_set_current_timestamp failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_append_body_values(
                &encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("key1"),
                FLB_LOG_EVENT_CSTRING_VALUE("value1"),

                FLB_LOG_EVENT_STRING_VALUE("key2", (size_t)4),
                FLB_LOG_EVENT_STRING_VALUE("value2", (size_t)6));

    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_append_body_values failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_commit_record(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_commit_record failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = compare_msgpack_format_fluentbit_v2(encoder.output_buffer, encoder.output_length,
                                              NULL, &expected_body);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare error");
    }

    flb_log_event_encoder_destroy(&encoder);
}

static void basic_format_fluent_bit_v1()
{
    struct flb_log_event_encoder encoder;
    int ret;
    char *expected_strs[] = {"key1", "value1", "key2", "value2"};
    struct str_list expected_body = {
                     .size = sizeof(expected_strs)/sizeof(char*),
                     .lists = &expected_strs[0],
    };

    ret = flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V1);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_init failed");
        return;
    }

    ret = flb_log_event_encoder_begin_record(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_begin_record failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_set_current_timestamp(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_set_current_timestamp failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_append_body_values(
                &encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("key1"),
                FLB_LOG_EVENT_CSTRING_VALUE("value1"),

                FLB_LOG_EVENT_STRING_VALUE("key2", (size_t)4),
                FLB_LOG_EVENT_STRING_VALUE("value2", (size_t)6));

    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_append_body_values failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_commit_record(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_commit_record failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = compare_msgpack_format_fluentbit_v1(encoder.output_buffer, encoder.output_length,
                                              &expected_body);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare error");
    }

    flb_log_event_encoder_destroy(&encoder);
}

static void basic_metadata_format_fluent_bit_v2()
{
    struct flb_log_event_encoder encoder;
    int ret;
    char *expected_strs_body[] = {"key1", "value1", "key2", "value2"};
    struct str_list expected_body = {
                     .size = sizeof(expected_strs_body)/sizeof(char*),
                     .lists = &expected_strs_body[0],
    };
    char *expected_strs_metadata[] = {"version", "2.1", "debug", "false"};
    struct str_list expected_metadata = {
                     .size = sizeof(expected_strs_metadata)/sizeof(char*),
                     .lists = &expected_strs_metadata[0],
    };


    ret = flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_init failed");
        return;
    }

    ret = flb_log_event_encoder_begin_record(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_begin_record failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_set_current_timestamp(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_set_current_timestamp failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_append_body_values(
                &encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("key1"),
                FLB_LOG_EVENT_CSTRING_VALUE("value1"),

                FLB_LOG_EVENT_STRING_VALUE("key2", (size_t)4),
                FLB_LOG_EVENT_STRING_VALUE("value2", (size_t)6));

    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_append_body_values failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_append_metadata_values(
                &encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("version"),
                FLB_LOG_EVENT_DOUBLE_VALUE(2.1),

                FLB_LOG_EVENT_STRING_VALUE("debug", 5),
                FLB_LOG_EVENT_BOOLEAN_VALUE(FLB_FALSE));
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_append_metadata_values failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }


    ret = flb_log_event_encoder_commit_record(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_commit_record failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = compare_msgpack_format_fluentbit_v2(encoder.output_buffer, encoder.output_length,
                                              &expected_metadata, &expected_body);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("compare error");
    }

    flb_log_event_encoder_destroy(&encoder);
}

static void emit_raw_record()
{
    struct flb_log_event_encoder encoder;
    int ret;
    int unused_type = 0;
    char *json = "{\"key\":\"value\"}";
    char *buf = NULL;
    size_t buf_size = 0;

    ret = flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_init failed");
        return;
    }

    if (!TEST_CHECK(encoder.output_length == 0)) {
        TEST_MSG("output_length is not 0");
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_begin_record(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_begin_record failed. ret=%d", ret);
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_set_current_timestamp(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_set_current_timestamp failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_pack_json(json, strlen(json), &buf, &buf_size, &unused_type, NULL);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_pack_json failed. ret=%d", ret);
        flb_log_event_encoder_destroy(&encoder);
        return;
    }
    if (!TEST_CHECK(buf_size > 0)) {
        TEST_MSG("msgpack size is 0");
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_emit_raw_record(&encoder, buf, buf_size);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_emit_raw_record failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_free(buf);
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_commit_record(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_commit_record failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_free(buf);
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    if (!TEST_CHECK(encoder.output_length > 0)) {
        TEST_MSG("output_length is 0");
    }
    flb_free(buf);
    flb_log_event_encoder_destroy(&encoder);
}

/* Validate that an empty map can be used as a metadata value */
static void metadata_with_empty_map()
{
    struct flb_log_event_encoder encoder;
    msgpack_unpacked             result;
    msgpack_object               root;
    msgpack_object               metadata;
    int                          ret;
    size_t                       off = 0;

    ret = flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_init failed");
        return;
    }

    ret = flb_log_event_encoder_begin_record(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_begin_record failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_set_current_timestamp(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_set_current_timestamp failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    /* append the metadata key */
    ret = flb_log_event_encoder_append_metadata_values(
                &encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("otlp"));
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_append_metadata_values failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    /* open and immediately close an empty map as the value */
    ret = flb_log_event_encoder_begin_map(&encoder, FLB_LOG_EVENT_METADATA);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_begin_map for empty map failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_commit_map(&encoder, FLB_LOG_EVENT_METADATA);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_commit_map for empty map failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    ret = flb_log_event_encoder_commit_record(&encoder);
    if (!TEST_CHECK(ret == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_commit_record failed. ret=%s",
                 flb_log_event_encoder_get_error_description(ret));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, encoder.output_buffer,
                            encoder.output_length, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;

        if (!TEST_CHECK(root.type == MSGPACK_OBJECT_ARRAY && root.via.array.size == 2)) {
            TEST_MSG("root type error");
        }
        else {
            metadata = root.via.array.ptr[0].via.array.ptr[1];

            if (!TEST_CHECK(metadata.type == MSGPACK_OBJECT_MAP && metadata.via.map.size == 1)) {
                TEST_MSG("metadata map size error");
            }
            else {
                if (!TEST_CHECK(msgpack_strncmp("otlp", 4,
                                               metadata.via.map.ptr[0].key) == 0)) {
                    TEST_MSG("metadata key mismatch");
                }

                if (!TEST_CHECK(metadata.via.map.ptr[0].val.type == MSGPACK_OBJECT_MAP &&
                                metadata.via.map.ptr[0].val.via.map.size == 0)) {
                    TEST_MSG("metadata value is not empty map");
                }
            }
        }
    }
    else {
        TEST_MSG("msgpack unpack failed");
    }

    msgpack_unpacked_destroy(&result);

    flb_log_event_encoder_destroy(&encoder);
}

/* This test case encodes a log event with a specific timestamp
 * value and then it checks the raw data to ensure that regardless
 * of the host byte order the value is encoded in network order.
 */
static void timestamp_encoding()
{
    uint8_t                     *encoder_buffer;
    struct flb_time              timestamp;
    struct flb_log_event_encoder encoder;
    int                          result;
    size_t                       index;

    timestamp.tm.tv_sec  = 0x00C0FFEE;
    timestamp.tm.tv_nsec = 0;

    result = flb_log_event_encoder_init(&encoder,
                                        FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    if (!TEST_CHECK(result == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_init failed");
        return;
    }

    result = flb_log_event_encoder_begin_record(&encoder);
    if (!TEST_CHECK(result == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_begin_record failed. result=%s",
                 flb_log_event_encoder_get_error_description(result));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    result = flb_log_event_encoder_set_timestamp(&encoder, &timestamp);
    if (!TEST_CHECK(result == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_set_current_timestamp failed. result=%s",
                 flb_log_event_encoder_get_error_description(result));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    result = flb_log_event_encoder_append_body_values(
                &encoder,
                FLB_LOG_EVENT_CSTRING_VALUE("test"),
                FLB_LOG_EVENT_CSTRING_VALUE("value"));

    if (!TEST_CHECK(result == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_append_body_values failed. result=%s",
                 flb_log_event_encoder_get_error_description(result));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    result = flb_log_event_encoder_commit_record(&encoder);
    if (!TEST_CHECK(result == FLB_EVENT_ENCODER_SUCCESS)) {
        TEST_MSG("flb_log_event_encoder_commit_record failed. result=%s",
                 flb_log_event_encoder_get_error_description(result));
        flb_log_event_encoder_destroy(&encoder);
        return;
    }

    encoder_buffer = (uint8_t *) encoder.output_buffer;

    result = FLB_FALSE;

    for (index = 0 ; index < encoder.output_length  - 4 ; index++) {
        if (encoder_buffer[index + 0] == 0x00 &&
            encoder_buffer[index + 1] == 0xC0 &&
            encoder_buffer[index + 2] == 0xFF &&
            encoder_buffer[index + 3] == 0xEE) {
            result = FLB_TRUE;

            break;
        }
    }

    if (!TEST_CHECK(result == FLB_TRUE)) {
        TEST_MSG("timestamp value not encoded in network order");
    }

    flb_log_event_encoder_destroy(&encoder);
}

TEST_LIST = {
    { "basic_format_fluent_bit_v2", basic_format_fluent_bit_v2},
    { "basic_format_fluent_bit_v1", basic_format_fluent_bit_v1},
    { "basic_metadata_format_fluent_bit_v2", basic_metadata_format_fluent_bit_v2},
    { "create_destroy", create_destroy},
    { "create_unsupported_format", create_unsupported_format},
    { "init_destroy", init_destroy},
    { "init_unsupported_format", init_unsupported_format},
    { "emit_raw_record", emit_raw_record},
    { "metadata_with_empty_map", metadata_with_empty_map},
    { "timestamp_encoding", timestamp_encoding},
    { NULL, NULL }
};
