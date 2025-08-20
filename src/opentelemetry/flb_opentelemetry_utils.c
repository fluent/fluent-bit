/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_opentelemetry.h>

#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_time.h>

int flb_otel_utils_find_map_entry_by_key(msgpack_object_map *map,
                                         char *key,
                                         size_t match_index,
                                         int case_insensitive)
{
    int     result;
    int     index;
    int key_len;
    size_t  match_count;

    if (!key) {
        return -1;
    }

    key_len = strlen(key);
    match_count = 0;

    for (index = 0 ; index < (int) map->size ; index++) {
        if (key_len != map->ptr[index].key.via.str.size) {
            continue;
        }

        if (map->ptr[index].key.type == MSGPACK_OBJECT_STR) {
            if (case_insensitive) {
                result = strncasecmp(map->ptr[index].key.via.str.ptr,
                                     key,
                                     map->ptr[index].key.via.str.size);
            }
            else {
                result = strncmp(map->ptr[index].key.via.str.ptr,
                                 key,
                                 map->ptr[index].key.via.str.size);
            }

            if (result == 0) {
                if (match_count == match_index) {
                    return index;
                }

                match_count++;
            }
        }
    }

    return -1;
}

int flb_otel_utils_json_payload_get_wrapped_value(msgpack_object *wrapper,
                                                  msgpack_object **value,
                                                  int            *type)
{
    int internal_type;
    msgpack_object     *kv_value = NULL;
    msgpack_object_str *kv_key = NULL;
    msgpack_object_map *map = NULL;

    if (wrapper->type != MSGPACK_OBJECT_MAP) {
        return -1;
    }

    map = &wrapper->via.map;
    kv_value = NULL;
    internal_type = -1;

    if (map->size == 1) {
        if (map->ptr[0].key.type == MSGPACK_OBJECT_STR) {
            kv_value = &map->ptr[0].val;
            kv_key = &map->ptr[0].key.via.str;

            if (strncasecmp(kv_key->ptr, "stringValue",  kv_key->size) == 0) {
                if (kv_value->type == MSGPACK_OBJECT_NIL) {
                    internal_type = MSGPACK_OBJECT_NIL;
                }
                else if (kv_value->type != MSGPACK_OBJECT_STR) {
                    /* If the value is not a string, we cannot process it */
                    return -2;
                }
                internal_type = MSGPACK_OBJECT_STR;
            }
            else if (strncasecmp(kv_key->ptr, "boolValue",  kv_key->size) == 0) {
                if (kv_value->type != MSGPACK_OBJECT_BOOLEAN) {
                    /* If the value is not a boolean, we cannot process it */
                    return -2;
                }
                internal_type = MSGPACK_OBJECT_BOOLEAN;
            }
            else if (strncasecmp(kv_key->ptr, "intValue",  kv_key->size) == 0) {
                if (kv_value->type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
                    kv_value->type != MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                    /* If the value is not an integer, we cannot process it */
                    return -2;
                }
                internal_type = MSGPACK_OBJECT_POSITIVE_INTEGER;
            }
            else if (strncasecmp(kv_key->ptr, "doubleValue",  kv_key->size) == 0) {
                if (kv_value->type != MSGPACK_OBJECT_FLOAT32 &&
                    kv_value->type != MSGPACK_OBJECT_FLOAT64) {
                    /* If the value is not a float, we cannot process it */
                    return -2;
                }
                internal_type = MSGPACK_OBJECT_FLOAT;
            }
            else if (strncasecmp(kv_key->ptr, "bytesValue",  kv_key->size) == 0) {
                if (kv_value->type != MSGPACK_OBJECT_BIN) {
                    /* If the value is not binary, we cannot process it */
                    return -2;
                }
                internal_type = MSGPACK_OBJECT_BIN;
            }
            else if (strncasecmp(kv_key->ptr, "arrayValue",  kv_key->size) == 0) {
                if (kv_value->type != MSGPACK_OBJECT_ARRAY &&
                    kv_value->type != MSGPACK_OBJECT_MAP) {
                    /* If the value is not an array or map, we cannot process it */
                    return -2;
                }
                internal_type = MSGPACK_OBJECT_ARRAY;
            }
            else if (strncasecmp(kv_key->ptr, "kvlistValue",  kv_key->size) == 0) {
                if (kv_value->type != MSGPACK_OBJECT_MAP) {
                    /* If the value is not a map, we cannot process it */
                    return -2;
                }
                internal_type = MSGPACK_OBJECT_MAP;
            }
        }
        else {
            printf("Unsupported key type: %d\n", map->ptr[0].key.type);
        }
    }

    if (internal_type != -1) {
        if (type != NULL) {
            *type  = internal_type;
        }

        if (value != NULL) {
            *value = kv_value;
        }

        if (kv_value->type == MSGPACK_OBJECT_MAP) {
            map = &kv_value->via.map;

            if (map->size == 1) {
                kv_value = &map->ptr[0].val;
                kv_key = &map->ptr[0].key.via.str;

                if (strncasecmp(kv_key->ptr, "values", kv_key->size) == 0) {
                    if (value != NULL) {
                        *value = kv_value;
                    }
                }
                else {
                    return -3;
                }
            }
        }
    }
    else {
        return -2;
    }

    return 0;
}

int flb_otel_utils_json_payload_append_converted_value(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object)
{
    int result;

    result = FLB_EVENT_ENCODER_SUCCESS;

    switch (object->type) {
        case MSGPACK_OBJECT_BOOLEAN:
            result = flb_log_event_encoder_append_boolean(
                        encoder,
                        target_field,
                        object->via.boolean);
            break;

        case MSGPACK_OBJECT_POSITIVE_INTEGER:
            result = flb_log_event_encoder_append_uint64(
                        encoder,
                        target_field,
                        object->via.u64);
            break;
        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            result = flb_log_event_encoder_append_int64(
                        encoder,
                        target_field,
                        object->via.i64);
            break;

        case MSGPACK_OBJECT_FLOAT32:
        case MSGPACK_OBJECT_FLOAT64:
            result = flb_log_event_encoder_append_double(
                        encoder,
                        target_field,
                        object->via.f64);
            break;

        case MSGPACK_OBJECT_STR:
            /* If the string is empty or null, append an empty string */
            result = flb_log_event_encoder_append_string(
                        encoder,
                        target_field,
                        (char *) object->via.str.ptr,
                        object->via.str.size);
            break;
        case MSGPACK_OBJECT_NIL:
            /* Append a null value */
            result = flb_log_event_encoder_append_string(
                        encoder,
                        target_field,
                        "", 0);
            break;
        case MSGPACK_OBJECT_BIN:
            result = flb_log_event_encoder_append_binary(
                        encoder,
                        target_field,
                        (char *) object->via.bin.ptr,
                        object->via.bin.size);
            break;

        case MSGPACK_OBJECT_ARRAY:
            result = flb_otel_utils_json_payload_append_converted_array(
                        encoder,
                        target_field,
                        object);
            break;

        case MSGPACK_OBJECT_MAP:
            result = flb_otel_utils_json_payload_append_converted_map(
                        encoder,
                        target_field,
                        object);
            break;
        default:
            break;
    }

    return result;
}

int flb_otel_utils_json_payload_append_unwrapped_value(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object,
            int *encoder_result)
{
    char            temporary_buffer[33];
    int             unwrap_value;
    int             result;
    msgpack_object *value;
    int             type;

    result = flb_otel_utils_json_payload_get_wrapped_value(object,
                                            &value,
                                            &type);

    if (result == 0) {
        unwrap_value = FLB_FALSE;

        if (type == MSGPACK_OBJECT_STR) {
            unwrap_value = FLB_TRUE;
        }
        else if (type == MSGPACK_OBJECT_BOOLEAN) {
            unwrap_value = FLB_TRUE;
        }
        else if (type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            if (value->type == MSGPACK_OBJECT_STR) {
                memset(temporary_buffer, 0, sizeof(temporary_buffer));

                if (value->via.str.size < sizeof(temporary_buffer)) {
                    strncpy(temporary_buffer,
                            value->via.str.ptr,
                            value->via.str.size);
                }
                else {
                    strncpy(temporary_buffer,
                            value->via.str.ptr,
                            sizeof(temporary_buffer) - 1);
                }

                result = flb_log_event_encoder_append_int64(
                            encoder,
                            target_field,
                            strtoll(temporary_buffer, NULL, 10));
            }
            else {
                unwrap_value = FLB_TRUE;
            }
        }
        else if (type == MSGPACK_OBJECT_FLOAT) {
            unwrap_value = FLB_TRUE;
        }
        else if (type == MSGPACK_OBJECT_BIN) {
            unwrap_value = FLB_TRUE;
        }
        else if (type == MSGPACK_OBJECT_ARRAY) {
            result = flb_otel_utils_json_payload_append_converted_array(encoder,
                                                         target_field,
                                                         value);
        }
        else if (type == MSGPACK_OBJECT_MAP) {
            result = flb_otel_utils_json_payload_append_converted_kvlist(encoder,
                                                          target_field,
                                                          value);
        }
        else {
            return -2;
        }

        if (unwrap_value) {
            result = flb_otel_utils_json_payload_append_converted_value(encoder,
                                                                        target_field,
                                                                        value);
        }

        *encoder_result = result;

        return 0;
    }
    else {
        return -1;
    }

    return -1;
}

int flb_otel_utils_json_payload_append_converted_map(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object)
{
    int                 encoder_result;
    int                 result;
    size_t              index;
    msgpack_object_map *map;

    map = &object->via.map;

    result = flb_otel_utils_json_payload_append_unwrapped_value(
                encoder,
                target_field,
                object,
                &encoder_result);

    if (result == 0) {
        return encoder_result;
    }

    result = flb_log_event_encoder_begin_map(encoder, target_field);

    for (index = 0 ;
         index < map->size &&
         result == FLB_EVENT_ENCODER_SUCCESS;
         index++) {
        result = flb_otel_utils_json_payload_append_converted_value(
                    encoder,
                    target_field,
                    &map->ptr[index].key);

        if (result == FLB_EVENT_ENCODER_SUCCESS) {
            result = flb_otel_utils_json_payload_append_converted_value(
                        encoder,
                        target_field,
                        &map->ptr[index].val);
        }
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_map(encoder, target_field);
    }
    else {
        flb_log_event_encoder_rollback_map(encoder, target_field);
    }

    return result;
}

int flb_otel_utils_json_payload_append_converted_array(struct flb_log_event_encoder *encoder,
                                                       int target_field,
                                                       msgpack_object *object)
{
    int                   result;
    size_t                index;
    msgpack_object_array *array;

    array = &object->via.array;

    result = flb_log_event_encoder_begin_array(encoder, target_field);

    for (index = 0 ;
         index < array->size &&
         result == FLB_EVENT_ENCODER_SUCCESS;
         index++) {
        result = flb_otel_utils_json_payload_append_converted_value(
                    encoder,
                    target_field,
                    &array->ptr[index]);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_array(encoder, target_field);
    }
    else {
        flb_log_event_encoder_rollback_array(encoder, target_field);
    }

    return result;
}

int flb_otel_utils_json_payload_append_converted_kvlist(
            struct flb_log_event_encoder *encoder,
            int target_field,
            msgpack_object *object)
{
    int                   value_index;
    int                   key_index;
    int                   result;
    int                   pack_null_value = FLB_FALSE;
    int                   pack_string_value = FLB_FALSE;
    int                   pack_value = FLB_FALSE;
    size_t                index;
    msgpack_object_array *array;
    msgpack_object_map   *entry;

    array = &object->via.array;

    result = flb_log_event_encoder_begin_map(encoder, target_field);

    for (index = 0 ;
         index < array->size &&
         result == FLB_EVENT_ENCODER_SUCCESS;
         index++) {

        if (array->ptr[index].type != MSGPACK_OBJECT_MAP) {
            result = FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
        }
        else {
            entry = &array->ptr[index].via.map;

            key_index = flb_otel_utils_find_map_entry_by_key(entry, "key", 0, FLB_TRUE);

            if (key_index == -1) {
                result = FLB_EVENT_ENCODER_ERROR_INVALID_ARGUMENT;
            }

            value_index = -1;
            pack_null_value = FLB_FALSE;
            pack_string_value = FLB_FALSE;
            pack_value = FLB_FALSE;

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                value_index = flb_otel_utils_find_map_entry_by_key(entry, "value", 0, FLB_TRUE);

                if (value_index >= 0 &&
                    entry->ptr[value_index].val.type == MSGPACK_OBJECT_MAP &&
                    entry->ptr[value_index].val.via.map.size == 0) {
                    /*
                     * if value is an empty map it represents an unset value, pack as NULL
                     */
                    pack_null_value = FLB_TRUE;
                }
            }

            if (value_index == -1) {
                /*
                 * if value is missing basically is 'unset' and handle as Empty() in OTel world, in
                 * this case we just pack an empty string value
                 */
                pack_string_value = FLB_TRUE;
            }
            else if (!pack_null_value) {
                pack_value = FLB_TRUE;
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                result = flb_otel_utils_json_payload_append_converted_value(
                            encoder,
                            target_field,
                            &entry->ptr[key_index].val);
            }

            if (result == FLB_EVENT_ENCODER_SUCCESS) {
                if (pack_null_value) {
                    /* pack NULL for unset values (empty maps) */
                    result = flb_log_event_encoder_append_null(encoder, target_field);
                }
                else if (pack_string_value) {
                    /* if the value is not set, register an empty string as value */
                    result = flb_log_event_encoder_append_string(
                                encoder,
                                target_field,
                                "", 0);
                }
                else if (pack_value) {
                    /* expected value must come in a map */
                    if (entry->ptr[value_index].val.type != MSGPACK_OBJECT_MAP) {
                        result = -1;
                        break;
                    }
                    else {
                        result = flb_otel_utils_json_payload_append_converted_value(
                                    encoder,
                                    target_field,
                                    &entry->ptr[value_index].val);
                    }
                }
            }
        }
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_map(encoder, target_field);
    }
    else {
        flb_log_event_encoder_rollback_map(encoder, target_field);
    }

    return result;
}

static int hex_to_int(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    return -1;
}

/* convert an hex string to the expected id in out_size bytes */
int flb_otel_utils_hex_to_id(const char *str, int len, unsigned char *out_buf, int out_size)
{
    int i;
    int high;
    int low;

    if (len % 2 != 0) {
        return -1;
    }

    for (i = 0; i < len; i += 2) {
        if (!isxdigit(str[i]) || !isxdigit(str[i + 1])) {
            return -1;
        }

        high = hex_to_int(str[i]);
        low = hex_to_int(str[i + 1]);

        if (high == -1 || low == -1) {
            return -1;
        }

        out_buf[i / 2] = (high << 4) | low;
    }

    return 0;
}

uint64_t flb_otel_utils_convert_string_number_to_u64(char *str, size_t len)
{
    uint64_t val;
    size_t i;
    char tmp[32];

    if (len > sizeof(tmp) - 1) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        if (!isdigit((unsigned char) str[i])) {
            return 0;
        }
    }

    memcpy(tmp, str, len);
    tmp[len] = '\0';

    val = strtoull(tmp, NULL, 10);
    return val;
}
