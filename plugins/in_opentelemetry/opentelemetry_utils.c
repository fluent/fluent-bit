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

#include <fluent-bit/flb_input_plugin.h>
#include <ctype.h>

int find_map_entry_by_key(msgpack_object_map *map,
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

int json_payload_get_wrapped_value(msgpack_object *wrapper,
                                   msgpack_object **value,
                                   int            *type)
{
    int                 internal_type;
    msgpack_object     *kv_value;
    msgpack_object_str *kv_key;
    msgpack_object_map *map;

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

            if (strncasecmp(kv_key->ptr, "stringValue",  kv_key->size) == 0 ||
                strncasecmp(kv_key->ptr, "string_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_STR;
            }
            else if (strncasecmp(kv_key->ptr, "boolValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "bool_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_BOOLEAN;
            }
            else if (strncasecmp(kv_key->ptr, "intValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "int_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_POSITIVE_INTEGER;
            }
            else if (strncasecmp(kv_key->ptr, "doubleValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "double_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_FLOAT;
            }
            else if (strncasecmp(kv_key->ptr, "bytesValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "bytes_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_BIN;
            }
            else if (strncasecmp(kv_key->ptr, "arrayValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "array_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_ARRAY;
            }
            else if (strncasecmp(kv_key->ptr, "kvlistValue",  kv_key->size) == 0 ||
                     strncasecmp(kv_key->ptr, "kvlist_value", kv_key->size) == 0) {
                internal_type = MSGPACK_OBJECT_MAP;
            }
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

/* convert an hex string to the expected id (16 bytes) */
int hex_to_id(char *str, int len, unsigned char *out_buf, int out_size)
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

uint64_t convert_string_number_to_u64(char *str, size_t len)
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
