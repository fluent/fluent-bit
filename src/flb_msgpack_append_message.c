/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2023 The Fluent Bit Authors
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

#include <fluent-bit/flb_msgpack_append_message.h>

int flb_msgpack_append_message_to_record(char **result_buffer,
                                         size_t *result_size,
                                         flb_sds_t message_key_name,
                                         char *base_object_buffer,
                                         size_t base_object_size,
                                         char *message_buffer,
                                         size_t message_size,
                                         int message_type)
{
    int                result = FLB_MAP_NOT_MODIFIED;
    char              *modified_data_buffer;
    int                modified_data_size;
    msgpack_object_kv *new_map_entries[1];
    msgpack_object_kv  message_entry;
    *result_buffer = NULL;
    *result_size = 0;
    modified_data_buffer = NULL;

    if (message_key_name != NULL) {
        new_map_entries[0] = &message_entry;

        message_entry.key.type = MSGPACK_OBJECT_STR;
        message_entry.key.via.str.size = flb_sds_len(message_key_name);
        message_entry.key.via.str.ptr  = message_key_name;

        if (message_type == MSGPACK_OBJECT_BIN) {
            message_entry.val.type = MSGPACK_OBJECT_BIN;
            message_entry.val.via.bin.size = message_size;
            message_entry.val.via.bin.ptr  = message_buffer;
        }
        else if (message_type == MSGPACK_OBJECT_STR) {
            message_entry.val.type = MSGPACK_OBJECT_STR;
            message_entry.val.via.str.size = message_size;
            message_entry.val.via.str.ptr  = message_buffer;
        }
        else {
            result = FLB_MAP_EXPANSION_INVALID_VALUE_TYPE;
        }

        if (result == FLB_MAP_NOT_MODIFIED) {
            result = flb_msgpack_expand_map(base_object_buffer,
                                            base_object_size,
                                            new_map_entries, 1,
                                            &modified_data_buffer,
                                            &modified_data_size);
            if (result == 0) {
                result = FLB_MAP_EXPAND_SUCCESS;
            }
            else {
                result = FLB_MAP_EXPANSION_ERROR;
            }
        }
    }

    if (result == FLB_MAP_EXPAND_SUCCESS) {
        *result_buffer = modified_data_buffer;
        *result_size = modified_data_size;
    }

    return result;
}
