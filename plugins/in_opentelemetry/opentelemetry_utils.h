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

#ifndef FLB_IN_OPENTELEMETRY_UTILS_H
#define FLB_IN_OPENTELEMETRY_UTILS_H

#include <fluent-bit/flb_input_plugin.h>

int find_map_entry_by_key(msgpack_object_map *map,
                          char *key,
                          size_t match_index,
                          int case_insensitive);

int json_payload_get_wrapped_value(msgpack_object *wrapper,
                                   msgpack_object **value,
                                   int            *type);

int hex_to_id(char *str, int len, unsigned char *out_buf, int out_size);
uint64_t convert_string_number_to_u64(char *str, size_t len);

#endif
