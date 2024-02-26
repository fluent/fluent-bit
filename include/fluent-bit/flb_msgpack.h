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

#ifndef FLB_MSGPACK_H
#define FLB_MSGPACK_H

#include <fluent-bit/flb_sds.h>
#include <msgpack.h>

int flb_msgpack_strcmp_str_len(msgpack_object *o, char *str, size_t str_len);
int flb_msgpack_strcmp_str(msgpack_object *o, char *str);
int flb_msgpack_strcmp_sds(msgpack_object *o, flb_sds_t str);
int flb_msgpack_strcmp_msgpack_str(msgpack_object *o1, msgpack_object *o2);

msgpack_object *flb_msgpack_get_value_from_map(msgpack_object *o, char *str, size_t str_len);
msgpack_object *flb_msgpack_get_value_from_nested_map(msgpack_object *o, char **strs, size_t strs_len);

#endif /* FLB_MSGPACK_H */
