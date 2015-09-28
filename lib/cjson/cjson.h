/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015 Treasure Data Inc.
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

#ifndef FLB_JSON_H
#define FLB_JSON_H

/*
 * cJSON is a very useful project but it namespace it's getting me crazy,
 * here I defined some aliases to make it easy to read/use in our code inside
 * Fluent Bit.
 *
 * cJSON taken from:
 *
 *   https://github.com/kbranigan/cJSON
 */

#include "cJSON.h"

#define json_t                  cJSON
#define json_create_null        cJSON_CreateNull
#define json_create_true        cJSON_CreateTrue
#define json_create_false       cJSON_CreateFalse
#define json_create_bool        cJSON_CreateBool
#define json_create_number      cJSON_CreateNumber
#define json_create_string      cJSON_CreateString
#define json_create_array       cJSON_CreateArray
#define json_create_object      cJSON_CreateObject
#define json_add_to_array       cJSON_AddItemToArray
#define json_add_to_object      cJSON_AddItemToObject
#define json_parse              cJSON_Parse
#define json_print              cJSON_Print
#define json_print_unformatted  cJSON_PrintUnformatted
#define json_delete             cJSON_Delete
#define json_get_array_size     cJSON_GetArraySize
#define json_get_array_item     cJSON_GetArrayItem
#define json_get_object_item    cJSON_GetObjectItem
#define json_get_error          cJSON_GetErrorPtr

#endif
