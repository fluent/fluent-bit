/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
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


#ifndef FLB_STD_HELPER_H
#define FLB_STD_HELPER_H

#include "stackdriver.h"

int cmp_helper(msgpack_object key, const char* str, const int size);

int assign_subfield_str(msgpack_object_kv *tmp_p, const char* str, 
                        const int size, flb_sds_t *subfield);

int assign_subfield_bool(msgpack_object_kv *tmp_p, const char* str, 
                         const int size, int *subfield);

int assign_subfield_int(msgpack_object_kv *tmp_p, const char* str, 
                        const int size, int *subfield);

#endif
