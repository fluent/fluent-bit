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


#ifndef FLB_STD_HELPER_H
#define FLB_STD_HELPER_H

#include "stackdriver.h"

/* 
 * Compare obj->via.str and str. 
 * Return FLB_TRUE if they are equal. 
 * Return FLB_FALSE if obj->type is not string or they are not equal
 */
int equal_obj_str(msgpack_object obj, const char *str, const int size);

int validate_key(msgpack_object obj, const char *str, const int size);

/* 
 * if obj->type is string, assign obj->val to subfield 
 * Otherwise leave the subfield untouched
 */
void try_assign_subfield_str(msgpack_object obj, flb_sds_t *subfield);

/* 
 * if obj->type is boolean, assign obj->val to subfield 
 * Otherwise leave the subfield untouched
 */
void try_assign_subfield_bool(msgpack_object obj, int *subfield);

/* 
 * if obj->type is valid, assign obj->val to subfield 
 * Otherwise leave the subfield untouched
 */
void try_assign_subfield_int(msgpack_object obj, int64_t *subfield);

#endif
