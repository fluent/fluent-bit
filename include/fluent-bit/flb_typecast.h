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

#ifndef FLB_TYPECAST_H
#define FLB_TYPECAST_H

#include <fluent-bit/flb_typecast.h>
#include <fluent-bit/flb_sds.h>
#include <inttypes.h>
#include <msgpack.h>

typedef enum {
    FLB_TYPECAST_TYPE_NUMBER = 0, /* from_type only */
    FLB_TYPECAST_TYPE_INT,
    FLB_TYPECAST_TYPE_UINT,
    FLB_TYPECAST_TYPE_FLOAT,
    FLB_TYPECAST_TYPE_BOOL,
    FLB_TYPECAST_TYPE_STR,
    FLB_TYPECAST_TYPE_HEX,
    FLB_TYPECAST_TYPE_ERROR,
} flb_typecast_type_t;

struct flb_typecast_rule {
    flb_typecast_type_t from_type;
    flb_typecast_type_t to_type;
};

struct flb_typecast_value {
    flb_typecast_type_t type;
    union {
        char      boolean; /* bool */
        int64_t   i_num;   /* int  */
        uint64_t  ui_num;  /* uint, hex */
        double    d_num;   /* float */
        flb_sds_t str;     /* string */
    } val;
};

flb_typecast_type_t flb_typecast_str_to_type_t(char *type_str, int type_len);
const char * flb_typecast_type_t_to_str(flb_typecast_type_t type);
int flb_typecast_rule_destroy(struct flb_typecast_rule *rule);
struct flb_typecast_rule *flb_typecast_rule_create(char *from_type, int from_len,
                                                   char *to_type, int to_len);
int flb_typecast_value_destroy(struct flb_typecast_value* val);
struct flb_typecast_value *flb_typecast_value_create(msgpack_object input,
                                                     struct flb_typecast_rule *rule);
int flb_typecast_pack(msgpack_object input,
                      struct flb_typecast_rule *rule,
                      msgpack_packer *pck);
#endif
