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

#ifndef FLB_RA_KEY_H
#define FLB_RA_KEY_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>
#include <monkey/mk_core.h>
#include <msgpack.h>

enum ra_types {
    FLB_RA_BOOL = 0,
    FLB_RA_INT,
    FLB_RA_FLOAT,
    FLB_RA_STRING,
    FLB_RA_NULL,
    FLB_RA_BINARY
};

enum ra_storage_type {
    FLB_RA_COPY = 0,
    FLB_RA_REF
};

/* condition value types */
typedef union {
    bool boolean;
    int64_t i64;
    double f64;
    flb_sds_t string;
    flb_sds_t binary;
    struct {
        const char *buf;
        size_t len;
    } ref;
} ra_val;

/* Represent any value object */
struct flb_ra_value {
    int type;
    int storage; /* FLB_RA_COPY or FLB_RA_REF */
    msgpack_object o;
    ra_val val;
};

const char *flb_ra_value_buffer(struct flb_ra_value *v, size_t *len);

struct flb_ra_value *flb_ra_key_to_value_ext(flb_sds_t ckey,
                                             msgpack_object map,
                                             struct mk_list *subkeys,
                                             int copy);
struct flb_ra_value *flb_ra_key_to_value(flb_sds_t ckey,
                                         msgpack_object map,
                                         struct mk_list *subkeys);
void flb_ra_key_value_destroy(struct flb_ra_value *v);

int flb_ra_key_value_get(flb_sds_t ckey, msgpack_object map,
                         struct mk_list *subkeys,
                         msgpack_object **start_key,
                         msgpack_object **out_key, msgpack_object **out_val);

int flb_ra_key_strcmp(flb_sds_t ckey, msgpack_object map,
                      struct mk_list *subkeys, char *str, int len);
int flb_ra_key_regex_match(flb_sds_t ckey, msgpack_object map,
                           struct mk_list *subkeys, struct flb_regex *regex,
                           struct flb_regex_search *result);
int flb_ra_key_value_append(struct flb_ra_parser *rp, msgpack_object obj,
                            msgpack_object *in_val, msgpack_packer *mp_pck);
int flb_ra_key_value_update(struct flb_ra_parser *rp, msgpack_object obj,
                            msgpack_object *in_key, msgpack_object *in_val,
                            msgpack_packer *mp_pck);
#endif
