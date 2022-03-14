/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021 Eduardo Silva <eduardo@calyptia.com>
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

#ifndef CMT_VARIANT_H
#define CMT_VARIANT_H

#define CMT_VARIANT_STRING    1
#define CMT_VARIANT_BOOL      2
#define CMT_VARIANT_INT       3
#define CMT_VARIANT_DOUBLE    4
#define CMT_VARIANT_ARRAY     5
#define CMT_VARIANT_KVLIST    6
#define CMT_VARIANT_BYTES     7
#define CMT_VARIANT_REFERENCE 8

struct cmt_array;
struct cmt_kvlist;

struct cmt_variant {
    int type;

    union {
        cmt_sds_t as_string;
        cmt_sds_t as_bytes;
        unsigned int as_bool;
        int as_int;
        double as_double;
        void *as_reference;
        struct cmt_array *as_array;
        struct cmt_kvlist *as_kvlist;
    } data;
};

struct cmt_variant *cmt_variant_create_from_string(char *value);
struct cmt_variant *cmt_variant_create_from_bytes(char *value, size_t length);
struct cmt_variant *cmt_variant_create_from_bool(int value);
struct cmt_variant *cmt_variant_create_from_int(int value);
struct cmt_variant *cmt_variant_create_from_double(double value);
struct cmt_variant *cmt_variant_create_from_array(struct cmt_array *value);
struct cmt_variant *cmt_variant_create_from_kvlist(struct cmt_kvlist *value);
struct cmt_variant *cmt_variant_create_from_reference(void *value);
struct cmt_variant *cmt_variant_create();

void cmt_variant_destroy(struct cmt_variant *instance);

#endif