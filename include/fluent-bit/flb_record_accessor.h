/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#ifndef FLB_RECORD_ACCESSOR_H
#define FLB_RECORD_ACCESSOR_H

#include <fluent-bit/flb_info.h>
#include <monkey/mk_core.h>
#include <msgpack.h>

struct flb_record_accessor {
    size_t size_hint;
    struct mk_list list;         /* List of parsed strings */
};

struct flb_record_accessor *flb_ra_create(char *str);
void flb_ra_destroy(struct flb_record_accessor *ra);
void flb_ra_dump(struct flb_record_accessor *ra);
flb_sds_t flb_ra_translate(struct flb_record_accessor *ra,
                           char *tag, int tag_len,
                           msgpack_object map);

#endif
