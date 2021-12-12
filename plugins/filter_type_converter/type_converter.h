/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#ifndef FLB_FILTER_TYPE_CONVERTER_H
#define FLB_FILTER_TYPE_CONVERTER_H

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_typecast.h>
#include <fluent-bit/flb_record_accessor.h>

struct conv_entry {
    flb_sds_t from_key;
    struct flb_record_accessor *from_ra;
    flb_sds_t to_key;
    struct flb_typecast_rule *rule;
    struct mk_list _head;
};

struct type_converter_ctx {
    struct mk_list conv_entries;
    struct flb_filter_instance *ins;
};

#endif
