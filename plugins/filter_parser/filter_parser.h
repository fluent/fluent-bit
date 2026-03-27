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

#ifndef FLB_FILTER_PARSER_H
#define FLB_FILTER_PARSER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

struct filter_parser {
    struct flb_parser *parser;
    struct mk_list _head;
};

struct filter_parser_ctx {
    flb_sds_t key_name;
    int    key_name_len;
    struct flb_record_accessor *ra_key;
    int    reserve_data;
    int    preserve_key;
    flb_sds_t nest_under;
    struct mk_list parsers;
    struct flb_filter_instance *ins;
};

#endif /* FLB_FILTER_PARSER_H */
