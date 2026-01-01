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

#ifndef FLB_OUT_DATADOG_REMAP_H
#define FLB_OUT_DATADOG_REMAP_H

#include "datadog.h"

typedef int (*dd_attr_remap_to_tag_fn)(const char*, msgpack_object, flb_sds_t*);

struct dd_attr_tag_remapping {
    char* origin_attr_name; /* original attribute name */
    char* remap_tag_name;   /* tag name to remap to */
    dd_attr_remap_to_tag_fn remap_to_tag;  /* remapping function */
};

extern const struct dd_attr_tag_remapping remapping[];

int dd_attr_need_remapping(const msgpack_object key, const msgpack_object val);

#endif // FLB_OUT_DATADOG_REMAP_H
