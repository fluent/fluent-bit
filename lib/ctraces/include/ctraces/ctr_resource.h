/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#ifndef CTR_RESOURCE_H
#define CTR_RESOURCE_H

#include <ctraces/ctraces.h>

struct ctrace_resource {
    uint32_t dropped_attr_count;      /* number of attributes that were discarded */
    struct ctrace_attributes *attr;   /* attributes */
};

struct ctrace_resource_span {
    struct ctrace_resource *resource;
    struct cfl_list scope_spans;
    cfl_sds_t schema_url;
    struct cfl_list _head;               /* link to ctraces->resource_span list */
};

/* resource */
struct ctrace_resource *ctr_resource_create();
struct ctrace_resource *ctr_resource_create_default();
int ctr_resource_set_attributes(struct ctrace_resource *res, struct ctrace_attributes *attr);
void ctr_resource_set_dropped_attr_count(struct ctrace_resource *res, uint32_t count);
void ctr_resource_destroy(struct ctrace_resource *res);

/* resource_span */
struct ctrace_resource_span *ctr_resource_span_create(struct ctrace *ctx);
struct ctrace_resource *ctr_resource_span_get_resource(struct ctrace_resource_span *resource_span);
int ctr_resource_span_set_schema_url(struct ctrace_resource_span *resource_span, char *url);
void ctr_resource_span_destroy(struct ctrace_resource_span *resource_span);

#endif
