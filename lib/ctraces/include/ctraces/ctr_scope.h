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

#ifndef CTR_SCOPE_SPAN_H
#define CTR_SCOPE_SPAN_H

#include <ctraces/ctraces.h>
#include <ctraces/ctr_resource.h>

struct ctrace_instrumentation_scope {
    cfl_sds_t name;
    cfl_sds_t version;
    uint32_t dropped_attr_count;      /* number of attributes that were discarded */
    struct ctrace_attributes *attr;   /* attributes */
};

struct ctrace_scope_span {
    struct ctrace_instrumentation_scope *instrumentation_scope;
    struct cfl_list spans;
    cfl_sds_t schema_url;

     /* parent resource span */
    struct ctrace_resource_span *resource_span;

    /* link to ctrace_resource_span->scope_spans list */
    struct cfl_list _head;
};

/* scope span */
struct ctrace_scope_span *ctr_scope_span_create(struct ctrace_resource_span *resource_span);
void ctr_scope_span_destroy(struct ctrace_scope_span *scope_span);
int ctr_scope_span_set_schema_url(struct ctrace_scope_span *scope_span, char *url);
void ctr_scope_span_set_instrumentation_scope(struct ctrace_scope_span *scope_span, struct ctrace_instrumentation_scope *ins_scope);

/* instrumentation scope */
struct ctrace_instrumentation_scope *ctr_instrumentation_scope_create(char *name, char *version,
                                                                      uint32_t dropped_attr_count,
                                                                      struct ctrace_attributes *attr);
void ctr_instrumentation_scope_destroy(struct ctrace_instrumentation_scope *ins_scope);

#endif

