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

#include <ctraces/ctraces.h>

struct ctrace_scope_span *ctr_scope_span_create(struct ctrace_resource_span *resource_span)
{
    struct ctrace_scope_span *scope_span;

    scope_span = calloc(1, sizeof(struct ctrace_scope_span));
    if (!scope_span) {
        ctr_errno();
        return NULL;
    }
    cfl_list_init(&scope_span->spans);
    cfl_list_add(&scope_span->_head, &resource_span->scope_spans);
    scope_span->resource_span = resource_span;

    return scope_span;
}

void ctr_scope_span_destroy(struct ctrace_scope_span *scope_span)
{
    struct cfl_list *tmp;
    struct cfl_list *head;
    struct ctrace_span *span;

    /* release instrumentation scope if set */
    if (scope_span->instrumentation_scope) {
        ctr_instrumentation_scope_destroy(scope_span->instrumentation_scope);
    }

    /* remove linked spans */
    cfl_list_foreach_safe(head, tmp, &scope_span->spans) {
        span = cfl_list_entry(head, struct ctrace_span, _head);
        ctr_span_destroy(span);
    }

    if (scope_span->schema_url) {
        cfl_sds_destroy(scope_span->schema_url);
    }

    cfl_list_del(&scope_span->_head);
    free(scope_span);
}

/* Set the schema_url for a resource_span */
int ctr_scope_span_set_schema_url(struct ctrace_scope_span *scope_span, char *url)
{
    if (scope_span->schema_url) {
        cfl_sds_destroy(scope_span->schema_url);
    }

    scope_span->schema_url = cfl_sds_create(url);
    if (!scope_span->schema_url) {
        return -1;
    }

    return 0;
}

void ctr_scope_span_set_instrumentation_scope(struct ctrace_scope_span *scope_span,
                                              struct ctrace_instrumentation_scope *scope)
{
    /* Safeguard against leaks */
    if (scope_span->instrumentation_scope != NULL) {
        ctr_instrumentation_scope_destroy(scope_span->instrumentation_scope);
    }

    scope_span->instrumentation_scope = scope;
}

struct ctrace_instrumentation_scope *ctr_instrumentation_scope_create(char *name, char *version,
                                                                      uint32_t dropped_attr_count,
                                                                      struct ctrace_attributes *attr)
{
    struct ctrace_instrumentation_scope *ins_scope;

    ins_scope = calloc(1, sizeof(struct ctrace_instrumentation_scope));
    if (!ins_scope) {
        ctr_errno();
        return NULL;
    }

    if (name) {
        ins_scope->name = cfl_sds_create(name);
    }
    if (version) {
        ins_scope->version = cfl_sds_create(version);
    }

    ins_scope->dropped_attr_count = dropped_attr_count;
    ins_scope->attr = attr;

    return ins_scope;
}

void ctr_instrumentation_scope_destroy(struct ctrace_instrumentation_scope *ins_scope)
{
    if (ins_scope->name) {
        cfl_sds_destroy(ins_scope->name);
    }

    if (ins_scope->version) {
        cfl_sds_destroy(ins_scope->version);
    }

    if (ins_scope->attr) {
        ctr_attributes_destroy(ins_scope->attr);
    }

    free(ins_scope);
}

