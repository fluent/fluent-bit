/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <lauxlib.h>
#include <ctraces/ctraces.h>

#include "calyptia_traces_to_lua.h"
#include "cfl_to_lua.h"

static void push_attributes(lua_State *L, struct ctrace_attributes *attr)
{
    struct cfl_kvlist *kvlist;

    kvlist = attr->kv;
    push_kvlist(L, kvlist);
}

static void push_instrumentation_scope(lua_State *L, struct ctrace_instrumentation_scope *ins_scope)
{
    lua_createtable(L, 0, 4);

    if (ins_scope->name) {
        push_string(L, ins_scope->name, cfl_sds_len(ins_scope->name));
        lua_setfield(L, -2, "name");
    }

    if (ins_scope->version) {
        push_string(L, ins_scope->version, cfl_sds_len(ins_scope->version));
        lua_setfield(L, -2, "version");
    }

    if (ins_scope->attr) {
        push_attributes(L, ins_scope->attr);
        lua_setfield(L, -2, "attributes");
    }

    lua_pushinteger(L, ins_scope->dropped_attr_count);
    lua_setfield(L, -2, "droppedAttributesCount");
}

static void push_id(lua_State *L, struct ctrace_id *id)
{
    cfl_sds_t encoded_id;

    if (id) {
        encoded_id = ctr_id_to_lower_base16(id);

        if (encoded_id != NULL) {
            lua_pushstring(L, encoded_id);
            cfl_sds_destroy(encoded_id);
        }
        else {
            lua_pushnil(L);
        }
    }
    else {
        lua_pushnil(L);
    }
}

static void push_events(lua_State *L, struct cfl_list *events)
{
    int count;
    struct cfl_list *head;
    struct ctrace_span_event *event;

    count = cfl_list_size(events);
    if (!count) {
      lua_pushnil(L);
      return;
    }

    lua_createtable(L, count, 0);

    cfl_list_foreach(head, events) {
        event = cfl_list_entry(head, struct ctrace_span_event, _head);

        lua_createtable(L, 0, 4);

        push_timestamp_as_string(L, event->time_unix_nano);
        lua_setfield(L, -2, "timeUnixNano");

        if (event->name) {
            push_string(L, event->name, cfl_sds_len(event->name));
        }
        else {
            lua_pushnil(L);
        }
        lua_setfield(L, -2, "name");

        if (event->attr) {
            push_attributes(L, event->attr);
        }
        else {
            lua_pushnil(L);
        }
        lua_setfield(L, -2, "attributes");

        lua_pushinteger(L, event->dropped_attr_count);
        lua_setfield(L, -2, "droppedAttributesCount");

        lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
    }
}

static void push_links(lua_State *L, struct cfl_list *links)
{
    int count;
    struct cfl_list *head;
    struct ctrace_link *link;

    count = cfl_list_size(links);
    lua_createtable(L, count, 0);

    cfl_list_foreach(head, links) {
        link = cfl_list_entry(head, struct ctrace_link, _head);

        lua_createtable(L, 0, 5);

        push_id(L, link->trace_id);
        lua_setfield(L, -2, "traceId");

        push_id(L, link->span_id);
        lua_setfield(L, -2, "spanId");

        if (link->trace_state) {
            push_string(L, link->trace_state, cfl_sds_len(link->trace_state));
            lua_setfield(L, -2, "traceState");
        }

        if (link->attr) {
            push_attributes(L, link->attr);
            lua_setfield(L, -2, "attributes");
        }

        lua_pushinteger(L, link->dropped_attr_count);
        lua_setfield(L, -2, "droppedAttributesCount");

        lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
    }
}

static void push_span(lua_State *L, struct ctrace_span *span)
{
    lua_createtable(L, 0, 13);

    push_id(L, span->trace_id);
    lua_setfield(L, -2, "traceId");

    push_id(L, span->span_id);
    lua_setfield(L, -2, "spanId");

    push_id(L, span->parent_span_id);
    lua_setfield(L, -2, "parentSpanId");

    if (span->trace_state) {
        push_string(L, span->trace_state, cfl_sds_len(span->trace_state));
        lua_setfield(L, -2, "traceState");
    }

    if (span->name) {
        push_string(L, span->name, cfl_sds_len(span->name));
        lua_setfield(L, -2, "name");
    }

    lua_pushinteger(L, span->kind);
    lua_setfield(L, -2, "kind");

    push_timestamp_as_string(L, span->start_time_unix_nano);
    lua_setfield(L, -2, "startTimeUnixNano");

    push_timestamp_as_string(L, span->end_time_unix_nano);
    lua_setfield(L, -2, "endTimeUnixNano");

    if (span->attr) {
        push_attributes(L, span->attr);
        lua_setfield(L, -2, "attributes");
    }

    lua_pushinteger(L, span->dropped_attr_count);
    lua_setfield(L, -2, "droppedAttributesCount");

    push_events(L, &span->events);
    lua_setfield(L, -2, "events");

    push_links(L, &span->links);
    lua_setfield(L, -2, "links");

    lua_createtable(L, 0, 2);
    lua_pushinteger(L, span->status.code);
    lua_setfield(L, -2, "code");
    if (span->status.message) {
        push_string(L, span->status.message, cfl_sds_len(span->status.message));
        lua_setfield(L, -2, "message");
    }
    lua_setfield(L, -2, "status");
}

static void push_spans(lua_State *L, struct ctrace_scope_span *scope_span)
{
    struct cfl_list *head;
    struct ctrace_span *span;
    size_t count;

    /* scopeSpans */
    count = cfl_list_size(&scope_span->spans);
    lua_createtable(L, count, 0);

    cfl_list_foreach(head, &scope_span->spans) {
        span = cfl_list_entry(head, struct ctrace_span, _head);

        push_span(L, span);

        size_t objlen = lua_objlen(L, -2);
        lua_rawseti(L, -2, objlen + 1);
    }
}

static void push_scope_spans(lua_State *L, struct ctrace_resource_span *resource_span)
{
    struct cfl_list *head;
    struct ctrace_scope_span *scope_span;
    size_t count;

    /* scopeSpans */
    count = cfl_list_size(&resource_span->scope_spans);
    lua_createtable(L, count, 0);

    cfl_list_foreach(head, &resource_span->scope_spans) {
        scope_span = cfl_list_entry(head, struct ctrace_scope_span, _head);

        lua_createtable(L, 0, 3);

        if (scope_span->schema_url) {
            push_string(L, scope_span->schema_url, cfl_sds_len(scope_span->schema_url));
            lua_setfield(L, -2, "schemaUrl");
        }

        push_instrumentation_scope(L, scope_span->instrumentation_scope);
        lua_setfield(L, -2, "scope");

        push_spans(L, scope_span);
        lua_setfield(L, -2, "spans");

        size_t objlen = lua_objlen(L, -2);
        lua_rawseti(L, -2, objlen + 1);
    }
}

int calyptia_traces_to_lua(lua_State *L, struct ctrace *ctx)
{
    int count;
    struct cfl_list *head;
    struct ctrace_resource_span *resource_span;
    struct ctrace_resource *resource;

    if (ctx == NULL) {
        return luaL_error(L, "Invalid trace context provided.");
    }
    /* resourceSpans */
    count = cfl_list_size(&ctx->resource_spans);
    lua_createtable(L, count, 0);

    cfl_list_foreach(head, &ctx->resource_spans) {
        resource_span = cfl_list_entry(head, struct ctrace_resource_span, _head);
        lua_createtable(L, 0, 3);

        resource = resource_span->resource;
        lua_createtable(L, 0, 2);

        if (resource->attr) {
            push_attributes(L, resource->attr);
            lua_setfield(L, -2, "attributes");
        }

        lua_pushinteger(L, resource->dropped_attr_count);
        lua_setfield(L, -2, "droppedAttributesCount");

        lua_setfield(L, -2, "resource");

        if (resource_span->schema_url) {
            push_string(L, resource_span->schema_url, cfl_sds_len(resource_span->schema_url));
            lua_setfield(L, -2, "schemaUrl");
        }

        push_scope_spans(L, resource_span);
        lua_setfield(L, -2, "scopeSpans");

        lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
    }

    return 0;
}
