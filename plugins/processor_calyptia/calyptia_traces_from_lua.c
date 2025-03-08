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

#include "calyptia_traces_from_lua.h"
#include "lua_to_cfl.h"

static void lua_to_attributes(lua_State *L, struct ctrace_attributes *attr);

static struct ctrace_id *lua_to_id(lua_State *L)
{
    cfl_sds_t tmp_sds;
    struct ctrace_id *cid;

    if (lua_type(L, -1) != LUA_TSTRING) {
        return NULL;
    }

    tmp_sds = lua_to_sds(L);
    cid = ctr_id_from_base16(tmp_sds);
    cfl_sds_destroy(tmp_sds);
    return cid;
}

static void lua_to_links(lua_State *L, struct ctrace_span *span)
{
    struct ctrace_link *link;
    size_t count;
    size_t i;
    struct ctrace_id *trace_id;

    if (lua_type(L, -1) != LUA_TTABLE) {
        return;
    }

    count = lua_objlen(L, -1);
    for (i = 1; i <= count; i++) {
        lua_rawgeti(L, -1, i);

        lua_getfield(L, -1, "traceId");
        trace_id = lua_to_id(L);
        lua_pop(L, 1);

        link = ctr_link_create_with_cid(span, trace_id, span->span_id);
        ctr_id_destroy(trace_id);
        if (!link) {
          lua_pop(L, 1);
          return;
        }

        lua_getfield(L, -1, "droppedAttributesCount");
        link->dropped_attr_count = lua_to_uint(L);
        lua_pop(L, 1);

        lua_getfield(L, -1, "traceState");
        if (lua_type(L, -1) == LUA_TSTRING) {
            ctr_link_set_trace_state(link, (char *) lua_tostring(L, -1));
        }
        lua_pop(L, 1);

        lua_getfield(L, -1, "attributes");
        lua_to_attributes(L, link->attr);
        lua_pop(L, 1);

        lua_pop(L, 1); /* pop the link we just processed */
    }
}

static void lua_to_events(lua_State *L, struct ctrace_span *span)
{
    struct ctrace_span_event *event;
    size_t count;
    size_t i;
    const char *name;

    if (lua_type(L, -1) != LUA_TTABLE) {
        return;
    }

    count = lua_objlen(L, -1);
    for (i = 1; i <= count; i++) {
        lua_rawgeti(L, -1, i);

        lua_getfield(L, -1, "name");
        name = lua_tostring(L, -1);
        lua_pop(L, 1);

        event = ctr_span_event_add(span, (char *)name);
        if (!event) {
          lua_pop(L, 1);
          return;
        }

        lua_getfield(L, -1, "timeUnixNano");
        event->time_unix_nano = lua_to_uint(L);
        lua_pop(L, 1);

        lua_getfield(L, -1, "attributes");
        lua_to_attributes(L, event->attr);
        lua_pop(L, 1);

        lua_getfield(L, -1, "droppedAttributesCount");
        event->dropped_attr_count = lua_to_uint(L);
        lua_pop(L, 1);

        lua_pop(L, 1); /* pop the event we just processed */
    }
}

static struct ctrace_instrumentation_scope *
lua_to_instrumentation_scope(lua_State *L, int index)
{
    struct ctrace_instrumentation_scope *scope;
    struct ctrace_attributes *attr;
    cfl_sds_t name;
    cfl_sds_t version;
    uint32_t dropped_attr_count;

    lua_getfield(L, index, "name");
    name = lua_to_sds(L);
    lua_pop(L, 1); /* pop name */

    lua_getfield(L, index, "version");
    version = lua_to_sds(L);
    lua_pop(L, 1); /* pop version */

    lua_getfield(L, index, "attributes");
    attr = ctr_attributes_create();
    lua_to_attributes(L, attr);
    lua_pop(L, 1); /* pop attributes */

    lua_getfield(L, index, "droppedAttributesCount");
    dropped_attr_count = lua_to_uint(L);
    lua_pop(L, 1); /* pop droppedAttributesCount */

    scope = ctr_instrumentation_scope_create(name, version, dropped_attr_count,
                                             attr);
    cfl_sds_destroy(name);
    cfl_sds_destroy(version);

    return scope;
}

static void lua_to_attributes(lua_State *L, struct ctrace_attributes *attr)
{
    if (lua_type(L, -1) != LUA_TTABLE || !attr) {
        return;
    }

    cfl_kvlist_destroy(attr->kv);
    attr->kv = lua_map_to_variant(L);
}

static void lua_to_spans(lua_State *L, struct ctrace *ctx,
                         struct ctrace_scope_span *scope_span)
{
    size_t count;
    struct ctrace_span *span;
    cfl_sds_t name;
    size_t i;
    struct ctrace_id *parent_span_id;

    if (lua_type(L, -1) != LUA_TTABLE) {
        return;
    }

    count = lua_objlen(L, -1);
    for (i = 1; i <= count; i++) {
        lua_rawgeti(L, -1, i);

        lua_getfield(L, -1, "name");
        name = lua_to_sds(L);
        lua_pop(L, 1);

        span = ctr_span_create(ctx, scope_span, name, NULL);
        if (!span) {
          cfl_sds_destroy(name);
          lua_pop(L, 1);
          return;
        }
        cfl_sds_destroy(name);

        lua_getfield(L, -1, "traceId");
        span->trace_id = lua_to_id(L);
        lua_pop(L, 1);

        lua_getfield(L, -1, "spanId");
        span->span_id = lua_to_id(L);
        lua_pop(L, 1);

        lua_getfield(L, -1, "parentSpanId");
        parent_span_id = lua_to_id(L);
        lua_pop(L, 1);
        if (parent_span_id) {
            ctr_span_set_parent_span_id_with_cid(span, parent_span_id);
            ctr_id_destroy(parent_span_id);
        }

        lua_getfield(L, -1, "kind");
        span->kind = lua_to_int(L);
        lua_pop(L, 1); /* pop "kind" */

        lua_getfield(L, -1, "startTimeUnixNano");
        span->start_time_unix_nano = lua_to_uint(L);
        lua_pop(L, 1); /* pop "startTimeUnixNano" */

        lua_getfield(L, -1, "endTimeUnixNano");
        span->end_time_unix_nano = lua_to_uint(L);
        lua_pop(L, 1); /* pop "endTimeUnixNano" */

        lua_getfield(L, -1, "attributes");
        lua_to_attributes(L, span->attr);
        lua_pop(L, 1);

        lua_getfield(L, -1, "events");
        lua_to_events(L, span);
        lua_pop(L, 1); /* pop events */

        lua_getfield(L, -1, "links");
        lua_to_links(L, span);
        lua_pop(L, 1); /* pop links */

        lua_pop(L, 1); /* pop the span we just processed */
    }
}

static void lua_to_scope_spans(lua_State *L, struct ctrace *ctx,
                               struct ctrace_resource_span *resource_span)
{
    size_t count;
    size_t i;
    struct ctrace_scope_span *scope_span;

    if (lua_type(L, -1) != LUA_TTABLE) {
        return;
    }

    count = lua_objlen(L, -1);

    for (i = 1; i <= count; i++) {
        scope_span = ctr_scope_span_create(resource_span);

        lua_rawgeti(L, -1, i);

        lua_getfield(L, -1, "schemaUrl");
        scope_span->schema_url = lua_to_sds(L);
        lua_pop(L, 1); /* pop "schemaUrl" */

        lua_getfield(L, -1, "scope");
        scope_span->instrumentation_scope
            = lua_to_instrumentation_scope(L, lua_gettop(L));
        lua_pop(L, 1); /* pop "scope" */

        lua_getfield(L, -1, "spans");
        lua_to_spans(L, ctx, scope_span);
        lua_pop(L, 1); /* pop "spans" */

        lua_pop(L, 1); /* pop the scope_span we just processed */
    }
}

static void lua_to_resource_spans(lua_State *L, struct ctrace *ctx)
{
    size_t count;
    size_t i;
    struct ctrace_resource_span *resource_span;

    if (lua_type(L, -1) != LUA_TTABLE) {
        return;
    }

    count = lua_objlen(L, -1);

    for (i = 1; i <= count; i++) {
        resource_span = ctr_resource_span_create(ctx);

        lua_rawgeti(L, -1, i);

        lua_getfield(L, -1, "resource");

        lua_getfield(L, -1, "attributes");
        lua_to_attributes(L, resource_span->resource->attr);
        lua_pop(L, 1); /* pop "attributes" */

        lua_getfield(L, -1, "droppedAttributesCount");
        resource_span->resource->dropped_attr_count = lua_to_uint(L);
        lua_pop(L, 1); /* pop "droppedAttributesCount" */

        lua_pop(L, 1); /* pop "resource" */

        lua_getfield(L, -1, "schemaUrl");
        resource_span->schema_url = lua_to_sds(L);
        lua_pop(L, 1); /* pop "schemaUrl" */

        lua_getfield(L, -1, "scopeSpans");
        lua_to_scope_spans(L, ctx, resource_span);
        lua_pop(L, 1); /* pop "scopeSpans" */

        lua_pop(L, 1); /* pop the resourceSpan we just processed */
    }
}

int calyptia_traces_from_lua(lua_State *L, struct ctrace *ctx)
{
    lua_to_resource_spans(L, ctx);

    return 0;
}
