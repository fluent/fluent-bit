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

#include <fluent-bit/flb_mem.h>
#include <cfl/cfl_container.h>
#include <opentelemetry/proto/metrics/v1/metrics.pb-c.h>
#include <opentelemetry/proto/collector/trace/v1/trace_service.pb-c.h>
#include "fts_telemetry.h"
#include "fts_helpers.h"

struct telemetry_call {
    struct fts_runtime *ctx;
    struct cfl_variant *snapshot;
    const char *tag;
    int tag_len;
};

static struct cfl_variant *field(struct cfl_variant *map, const char *key)
{
    struct cfl_kvpair *pair;

    if (!map || map->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    pair = fts_find_pair(map, key, strlen(key));
    if (!pair) {
        return NULL;
    }

    return pair->val;
}

static struct cfl_variant *new_map(void)
{
    struct cfl_kvlist *map;
    struct cfl_variant *value;

    map = cfl_kvlist_create();
    if (!map) {
        return NULL;
    }

    value = cfl_variant_create_from_kvlist(map);
    if (!value) {
        cfl_kvlist_destroy(map);
    }

    return value;
}

static struct cfl_variant *new_array(void)
{
    struct cfl_array *array;
    struct cfl_variant *value;

    array = cfl_array_create(0);
    if (!array) {
        return NULL;
    }
    cfl_array_resizable(array, CFL_TRUE);

    value = cfl_variant_create_from_array(array);
    if (!value) {
        cfl_array_destroy(array);
    }

    return value;
}

/* the receiver owns value on success and failure */
static int put(struct cfl_variant *map, const char *key, struct cfl_variant *value)
{
    if (!value || cfl_kvlist_insert(map->data.as_kvlist, (char *) key, value) != 0) {
        cfl_variant_destroy(value);
        return -1;
    }

    return 0;
}

static int clone_field(struct cfl_variant *map, const char *name, struct cfl_variant *source)
{
    struct cfl_variant *value;

    if (source) {
        value = fts_copy_value(source, 0);
    }
    else {
        value = new_map();
    }

    return put(map, name, value);
}

static struct cfl_variant *snapshot(struct cfl_variant *resource, struct cfl_variant *scope,
                                    struct cfl_variant *item)
{
    struct cfl_variant *result;
    struct cfl_variant *context;
    struct cfl_variant *url;
    struct cfl_variant *value;

    result = new_map();
    if (!result) {
        return NULL;
    }

    if (clone_field(result, "item", item) != 0 ||
        clone_field(result, "resource", field(resource, "resource")) != 0 ||
        clone_field(result, "scope", field(scope, "scope")) != 0) {
        goto failure;
    }

    context = field(result, "resource");
    if (!field(context, "attributes") && put(context, "attributes", new_map()) != 0) {
        goto failure;
    }

    context = field(result, "scope");
    if (!field(context, "attributes") && put(context, "attributes", new_map()) != 0) {
        goto failure;
    }

    url = field(resource, "schema_url");
    if (url) {
        value = fts_copy_value(url, 0);
    }
    else {
        value = cfl_variant_create_from_string("");
    }
    if (put(result, "resource_schema_url", value) != 0) {
        goto failure;
    }

    url = field(scope, "schema_url");
    if (url) {
        value = fts_copy_value(url, 0);
    }
    else {
        value = cfl_variant_create_from_string("");
    }
    if (put(result, "scope_schema_url", value) != 0) {
        goto failure;
    }

    return result;

failure:
    cfl_variant_destroy(result);
    return NULL;
}

int fts_register_telemetry_helpers(lua_State *l)
{
    if (fts_load_helpers(l, fts_telemetry_helpers, sizeof(fts_telemetry_helpers) - 1,
                         "fluentbit.telemetry_helpers") != 0) {
        return -1;
    }

    return 0;
}

int fts_run_telemetry(lua_State *l)
{
    struct telemetry_call *call;
    struct fts_value *owner;
    struct fts_value *emissions;
    const char *signal;
    const char *result;
    size_t length;
    size_t i;
    int original;
    int raw;
    int output;
    int module;
    int view;
    int drop = FLB_FALSE;

    call = lua_touserdata(l, 1);
    if (call->ctx->adapter->event_type == FLB_PROCESSOR_METRICS) {
        signal = "metrics";
    }
    else {
        signal = "traces";
    }

    /* mutable snapshot handed to the policy */
    owner = fts_push_owned(l, NULL, FLB_FALSE);
    fts_charge_value(l, owner, fts_value_cost(call->snapshot, 0));
    owner->owned = fts_copy_value(call->snapshot, 0);
    if (!owner->owned) {
        return luaL_error(l, "cannot create telemetry snapshot");
    }
    raw = lua_gettop(l);

    /* read-only copy used to validate the edits */
    owner = fts_push_owned(l, NULL, FLB_TRUE);
    fts_charge_value(l, owner, fts_value_cost(call->snapshot, 0));
    owner->owned = fts_copy_value(call->snapshot, 0);
    if (!owner->owned) {
        return luaL_error(l, "cannot preserve original telemetry fields");
    }
    original = lua_gettop(l);

    emissions = fts_push_owned(l, NULL, FLB_FALSE);
    fts_charge_value(l, emissions, 256);
    emissions->owned = new_array();
    if (!emissions->owned) {
        return luaL_error(l, "cannot create emissions array");
    }
    output = lua_gettop(l);

    lua_rawgeti(l, LUA_REGISTRYINDEX, call->ctx->module_ref);
    module = lua_gettop(l);

    lua_getfield(l, module, "_fts_wrap");
    lua_pushvalue(l, raw);
    lua_pushstring(l, signal);
    lua_pushvalue(l, output);
    if (call->tag) {
        lua_pushlstring(l, call->tag, call->tag_len);
    }
    else {
        lua_pushlstring(l, "", 0);
    }
    lua_call(l, 4, 1);
    view = lua_gettop(l);

    lua_rawgeti(l, LUA_REGISTRYINDEX, call->ctx->policy_ref);
    lua_pushvalue(l, view);
    lua_call(l, 1, 1);

    if (!lua_isnil(l, -1)) {
        result = NULL;
        if (lua_type(l, -1) == LUA_TSTRING) {
            result = lua_tolstring(l, -1, &length);
        }

        if (!result || length != 4 || (memcmp(result, "keep", 4) && memcmp(result, "drop", 4))) {
            return luaL_error(l, "callback must return nil, fb.KEEP or fb.DROP");
        }
        drop = memcmp(result, "drop", 4) == 0;
    }

    if (!drop) {
        lua_getfield(l, module, "_fts_validate_telemetry");
        lua_pushvalue(l, raw);
        lua_pushstring(l, signal);
        lua_pushvalue(l, original);
        lua_call(l, 3, 0);
    }

    for (i = 0; i < emissions->owned->data.as_array->entry_count; i++) {
        lua_getfield(l, module, "_fts_validate_telemetry");
        owner = fts_push_owned(l, NULL, FLB_FALSE);
        fts_charge_value(l, owner, fts_value_cost(emissions->owned->data.as_array->entries[i], 0));
        owner->owned = fts_copy_value(emissions->owned->data.as_array->entries[i], 0);
        if (!owner->owned) {
            return luaL_error(l, "cannot validate emitted metric");
        }
        lua_pushstring(l, signal);
        lua_call(l, 2, 0);
    }

    lua_pushstring(l, drop ? "drop" : "keep");
    lua_pushvalue(l, raw);
    lua_pushvalue(l, output);
    return 3;
}

static struct cfl_variant *group_from_snapshot(struct cfl_variant *value, int metrics)
{
    struct cfl_variant *resource;
    struct cfl_variant *scope;
    struct cfl_variant *scopes;
    struct cfl_variant *items;
    struct cfl_variant *item = NULL;

    resource = new_map();
    scope = new_map();
    scopes = new_array();
    items = new_array();
    if (!resource || !scope || !scopes || !items) {
        goto failure;
    }

    if (clone_field(resource, "resource", field(value, "resource")) != 0 ||
        clone_field(resource, "schema_url", field(value, "resource_schema_url")) != 0 ||
        clone_field(scope, "scope", field(value, "scope")) != 0 ||
        clone_field(scope, "schema_url", field(value, "scope_schema_url")) != 0) {
        goto failure;
    }

    item = fts_copy_value(field(value, "item"), 0);
    if (!item || cfl_array_append(items->data.as_array, item) != 0) {
        goto failure;
    }
    item = NULL;

    if (put(scope, metrics ? "metrics" : "spans", items) != 0) {
        items = NULL;
        goto failure;
    }
    items = NULL;

    if (cfl_array_append(scopes->data.as_array, scope) != 0) {
        goto failure;
    }
    scope = NULL;

    if (put(resource, metrics ? "scope_metrics" : "scope_spans", scopes) != 0) {
        scopes = NULL;
        goto failure;
    }

    return resource;

failure:
    cfl_variant_destroy(resource);
    cfl_variant_destroy(scope);
    cfl_variant_destroy(scopes);
    cfl_variant_destroy(items);
    cfl_variant_destroy(item);
    return NULL;
}

static int stage(struct cfl_variant *groups, struct cfl_variant *value, int metrics,
                  size_t *used, size_t limit)
{
    struct cfl_variant *group;
    ProtobufCMessage *message;
    struct fts_proto_budget budget = {0, limit};
    const ProtobufCMessageDescriptor *descriptor;
    ProtobufCMessage *item;
    size_t cost;
    size_t length;
    size_t prefix;

    group = group_from_snapshot(value, metrics);
    if (!group) {
        return -1;
    }

    if (metrics) {
        descriptor = &opentelemetry__proto__metrics__v1__resource_metrics__descriptor;
    }
    else {
        descriptor = &opentelemetry__proto__trace__v1__resource_spans__descriptor;
    }

    message = fts_proto_build(descriptor, group, &budget, 0);
    if (!message) {
        cfl_variant_destroy(group);
        return -1;
    }

    if (metrics) {
        item = &((Opentelemetry__Proto__Metrics__V1__ResourceMetrics *) message)->
                 scope_metrics[0]->metrics[0]->base;
    }
    else {
        item = &((Opentelemetry__Proto__Trace__V1__ResourceSpans *) message)->
                 scope_spans[0]->spans[0]->base;
    }

    /*
     * Account item bytes and its repeated-field framing here. Coalesced
     * resource/scope bytes are checked once in the final serialized output.
     */
    cost = protobuf_c_message_get_packed_size(item);
    prefix = 1;
    for (length = cost; length >= 128; length >>= 7) {
        prefix++;
    }
    cost += prefix + 1;
    protobuf_c_message_free_unpacked(message, NULL);

    if (cost > limit || *used > limit - cost ||
        cfl_array_append(groups->data.as_array, group) != 0) {
        cfl_variant_destroy(group);
        return -1;
    }

    *used += cost;
    return 0;
}

/* Coalesce adjacent unchanged contexts without teaching policies about groups. */
static int append_group(struct cfl_variant *groups, struct cfl_variant *group, int metrics)
{
    struct cfl_array *list;
    struct cfl_variant *previous;
    struct cfl_variant *a;
    struct cfl_variant *b;
    struct cfl_variant *items;
    struct cfl_variant *source;
    struct cfl_variant *item;
    const char *scope_key = metrics ? "scope_metrics" : "scope_spans";
    const char *item_key = metrics ? "metrics" : "spans";
    size_t i;

    list = groups->data.as_array;
    if (group->type != CFL_VARIANT_BYTES && list->entry_count > 0 &&
        list->entries[list->entry_count - 1]->type != CFL_VARIANT_BYTES) {
        previous = list->entries[list->entry_count - 1];
        a = field(previous, scope_key)->data.as_array->entries[0];
        b = field(group, scope_key)->data.as_array->entries[0];

        if (fts_values_equal(field(previous, "resource"), field(group, "resource"), 0) &&
            fts_values_equal(field(previous, "schema_url"), field(group, "schema_url"), 0) &&
            fts_values_equal(field(a, "scope"), field(b, "scope"), 0) &&
            fts_values_equal(field(a, "schema_url"), field(b, "schema_url"), 0)) {
            items = field(a, item_key);
            source = field(b, item_key);
            for (i = 0; i < source->data.as_array->entry_count; i++) {
                item = source->data.as_array->entries[i];
                source->data.as_array->entries[i] = NULL;
                cfl_container_release_variant(item);
                if (cfl_array_append(items->data.as_array, item) != 0) {
                    cfl_variant_destroy(item);
                    cfl_variant_destroy(group);
                    return -1;
                }
            }
            cfl_variant_destroy(group);
            return 0;
        }
    }

    if (cfl_array_append(groups->data.as_array, group) != 0) {
        cfl_variant_destroy(group);
        return -1;
    }

    return 0;
}

/* Decode resource/scope context without recursively materializing their items. */
static struct cfl_variant *read_context(const ProtobufCMessage *message,
                                       const char *children, struct fts_proto_budget *budget)
{
    const ProtobufCFieldDescriptor *descriptor;
    ProtobufCMessage *copy;
    struct cfl_variant *result;

    descriptor = protobuf_c_message_descriptor_get_field_by_name(message->descriptor, children);
    copy = flb_malloc(message->descriptor->sizeof_message);
    if (!copy) {
        flb_errno();
        return NULL;
    }

    if (!descriptor) {
        flb_free(copy);
        return NULL;
    }

    /* shallow copy with the children field emptied */
    memcpy(copy, message, message->descriptor->sizeof_message);
    *(size_t *) ((char *) copy + descriptor->quantifier_offset) = 0;
    *(void **) ((char *) copy + descriptor->offset) = NULL;

    budget->used = 0;
    result = fts_proto_read(copy, budget, 0);
    flb_free(copy);

    return result;
}

static ProtobufCMessage **children_of(const ProtobufCMessage *message,
                                      const char *name, size_t *count)
{
    const ProtobufCFieldDescriptor *field;

    field = protobuf_c_message_descriptor_get_field_by_name(message->descriptor, name);
    *count = *(size_t *) ((char *) message + field->quantifier_offset);
    return *(ProtobufCMessage ***) ((char *) message + field->offset);
}

/*
 * Keep a failed original item without requiring it to fit the typed API's
 * nesting/memory budget. Its siblings still receive independent callbacks.
 */
static struct cfl_variant *opaque_group(ProtobufCMessage *resource,
                                        ProtobufCMessage *scope, ProtobufCMessage *item,
                                        int metrics)
{
    const ProtobufCFieldDescriptor *resource_field;
    const ProtobufCFieldDescriptor *scope_field;
    const char *scope_name;
    const char *item_name;
    ProtobufCMessage *resource_copy;
    ProtobufCMessage *scope_copy;
    struct cfl_variant *result;
    uint8_t *buffer;
    size_t size;

    resource_copy = flb_malloc(resource->descriptor->sizeof_message);
    scope_copy = flb_malloc(scope->descriptor->sizeof_message);
    if (!resource_copy || !scope_copy) {
        flb_errno();
        flb_free(resource_copy);
        flb_free(scope_copy);
        return NULL;
    }

    /* shallow copies linked so they only reference the single item */
    memcpy(resource_copy, resource, resource->descriptor->sizeof_message);
    memcpy(scope_copy, scope, scope->descriptor->sizeof_message);

    if (metrics) {
        scope_name = "scope_metrics";
        item_name = "metrics";
    }
    else {
        scope_name = "scope_spans";
        item_name = "spans";
    }

    resource_field = protobuf_c_message_descriptor_get_field_by_name(resource->descriptor,
                                                                     scope_name);
    scope_field = protobuf_c_message_descriptor_get_field_by_name(scope->descriptor, item_name);

    *(size_t *) ((char *) resource_copy + resource_field->quantifier_offset) = 1;
    *(ProtobufCMessage ***) ((char *) resource_copy + resource_field->offset) = &scope_copy;
    *(size_t *) ((char *) scope_copy + scope_field->quantifier_offset) = 1;
    *(ProtobufCMessage ***) ((char *) scope_copy + scope_field->offset) = &item;

    size = protobuf_c_message_get_packed_size(resource_copy);
    buffer = flb_malloc(size ? size : 1);
    if (!buffer) {
        flb_errno();
        flb_free(scope_copy);
        flb_free(resource_copy);
        return NULL;
    }

    protobuf_c_message_pack(resource_copy, buffer);
    result = cfl_variant_create_from_bytes((char *) buffer, size, CFL_FALSE);
    flb_free(buffer);

    flb_free(scope_copy);
    flb_free(resource_copy);

    return result;
}

int fts_telemetry_transform(struct flb_processor_instance *ins, char *buffer, size_t size,
                            char **output, size_t *output_size, const char *tag, int tag_len)
{
    struct fts_runtime *ctx = ins->context;
    struct fts_proto_budget budget;
    ProtobufCMessage *message = NULL;
    const ProtobufCMessageDescriptor *descriptor;
    struct cfl_variant *resource = NULL;
    struct cfl_variant *scope = NULL;
    struct cfl_variant *original_item = NULL;
    struct cfl_variant *result = NULL;
    struct cfl_variant *groups = NULL;
    ProtobufCMessage **resources;
    ProtobufCMessage **scopes;
    ProtobufCMessage **items;
    size_t resource_count;
    size_t scope_count;
    size_t item_count;
    struct cfl_variant *value = NULL;
    struct cfl_variant *pending = NULL;
    struct cfl_variant *item;
    struct fts_value *edited;
    struct fts_value *emissions;
    struct telemetry_call call;
    lua_State *l = ctx->vm->state;
    size_t r;
    size_t s;
    size_t i;
    size_t e;
    size_t used = 0;
    size_t pending_cost;
    int metrics = ctx->adapter->event_type == FLB_PROCESSOR_METRICS;
    const char *resource_key = metrics ? "resource_metrics" : "resource_spans";
    const char *scope_key = metrics ? "scope_metrics" : "scope_spans";
    const char *item_key = metrics ? "metrics" : "spans";
    int base;
    int ret;
    int errors = 0;
    int failed;
    const char *phase = "decode OTLP";

    *output = NULL;
    *output_size = 0;

    if (metrics) {
        descriptor = &opentelemetry__proto__metrics__v1__metrics_data__descriptor;
    }
    else {
        descriptor =
            &opentelemetry__proto__collector__trace__v1__export_trace_service_request__descriptor;
    }

    budget.used = 0;
    budget.limit = ctx->memory_limit;

    message = protobuf_c_message_unpack(descriptor, NULL, size, (uint8_t *) buffer);
    if (!message) {
        goto failure;
    }

    result = new_map();
    groups = new_array();
    if (!result || !groups) {
        goto failure;
    }

    phase = "read resource groups";
    resources = children_of(message, resource_key, &resource_count);
    for (r = 0; r < resource_count; r++) {
        resource = read_context(resources[r], scope_key, &budget);
        scopes = children_of(resources[r], scope_key, &scope_count);
        for (s = 0; s < scope_count; s++) {
            scope = read_context(scopes[s], item_key, &budget);
            items = children_of(scopes[s], item_key, &item_count);
            for (i = 0; i < item_count; i++) {
                phase = "create telemetry snapshot";
                budget.used = 0;

                original_item = NULL;
                if (resource && scope) {
                    original_item = fts_proto_read(items[i], &budget, 0);
                }

                value = NULL;
                if (original_item) {
                    value = snapshot(resource, scope, original_item);
                }
                cfl_variant_destroy(original_item);
                original_item = NULL;

                if (!value) {
                    errors++;
                    if (errors <= 5) {
                        flb_plg_error(ins, "FTS telemetry item exceeds snapshot limits; %s",
                                      strcmp(ctx->error_mode, "keep") == 0 ?
                                      "original item kept" : "item dropped");
                    }

                    if (strcmp(ctx->error_mode, "keep") == 0) {
                        item = opaque_group(resources[r], scopes[s], items[i], metrics);
                        if (!item || append_group(groups, item, metrics) != 0) {
                            goto failure;
                        }
                    }
                    continue;
                }

                base = lua_gettop(l);
                call.ctx = ctx;
                call.snapshot = value;
                call.tag = tag;
                call.tag_len = tag_len;
                ret = fts_runtime_call(ctx, &call, 3);

                pending = new_array();
                pending_cost = used;
                failed = ret != 0 || !pending;

                if (!failed) {
                    edited = lua_touserdata(l, base + 2);
                    emissions = lua_touserdata(l, base + 3);

                    if (strcmp(lua_tostring(l, base + 1), "keep") == 0 &&
                        stage(pending, edited->owned, metrics, &pending_cost,
                              ctx->output_limit) != 0) {
                        failed = FLB_TRUE;
                    }

                    for (e = 0; !failed && e < emissions->owned->data.as_array->entry_count; e++) {
                        if (stage(pending, emissions->owned->data.as_array->entries[e], metrics,
                                  &pending_cost, ctx->output_limit) != 0) {
                            failed = FLB_TRUE;
                        }
                    }
                }

                if (failed) {
                    errors++;
                    if (errors <= 5) {
                        flb_plg_error(ins, "FTS telemetry policy failed: %.256s; edits rolled back",
                                      ret && lua_type(l, -1) == LUA_TSTRING ?
                                      lua_tostring(l, -1) :
                                      "invalid telemetry fields or output limit");
                    }

                    /* restart staging, keeping the original item when configured */
                    cfl_variant_destroy(pending);
                    pending = new_array();
                    pending_cost = used;
                    if (!pending || (strcmp(ctx->error_mode, "keep") == 0 &&
                                     stage(pending, value, metrics, &pending_cost,
                                           ctx->output_limit) != 0)) {
                        lua_settop(l, base);
                        goto failure;
                    }
                }

                for (e = 0; e < pending->data.as_array->entry_count; e++) {
                    item = pending->data.as_array->entries[e];
                    pending->data.as_array->entries[e] = NULL;
                    cfl_container_release_variant(item);
                    if (append_group(groups, item, metrics) != 0) {
                        lua_settop(l, base);
                        goto failure;
                    }
                }

                used = pending_cost;
                cfl_variant_destroy(pending);
                pending = NULL;
                cfl_variant_destroy(value);
                value = NULL;
                lua_settop(l, base);
            }
            cfl_variant_destroy(scope);
            scope = NULL;
        }
        cfl_variant_destroy(resource);
        resource = NULL;
    }

    if (put(result, resource_key, groups) != 0) {
        groups = NULL;
        goto failure;
    }
    groups = NULL;

    protobuf_c_message_free_unpacked(message, NULL);
    message = NULL;

    /* transport staging is bounded by output_limit, independently of the VM */
    budget.used = 0;
    budget.limit = SIZE_MAX;
    phase = "encode typed OTLP values";

    message = fts_proto_build(descriptor, result, &budget, 0);
    if (!message) {
        goto failure;
    }

    *output_size = protobuf_c_message_get_packed_size(message);
    if (*output_size > ctx->output_limit) {
        goto failure;
    }

    *output = flb_malloc(*output_size ? *output_size : 1);
    if (!*output) {
        flb_errno();
        goto failure;
    }

    protobuf_c_message_pack(message, (uint8_t *) *output);
    protobuf_c_message_free_unpacked(message, NULL);

    cfl_variant_destroy(resource);
    cfl_variant_destroy(scope);
    cfl_variant_destroy(original_item);
    cfl_variant_destroy(result);

    ctx->instructions_left = ctx->instruction_limit;
    lua_gc(l, LUA_GCCOLLECT, 0);

    if (errors > 5) {
        flb_plg_warn(ins, "%d additional telemetry policy errors in this chunk", errors - 5);
    }

    return errors;

failure:
    if (message) {
        protobuf_c_message_free_unpacked(message, NULL);
    }

    cfl_variant_destroy(resource);
    cfl_variant_destroy(scope);
    cfl_variant_destroy(original_item);
    cfl_variant_destroy(result);
    cfl_variant_destroy(groups);
    cfl_variant_destroy(value);
    cfl_variant_destroy(pending);

    ctx->instructions_left = ctx->instruction_limit;
    lua_gc(l, LUA_GCCOLLECT, 0);

    flb_free(*output);
    *output = NULL;
    *output_size = 0;

    flb_plg_error(ins, "cannot construct FTS telemetry output (%s); edits discarded", phase);
    return -1;
}
