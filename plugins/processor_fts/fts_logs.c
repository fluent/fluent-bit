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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_byteswap.h>
#include <fluent-bit/flb_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_conditionals.h>
#include <cfl/cfl_container.h>
#include <math.h>
#include "fts.h"
#include "fts_helpers.h"

/* Log semantics remain in the log adapter. */
static int values_equal(struct cfl_variant *a, struct cfl_variant *b);
static struct cfl_object *object_from_variant(struct cfl_variant *v);

/* All Lua allocation, callbacks and validation run within one protected call. */
struct record_call {
    struct fts_runtime *ctx;
    struct flb_mp_chunk_cobj *chunk;
    struct cfl_variant *result_body;
    struct cfl_variant *result_metadata;
    struct flb_mp_chunk_record *record;
    struct cfl_object *attributes;
    struct cfl_object *metadata;
    const char *tag;
    int tag_len;
};

static struct fts_value *push_clone_in(lua_State *l, struct cfl_variant *source,
                                       struct flb_mp_chunk_cobj *chunk)
{
    struct fts_value *value;
    struct cfl_arena *arena;
    size_t cost;

    value = fts_push_owned(l, NULL, FLB_FALSE);
    cost = fts_value_cost(source, 0);
    fts_charge_value(l, value, cost);

    arena = flb_mp_chunk_cobj_value_pool_get(chunk, cost > SIZE_MAX / 4 ? SIZE_MAX : cost * 4);
    value->owned = fts_copy_value_in(source, 0, arena);
    if (!value->owned && arena) {
        value->owned = fts_copy_value(source, 0);
    }

    if (!value->owned) {
        luaL_error(l, "cannot copy log value (allocation or nesting limit)");
    }

    return value;
}

static struct fts_value *push_clone(lua_State *l, struct cfl_variant *source)
{
    return push_clone_in(l, source, NULL);
}

static int has_otel_context(struct cfl_object *obj)
{
    struct cfl_kvpair *pair;

    if (!obj || !obj->variant || obj->variant->type != CFL_VARIANT_KVLIST) {
        return FLB_FALSE;
    }

    pair = fts_find_pair(obj->variant, "schema", 6);
    return pair && pair->val->type == CFL_VARIANT_STRING &&
           cfl_variant_size_get(pair->val) == 4 &&
           memcmp(pair->val->data.as_string, "otlp", 4) == 0;
}

static struct cfl_variant *raw_field(lua_State *l, int table, enum fts_key key)
{
    struct cfl_variant *v;

    fts_getfield(l, table, key);
    v = fts_resolve_value(l, -1, 0);
    lua_pop(l, 1);

    return v;
}

/*
 * Push the field to pin its owner; return its tree only when the policy changed it.
 * The caller copies it into the chunk after the protected call.
 */
static struct cfl_variant *push_record_result(lua_State *l, int table, enum fts_key key,
                                              struct fts_value *original)
{
    struct cfl_variant *value;

    fts_getfield(l, table, key);
    if (lua_touserdata(l, -1) == original && (!original->dirty || original->inplace)) {
        /* In-place edits already live in the chunk's tree. */
        if (original->inplace && original->depth_changed &&
            fts_value_cost(original->owned, 0) == SIZE_MAX) {
            luaL_error(l, "cannot copy log value (allocation or nesting limit)");
        }
        return NULL;
    }

    value = fts_resolve_value(l, -1, 0);

    /* Keep nesting failures item-local instead of failing the chunk copy. */
    if ((lua_touserdata(l, -1) != original || original->depth_changed) &&
        fts_value_cost(value, 0) == SIZE_MAX) {
        luaL_error(l, "cannot copy log value (allocation or nesting limit)");
    }

    return value;
}

/* Lua may retain policy trees, so the chunk receives its own copy. */
static struct cfl_object *result_object(struct flb_mp_chunk_cobj *chunk,
                                        struct cfl_variant *source)
{
    struct cfl_variant *value;
    struct cfl_object *obj;
    struct cfl_arena *arena;
    size_t cost;

    cost = fts_value_cost(source, 0);
    if (cost == SIZE_MAX) {
        return NULL;
    }

    arena = flb_mp_chunk_cobj_value_pool_get(chunk, cost > SIZE_MAX / 4 ? SIZE_MAX : cost * 4);
    value = fts_copy_value_in(source, 0, arena);
    if (!value && arena) {
        value = fts_copy_value(source, 0);
    }

    if (!value) {
        return NULL;
    }

    obj = object_from_variant(value);
    if (!obj) {
        cfl_variant_destroy(value);
    }

    return obj;
}

static void push_field_clone(lua_State *l, int table, enum fts_key key)
{
    struct cfl_variant *v;

    v = raw_field(l, table, key);
    push_clone(l, v);
}

static void validate_map(lua_State *l, struct cfl_variant *v, const char *name)
{
    if (v == NULL || v->type != CFL_VARIANT_KVLIST) {
        luaL_error(l, "%s must be a typed map", name);
    }
}

static void validate_utf8(lua_State *l, struct cfl_variant *v, struct cfl_variant *original,
                          int depth, int payload)
{
    struct cfl_list *head;
    struct cfl_list *original_head;
    struct cfl_list *original_end;
    struct cfl_kvpair *pair;
    struct cfl_kvpair *previous;
    struct cfl_variant *old_value;
    size_t i;
    size_t original_index = 0;
    size_t original_count;
    int same_key;

    if (values_equal(v, original) || v == NULL) {
        return;
    }

    if (depth >= FTS_MAX_DEPTH) {
        luaL_error(l, "telemetry nesting exceeds limit");
    }

    if (payload && v->type == CFL_VARIANT_UINT && v->data.as_uint64 > INT64_MAX) {
        luaL_error(l, "OTel AnyValue integers must fit signed 64 bits");
    }

    if (v->type == CFL_VARIANT_STRING &&
        memchr(v->data.as_string, '\0', cfl_variant_size_get(v))) {
        luaL_error(l, "OTel strings cannot contain NUL in this exporter; use fb.bytes");
    }

    if (v->type == CFL_VARIANT_STRING &&
        !fts_valid_utf8(v->data.as_string, cfl_variant_size_get(v))) {
        luaL_error(l, "OTel strings must be valid UTF-8; use fb.bytes for binary values");
    }
    else if (v->type == CFL_VARIANT_KVLIST) {
        original_end = original && original->type == CFL_VARIANT_KVLIST ?
                       &original->data.as_kvlist->list : NULL;
        original_head = original_end ? original_end->next : NULL;

        cfl_list_foreach(head, &v->data.as_kvlist->list) {
            pair = cfl_list_entry(head, struct cfl_kvpair, _head);
            previous = NULL;

            /* Set/remove preserve order; match duplicate occurrences positionally. */
            while (original_head != original_end) {
                previous = cfl_list_entry(original_head, struct cfl_kvpair, _head);
                original_head = original_head->next;
                same_key = cfl_sds_len(previous->key) == cfl_sds_len(pair->key) &&
                           memcmp(previous->key, pair->key, cfl_sds_len(pair->key)) == 0;
                if (same_key) {
                    break;
                }
                previous = NULL;
            }

            /* Only new keys need validation; inherited keys were already accepted. */
            if (previous == NULL) {
                if (memchr(pair->key, '\0', cfl_sds_len(pair->key))) {
                    luaL_error(l, "OTel keys cannot contain NUL in this exporter");
                }
                if (!fts_valid_utf8(pair->key, cfl_sds_len(pair->key))) {
                    luaL_error(l, "OTel keys must be valid UTF-8");
                }
            }

            validate_utf8(l, pair->val, previous ? previous->val : NULL, depth + 1, payload);
        }
    }
    else if (v->type == CFL_VARIANT_ARRAY) {
        original_count = original && original->type == CFL_VARIANT_ARRAY ?
                         original->data.as_array->entry_count : 0;

        for (i = 0; i < v->data.as_array->entry_count; i++) {
            old_value = original_index < original_count ?
                        original->data.as_array->entries[original_index] : NULL;

            if (old_value && !values_equal(v->data.as_array->entries[i], old_value) &&
                v->data.as_array->entry_count - i > original_count - original_index) {
                /* An inserted value must not shift validation of inherited values. */
                old_value = NULL;
            }
            else if (old_value) {
                original_index++;
            }

            validate_utf8(l, v->data.as_array->entries[i], old_value, depth + 1, payload);
        }
    }
}

static struct cfl_variant *map_field(struct cfl_variant *map, const char *key)
{
    struct cfl_kvpair *pair;

    if (!map || map->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    pair = fts_find_pair(map, key, strlen(key));
    return pair ? pair->val : NULL;
}

static struct cfl_variant *log_field(struct cfl_variant *metadata, const char *key)
{
    struct cfl_variant *value;

    value = map_field(map_field(metadata, "otlp"), key);
    return value ? value : map_field(metadata, key);
}

static void push_changed_fields(lua_State *l, struct record_call *call,
                                struct cfl_variant *metadata, struct cfl_variant *context)
{
    const char *fields[] = {"severity_number", "severity_text", "trace_flags", "trace_id",
                            "span_id", "event_name", "timestamp", "observed_timestamp",
                            "attributes", "dropped_attributes_count", NULL};
    const char *context_keys[] = {"resource", "scope", NULL};
    const char *properties[] = {"name", "version", "schema_url", "attributes",
                                "dropped_attributes_count", NULL};
    struct cfl_variant *current;
    struct cfl_variant *original;
    char key[64];
    int i;
    int j;

    lua_newtable(l);

    /* Log record fields */
    for (i = 0; fields[i]; i++) {
        lua_pushboolean(l, !values_equal(log_field(metadata, fields[i]),
                                         log_field(call->record->cobj_metadata->variant,
                                                   fields[i])));
        lua_setfield(l, -2, fields[i]);
    }

    /* Resource and scope properties, keyed as 'kind.property' */
    for (i = 0; context_keys[i]; i++) {
        current = map_field(context, context_keys[i]);
        original = map_field(call->attributes->variant, context_keys[i]);

        for (j = 0; properties[j]; j++) {
            snprintf(key, sizeof(key), "%s.%s", context_keys[i], properties[j]);
            lua_pushboolean(l, !values_equal(map_field(current, properties[j]),
                                             map_field(original, properties[j])));
            lua_setfield(l, -2, key);
        }
    }
}

static int empty_context_map(struct cfl_variant *value, int kind)
{
    struct cfl_kvpair *pair;

    if (!value || value->type != CFL_VARIANT_KVLIST) {
        return value == NULL;
    }

    if (cfl_kvlist_count(value->data.as_kvlist) == 0) {
        return FLB_TRUE;
    }

    if (kind && cfl_kvlist_count(value->data.as_kvlist) == 1) {
        pair = fts_find_pair(value, "attributes", 10);
        return pair && empty_context_map(pair->val, FLB_FALSE);
    }

    return FLB_FALSE;
}

static int key_pair_compare(const void *a, const void *b)
{
    const struct cfl_kvpair *left = *(struct cfl_kvpair * const *) a;
    const struct cfl_kvpair *right = *(struct cfl_kvpair * const *) b;
    size_t left_length = cfl_sds_len(left->key);
    size_t right_length = cfl_sds_len(right->key);

    if (left_length != right_length) {
        return left_length < right_length ? -1 : 1;
    }

    return memcmp(left->key, right->key, left_length);
}

/* TRUE when a map repeats a key; sorting keeps adversarial maps O(n log n) */
static int has_duplicate_keys(struct cfl_variant *value)
{
    int count;
    int i;
    int j;
    int duplicate = FLB_FALSE;
    struct cfl_list *head;
    struct cfl_kvpair **pairs;

    if (!value || value->type != CFL_VARIANT_KVLIST) {
        return FLB_FALSE;
    }

    count = cfl_kvlist_count(value->data.as_kvlist);
    if (count < 2) {
        return FLB_FALSE;
    }

    pairs = flb_malloc(sizeof(struct cfl_kvpair *) * count);
    if (!pairs) {
        flb_errno();
        /* without memory to check, compare strictly */
        return FLB_TRUE;
    }

    i = 0;
    cfl_list_foreach(head, &value->data.as_kvlist->list) {
        pairs[i++] = cfl_list_entry(head, struct cfl_kvpair, _head);
    }

    if (count <= 8) {
        for (i = 0; i < count && !duplicate; i++) {
            for (j = i + 1; j < count; j++) {
                if (key_pair_compare(&pairs[i], &pairs[j]) == 0) {
                    duplicate = FLB_TRUE;
                    break;
                }
            }
        }
    }
    else {
        qsort(pairs, count, sizeof(struct cfl_kvpair *), key_pair_compare);
        for (i = 1; i < count; i++) {
            if (key_pair_compare(&pairs[i - 1], &pairs[i]) == 0) {
                duplicate = FLB_TRUE;
                break;
            }
        }
    }

    flb_free(pairs);
    return duplicate;
}

static int pair_key_equal(struct cfl_kvpair *left, struct cfl_kvpair *right)
{
    return cfl_sds_len(left->key) == cfl_sds_len(right->key) &&
           memcmp(left->key, right->key, cfl_sds_len(left->key)) == 0;
}

static int empty_attributes_pair(struct cfl_kvpair *pair)
{
    return cfl_sds_len(pair->key) == 10 && memcmp(pair->key, "attributes", 10) == 0 &&
           empty_context_map(pair->val, FLB_FALSE);
}

/*
 * Positional comparison of a resource or scope map with duplicate keys, where
 * matching by name would hide edits to later duplicates. Empty attributes
 * placeholders are ignored on both sides.
 */
static int context_kind_equal_positional(struct cfl_variant *left, struct cfl_variant *right)
{
    struct cfl_list *a;
    struct cfl_list *b;
    struct cfl_list *a_end = &left->data.as_kvlist->list;
    struct cfl_list *b_end = &right->data.as_kvlist->list;
    struct cfl_kvpair *pa;
    struct cfl_kvpair *pb;

    a = a_end->next;
    b = b_end->next;
    while (1) {
        while (a != a_end && empty_attributes_pair(cfl_list_entry(a, struct cfl_kvpair, _head))) {
            a = a->next;
        }
        while (b != b_end && empty_attributes_pair(cfl_list_entry(b, struct cfl_kvpair, _head))) {
            b = b->next;
        }
        if (a == a_end || b == b_end) {
            return a == a_end && b == b_end;
        }

        pa = cfl_list_entry(a, struct cfl_kvpair, _head);
        pb = cfl_list_entry(b, struct cfl_kvpair, _head);
        if (!pair_key_equal(pa, pb) || !values_equal(pa->val, pb->val)) {
            return FLB_FALSE;
        }
        a = a->next;
        b = b->next;
    }
}

static int context_kind_equal(struct cfl_variant *left, struct cfl_variant *right)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_variant *other;

    if (!left || !right) {
        return empty_context_map(left, FLB_TRUE) && empty_context_map(right, FLB_TRUE);
    }

    if (left->type != CFL_VARIANT_KVLIST || right->type != CFL_VARIANT_KVLIST) {
        return values_equal(left, right);
    }

    if (has_duplicate_keys(left) || has_duplicate_keys(right)) {
        return context_kind_equal_positional(left, right);
    }

    cfl_list_foreach(head, &left->data.as_kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        other = map_field(right, pair->key);
        if (strcmp(pair->key, "attributes") == 0 &&
            empty_context_map(pair->val, FLB_FALSE) && empty_context_map(other, FLB_FALSE)) {
            continue;
        }
        if (!values_equal(pair->val, other)) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(head, &right->data.as_kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        other = map_field(left, pair->key);
        if (!other &&
            !(strcmp(pair->key, "attributes") == 0 && empty_context_map(pair->val, FLB_FALSE))) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static int context_attributes_equal(struct cfl_variant *left, struct cfl_variant *right)
{
    struct cfl_list *head;
    struct cfl_list *a;
    struct cfl_list *b;
    struct cfl_kvpair *pair;
    struct cfl_kvpair *pb;
    struct cfl_variant *other;

    if (!left || !right ||
        left->type != CFL_VARIANT_KVLIST || right->type != CFL_VARIANT_KVLIST) {
        return values_equal(left, right);
    }

    /* duplicate keys are compared by position so later duplicates count */
    if (has_duplicate_keys(left) || has_duplicate_keys(right)) {
        a = left->data.as_kvlist->list.next;
        b = right->data.as_kvlist->list.next;
        while (a != &left->data.as_kvlist->list && b != &right->data.as_kvlist->list) {
            pair = cfl_list_entry(a, struct cfl_kvpair, _head);
            pb = cfl_list_entry(b, struct cfl_kvpair, _head);
            if (!pair_key_equal(pair, pb)) {
                return FLB_FALSE;
            }
            if (strcmp(pair->key, "resource") == 0 || strcmp(pair->key, "scope") == 0) {
                if (!context_kind_equal(pair->val, pb->val)) {
                    return FLB_FALSE;
                }
            }
            else if (!values_equal(pair->val, pb->val)) {
                return FLB_FALSE;
            }
            a = a->next;
            b = b->next;
        }
        return a == &left->data.as_kvlist->list && b == &right->data.as_kvlist->list;
    }

    cfl_list_foreach(head, &left->data.as_kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        other = map_field(right, pair->key);
        if (strcmp(pair->key, "resource") == 0 || strcmp(pair->key, "scope") == 0) {
            if (!context_kind_equal(pair->val, other)) {
                return FLB_FALSE;
            }
        }
        else if (!values_equal(pair->val, other)) {
            return FLB_FALSE;
        }
    }

    cfl_list_foreach(head, &right->data.as_kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (!map_field(left, pair->key)) {
            return FLB_FALSE;
        }
    }

    return FLB_TRUE;
}

static void require_plain_table(lua_State *l, int index, const char *name)
{
    luaL_checktype(l, index, LUA_TTABLE);
    if (lua_getmetatable(l, index)) {
        lua_pop(l, 1);
        luaL_error(l, "%s must not have a metatable", name);
    }
}

static int run_record(lua_State *l)
{
    struct record_call *call;
    struct fts_value *original_body;
    struct fts_value *original_metadata;
    struct fts_value *attributes = NULL;
    struct fts_value *metadata = NULL;
    struct cfl_object current_metadata;
    const char *result;
    size_t result_length;
    lua_Number sec;
    lua_Number nsec;
    int event;
    int context = 0;
    int validator = 0;
    int cleanup = 0;

    call = lua_touserdata(l, 1);

    /* Expire record handles from earlier callbacks before creating new ones. */
    call->ctx->generation++;

    /* Build the event table: tag, body, metadata and timestamp */
    lua_createtable(l, 0, 4);
    event = lua_gettop(l);

    if (!call->ctx->tag_ready) {
        lua_pushlstring(l, call->tag, call->tag_len);
        lua_rawseti(l, LUA_REGISTRYINDEX, call->ctx->tag_ref);
        call->ctx->tag_ready = FLB_TRUE;
    }
    lua_rawgeti(l, LUA_REGISTRYINDEX, call->ctx->tag_ref);
    fts_setfield(l, event, FTS_KEY_TAG);

    original_body = fts_push_borrowed(l, call->record->cobj_record->variant);
    lua_pushvalue(l, -1);
    fts_setfield(l, event, FTS_KEY_BODY);

    original_metadata = fts_push_borrowed(l, call->record->cobj_metadata->variant);
    lua_pushvalue(l, -1);
    fts_setfield(l, event, FTS_KEY_METADATA);

    lua_createtable(l, 0, 2);
    lua_pushnumber(l, call->record->event.timestamp.tm.tv_sec);
    fts_setfield(l, -2, FTS_KEY_SEC);
    lua_pushnumber(l, call->record->event.timestamp.tm.tv_nsec);
    fts_setfield(l, -2, FTS_KEY_NSEC);
    fts_setfield(l, event, FTS_KEY_TIMESTAMP);

    /* Group context: attributes and metadata are policy-owned clones */
    if (call->attributes) {
        lua_createtable(l, 0, 2);
        context = lua_gettop(l);

        attributes = push_clone(l, call->attributes->variant);

        /* Pin C-held userdata independently of mutable table fields. */
        lua_pushvalue(l, -1);
        fts_setfield(l, context, FTS_KEY_ATTRIBUTES);

        metadata = push_clone(l, call->metadata->variant);
        lua_pushvalue(l, -1);
        fts_setfield(l, context, FTS_KEY_METADATA);

        lua_pushvalue(l, context);
        fts_setfield(l, event, FTS_KEY_CONTEXT);

        /* Semantic aliases are populated by the module without copying data. */
    }

    if (has_otel_context(call->metadata)) {
        lua_rawgeti(l, LUA_REGISTRYINDEX, call->ctx->module_ref);
        lua_getfield(l, -1, "_attach");
        lua_pushvalue(l, event);
        lua_call(l, 1, 2);
        cleanup = lua_gettop(l);
        validator = cleanup - 1;
    }

    original_metadata->dirty = FLB_FALSE;
    if (attributes) {
        attributes->dirty = FLB_FALSE;
        metadata->dirty = FLB_FALSE;
    }

    /* Run the policy callback */
    lua_rawgeti(l, LUA_REGISTRYINDEX, call->ctx->policy_ref);
    lua_pushvalue(l, event);
    lua_call(l, 1, 1);

    if (!lua_isnil(l, -1)) {
        result = lua_type(l, -1) == LUA_TSTRING ? lua_tolstring(l, -1, &result_length) : NULL;
        if (result && result_length == 4 && memcmp(result, "drop", 4) == 0) {
            lua_pushliteral(l, "drop");
            return 1;
        }
        if (!result || result_length != 4 || memcmp(result, "keep", 4) != 0) {
            return luaL_error(l, "callback must return nil, fb.KEEP or fb.DROP");
        }
    }

    /* Validation must not execute policy code through table metamethods. */
    require_plain_table(l, event, "log event");

    /* Roots: metadata and context cannot be replaced */
    fts_getfield(l, event, FTS_KEY_METADATA);
    if (lua_touserdata(l, -1) != original_metadata) {
        return luaL_error(l, "metadata root cannot be replaced");
    }
    lua_pop(l, 1);

    fts_getfield(l, event, FTS_KEY_CONTEXT);
    if (context ? !lua_rawequal(l, -1, context) : !lua_isnil(l, -1)) {
        return luaL_error(l, "context root cannot be replaced");
    }
    lua_pop(l, 1);

    if (context) {
        require_plain_table(l, context, "log context");
    }

    validate_map(l, raw_field(l, event, FTS_KEY_BODY), "body");
    validate_map(l, raw_field(l, event, FTS_KEY_METADATA), "metadata");

    /* Timestamp: validate only when the policy changed it */
    fts_getfield(l, event, FTS_KEY_TIMESTAMP);
    require_plain_table(l, -1, "log timestamp");
    fts_getfield(l, -1, FTS_KEY_SEC);
    fts_getfield(l, -2, FTS_KEY_NSEC);
    if (lua_type(l, -2) != LUA_TNUMBER || lua_type(l, -1) != LUA_TNUMBER) {
        return luaL_error(l, "timestamp sec/nsec must be numbers");
    }

    sec = lua_tonumber(l, -2);
    nsec = lua_tonumber(l, -1);
    if ((sec != (lua_Number) call->record->event.timestamp.tm.tv_sec ||
         nsec != (lua_Number) call->record->event.timestamp.tm.tv_nsec) &&
        (!isfinite(sec) || sec < 0 ||
         sec > (sizeof(time_t) > 4 ? 4294967293.0 : 2147483647.0) ||
         sec != floor(sec) || !isfinite(nsec) || nsec < 0 || nsec > 999999999 ||
         nsec != floor(nsec))) {
        return luaL_error(l, "timestamp out of range");
    }
    lua_pop(l, 3);

    if (validator) {
        lua_pushvalue(l, validator);
        lua_pushnumber(l, call->record->event.timestamp.tm.tv_sec);
        lua_pushnumber(l, call->record->event.timestamp.tm.tv_nsec);
        lua_call(l, 2, 0);
    }

    /* Context fields may only change through set/remove */
    if (context) {
        if (raw_field(l, context, FTS_KEY_ATTRIBUTES) != attributes->owned ||
            raw_field(l, context, FTS_KEY_METADATA) != metadata->owned) {
            return luaL_error(l, "replace context fields through set/remove, not root assignment");
        }

        validate_map(l, raw_field(l, context, FTS_KEY_ATTRIBUTES), "context attributes");
        validate_map(l, raw_field(l, context, FTS_KEY_METADATA), "context metadata");

        if (!validator) {
            memset(&current_metadata, 0, sizeof(current_metadata));
            current_metadata.variant = metadata->owned;
            if (has_otel_context(&current_metadata)) {
                return luaL_error(l, "transport schema cannot be changed");
            }
        }
    }

    /* OTLP semantic validation */
    if (has_otel_context(call->metadata)) {
        lua_rawgeti(l, LUA_REGISTRYINDEX, call->ctx->module_ref);
        lua_getfield(l, -1, "_validate");
        lua_pushvalue(l, event);
        lua_pushnumber(l, call->record->event.timestamp.tm.tv_sec);
        lua_pushnumber(l, call->record->event.timestamp.tm.tv_nsec);
        push_changed_fields(l, call, raw_field(l, event, FTS_KEY_METADATA), attributes->owned);
        lua_call(l, 4, 0);

        validate_utf8(l, raw_field(l, event, FTS_KEY_BODY),
                      call->record->cobj_record->variant, 0, FLB_TRUE);
        validate_utf8(l, raw_field(l, event, FTS_KEY_METADATA),
                      call->record->cobj_metadata->variant, 0, FLB_FALSE);
        validate_utf8(l, log_field(raw_field(l, event, FTS_KEY_METADATA), "attributes"),
                      log_field(call->record->cobj_metadata->variant, "attributes"),
                      0, FLB_TRUE);
        validate_utf8(l, attributes->owned, call->attributes->variant, 0, FLB_TRUE);
        validate_utf8(l, metadata->owned, call->metadata->variant, 0, FLB_FALSE);
    }

    if (cleanup && lua_istable(l, cleanup) &&
        (original_metadata->dirty || (attributes && attributes->dirty))) {
        lua_rawgeti(l, LUA_REGISTRYINDEX, call->ctx->module_ref);
        lua_getfield(l, -1, "_cleanup");
        lua_pushvalue(l, cleanup);
        lua_call(l, 1, 0);
        lua_pop(l, 1);
    }

    /*
     * Determine final changes only after all helpers have finished. Results:
     * "keep", body, metadata, context attributes, context metadata, sec, nsec.
     */
    lua_pushliteral(l, "keep");

    call->result_body = push_record_result(l, event, FTS_KEY_BODY, original_body);
    call->result_metadata = push_record_result(l, event, FTS_KEY_METADATA, original_metadata);

    if (context && attributes->dirty &&
        !(has_otel_context(call->metadata) ?
          context_attributes_equal(attributes->owned, call->attributes->variant) :
          values_equal(attributes->owned, call->attributes->variant))) {
        push_field_clone(l, context, FTS_KEY_ATTRIBUTES);
    }
    else {
        lua_pushnil(l);
    }

    if (context && metadata->dirty && !values_equal(metadata->owned, call->metadata->variant)) {
        push_field_clone(l, context, FTS_KEY_METADATA);
    }
    else {
        lua_pushnil(l);
    }

    lua_pushnumber(l, sec);
    lua_pushnumber(l, nsec);

    return 7;
}

static struct cfl_object *object_from_variant(struct cfl_variant *v)
{
    struct cfl_object *obj;

    obj = cfl_object_create();
    if (!obj) {
        return NULL;
    }

    obj->type = CFL_OBJECT_KVLIST;
    obj->variant = v;

    return obj;
}

static struct cfl_object *copy_object(struct cfl_object *source)
{
    struct cfl_variant *v;
    struct cfl_object *obj;

    v = fts_copy_value(source->variant, 0);
    if (!v) {
        return NULL;
    }

    obj = object_from_variant(v);
    if (!obj) {
        cfl_variant_destroy(v);
    }

    return obj;
}

static int values_equal(struct cfl_variant *a, struct cfl_variant *b)
{
    struct cfl_list *left;
    struct cfl_list *right;
    struct cfl_kvpair *pa;
    struct cfl_kvpair *pb;
    size_t i;

    if (!a || !b || a == b) {
        return a == b;
    }

    if (a->type != b->type) {
        return FLB_FALSE;
    }

    switch (a->type) {
    case CFL_VARIANT_NULL:
        return FLB_TRUE;
    case CFL_VARIANT_BOOL:
        return a->data.as_bool == b->data.as_bool;
    case CFL_VARIANT_INT:
        return a->data.as_int64 == b->data.as_int64;
    case CFL_VARIANT_UINT:
        return a->data.as_uint64 == b->data.as_uint64;
    case CFL_VARIANT_DOUBLE:
        return memcmp(&a->data.as_double, &b->data.as_double, sizeof(double)) == 0;
    case CFL_VARIANT_STRING:
    case CFL_VARIANT_BYTES:
        return cfl_variant_size_get(a) == cfl_variant_size_get(b) &&
               memcmp(a->data.as_string, b->data.as_string, cfl_variant_size_get(a)) == 0;
    case CFL_VARIANT_ARRAY:
        if (a->data.as_array->entry_count != b->data.as_array->entry_count) {
            return FLB_FALSE;
        }
        for (i = 0; i < a->data.as_array->entry_count; i++) {
            if (!values_equal(a->data.as_array->entries[i], b->data.as_array->entries[i])) {
                return FLB_FALSE;
            }
        }
        return FLB_TRUE;
    case CFL_VARIANT_KVLIST:
        left = a->data.as_kvlist->list.next;
        right = b->data.as_kvlist->list.next;
        while (left != &a->data.as_kvlist->list && right != &b->data.as_kvlist->list) {
            pa = cfl_list_entry(left, struct cfl_kvpair, _head);
            pb = cfl_list_entry(right, struct cfl_kvpair, _head);
            if (cfl_sds_len(pa->key) != cfl_sds_len(pb->key) ||
                memcmp(pa->key, pb->key, cfl_sds_len(pa->key)) != 0 ||
                !values_equal(pa->val, pb->val)) {
                return FLB_FALSE;
            }
            left = left->next;
            right = right->next;
        }
        return left == &a->data.as_kvlist->list && right == &b->data.as_kvlist->list;
    default:
        return FLB_FALSE;
    }
}

static int context_identity_key(struct cfl_kvpair *pair)
{
    return (cfl_sds_len(pair->key) == 11 && memcmp(pair->key, "resource_id", 11) == 0) ||
           (cfl_sds_len(pair->key) == 8 && memcmp(pair->key, "scope_id", 8) == 0);
}

/* Compare group metadata ignoring the transport identity keys. */
static int context_metadata_equal(struct cfl_variant *left, struct cfl_variant *right)
{
    struct cfl_list *a;
    struct cfl_list *b;
    struct cfl_kvpair *x;
    struct cfl_kvpair *y;

    if (left->type != CFL_VARIANT_KVLIST || right->type != CFL_VARIANT_KVLIST) {
        return FLB_FALSE;
    }

    a = left->data.as_kvlist->list.next;
    b = right->data.as_kvlist->list.next;

    for (;;) {
        while (a != &left->data.as_kvlist->list &&
               context_identity_key(cfl_list_entry(a, struct cfl_kvpair, _head))) {
            a = a->next;
        }
        while (b != &right->data.as_kvlist->list &&
               context_identity_key(cfl_list_entry(b, struct cfl_kvpair, _head))) {
            b = b->next;
        }

        if (a == &left->data.as_kvlist->list || b == &right->data.as_kvlist->list) {
            return a == &left->data.as_kvlist->list && b == &right->data.as_kvlist->list;
        }

        x = cfl_list_entry(a, struct cfl_kvpair, _head);
        y = cfl_list_entry(b, struct cfl_kvpair, _head);
        if (cfl_sds_len(x->key) != cfl_sds_len(y->key) ||
            memcmp(x->key, y->key, cfl_sds_len(x->key)) != 0 ||
            !values_equal(x->val, y->val)) {
            return FLB_FALSE;
        }

        a = a->next;
        b = b->next;
    }
}

/* Replace or add a regenerated transport ID; takes ownership of 'value'. */
static int set_transport_id(struct cfl_variant *metadata, const char *name,
                            struct cfl_variant *value)
{
    struct cfl_kvpair *pair;

    if (!value) {
        return -1;
    }

    pair = fts_find_pair(metadata, name, strlen(name));
    if (!pair) {
        if (cfl_kvlist_insert(metadata->data.as_kvlist, (char *) name, value) != 0) {
            cfl_variant_destroy(value);
            return -1;
        }
        return 0;
    }

    cfl_variant_destroy(pair->val);
    pair->val = value;
    cfl_container_move_variant_to_kvlist(metadata->data.as_kvlist, value);

    return 0;
}

static struct cfl_object *empty_object(void)
{
    struct cfl_kvlist *map;
    struct cfl_variant *v;
    struct cfl_object *obj;

    map = cfl_kvlist_create();
    if (!map) {
        return NULL;
    }

    v = cfl_variant_create_from_kvlist(map);
    if (!v) {
        cfl_kvlist_destroy(map);
        return NULL;
    }

    obj = object_from_variant(v);
    if (!obj) {
        cfl_variant_destroy(v);
    }

    return obj;
}

static int append_marker(struct flb_mp_chunk_cobj *out, int type,
                         struct cfl_object *attributes, struct cfl_object *metadata,
                         struct flb_mp_chunk_record **marker)
{
    struct flb_mp_chunk_record *record;

    record = flb_mp_chunk_record_create(out);
    if (!record) {
        return -1;
    }
    record->event.timestamp.tm.tv_sec = type;

    if (type == FLB_LOG_EVENT_GROUP_START) {
        record->cobj_record = copy_object(attributes);
        record->cobj_metadata = copy_object(metadata);
    }
    else {
        /* Later processors expect decoded group ends to carry empty maps. */
        record->cobj_record = empty_object();
        record->cobj_metadata = empty_object();
    }

    if (!record->cobj_record || !record->cobj_metadata) {
        flb_mp_chunk_cobj_record_destroy(NULL, record);
        return -1;
    }

    if (type == FLB_LOG_EVENT_GROUP_START) {
        record->cobj_group_attributes = record->cobj_record;
        record->cobj_group_metadata = record->cobj_metadata;
    }

    cfl_list_add(&record->_head, &out->records);
    if (marker) {
        *marker = record;
    }

    return 0;
}

/* MessagePack wire size, separate from conservative policy-memory accounting. */
static size_t wire_value_size(struct cfl_variant *value, int depth)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    size_t size;
    size_t child;
    size_t count;
    size_t index;
    int64_t signed_value;
    uint64_t unsigned_value;

    if (!value || depth > FTS_MAX_DEPTH) {
        return SIZE_MAX;
    }

    switch (value->type) {
    case CFL_VARIANT_NULL:
    case CFL_VARIANT_BOOL:
        return 1;
    case CFL_VARIANT_DOUBLE:
        return 9;
    case CFL_VARIANT_INT:
        signed_value = value->data.as_int64;
        if (signed_value < 0) {
            if (signed_value >= -32) {
                return 1;
            }
            else if (signed_value >= INT8_MIN) {
                return 2;
            }
            else if (signed_value >= INT16_MIN) {
                return 3;
            }
            else if (signed_value >= INT32_MIN) {
                return 5;
            }
            return 9;
        }
        unsigned_value = signed_value;
        break;
    case CFL_VARIANT_UINT:
        unsigned_value = value->data.as_uint64;
        break;
    case CFL_VARIANT_STRING:
        size = cfl_variant_size_get(value);
        if (size > SIZE_MAX - 5) {
            return SIZE_MAX;
        }
        if (size < 32) {
            return size + 1;
        }
        else if (size <= UINT8_MAX) {
            return size + 2;
        }
        else if (size <= UINT16_MAX) {
            return size + 3;
        }
        return size + 5;
    case CFL_VARIANT_BYTES:
        size = cfl_variant_size_get(value);
        if (size > SIZE_MAX - 5) {
            return SIZE_MAX;
        }
        if (size <= UINT8_MAX) {
            return size + 2;
        }
        else if (size <= UINT16_MAX) {
            return size + 3;
        }
        return size + 5;
    case CFL_VARIANT_ARRAY:
    case CFL_VARIANT_KVLIST:
        if (value->type == CFL_VARIANT_ARRAY) {
            count = value->data.as_array->entry_count;
        }
        else {
            count = cfl_kvlist_count(value->data.as_kvlist);
        }

        /* The CFL serializer reserves a map32 header even for small maps. */
        if (value->type == CFL_VARIANT_KVLIST) {
            size = 5;
        }
        else if (count < 16) {
            size = 1;
        }
        else if (count <= UINT16_MAX) {
            size = 3;
        }
        else {
            size = 5;
        }

        if (value->type == CFL_VARIANT_ARRAY) {
            for (index = 0; index < count; index++) {
                child = wire_value_size(value->data.as_array->entries[index], depth + 1);
                if (child > SIZE_MAX - size) {
                    return SIZE_MAX;
                }
                size += child;
            }
        }
        else {
            cfl_list_foreach(head, &value->data.as_kvlist->list) {
                pair = cfl_list_entry(head, struct cfl_kvpair, _head);

                /* key: string header plus bytes */
                child = cfl_sds_len(pair->key);
                if (size > SIZE_MAX - 5 || child > SIZE_MAX - size - 5) {
                    return SIZE_MAX;
                }
                if (child < 32) {
                    size += child + 1;
                }
                else if (child <= UINT8_MAX) {
                    size += child + 2;
                }
                else if (child <= UINT16_MAX) {
                    size += child + 3;
                }
                else {
                    size += child + 5;
                }

                /* value */
                child = wire_value_size(pair->val, depth + 1);
                if (child > SIZE_MAX - size) {
                    return SIZE_MAX;
                }
                size += child;
            }
        }
        return size;
    default:
        return SIZE_MAX;
    }

    /* Non-negative integers */
    if (unsigned_value <= 127) {
        return 1;
    }
    else if (unsigned_value <= UINT8_MAX) {
        return 2;
    }
    else if (unsigned_value <= UINT16_MAX) {
        return 3;
    }
    else if (unsigned_value <= UINT32_MAX) {
        return 5;
    }
    return 9;
}

struct borrowed_record {
    struct flb_mp_chunk_record *source;
    struct flb_mp_chunk_record *result;
    int body;
    int metadata;
    int pooled;
    struct cfl_list _head;
};

#define BORROW_BLOCK_ENTRIES 64
#define BORROW_BLOCK_LIMIT 8

struct borrowed_record_block {
    struct borrowed_record_block *next;
    size_t used;
    struct borrowed_record records[BORROW_BLOCK_ENTRIES];
};

struct borrowed_record_pool {
    struct borrowed_record_block *blocks;
    size_t count;
};

/* This pool owns bookkeeping only, never policy values or borrowed objects. */
static struct borrowed_record *borrow_record_create(struct borrowed_record_pool *pool)
{
    struct borrowed_record_block *block;
    struct borrowed_record *record;

    block = pool->blocks;
    if ((!block || block->used == BORROW_BLOCK_ENTRIES) && pool->count < BORROW_BLOCK_LIMIT) {
        /* On failure fall back to an individual heap allocation below */
        block = flb_calloc(1, sizeof(struct borrowed_record_block));
        if (block) {
            block->next = pool->blocks;
            pool->blocks = block;
            pool->count++;
        }
    }

    if (block && block->used < BORROW_BLOCK_ENTRIES) {
        record = &block->records[block->used++];
        record->pooled = FLB_TRUE;
        return record;
    }

    record = flb_calloc(1, sizeof(struct borrowed_record));
    if (!record) {
        flb_errno();
    }

    return record;
}

/* Ownership moves only after the entire staged chunk has been constructed. */
static void release_borrowed_records(struct cfl_list *records,
                                     struct borrowed_record_pool *pool, int commit)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct borrowed_record *record;
    struct borrowed_record_block *block;

    cfl_list_foreach_safe(head, tmp, records) {
        record = cfl_list_entry(head, struct borrowed_record, _head);

        if (record->body) {
            if (commit) {
                record->source->cobj_record = NULL;
            }
            else {
                record->result->cobj_record = NULL;
            }
        }

        if (record->metadata) {
            if (commit) {
                record->source->cobj_metadata = NULL;
            }
            else {
                record->result->cobj_metadata = NULL;
            }
        }

        cfl_list_del(head);
        if (!record->pooled) {
            flb_free(record);
        }
    }

    while (pool->blocks) {
        block = pool->blocks;
        pool->blocks = block->next;
        flb_free(block);
    }
    pool->count = 0;
}

/*
 * A following filter forces serialization; a following native processor may
 * mutate CFL containers and therefore requires ordinary heap-backed values.
 */
static int serializes_after_callback(struct flb_processor_instance *ins)
{
    struct flb_processor *parent = ins->pu->parent;
    struct mk_list *next = ins->pu->_head.next;
    struct flb_processor_unit *unit;

    if (next == &parent->logs) {
        return FLB_TRUE;
    }

    unit = mk_list_entry(next, struct flb_processor_unit, _head);
    return unit->unit_type == FLB_PROCESSOR_UNIT_FILTER;
}

/*
 * Open a group with the source context of a group that continues in the next
 * append, charging it to the output limit. OTLP transport IDs are fresh, so
 * the group never merges with an earlier group of this chunk.
 */
static int reopen_source_group(struct fts_runtime *ctx, struct flb_mp_chunk_cobj *out,
                               struct cfl_object *source_attrs,
                               struct cfl_object *source_meta,
                               int resource_id, int scope_id, size_t *output_bytes)
{
    size_t cost;
    struct cfl_object attrs = {0};
    struct cfl_object meta = {0};
    struct cfl_variant *id_value;
    struct flb_mp_chunk_record *group = NULL;

    cost = 32;
    if (*output_bytes > ctx->output_limit || ctx->output_limit - *output_bytes < cost) {
        return -1;
    }
    *output_bytes += cost;

    attrs.type = CFL_OBJECT_KVLIST;
    attrs.variant = source_attrs->variant;
    meta.type = CFL_OBJECT_KVLIST;
    meta.variant = source_meta ? source_meta->variant : NULL;

    cost = wire_value_size(attrs.variant, 0);
    if (cost > ctx->output_limit || *output_bytes > ctx->output_limit - cost) {
        return -1;
    }
    *output_bytes += cost;

    cost = wire_value_size(meta.variant, 0);
    if (cost > ctx->output_limit || *output_bytes > ctx->output_limit - cost) {
        return -1;
    }
    *output_bytes += cost;

    if (append_marker(out, FLB_LOG_EVENT_GROUP_START, &attrs, &meta, &group) != 0) {
        return -1;
    }

    if (has_otel_context(group->cobj_metadata)) {
        id_value = cfl_variant_create_from_int64(resource_id);
        if (set_transport_id(group->cobj_metadata->variant, "resource_id", id_value) != 0) {
            return -1;
        }
        id_value = cfl_variant_create_from_int64(scope_id);
        if (set_transport_id(group->cobj_metadata->variant, "scope_id", id_value) != 0) {
            return -1;
        }
    }

    return 0;
}

int fts_process_logs(struct flb_processor_instance *ins, void *data,
                     const char *tag, int tag_len)
{
    struct cfl_list borrowed;
    struct borrowed_record_pool borrow_pool = {0};
    struct borrowed_record *borrow;
    struct fts_runtime *ctx = ins->context;
    struct flb_mp_chunk_cobj *chunk = data;
    struct flb_mp_chunk_cobj *out = NULL;
    struct flb_mp_chunk_record *record;
    struct flb_mp_chunk_record *next;
    struct flb_mp_chunk_record *group = NULL;
    struct flb_mp_chunk_record *last_group = NULL;
    struct cfl_variant *last_source_id = NULL;
    struct cfl_kvpair *source_id;
    struct cfl_kvpair *last_resource;
    struct cfl_kvpair *current_resource;
    struct cfl_kvpair *last_identity;
    int resource_id = 0;
    struct cfl_object *source_attrs = NULL;
    struct cfl_object *source_meta = NULL;
    struct cfl_object attrs;
    struct cfl_object meta;
    struct record_call call;
    struct flb_condition *condition;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_variant *body;
    struct cfl_variant *metadata;
    struct fts_value *context_attrs;
    struct fts_value *context_meta;
    lua_State *l = ctx->vm->state;
    int ret;
    int type;
    int group_number = 0;
    int emitted_group_number = -1;
    int selected;
    int base;
    int emitted_id = 0;
    int errors = 0;
    int source_open = FLB_FALSE;
    struct flb_mp_chunk_record *continuation_end = NULL;
    size_t undo_mark;
    struct cfl_variant *id_value;
    size_t output_bytes = 0;
    size_t cost;

    ctx->tag_ready = FLB_FALSE;
    cfl_list_init(&borrowed);

    chunk->record_pool_enabled = FLB_TRUE;
    if (serializes_after_callback(ins)) {
        flb_mp_chunk_cobj_value_pool_enable(chunk);
    }

    /* Decode every record of the chunk, ignoring the condition for now */
    condition = chunk->condition;
    chunk->condition = NULL;
    while ((ret = flb_mp_chunk_cobj_record_next(chunk, &record)) == FLB_MP_CHUNK_RECORD_OK) {
    }
    chunk->condition = condition;
    chunk->record_pos = NULL;
    if (ret != FLB_MP_CHUNK_RECORD_EOF) {
        goto failure;
    }

    /* Staged output chunk; it replaces the original records on success */
    out = flb_calloc(1, sizeof(struct flb_mp_chunk_cobj));
    if (!out) {
        flb_errno();
        goto failure;
    }
    cfl_list_init(&out->records);
    out->record_pool_enabled = FLB_TRUE;

    /*
     * Records before an end marker that precedes any start belong to a group
     * opened by a previous append: they keep no context and the end marker is
     * forwarded to close that group.
     */
    cfl_list_foreach(head, &chunk->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        if (flb_log_event_decoder_get_record_type(&record->event, &type) != 0) {
            goto failure;
        }
        if (type == FLB_LOG_EVENT_GROUP_END) {
            continuation_end = record;
            break;
        }
        if (type == FLB_LOG_EVENT_GROUP_START) {
            break;
        }
    }

    cfl_list_foreach(head, &chunk->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);

        /* Group markers update the source context and are not copied as-is */
        if (flb_log_event_decoder_get_record_type(&record->event, &type) != 0) {
            goto failure;
        }

        if (type == FLB_LOG_EVENT_GROUP_START) {
            /* A nested start establishes a new flat transport context. */
            source_attrs = record->cobj_record;
            source_meta = record->cobj_metadata;
            source_open = FLB_TRUE;
            group_number++;
            continue;
        }

        if (type == FLB_LOG_EVENT_GROUP_END) {
            if (record == continuation_end) {
                if (output_bytes > ctx->output_limit || ctx->output_limit - output_bytes < 32) {
                    goto failure;
                }
                output_bytes += 32;
                if (append_marker(out, FLB_LOG_EVENT_GROUP_END, NULL, NULL, NULL) != 0) {
                    goto failure;
                }
                continuation_end = NULL;
                continue;
            }

            /* Stray ends carry no record and do not invalidate healthy siblings. */
            source_attrs = NULL;
            source_meta = NULL;
            source_open = FLB_FALSE;
            continue;
        }

        /* Defaults for records that are not selected or keep their values */
        selected = !condition || flb_condition_evaluate(condition, record);
        memset(&attrs, 0, sizeof(attrs));
        memset(&meta, 0, sizeof(meta));
        attrs.variant = source_attrs ? source_attrs->variant : NULL;
        meta.variant = source_meta ? source_meta->variant : NULL;
        base = lua_gettop(l);
        ret = 0;
        body = NULL;
        metadata = NULL;

        /* Run the policy for selected records */
        if (selected) {
            memset(&call, 0, sizeof(call));
            call.ctx = ctx;
            call.chunk = chunk;
            call.record = record;
            call.attributes = source_attrs;
            call.metadata = source_meta;
            call.tag = tag;
            call.tag_len = tag_len;

            /*
             * Plain records edit the chunk's heap tree in place; the undo log
             * keeps the whole chunk reversible until its output is final.
             */
            undo_mark = ctx->undo_count;
            ctx->inplace_ok = !source_attrs && ctx->undo_held <= ctx->memory_limit;
            ret = fts_runtime_call(ctx, &call, 7);
            ctx->inplace_ok = FLB_FALSE;
            ctx->native_bytes -= ctx->undo_charged;
            ctx->undo_charged = 0;

            if (ret != 0) {
                fts_undo_rollback(ctx, undo_mark);
                errors++;
                if (errors <= 5) {
                    flb_plg_error(ins, "log policy failed: %.256s; edits rolled back",
                                  lua_type(l, -1) == LUA_TSTRING ?
                                  lua_tostring(l, -1) : "non-string error");
                }
                if (strcmp(ctx->error_mode, "drop") == 0) {
                    lua_settop(l, base);
                    continue;
                }
            }
            else if (lua_type(l, base + 1) == LUA_TSTRING &&
                     strcmp(lua_tostring(l, base + 1), "drop") == 0) {
                lua_settop(l, base);
                continue;
            }
            else {
                body = call.result_body;
                metadata = call.result_metadata;
                context_attrs = lua_touserdata(l, base + 4);
                context_meta = lua_touserdata(l, base + 5);
                if (context_attrs) {
                    attrs.variant = context_attrs->owned;
                }
                if (context_meta) {
                    meta.variant = context_meta->owned;
                }
            }

            /* a group context would split the group continued from a previous append */
            if (continuation_end && attrs.variant) {
                fts_undo_rollback(ctx, undo_mark);
                errors++;
                if (errors <= 5) {
                    flb_plg_error(ins, "log policy failed: records continuing a group "
                                  "from a previous chunk cannot set a context; "
                                  "edits rolled back");
                }
                if (strcmp(ctx->error_mode, "drop") == 0) {
                    lua_settop(l, base);
                    continue;
                }
                ret = -1;
                body = NULL;
                metadata = NULL;
                attrs.variant = NULL;
                meta.variant = NULL;
            }
        }

        /* Close the open group when the record's context no longer matches it */
        if (group && (!attrs.variant || emitted_group_number != group_number ||
                      !values_equal(group->cobj_record->variant, attrs.variant) ||
                      !(has_otel_context(group->cobj_metadata) ?
                        context_metadata_equal(group->cobj_metadata->variant, meta.variant) :
                        values_equal(group->cobj_metadata->variant, meta.variant)))) {
            if (append_marker(out, FLB_LOG_EVENT_GROUP_END, NULL, NULL, NULL) != 0) {
                lua_settop(l, base);
                goto failure;
            }
            group = NULL;
        }

        /* Open a new group, charging its marker and context to the output limit */
        if (attrs.variant && !group) {
            if (output_bytes > ctx->output_limit || ctx->output_limit - output_bytes < 32) {
                lua_settop(l, base);
                goto failure;
            }
            output_bytes += 32;

            cost = wire_value_size(attrs.variant, 0);
            if (cost > ctx->output_limit || output_bytes > ctx->output_limit - cost) {
                lua_settop(l, base);
                goto failure;
            }
            output_bytes += cost;

            cost = wire_value_size(meta.variant, 0);
            if (cost > ctx->output_limit || output_bytes > ctx->output_limit - cost) {
                lua_settop(l, base);
                goto failure;
            }
            output_bytes += cost;

            attrs.type = CFL_OBJECT_KVLIST;
            meta.type = CFL_OBJECT_KVLIST;
            if (append_marker(out, FLB_LOG_EVENT_GROUP_START, &attrs, &meta, &group) != 0) {
                lua_settop(l, base);
                goto failure;
            }

            /* OTLP groups get regenerated resource_id/scope_id transport IDs */
            if (has_otel_context(group->cobj_metadata)) {
                /* Groups without a source ID never share a resource with others. */
                source_id = fts_find_pair(source_meta->variant, "resource_id", 11);
                last_resource = last_group ?
                                fts_find_pair(last_group->cobj_record->variant, "resource", 8) :
                                NULL;
                current_resource = fts_find_pair(group->cobj_record->variant, "resource", 8);

                if (source_id && last_group && last_source_id &&
                    values_equal(last_source_id, source_id->val) &&
                    context_kind_equal(last_resource ? last_resource->val : NULL,
                                       current_resource ? current_resource->val : NULL)) {
                    last_identity = fts_find_pair(last_group->cobj_metadata->variant,
                                                  "resource_id", 11);
                    id_value = fts_copy_value(last_identity->val, 0);
                }
                else {
                    id_value = cfl_variant_create_from_int64(resource_id++);
                }

                if (set_transport_id(group->cobj_metadata->variant, "resource_id",
                                     id_value) != 0) {
                    lua_settop(l, base);
                    goto failure;
                }

                id_value = cfl_variant_create_from_int64(emitted_id++);
                if (set_transport_id(group->cobj_metadata->variant, "scope_id", id_value) != 0) {
                    lua_settop(l, base);
                    goto failure;
                }

                last_group = group;
                last_source_id = source_id ? source_id->val : NULL;
            }
            else {
                last_group = NULL;
                last_source_id = NULL;
            }
            emitted_group_number = group_number;
        }

        if (!attrs.variant) {
            last_group = NULL;
            last_source_id = NULL;
        }

        /* Charge the record framing, body and metadata to the output limit */
        if (output_bytes > ctx->output_limit || ctx->output_limit - output_bytes < 16) {
            lua_settop(l, base);
            goto failure;
        }
        output_bytes += 16;

        cost = wire_value_size(body ? body : record->cobj_record->variant, 0);
        if (cost > ctx->output_limit || output_bytes > ctx->output_limit - cost) {
            lua_settop(l, base);
            goto failure;
        }
        output_bytes += cost;

        cost = wire_value_size(metadata ? metadata : record->cobj_metadata->variant, 0);
        if (cost > ctx->output_limit || output_bytes > ctx->output_limit - cost) {
            lua_settop(l, base);
            goto failure;
        }
        output_bytes += cost;

        /*
         * Build the output record: changed roots are copied into the chunk,
         * unchanged roots are borrowed from the source record.
         */
        next = flb_mp_chunk_record_create(out);
        if (!next) {
            lua_settop(l, base);
            goto failure;
        }
        next->event = record->event;
        next->cobj_record = body ? result_object(chunk, body) : record->cobj_record;
        next->cobj_metadata = metadata ? result_object(chunk, metadata) : record->cobj_metadata;

        if (selected && ret == 0 &&
            (record->event.timestamp.tm.tv_sec != (time_t) lua_tonumber(l, base + 6) ||
             record->event.timestamp.tm.tv_nsec != (long) lua_tonumber(l, base + 7))) {
            next->event.timestamp.tm.tv_sec = (time_t) lua_tonumber(l, base + 6);
            next->event.timestamp.tm.tv_nsec = (long) lua_tonumber(l, base + 7);
            next->event.raw_timestamp = NULL;
        }

        if (!next->cobj_record || !next->cobj_metadata) {
            if (!body) {
                next->cobj_record = NULL;
            }
            if (!metadata) {
                next->cobj_metadata = NULL;
            }
            flb_mp_chunk_cobj_record_destroy(NULL, next);
            lua_settop(l, base);
            goto failure;
        }

        /* Track borrowed roots so ownership can be settled at commit/rollback */
        if (!body || !metadata) {
            borrow = borrow_record_create(&borrow_pool);
            if (!borrow) {
                if (!body) {
                    next->cobj_record = NULL;
                }
                if (!metadata) {
                    next->cobj_metadata = NULL;
                }
                flb_mp_chunk_cobj_record_destroy(NULL, next);
                lua_settop(l, base);
                goto failure;
            }
            borrow->source = record;
            borrow->result = next;
            borrow->body = !body;
            borrow->metadata = !metadata;
            cfl_list_add(&borrow->_head, &borrowed);
        }

        next->cobj_group_attributes = group ? group->cobj_record : NULL;
        next->cobj_group_metadata = group ? group->cobj_metadata : NULL;
        cfl_list_add(&next->_head, &out->records);
        lua_settop(l, base);
    }

    /*
     * A source group still open at the end continues in the next append: keep
     * the output group open when it carries the source context, otherwise close
     * it and reopen the source context for the records that follow.
     */
    if (source_open && source_attrs && group &&
        (emitted_group_number != group_number ||
         !values_equal(group->cobj_record->variant, source_attrs->variant) ||
         !(has_otel_context(group->cobj_metadata) ?
           context_metadata_equal(group->cobj_metadata->variant, source_meta->variant) :
           values_equal(group->cobj_metadata->variant, source_meta->variant)))) {
        if (append_marker(out, FLB_LOG_EVENT_GROUP_END, NULL, NULL, NULL) != 0) {
            goto failure;
        }
        group = NULL;
    }

    if (source_open && source_attrs) {
        if (!group) {
            if (reopen_source_group(ctx, out, source_attrs, source_meta, resource_id,
                                    emitted_id, &output_bytes) != 0) {
                goto failure;
            }
        }
    }
    else if (group && append_marker(out, FLB_LOG_EVENT_GROUP_END, NULL, NULL, NULL) != 0) {
        /* Close an unterminated transport group after its last retained record. */
        goto failure;
    }

    /* Commit: drop the source records and move the staged ones into the chunk */
    fts_undo_commit(ctx);
    release_borrowed_records(&borrowed, &borrow_pool, FLB_TRUE);

    cfl_list_foreach_safe(head, tmp, &chunk->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        flb_mp_chunk_cobj_record_destroy(NULL, record);
    }

    cfl_list_foreach_safe(head, tmp, &out->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        cfl_list_del(head);
        cfl_list_add(head, &chunk->records);
    }

    chunk->active_group_attributes = NULL;
    chunk->active_group_metadata = NULL;
    flb_mp_chunk_cobj_destroy(out);

    if (errors) {
        fts_report_policy_error(ins);
        if (errors > 5) {
            flb_plg_warn(ins, "%d additional policy errors in this chunk", errors - 5);
        }
    }

    ctx->instructions_left = ctx->instruction_limit;
    fts_collect(ctx, FLB_FALSE);

    return FLB_PROCESSOR_SUCCESS;

failure:
    fts_undo_rollback(ctx, 0);
    release_borrowed_records(&borrowed, &borrow_pool, FLB_FALSE);
    flb_mp_chunk_cobj_destroy(out);
    ctx->instructions_left = ctx->instruction_limit;
    fts_collect(ctx, FLB_FALSE);

    flb_plg_error(ins, "cannot construct policy output; edits discarded");
    if (strcmp(ctx->error_mode, "drop") == 0) {
        cfl_list_foreach_safe(head, tmp, &chunk->records) {
            record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
            flb_mp_chunk_cobj_record_destroy(NULL, record);
        }
        chunk->active_group_attributes = NULL;
        chunk->active_group_metadata = NULL;
        fts_report_policy_error(ins);
        return FLB_PROCESSOR_SUCCESS;
    }

    return FLB_PROCESSOR_FAILURE;
}

static int register_log_helpers(lua_State *l)
{
    if (fts_load_helpers(l, fts_log_helpers, sizeof(fts_log_helpers) - 1,
                         "fluentbit.log_helpers") != 0) {
        return -1;
    }

    return 0;
}

const struct fts_signal_adapter fts_logs_adapter = {
    .event_type = FLB_PROCESSOR_LOGS,
    .register_helpers = register_log_helpers,
    .run_callback = run_record
};
