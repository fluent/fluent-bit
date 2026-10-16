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

#include <yyjson.h>
#include <fluent-bit/flb_mem.h>
#include <cfl/cfl_container.h>
#include <cfl/cfl_arena.h>
#include <cfl/cfl_hash.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <ctype.h>
#include "fts.h"
#include "fts_helpers.h"

#define VALUE_MT "fluentbit.typed_value"
#define SAFE_INTEGER 9007199254740991.0

/* Empty input maps need no native allocation until a policy writes to them.
 * This immutable backing is never attached to a mutable CFL container. */
static struct cfl_kvlist empty_map = {
    .list = {&empty_map.list, &empty_map.list}
};
static struct cfl_variant empty_value = {
    .type = CFL_VARIANT_KVLIST,
    .data.as_kvlist = &empty_map
};

static struct fts_value *push_value(lua_State *l, struct cfl_variant *v, int readonly,
                                    int borrowed);

/* Record handles may borrow chunk storage, so they are valid only during the
 * callback that created them. copy() returns a value that can be kept. */
static struct fts_value *check_live(lua_State *l, struct fts_value *value)
{
    if (value->record && value->generation != value->ctx->generation) {
        luaL_error(l, "log value used after its callback; use copy() to keep it");
    }

    return value;
}

/* Only push_value() creates userdata of this exact size, and it stamps the
 * private runtime pointer; policies cannot forge either. Comparing them avoids
 * a metatable round trip on every typed call. */
static struct fts_value *check_value(lua_State *l, int index)
{
    struct fts_runtime *ctx;
    struct fts_value *value;

    lua_getallocf(l, (void **) &ctx);

    value = NULL;
    if (lua_type(l, index) == LUA_TUSERDATA && lua_objlen(l, index) == sizeof(*value)) {
        value = lua_touserdata(l, index);
    }

    if (!value || value->ctx != ctx) {
        luaL_argerror(l, index, "typed value expected");
        return NULL;
    }

    check_live(l, value);

    return value;
}

/* Only adapter callbacks call these: their closures carry the key strings
 * as upvalues, in fts_key order. */
void fts_getfield(lua_State *l, int index, enum fts_key key)
{
    if (index < 0 && index > LUA_REGISTRYINDEX) {
        index = lua_gettop(l) + index + 1;
    }

    lua_pushvalue(l, lua_upvalueindex(key + 1));
    lua_rawget(l, index);
}

void fts_setfield(lua_State *l, int index, enum fts_key key)
{
    if (index < 0 && index > LUA_REGISTRYINDEX) {
        index = lua_gettop(l) + index + 1;
    }

    lua_pushvalue(l, lua_upvalueindex(key + 1));
    lua_insert(l, -2);
    lua_rawset(l, index);
}

/* Compare stored entries, preserving duplicate keys and their order. */
int fts_values_equal(struct cfl_variant *a, struct cfl_variant *b, int depth)
{
    struct cfl_list *left;
    struct cfl_list *right;
    struct cfl_kvpair *x;
    struct cfl_kvpair *y;
    size_t i;

    if (a == b) {
        return FLB_TRUE;
    }

    if (!a || !b || a->type != b->type || depth >= FTS_MAX_DEPTH) {
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
            if (!fts_values_equal(a->data.as_array->entries[i],
                                  b->data.as_array->entries[i], depth + 1)) {
                return FLB_FALSE;
            }
        }

        return FLB_TRUE;
    case CFL_VARIANT_KVLIST:
        left = a->data.as_kvlist->list.next;
        right = b->data.as_kvlist->list.next;

        while (left != &a->data.as_kvlist->list && right != &b->data.as_kvlist->list) {
            x = cfl_list_entry(left, struct cfl_kvpair, _head);
            y = cfl_list_entry(right, struct cfl_kvpair, _head);
            if (cfl_sds_len(x->key) != cfl_sds_len(y->key) ||
                memcmp(x->key, y->key, cfl_sds_len(x->key)) != 0 ||
                !fts_values_equal(x->val, y->val, depth + 1)) {
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

static int equal_values(lua_State *l)
{
    lua_pushboolean(l, fts_values_equal(fts_resolve_value(l, 1, 0),
                                        fts_resolve_value(l, 2, 0), 0));
    return 1;
}

/* Arena copies are private native results. Script-visible snapshots use heap
 * ownership so retained Lua values remain independent of chunk lifetimes. */
struct cfl_variant *fts_copy_value_in(struct cfl_variant *v, int depth, struct cfl_arena *arena)
{
    struct cfl_variant *copy;
    struct cfl_variant *child;
    struct cfl_array *array;
    struct cfl_kvlist *map;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    size_t i;
    size_t length;

    if (!v || depth >= FTS_MAX_DEPTH) {
        return NULL;
    }

    switch (v->type) {
    case CFL_VARIANT_NULL:
        return cfl_variant_create_from_null_in(arena);
    case CFL_VARIANT_BOOL:
        return cfl_variant_create_from_bool_in(arena, v->data.as_bool);
    case CFL_VARIANT_INT:
        return cfl_variant_create_from_int64_in(arena, v->data.as_int64);
    case CFL_VARIANT_UINT:
        return cfl_variant_create_from_uint64_in(arena, v->data.as_uint64);
    case CFL_VARIANT_DOUBLE:
        return cfl_variant_create_from_double_in(arena, v->data.as_double);
    case CFL_VARIANT_STRING:
    case CFL_VARIANT_BYTES:
        if (arena) {
            if (v->type == CFL_VARIANT_STRING) {
                return cfl_variant_create_from_string_s_in(arena, v->data.as_string,
                                                            cfl_variant_size_get(v), CFL_FALSE);
            }
            return cfl_variant_create_from_bytes_in(arena, v->data.as_bytes,
                                                     cfl_variant_size_get(v), CFL_FALSE);
        }

        /* Consumers outside FTS read string and bytes lengths through cfl_sds_len(),
         * so heap copies always own a real sds payload. */
        length = cfl_variant_size_get(v);
        if (length > INT_MAX) {
            return NULL;
        }

        if (v->type == CFL_VARIANT_STRING) {
            copy = cfl_variant_create_from_string_s(v->data.as_string, length, CFL_FALSE);
        }
        else {
            copy = cfl_variant_create_from_bytes(v->data.as_bytes, length, CFL_FALSE);
        }

        if (!copy) {
            flb_errno();
        }
        return copy;
    case CFL_VARIANT_ARRAY:
        array = cfl_array_create_in(arena, v->data.as_array->entry_count);
        if (!array) {
            return NULL;
        }

        for (i = 0; i < v->data.as_array->entry_count; i++) {
            child = fts_copy_value_in(v->data.as_array->entries[i], depth + 1, arena);
            if (!child || cfl_array_append(array, child) != 0) {
                cfl_variant_destroy(child);
                cfl_array_destroy(array);
                return NULL;
            }
        }

        copy = cfl_variant_create_from_array_in(arena, array);
        if (!copy) {
            cfl_array_destroy(array);
        }
        return copy;
    case CFL_VARIANT_KVLIST:
        map = cfl_kvlist_create_in(arena);
        if (!map) {
            return NULL;
        }

        cfl_list_foreach(head, &v->data.as_kvlist->list) {
            pair = cfl_list_entry(head, struct cfl_kvpair, _head);
            child = fts_copy_value_in(pair->val, depth + 1, arena);
            if (!child ||
                cfl_kvlist_insert_s(map, pair->key, cfl_sds_len(pair->key), child) != 0) {
                cfl_variant_destroy(child);
                cfl_kvlist_destroy(map);
                return NULL;
            }
        }

        copy = cfl_variant_create_from_kvlist_in(arena, map);
        if (!copy) {
            cfl_kvlist_destroy(map);
        }
        return copy;
    default:
        return NULL;
    }
}

struct cfl_variant *fts_copy_value(struct cfl_variant *value, int depth)
{
    return fts_copy_value_in(value, depth, NULL);
}

/* Conservative accounting includes container overhead and every owned scalar. */
size_t fts_value_cost(struct cfl_variant *v, int depth)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    size_t total = 256;
    size_t child;
    size_t i;

    if (!v || depth >= FTS_MAX_DEPTH) {
        return SIZE_MAX;
    }

    if (v->type == CFL_VARIANT_STRING || v->type == CFL_VARIANT_BYTES) {
        child = cfl_variant_size_get(v);
        return child > SIZE_MAX - total ? SIZE_MAX : total + child;
    }

    if (v->type == CFL_VARIANT_ARRAY) {
        for (i = 0; i < v->data.as_array->entry_count; i++) {
            child = fts_value_cost(v->data.as_array->entries[i], depth + 1);
            if (child > SIZE_MAX - total) {
                return SIZE_MAX;
            }
            total += child;
        }
    }
    else if (v->type == CFL_VARIANT_KVLIST) {
        cfl_list_foreach(head, &v->data.as_kvlist->list) {
            pair = cfl_list_entry(head, struct cfl_kvpair, _head);
            child = cfl_sds_len(pair->key) + 128;
            if (child > SIZE_MAX - total) {
                return SIZE_MAX;
            }
            total += child;

            child = fts_value_cost(pair->val, depth + 1);
            if (child > SIZE_MAX - total) {
                return SIZE_MAX;
            }
            total += child;
        }
    }

    return total;
}

void fts_charge_value(lua_State *l, struct fts_value *owner, size_t bytes)
{
    struct fts_runtime *ctx = owner->ctx;

    if (bytes > ctx->memory_limit || ctx->native_bytes > ctx->memory_limit - bytes ||
        ctx->lua_bytes > ctx->memory_limit - ctx->native_bytes - bytes) {
        /* Native values are invisible to Lua's allocation-based GC pacing. */
        lua_gc(l, LUA_GCCOLLECT, 0);
    }

    if (bytes > ctx->memory_limit || ctx->native_bytes > ctx->memory_limit - bytes ||
        ctx->lua_bytes > ctx->memory_limit - ctx->native_bytes - bytes) {
        luaL_error(l, "Lua policy memory limit exceeded");
    }

    /* In-place additions become chunk data when the record callback ends. */
    if (owner->inplace) {
        ctx->undo_charged += bytes;
    }
    else {
        owner->charged += bytes;
    }

    ctx->native_bytes += bytes;
    if (bytes > SIZE_MAX - ctx->native_allocated) {
        ctx->native_allocated = SIZE_MAX;
    }
    else {
        ctx->native_allocated = ctx->native_allocated + bytes;
    }
}

/* No native ownership or reservation means no finalizer is needed.
 * A first write installs normal ownership before allocating storage. */
struct fts_value *fts_push_empty_map(lua_State *l)
{
    return fts_push_borrowed(l, &empty_value);
}

/* Record roots read the chunk's tree directly; the first write copies it. */
struct fts_value *fts_push_borrowed(lua_State *l, struct cfl_variant *source)
{
    struct fts_value *value;

    value = push_value(l, source, FLB_FALSE, FLB_TRUE);
    value->record = FLB_TRUE;
    value->generation = value->ctx->generation;

    return value;
}

/* Values written into a container come from the same allocator as it. */
static struct cfl_arena *container_arena(struct cfl_variant *container)
{
    if (container->type == CFL_VARIANT_KVLIST) {
        return container->data.as_kvlist->arena;
    }

    if (container->type == CFL_VARIANT_ARRAY) {
        return container->data.as_array->arena;
    }

    return NULL;
}

/* Exact byte matching: OTel attribute names are case sensitive. */
struct cfl_kvpair *fts_find_pair(struct cfl_variant *v, const char *key, size_t length)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    if (v->type != CFL_VARIANT_KVLIST) {
        return NULL;
    }

    cfl_list_foreach(head, &v->data.as_kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (cfl_sds_len(pair->key) == length && memcmp(pair->key, key, length) == 0) {
            return pair;
        }
    }

    return NULL;
}

/* Views retain their parent through their Lua environment. Resolve each use
 * rather than storing child pointers that set/remove could invalidate. */
struct cfl_variant *fts_resolve_value(lua_State *l, int index, int depth)
{
    struct fts_value *value;
    struct cfl_variant *parent;
    struct cfl_variant *result = NULL;
    struct cfl_kvpair *pair;
    const char *key;
    size_t length;
    lua_Number position;

    value = check_value(l, index);
    if (value->owned) {
        return value->owned;
    }

    if (value->cache && value->epoch == value->root->epoch) {
        check_live(l, value->root);
        return value->cache;
    }

    if (depth >= FTS_MAX_DEPTH || !lua_checkstack(l, 4)) {
        luaL_error(l, "typed value nesting exceeds limit");
    }

    lua_getfenv(l, index);
    lua_rawgeti(l, -1, 1);
    parent = fts_resolve_value(l, -1, depth + 1);
    lua_pop(l, 1);

    lua_rawgeti(l, -1, 2);
    if (parent->type == CFL_VARIANT_KVLIST && lua_type(l, -1) == LUA_TSTRING) {
        key = lua_tolstring(l, -1, &length);
        pair = fts_find_pair(parent, key, length);
        if (pair) {
            result = pair->val;
        }
    }
    else if (parent->type == CFL_VARIANT_ARRAY && lua_type(l, -1) == LUA_TNUMBER) {
        position = lua_tonumber(l, -1);
        if (position >= 1 && position <= parent->data.as_array->entry_count) {
            result = parent->data.as_array->entries[(size_t) position - 1];
        }
    }
    lua_pop(l, 2);

    if (!result) {
        luaL_error(l, "typed value path no longer exists");
    }

    value->cache = result;
    value->epoch = value->root->epoch;

    return result;
}

static struct fts_value *push_value(lua_State *l, struct cfl_variant *v, int readonly,
                                    int borrowed)
{
    struct fts_value *value;

    value = lua_newuserdata(l, sizeof(*value));
    value->owned = v;
    value->readonly = readonly;
    value->dirty = FLB_FALSE;
    value->depth_changed = !borrowed;
    value->borrowed = borrowed;
    value->record = FLB_FALSE;
    value->inplace = FLB_FALSE;
    value->generation = 0;
    value->charged = 0;
    value->root = NULL;
    value->cache = NULL;
    value->epoch = 0;
    lua_getallocf(l, (void **) &value->ctx);

    /* Borrowed storage is not owned, so it needs no finalizer. */
    if (borrowed) {
        lua_rawgeti(l, LUA_REGISTRYINDEX, value->ctx->empty_metatable_ref);
    }
    else {
        lua_rawgeti(l, LUA_REGISTRYINDEX, value->ctx->value_metatable_ref);
    }
    lua_setmetatable(l, -2);

    return value;
}

struct fts_value *fts_push_owned(lua_State *l, struct cfl_variant *v, int readonly)
{
    return push_value(l, v, readonly, FLB_FALSE);
}

static void push_view(lua_State *l, int parent, int key)
{
    struct fts_value *owner;
    struct fts_value *view;

    owner = check_value(l, parent);
    if (!owner->owned && !owner->root) {
        luaL_error(l, "typed value has no storage");
    }

    /* Views own no storage, so they use the finalizer-free metatable. */
    view = push_value(l, NULL, owner->readonly, FLB_TRUE);
    view->borrowed = FLB_FALSE;
    view->depth_changed = FLB_TRUE;
    view->root = owner->owned ? owner : owner->root;

    /* The environment pins the parent; slots 1 and 2 hold parent and key. */
    lua_createtable(l, 2, 0);
    lua_pushvalue(l, parent);
    lua_rawseti(l, -2, 1);
    lua_pushvalue(l, key);
    lua_rawseti(l, -2, 2);
    lua_setfenv(l, -2);
}

static int value_gc(lua_State *l)
{
    struct fts_value *value;

    /* Only the VM can call this private finalizer. */
    value = lua_touserdata(l, 1);
    if (!value->borrowed) {
        cfl_variant_destroy(value->owned);
    }

    value->owned = NULL;
    value->ctx->native_bytes -= value->charged;
    value->charged = 0;

    return 0;
}

static int value_type(lua_State *l)
{
    struct cfl_variant *v;
    const char *name;

    v = fts_resolve_value(l, 1, 0);
    switch (v->type) {
    case CFL_VARIANT_NULL:
        name = "null";
        break;
    case CFL_VARIANT_BOOL:
        name = "bool";
        break;
    case CFL_VARIANT_INT:
        name = "int64";
        break;
    case CFL_VARIANT_UINT:
        name = "uint64";
        break;
    case CFL_VARIANT_DOUBLE:
        name = "double";
        break;
    case CFL_VARIANT_STRING:
        name = "string";
        break;
    case CFL_VARIANT_BYTES:
        name = "bytes";
        break;
    case CFL_VARIANT_ARRAY:
        name = "array";
        break;
    case CFL_VARIANT_KVLIST:
        name = "map";
        break;
    default:
        return luaL_error(l, "unsupported telemetry type");
    }

    lua_pushstring(l, name);
    return 1;
}

static int push_scalar(lua_State *l, struct cfl_variant *v)
{
    char buffer[32];

    switch (v->type) {
    case CFL_VARIANT_NULL:
        lua_pushnil(l);
        break;
    case CFL_VARIANT_BOOL:
        lua_pushboolean(l, v->data.as_bool);
        break;
    case CFL_VARIANT_DOUBLE:
        lua_pushnumber(l, v->data.as_double);
        break;
    case CFL_VARIANT_STRING:
        lua_pushlstring(l, v->data.as_string, cfl_variant_size_get(v));
        break;
    case CFL_VARIANT_BYTES:
        lua_pushlstring(l, v->data.as_bytes, cfl_variant_size_get(v));
        break;
    case CFL_VARIANT_INT:
        snprintf(buffer, sizeof(buffer), "%" PRId64, v->data.as_int64);
        lua_pushstring(l, buffer);
        break;
    case CFL_VARIANT_UINT:
        snprintf(buffer, sizeof(buffer), "%" PRIu64, v->data.as_uint64);
        lua_pushstring(l, buffer);
        break;
    default:
        return luaL_error(l, "value() requires a scalar; use get() for containers");
    }

    return 1;
}

static int push_number(lua_State *l, struct cfl_variant *v)
{
    lua_Number number;

    if (v->type == CFL_VARIANT_INT) {
        if (v->data.as_int64 < -INT64_C(9007199254740991) ||
            v->data.as_int64 > INT64_C(9007199254740991)) {
            return luaL_error(l, "integer cannot be represented exactly as a Lua number");
        }
        number = v->data.as_int64;
    }
    else if (v->type == CFL_VARIANT_UINT) {
        if (v->data.as_uint64 > UINT64_C(9007199254740991)) {
            return luaL_error(l, "integer cannot be represented exactly as a Lua number");
        }
        number = v->data.as_uint64;
    }
    else if (v->type == CFL_VARIANT_DOUBLE) {
        number = v->data.as_double;
    }
    else {
        return luaL_error(l, "number() requires a numeric value");
    }

    lua_pushnumber(l, number);
    return 1;
}

static int value_scalar(lua_State *l)
{
    return push_scalar(l, fts_resolve_value(l, 1, 0));
}

static int value_number(lua_State *l)
{
    return push_number(l, fts_resolve_value(l, 1, 0));
}

static size_t array_index(lua_State *l, struct cfl_variant *v, int index)
{
    lua_Number position;

    if (lua_type(l, index) != LUA_TNUMBER) {
        luaL_error(l, "array index must be a number");
    }

    position = lua_tonumber(l, index);
    if (!isfinite(position) || position != floor(position) || position < 1 ||
        position > v->data.as_array->entry_count) {
        luaL_error(l, "array index out of bounds (indices start at 1)");
    }

    return (size_t) position - 1;
}

/* Resolve once without creating a Lua view for scalar reads. */
static struct cfl_variant *get_child(lua_State *l)
{
    struct cfl_variant *v;
    struct cfl_kvpair *pair;
    const char *key;
    size_t length;

    v = fts_resolve_value(l, 1, 0);
    if (v->type == CFL_VARIANT_KVLIST) {
        if (lua_type(l, 2) != LUA_TSTRING) {
            luaL_error(l, "map key must be a string");
        }

        key = lua_tolstring(l, 2, &length);
        pair = fts_find_pair(v, key, length);
        return pair ? pair->val : NULL;
    }

    if (v->type == CFL_VARIANT_ARRAY) {
        return v->data.as_array->entries[array_index(l, v, 2)];
    }

    luaL_error(l, "get() requires a map or array");
    return NULL;
}

static int value_get(lua_State *l)
{
    if (!get_child(l)) {
        lua_pushnil(l);
        return 1;
    }

    push_view(l, 1, 2);
    return 1;
}

/* Scalar convenience accessors retain strict types and missing-key semantics. */
static int get_scalar(lua_State *l, int type)
{
    struct cfl_variant *v;

    v = get_child(l);
    if (!v) {
        lua_pushnil(l);
        return 1;
    }

    if (type == CFL_VARIANT_DOUBLE) {
        return push_number(l, v);
    }

    if (v->type != type) {
        return luaL_error(l, "field has a different type than the requested scalar accessor");
    }

    return push_scalar(l, v);
}

static int value_get_string(lua_State *l)
{
    return get_scalar(l, CFL_VARIANT_STRING);
}

static int value_get_bool(lua_State *l)
{
    return get_scalar(l, CFL_VARIANT_BOOL);
}

static int value_get_number(lua_State *l)
{
    return get_scalar(l, CFL_VARIANT_DOUBLE);
}

enum {
    UNDO_SET_PAIR,
    UNDO_INSERT_PAIR,
    UNDO_REMOVE_PAIR,
    UNDO_SET_INDEX,
    UNDO_APPEND
};

/* Reserve before mutating so a recorded edit can never be lost. */
static void undo_reserve(lua_State *l, struct fts_runtime *ctx)
{
    struct fts_undo_entry *entries;
    size_t size;

    if (ctx->undo_count < ctx->undo_size) {
        return;
    }

    size = ctx->undo_size ? ctx->undo_size * 2 : 64;
    if (size > SIZE_MAX / sizeof(*entries)) {
        luaL_error(l, "cannot allocate edit log");
    }

    entries = flb_realloc(ctx->undo, size * sizeof(*entries));
    if (!entries) {
        flb_errno();
        luaL_error(l, "cannot allocate edit log");
    }

    ctx->undo = entries;
    ctx->undo_size = size;
}

static void undo_add(struct fts_runtime *ctx, int type, struct cfl_list *list,
                     struct cfl_kvpair *pair, struct cfl_list *prev,
                     struct cfl_array *array, size_t index, struct cfl_variant *old)
{
    struct fts_undo_entry *entry;
    struct cfl_variant *held_value = old;
    size_t held = 64;
    size_t cost;

    entry = &ctx->undo[ctx->undo_count++];
    entry->type = type;
    entry->list = list;
    entry->pair = pair;
    entry->prev = prev;
    entry->array = array;
    entry->index = index;
    entry->old = old;

    if (type == UNDO_REMOVE_PAIR) {
        held += 128 + cfl_sds_len(pair->key);
        held_value = pair->val;
    }

    if (held_value) {
        cost = fts_value_cost(held_value, 0);
        held = cost > SIZE_MAX - held ? SIZE_MAX : held + cost;
    }

    ctx->undo_held = held > SIZE_MAX - ctx->undo_held ? SIZE_MAX : ctx->undo_held + held;
}

/* Restore edits newer than mark, newest first. */
void fts_undo_rollback(struct fts_runtime *ctx, size_t mark)
{
    struct fts_undo_entry *entry;
    struct cfl_variant *current;

    while (ctx->undo_count > mark) {
        entry = &ctx->undo[--ctx->undo_count];
        switch (entry->type) {
        case UNDO_SET_PAIR:
            current = entry->pair->val;
            entry->pair->val = entry->old;
            cfl_variant_destroy(current);
            break;
        case UNDO_INSERT_PAIR:
            cfl_kvpair_destroy(entry->pair);
            break;
        case UNDO_REMOVE_PAIR:
            /* cfl_list_add_after() leaves next->prev stale; insert before next. */
            cfl_list_add_before(&entry->pair->_head, entry->prev->next, entry->list);
            break;
        case UNDO_SET_INDEX:
            current = entry->array->entries[entry->index];
            entry->array->entries[entry->index] = entry->old;
            cfl_variant_destroy(current);
            break;
        case UNDO_APPEND:
            current = entry->array->entries[--entry->array->entry_count];
            entry->array->entries[entry->array->entry_count] = NULL;
            cfl_variant_destroy(current);
            break;
        }
    }

    if (mark == 0) {
        ctx->undo_held = 0;
    }
}

/* Release replaced and removed values once the chunk output is final. */
void fts_undo_commit(struct fts_runtime *ctx)
{
    struct fts_undo_entry *entry;
    size_t index;

    for (index = 0; index < ctx->undo_count; index++) {
        entry = &ctx->undo[index];
        if (entry->type == UNDO_SET_PAIR || entry->type == UNDO_SET_INDEX) {
            cfl_variant_destroy(entry->old);
        }
        else if (entry->type == UNDO_REMOVE_PAIR) {
            cfl_kvpair_destroy(entry->pair);
        }
    }

    ctx->undo_count = 0;
    ctx->undo_held = 0;
}

static struct fts_value *root_value(lua_State *l, int index)
{
    struct fts_value *value;

    /* Public mutation entry points already verified the receiver. View
     * environments are private and retain only verified parent values. */
    value = lua_touserdata(l, index);
    return value->owned ? value : value->root;
}

static size_t cost_add(size_t a, size_t b)
{
    return b > SIZE_MAX - a ? SIZE_MAX : a + b;
}

static void credit_value(lua_State *l, struct fts_value *owner, size_t bytes)
{
    /* Replaced in-place data stays allocated in the undo log until commit. */
    if (owner->inplace) {
        return;
    }

    /* An unknown cost never releases reservations held by other values. */
    if (bytes == SIZE_MAX) {
        return;
    }

    if (bytes > owner->charged) {
        bytes = owner->charged;
    }

    owner->charged -= bytes;
    owner->ctx->native_bytes -= bytes;
}

static void charge_mutation(lua_State *l, int index, size_t overhead)
{
    size_t bytes = 256;
    size_t length;

    if (lua_type(l, index) == LUA_TUSERDATA) {
        bytes = fts_value_cost(fts_resolve_value(l, index, 0), 0);
        if (bytes == SIZE_MAX) {
            luaL_error(l, "typed value nesting exceeds limit");
        }
    }
    else if (lua_type(l, index) == LUA_TSTRING) {
        lua_tolstring(l, index, &length);
        bytes += length;
    }
    else if (lua_type(l, index) == LUA_TNUMBER) {
        if (!isfinite(lua_tonumber(l, index))) {
            luaL_error(l, "telemetry numbers must be finite");
        }
    }
    else if (lua_type(l, index) != LUA_TBOOLEAN) {
        luaL_error(l, "use typed telemetry values and fb.null");
    }

    fts_charge_value(l, root_value(l, 1), cost_add(bytes, overhead));
}

static struct cfl_variant *from_lua(lua_State *l, int index, struct cfl_arena *arena)
{
    const char *str;
    size_t length;
    lua_Number number;
    struct cfl_variant *v;

    switch (lua_type(l, index)) {
    case LUA_TUSERDATA:
        v = fts_copy_value_in(fts_resolve_value(l, index, 0), 0, arena);
        break;
    case LUA_TBOOLEAN:
        v = cfl_variant_create_from_bool_in(arena, lua_toboolean(l, index));
        break;
    case LUA_TSTRING:
        str = lua_tolstring(l, index, &length);
        v = cfl_variant_create_from_string_s_in(arena, (char *) str, length, CFL_FALSE);
        break;
    case LUA_TNUMBER:
        number = lua_tonumber(l, index);
        if (!isfinite(number)) {
            luaL_error(l, "number must be finite");
        }
        v = cfl_variant_create_from_double_in(arena, number);
        break;
    default:
        luaL_error(l, "use a scalar or typed value; use fb.null instead of nil");
        return NULL;
    }

    if (!v) {
        luaL_error(l, "cannot copy typed value (allocation or nesting limit)");
    }

    return v;
}

static void mark_dirty(lua_State *l, int index)
{
    struct fts_value *value;

    value = check_value(l, index);
    if (!value->owned) {
        value = value->root;
        check_live(l, value);
    }

    value->dirty = FLB_TRUE;
}

/* Copy a borrowed root before its first write; views address it by path. */
static void detach_root(lua_State *l, int index, int depth)
{
    struct fts_value *value;
    struct cfl_variant *copy;
    size_t cost;

    value = lua_touserdata(l, index);
    if (!value->owned) {
        if (depth >= FTS_MAX_DEPTH || !lua_checkstack(l, 4)) {
            luaL_error(l, "typed value nesting exceeds limit");
        }

        lua_getfenv(l, index);
        lua_rawgeti(l, -1, 1);
        detach_root(l, lua_gettop(l), depth + 1);
        lua_pop(l, 2);
        return;
    }

    if (!value->borrowed || value->inplace) {
        return;
    }

    check_live(l, value);

    /*
     * Chunk trees are edited in place with an undo log. Written values are
     * allocated from the container's own arena, if any. Shared empty maps
     * are immutable.
     */
    if (value->ctx->inplace_ok && value->owned != &empty_value) {
        value->inplace = FLB_TRUE;
        return;
    }

    cost = fts_value_cost(value->owned, 0);
    if (cost == SIZE_MAX) {
        luaL_error(l, "cannot copy log value (allocation or nesting limit)");
    }

    /* The finalizer skips borrowed storage, so charges are released on failure. */
    lua_rawgeti(l, LUA_REGISTRYINDEX, value->ctx->value_metatable_ref);
    lua_setmetatable(l, index);
    if (value->charged == 0) {
        fts_charge_value(l, value, cost);
    }

    copy = fts_copy_value(value->owned, 0);
    if (!copy) {
        luaL_error(l, "cannot copy log value (allocation or nesting limit)");
    }

    value->owned = copy;
    value->borrowed = FLB_FALSE;
}

static struct cfl_variant *writable_value(lua_State *l)
{
    struct fts_value *value;

    value = check_value(l, 1);
    if (value->readonly) {
        luaL_error(l, "typed value is read-only");
    }

    detach_root(l, 1, 0);
    (value->owned ? value : value->root)->epoch++;

    if (value->owned) {
        value->dirty = FLB_TRUE;
        return value->owned;
    }

    mark_dirty(l, 1);
    return fts_resolve_value(l, 1, 0);
}

static int value_set(lua_State *l)
{
    struct cfl_variant *v;
    struct cfl_variant *replacement;
    struct cfl_variant *old;
    struct cfl_kvpair *pair;
    struct cfl_kvpair *duplicate;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_list *prev;
    struct fts_value *self;
    struct fts_value *root;
    const char *key;
    size_t length;
    size_t position;

    v = writable_value(l);
    root = root_value(l, 1);
    if (root->inplace) {
        undo_reserve(l, root->ctx);
    }

    self = lua_touserdata(l, 1);
    if (!self->owned || lua_type(l, 3) == LUA_TUSERDATA) {
        root_value(l, 1)->depth_changed = FLB_TRUE;
    }

    if (v->type == CFL_VARIANT_KVLIST) {
        if (lua_type(l, 2) != LUA_TSTRING) {
            return luaL_error(l, "map key must be a string");
        }

        key = lua_tolstring(l, 2, &length);
        pair = fts_find_pair(v, key, length);
        charge_mutation(l, 3, pair ? 0 : 128 + length);
        replacement = from_lua(l, 3, container_arena(v));

        if (pair) {
            if (cfl_container_move_variant_to_kvlist(v->data.as_kvlist, replacement) != 0) {
                cfl_variant_destroy(replacement);
                return luaL_error(l, "cannot attach map value");
            }

            old = pair->val;
            pair->val = replacement;
            if (root->inplace) {
                undo_add(root->ctx, UNDO_SET_PAIR, NULL, pair, NULL, NULL, 0, old);
            }
            else {
                credit_value(l, root, fts_value_cost(old, 0));
                cfl_variant_destroy(old);
            }

            cfl_list_foreach_safe(head, tmp, &v->data.as_kvlist->list) {
                duplicate = cfl_list_entry(head, struct cfl_kvpair, _head);
                if (duplicate != pair && cfl_sds_len(duplicate->key) == length &&
                    memcmp(duplicate->key, key, length) == 0) {
                    if (root->inplace) {
                        undo_reserve(l, root->ctx);
                        prev = duplicate->_head.prev;
                        cfl_list_del(&duplicate->_head);
                        undo_add(root->ctx, UNDO_REMOVE_PAIR, &v->data.as_kvlist->list,
                                 duplicate, prev, NULL, 0, NULL);
                    }
                    else {
                        credit_value(l, root, cost_add(128 + length,
                                                       fts_value_cost(duplicate->val, 0)));
                        cfl_kvpair_destroy(duplicate);
                    }
                }
            }
        }
        else if (cfl_kvlist_insert_s(v->data.as_kvlist, (char *) key, length, replacement) != 0) {
            cfl_variant_destroy(replacement);
            return luaL_error(l, "cannot insert map value");
        }
        else if (root->inplace) {
            undo_add(root->ctx, UNDO_INSERT_PAIR, NULL,
                     cfl_list_entry_last(&v->data.as_kvlist->list, struct cfl_kvpair, _head),
                     NULL, NULL, 0, NULL);
        }
    }
    else if (v->type == CFL_VARIANT_ARRAY) {
        position = array_index(l, v, 2);
        charge_mutation(l, 3, 0);
        replacement = from_lua(l, 3, container_arena(v));

        if (cfl_container_move_variant_to_array(v->data.as_array, replacement) != 0) {
            cfl_variant_destroy(replacement);
            return luaL_error(l, "cannot attach array value");
        }

        old = v->data.as_array->entries[position];
        v->data.as_array->entries[position] = replacement;
        if (root->inplace) {
            undo_add(root->ctx, UNDO_SET_INDEX, NULL, NULL, NULL, v->data.as_array, position, old);
        }
        else {
            credit_value(l, root, fts_value_cost(old, 0));
            cfl_variant_destroy(old);
        }
    }
    else {
        return luaL_error(l, "set() requires a map or array");
    }

    return 0;
}

static int value_remove(lua_State *l)
{
    struct cfl_variant *v;
    struct cfl_kvpair *pair;
    struct cfl_list *head;
    struct cfl_list *next;
    struct cfl_list *prev;
    struct fts_value *owner;
    const char *key;
    size_t length;
    int removed = FLB_FALSE;

    v = writable_value(l);
    if (v->type != CFL_VARIANT_KVLIST || lua_type(l, 2) != LUA_TSTRING) {
        return luaL_error(l, "remove() requires a map and string key");
    }

    key = lua_tolstring(l, 2, &length);
    owner = root_value(l, 1);

    cfl_list_foreach_safe(head, next, &v->data.as_kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (cfl_sds_len(pair->key) == length && memcmp(pair->key, key, length) == 0) {
            if (owner->inplace) {
                undo_reserve(l, owner->ctx);
                prev = pair->_head.prev;
                cfl_list_del(&pair->_head);
                undo_add(owner->ctx, UNDO_REMOVE_PAIR, &v->data.as_kvlist->list,
                         pair, prev, NULL, 0, NULL);
            }
            else {
                credit_value(l, owner, cost_add(128 + length, fts_value_cost(pair->val, 0)));
                cfl_kvpair_destroy(pair);
            }
            removed = FLB_TRUE;
        }
    }

    lua_pushboolean(l, removed);
    return 1;
}

static int value_ensure_map(lua_State *l)
{
    struct cfl_variant *v;
    struct cfl_variant *child;
    struct cfl_kvlist *map;
    struct cfl_kvpair *pair;
    struct fts_value *root;
    const char *key;
    size_t length;

    v = fts_resolve_value(l, 1, 0);
    if (v->type != CFL_VARIANT_KVLIST || lua_type(l, 2) != LUA_TSTRING) {
        return luaL_error(l, "ensure_map() requires a map and string key");
    }

    key = lua_tolstring(l, 2, &length);
    pair = fts_find_pair(v, key, length);
    if (pair && pair->val->type != CFL_VARIANT_KVLIST) {
        return luaL_error(l, "existing field is not a map");
    }

    if (!pair) {
        v = writable_value(l);
        root = root_value(l, 1);
        root->depth_changed = FLB_TRUE;
        if (root->inplace) {
            undo_reserve(l, root->ctx);
        }

        fts_charge_value(l, root, 384 + length);

        map = cfl_kvlist_create_in(container_arena(v));
        child = map ? cfl_variant_create_from_kvlist_in(container_arena(v), map) : NULL;
        if (!child) {
            cfl_kvlist_destroy(map);
            return luaL_error(l, "cannot allocate map");
        }

        if (cfl_kvlist_insert_s(v->data.as_kvlist, (char *) key, length, child) != 0) {
            cfl_variant_destroy(child);
            return luaL_error(l, "cannot insert map");
        }

        if (root->inplace) {
            undo_add(root->ctx, UNDO_INSERT_PAIR, NULL,
                     cfl_list_entry_last(&v->data.as_kvlist->list, struct cfl_kvpair, _head),
                     NULL, NULL, 0, NULL);
        }
    }

    push_view(l, 1, 2);
    return 1;
}

static int value_len(lua_State *l)
{
    struct cfl_variant *v;

    v = fts_resolve_value(l, 1, 0);
    if (v->type == CFL_VARIANT_ARRAY) {
        lua_pushnumber(l, v->data.as_array->entry_count);
    }
    else if (v->type == CFL_VARIANT_KVLIST) {
        lua_pushnumber(l, cfl_kvlist_count(v->data.as_kvlist));
    }
    else {
        return luaL_error(l, "len() requires a map or array");
    }

    return 1;
}

static int value_keys(lua_State *l)
{
    struct cfl_variant *v;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    int i = 1;

    v = fts_resolve_value(l, 1, 0);
    if (v->type != CFL_VARIANT_KVLIST) {
        return luaL_error(l, "keys() requires a map");
    }

    lua_newtable(l);
    cfl_list_foreach(head, &v->data.as_kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        lua_pushlstring(l, pair->key, cfl_sds_len(pair->key));
        lua_rawseti(l, -2, i++);
    }

    return 1;
}

static int value_append(lua_State *l)
{
    struct cfl_variant *v;
    struct cfl_variant *child;
    struct fts_value *root;

    v = writable_value(l);
    root = root_value(l, 1);
    root->depth_changed = FLB_TRUE;
    if (v->type != CFL_VARIANT_ARRAY) {
        return luaL_error(l, "append() requires an array");
    }

    if (root->inplace) {
        undo_reserve(l, root->ctx);
    }

    charge_mutation(l, 2, 0);
    child = from_lua(l, 2, container_arena(v));
    cfl_array_resizable(v->data.as_array, CFL_TRUE);
    if (cfl_array_append(v->data.as_array, child) != 0) {
        cfl_variant_destroy(child);
        return luaL_error(l, "cannot append array value");
    }

    if (root->inplace) {
        undo_add(root->ctx, UNDO_APPEND, NULL, NULL, NULL, v->data.as_array, 0, NULL);
    }

    return 0;
}

static int new_integer(lua_State *l)
{
    const char *str;
    char *end;
    size_t length;
    size_t i;
    int is_unsigned;
    int64_t signed_value;
    uint64_t unsigned_value;
    lua_Number number;
    struct cfl_variant *v;
    struct fts_value *owner;

    owner = fts_push_owned(l, NULL, FLB_FALSE);
    fts_charge_value(l, owner, 256);
    is_unsigned = lua_toboolean(l, lua_upvalueindex(1));

    if (lua_type(l, 1) == LUA_TNUMBER) {
        number = lua_tonumber(l, 1);
        if (!isfinite(number) || number != floor(number) || fabs(number) > SAFE_INTEGER ||
            (is_unsigned && number < 0)) {
            return luaL_error(l, "use a decimal string for integers outside the safe Lua range");
        }

        if (is_unsigned) {
            v = cfl_variant_create_from_uint64((uint64_t) number);
        }
        else {
            v = cfl_variant_create_from_int64((int64_t) number);
        }
    }
    else {
        str = luaL_checklstring(l, 1, &length);
        i = (!is_unsigned && length > 0 && str[0] == '-') ? 1 : 0;
        if (i == length) {
            return luaL_error(l, "expected a decimal integer");
        }

        for (; i < length; i++) {
            if (str[i] < '0' || str[i] > '9') {
                return luaL_error(l, "expected a decimal integer");
            }
        }

        errno = 0;
        if (is_unsigned) {
            unsigned_value = strtoull(str, &end, 10);
            v = errno == ERANGE ? NULL : cfl_variant_create_from_uint64(unsigned_value);
        }
        else {
            signed_value = strtoll(str, &end, 10);
            v = errno == ERANGE ? NULL : cfl_variant_create_from_int64(signed_value);
        }

        if (errno == ERANGE) {
            return luaL_error(l, "integer outside 64-bit range");
        }
    }

    if (!v) {
        return luaL_error(l, "cannot allocate integer");
    }

    owner->owned = v;
    return 1;
}

static int new_container(lua_State *l)
{
    struct cfl_variant *v;
    struct fts_value *owner;
    struct cfl_kvlist *map;
    struct cfl_array *array;

    if (lua_gettop(l) != 0) {
        return luaL_error(l, "map()/array() create empty containers and take no arguments");
    }

    owner = fts_push_owned(l, NULL, FLB_FALSE);
    fts_charge_value(l, owner, 256);

    if (lua_toboolean(l, lua_upvalueindex(1))) {
        map = cfl_kvlist_create();
        v = map ? cfl_variant_create_from_kvlist(map) : NULL;
        if (!v) {
            cfl_kvlist_destroy(map);
        }
    }
    else {
        array = cfl_array_create(0);
        v = array ? cfl_variant_create_from_array(array) : NULL;
        if (!v) {
            cfl_array_destroy(array);
        }
    }

    if (!v) {
        return luaL_error(l, "cannot allocate container");
    }

    owner->owned = v;
    return 1;
}

static int new_bytes(lua_State *l)
{
    const char *str;
    size_t length;
    struct cfl_variant *v;
    struct fts_value *owner;

    if (lua_type(l, 1) != LUA_TSTRING) {
        return luaL_error(l, "bytes() requires a Lua string");
    }

    str = lua_tolstring(l, 1, &length);
    owner = fts_push_owned(l, NULL, FLB_FALSE);
    fts_charge_value(l, owner, length + 256);

    v = cfl_variant_create_from_bytes((char *) str, length, CFL_FALSE);
    if (!v) {
        return luaL_error(l, "cannot allocate bytes");
    }

    owner->owned = v;
    return 1;
}

static void push_folded_key(lua_State *l, const char *key, size_t length)
{
    luaL_Buffer buffer;
    size_t index;

    luaL_buffinit(l, &buffer);
    for (index = 0; index < length; index++) {
        luaL_addchar(&buffer, tolower((unsigned char) key[index]));
    }
    luaL_pushresult(&buffer);
}

/* Iterate the stored pairs, including duplicate parent keys. Named lookup
 * cannot visit all occurrences and is unsuitable for privacy operations. */
static void redact_value(lua_State *l, struct cfl_variant *value, int depth, int keys)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cfl_kvpair *pair;
    struct cfl_variant *replacement;
    struct cfl_variant *old;
    struct cfl_list *previous;
    struct fts_runtime *ctx;
    struct fts_value *owner;
    void *data;
    size_t length;
    size_t i;
    int match;
    int seen;
    int duplicate;

    lua_getallocf(l, &data);
    ctx = data;
    if (depth >= FTS_MAX_DEPTH || (!ctx->jit && --ctx->instructions_left <= 0)) {
        luaL_error(l, "redaction nesting or instruction limit exceeded");
    }

    if (!lua_checkstack(l, 8)) {
        luaL_error(l, "redaction stack limit exceeded");
    }

    owner = root_value(l, 1);

    if (value->type == CFL_VARIANT_ARRAY) {
        for (i = 0; i < value->data.as_array->entry_count; i++) {
            redact_value(l, value->data.as_array->entries[i], depth + 1, keys);
        }
    }
    else if (value->type == CFL_VARIANT_KVLIST) {
        lua_newtable(l);
        seen = lua_gettop(l);

        cfl_list_foreach_safe(head, tmp, &value->data.as_kvlist->list) {
            pair = cfl_list_entry(head, struct cfl_kvpair, _head);
            length = cfl_sds_len(pair->key);

            push_folded_key(l, pair->key, length);
            lua_rawget(l, keys);
            match = lua_toboolean(l, -1);
            lua_pop(l, 1);

            if (match) {
                lua_pushlstring(l, pair->key, length);
                lua_rawget(l, seen);
                duplicate = lua_toboolean(l, -1);
                lua_pop(l, 1);

                if (duplicate) {
                    if (owner->inplace) {
                        undo_reserve(l, owner->ctx);
                        previous = pair->_head.prev;
                        cfl_list_del(&pair->_head);
                        undo_add(owner->ctx, UNDO_REMOVE_PAIR, &value->data.as_kvlist->list,
                                 pair, previous, NULL, 0, NULL);
                    }
                    else {
                        credit_value(l, owner, cost_add(128 + length,
                                                        fts_value_cost(pair->val, 0)));
                        cfl_kvpair_destroy(pair);
                    }
                    continue;
                }

                lua_pushlstring(l, pair->key, length);
                lua_pushboolean(l, 1);
                lua_rawset(l, seen);

                if (owner->inplace) {
                    undo_reserve(l, owner->ctx);
                }

                charge_mutation(l, 3, 0);
                replacement = from_lua(l, 3, container_arena(value));
                if (cfl_container_move_variant_to_kvlist(value->data.as_kvlist,
                                                         replacement) != 0) {
                    cfl_variant_destroy(replacement);
                    luaL_error(l, "cannot attach redacted value");
                }

                old = pair->val;
                pair->val = replacement;
                if (owner->inplace) {
                    undo_add(owner->ctx, UNDO_SET_PAIR, NULL, pair, NULL, NULL, 0, old);
                }
                else {
                    credit_value(l, owner, fts_value_cost(old, 0));
                    cfl_variant_destroy(old);
                }
            }
            else {
                redact_value(l, pair->val, depth + 1, keys);
            }
        }

        lua_pop(l, 1);
    }
}

static int redact(lua_State *l)
{
    struct cfl_variant *value;
    const char *key;
    size_t length;
    size_t index;
    size_t count;
    int keys;

    luaL_checktype(l, 2, LUA_TTABLE);
    if (lua_isnoneornil(l, 3)) {
        lua_settop(l, 2);
        lua_pushliteral(l, "[REDACTED]");
    }

    value = writable_value(l);
    if (lua_type(l, 3) == LUA_TUSERDATA) {
        root_value(l, 1)->depth_changed = FLB_TRUE;
    }

    count = lua_objlen(l, 2);
    lua_newtable(l);
    keys = lua_gettop(l);

    for (index = 1; index <= count; index++) {
        lua_rawgeti(l, 2, index);
        luaL_checktype(l, -1, LUA_TSTRING);
        key = lua_tolstring(l, -1, &length);
        push_folded_key(l, key, length);
        lua_pushboolean(l, 1);
        lua_rawset(l, keys);
        lua_pop(l, 1);
    }

    redact_value(l, value, 0, keys);
    return 0;
}

/* An owned, writable copy that may outlive the callback. */
static int value_copy(lua_State *l)
{
    struct cfl_variant *source;
    struct fts_value *value;
    size_t cost;

    source = fts_resolve_value(l, 1, 0);
    cost = fts_value_cost(source, 0);
    if (cost == SIZE_MAX) {
        return luaL_error(l, "cannot copy typed value (allocation or nesting limit)");
    }

    value = fts_push_owned(l, NULL, FLB_FALSE);
    fts_charge_value(l, value, cost);

    value->owned = fts_copy_value(source, 0);
    if (!value->owned) {
        return luaL_error(l, "cannot copy typed value (allocation or nesting limit)");
    }

    return 1;
}

static const luaL_Reg value_methods[] = {
    {"__gc", value_gc},
    {"type", value_type},
    {"value", value_scalar},
    {"number", value_number},
    {"get", value_get},
    {"get_string", value_get_string},
    {"get_bool", value_get_bool},
    {"get_number", value_get_number},
    {"set", value_set},
    {"remove", value_remove},
    {"ensure_map", value_ensure_map},
    {"len", value_len},
    {"keys", value_keys},
    {"append", value_append},
    {"copy", value_copy},
    {NULL, NULL}
};

struct json_key_slot {
    yyjson_val *key;
    uint64_t hash;
};

static size_t json_value_cost(yyjson_val *value, int depth)
{
    yyjson_val *key;
    yyjson_val *item;
    size_t index;
    size_t count;
    size_t cost = 256;
    size_t child;

    if (depth >= FTS_MAX_DEPTH) {
        return SIZE_MAX;
    }

    if (yyjson_is_str(value)) {
        return cost + yyjson_get_len(value);
    }

    if (yyjson_is_obj(value)) {
        yyjson_obj_foreach(value, index, count, key, item) {
            child = json_value_cost(item, depth + 1);
            if (child > SIZE_MAX - cost ||
                yyjson_get_len(key) + 128 > SIZE_MAX - cost - child) {
                return SIZE_MAX;
            }
            cost += child + yyjson_get_len(key) + 128;
        }
    }
    else if (yyjson_is_arr(value)) {
        yyjson_arr_foreach(value, index, count, item) {
            child = json_value_cost(item, depth + 1);
            if (child > SIZE_MAX - cost) {
                return SIZE_MAX;
            }
            cost += child;
        }
    }

    return cost;
}

/* Strict JSON conversion preserves integer widths and rejects duplicate keys. */
static struct cfl_variant *json_value(yyjson_val *value, int depth, struct fts_runtime *ctx)
{
    struct cfl_variant *out;
    struct cfl_variant *child;
    struct cfl_array *array;
    struct cfl_kvlist *map;
    yyjson_val *key;
    yyjson_val *item;
    size_t index;
    size_t count;
    size_t capacity;
    size_t slot;
    uint64_t hash;
    struct json_key_slot *keys;

    if (depth >= FTS_MAX_DEPTH || (!ctx->jit && --ctx->instructions_left <= 0)) {
        return NULL;
    }

    if (yyjson_is_obj(value)) {
        map = cfl_kvlist_create();
        out = map ? cfl_variant_create_from_kvlist(map) : NULL;
        if (!out) {
            cfl_kvlist_destroy(map);
            return NULL;
        }

        count = yyjson_obj_size(value);
        capacity = 1;
        while (capacity < count * 2) {
            capacity *= 2;
        }

        keys = calloc(capacity, sizeof(*keys));
        if (keys == NULL) {
            flb_errno();
            cfl_variant_destroy(out);
            return NULL;
        }

        yyjson_obj_foreach(value, index, count, key, item) {
            hash = cfl_hash_64bits(yyjson_get_str(key), yyjson_get_len(key));
            slot = hash & (capacity - 1);
            while (keys[slot].key != NULL) {
                if ((!ctx->jit && --ctx->instructions_left <= 0) ||
                    (keys[slot].hash == hash &&
                     yyjson_get_len(keys[slot].key) == yyjson_get_len(key) &&
                     memcmp(yyjson_get_str(keys[slot].key), yyjson_get_str(key),
                            yyjson_get_len(key)) == 0)) {
                    free(keys);
                    cfl_variant_destroy(out);
                    return NULL;
                }
                slot = (slot + 1) & (capacity - 1);
            }

            keys[slot].key = key;
            keys[slot].hash = hash;

            child = json_value(item, depth + 1, ctx);
            if (!child || cfl_kvlist_insert_s(map, (char *) yyjson_get_str(key),
                                              yyjson_get_len(key), child) != 0) {
                free(keys);
                cfl_variant_destroy(child);
                cfl_variant_destroy(out);
                return NULL;
            }
        }

        free(keys);
        return out;
    }

    if (yyjson_is_arr(value)) {
        array = cfl_array_create(yyjson_arr_size(value));
        out = array ? cfl_variant_create_from_array(array) : NULL;
        if (!out) {
            cfl_array_destroy(array);
            return NULL;
        }

        yyjson_arr_foreach(value, index, count, item) {
            child = json_value(item, depth + 1, ctx);
            if (!child || cfl_array_append(array, child) != 0) {
                cfl_variant_destroy(child);
                cfl_variant_destroy(out);
                return NULL;
            }
        }

        return out;
    }

    if (yyjson_is_str(value)) {
        return cfl_variant_create_from_string_s((char *) yyjson_get_str(value),
                                                yyjson_get_len(value), CFL_FALSE);
    }

    if (yyjson_is_uint(value)) {
        return cfl_variant_create_from_uint64(yyjson_get_uint(value));
    }

    if (yyjson_is_sint(value)) {
        return cfl_variant_create_from_int64(yyjson_get_sint(value));
    }

    if (yyjson_is_real(value)) {
        return cfl_variant_create_from_double(yyjson_get_real(value));
    }

    if (yyjson_is_bool(value)) {
        return cfl_variant_create_from_bool(yyjson_get_bool(value));
    }

    if (yyjson_is_null(value)) {
        return cfl_variant_create_from_null();
    }

    return NULL;
}

static int parse_json(lua_State *l)
{
    struct fts_value *owner;
    struct fts_runtime *ctx;
    yyjson_doc *doc;
    const char *text;
    size_t length;
    size_t reservation;
    size_t cost;

    luaL_checktype(l, 1, LUA_TSTRING);
    text = lua_tolstring(l, 1, &length);
    if (length > 1048576) {
        return luaL_error(l, "JSON input exceeds 1 MiB");
    }

    owner = fts_push_owned(l, NULL, FLB_FALSE);
    ctx = owner->ctx;

    /* Bound the parser's temporary document separately from the owned value. */
    reservation = length * 16 + 256;
    fts_charge_value(l, owner, reservation);

    doc = yyjson_read(text, length, YYJSON_READ_BIGNUM_AS_RAW);
    if (!doc) {
        return luaL_error(l, "invalid JSON");
    }

    cost = json_value_cost(yyjson_doc_get_root(doc), 0);
    if (cost > ctx->memory_limit || ctx->native_bytes > ctx->memory_limit - cost ||
        ctx->lua_bytes > ctx->memory_limit - ctx->native_bytes - cost) {
        lua_gc(l, LUA_GCCOLLECT, 0);
        if (cost > ctx->memory_limit || ctx->native_bytes > ctx->memory_limit - cost ||
            ctx->lua_bytes > ctx->memory_limit - ctx->native_bytes - cost) {
            yyjson_doc_free(doc);
            return luaL_error(l, "JSON value exceeds policy memory or nesting limit");
        }
    }

    fts_charge_value(l, owner, cost);
    owner->owned = json_value(yyjson_doc_get_root(doc), 0, ctx);
    yyjson_doc_free(doc);
    credit_value(l, owner, reservation);

    if (!owner->owned) {
        return luaL_error(l,
                          "JSON exceeds type/depth/instruction limits or contains duplicate keys");
    }

    return 1;
}

/* Exact aggregation never rounds integer telemetry through lua_Number. */
static int add_metric_values(lua_State *l)
{
    struct cfl_variant *left;
    struct cfl_variant *right;
    struct fts_value *owner;
    int64_t a;
    int64_t b;
    uint64_t unsigned_value;
    uint64_t magnitude;
    uint64_t total;
    double x;
    double y;

    left = fts_resolve_value(l, 1, 0);
    right = fts_resolve_value(l, 2, 0);
    owner = fts_push_owned(l, NULL, FLB_FALSE);
    fts_charge_value(l, owner, 256);

    if (left->type == CFL_VARIANT_INT && right->type == CFL_VARIANT_INT) {
        a = left->data.as_int64;
        b = right->data.as_int64;
        if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b)) {
            return luaL_error(l, "metric integer aggregation overflow");
        }
        owner->owned = cfl_variant_create_from_int64(a + b);
    }
    else if (left->type == CFL_VARIANT_UINT && right->type == CFL_VARIANT_UINT) {
        if (left->data.as_uint64 > UINT64_MAX - right->data.as_uint64) {
            return luaL_error(l, "metric count aggregation overflow");
        }
        owner->owned = cfl_variant_create_from_uint64(left->data.as_uint64 +
                                                      right->data.as_uint64);
    }
    else if ((left->type == CFL_VARIANT_INT && right->type == CFL_VARIANT_UINT) ||
             (left->type == CFL_VARIANT_UINT && right->type == CFL_VARIANT_INT)) {
        if (left->type == CFL_VARIANT_INT) {
            a = left->data.as_int64;
        }
        else {
            a = right->data.as_int64;
        }

        if (left->type == CFL_VARIANT_UINT) {
            unsigned_value = left->data.as_uint64;
        }
        else {
            unsigned_value = right->data.as_uint64;
        }

        if (a < 0) {
            magnitude = (uint64_t) -(a + 1) + 1;
            if (unsigned_value < magnitude) {
                magnitude -= unsigned_value;
                if (magnitude == (uint64_t) INT64_MAX + 1) {
                    owner->owned = cfl_variant_create_from_int64(INT64_MIN);
                }
                else {
                    owner->owned = cfl_variant_create_from_int64(-(int64_t) magnitude);
                }
            }
            else {
                total = unsigned_value - magnitude;
                if (total <= INT64_MAX) {
                    owner->owned = cfl_variant_create_from_int64((int64_t) total);
                }
                else {
                    owner->owned = cfl_variant_create_from_uint64(total);
                }
            }
        }
        else {
            if (unsigned_value > UINT64_MAX - (uint64_t) a) {
                return luaL_error(l, "metric integer aggregation overflow");
            }

            total = unsigned_value + (uint64_t) a;
            if (total <= INT64_MAX) {
                owner->owned = cfl_variant_create_from_int64((int64_t) total);
            }
            else {
                owner->owned = cfl_variant_create_from_uint64(total);
            }
        }
    }
    else {
        if ((left->type != CFL_VARIANT_INT && left->type != CFL_VARIANT_UINT &&
             left->type != CFL_VARIANT_DOUBLE) ||
            (right->type != CFL_VARIANT_INT && right->type != CFL_VARIANT_UINT &&
             right->type != CFL_VARIANT_DOUBLE)) {
            return luaL_error(l, "metric aggregation requires numeric values");
        }

        if (left->type == CFL_VARIANT_DOUBLE) {
            x = left->data.as_double;
        }
        else if (left->type == CFL_VARIANT_INT) {
            x = (double) left->data.as_int64;
        }
        else {
            x = (double) left->data.as_uint64;
        }

        if (right->type == CFL_VARIANT_DOUBLE) {
            y = right->data.as_double;
        }
        else if (right->type == CFL_VARIANT_INT) {
            y = (double) right->data.as_int64;
        }
        else {
            y = (double) right->data.as_uint64;
        }

        if ((left->type != CFL_VARIANT_DOUBLE && fabs(x) > SAFE_INTEGER) ||
            (right->type != CFL_VARIANT_DOUBLE && fabs(y) > SAFE_INTEGER) || !isfinite(x + y)) {
            return luaL_error(l, "metric aggregation would lose precision or overflow");
        }
        owner->owned = cfl_variant_create_from_double(x + y);
    }

    if (!owner->owned) {
        return luaL_error(l, "cannot allocate aggregated value");
    }

    return 1;
}

int fts_register_values(lua_State *l)
{
    struct fts_value *null_owner;
    struct fts_runtime *ctx;
    int index;
    static const char *keys[] = {"tag", "body", "metadata", "timestamp", "sec", "nsec",
                                 "context", "attributes"};

    lua_getallocf(l, (void **) &ctx);
    for (index = 0; index < FTS_KEY_COUNT; index++) {
        lua_pushstring(l, keys[index]);
        ctx->key_refs[index] = luaL_ref(l, LUA_REGISTRYINDEX);
    }

    lua_pushliteral(l, "");
    ctx->tag_ref = luaL_ref(l, LUA_REGISTRYINDEX);

    /* Value metatable: finalizer plus the shared method table. */
    luaL_newmetatable(l, VALUE_MT);
    ctx->value_metatable = lua_topointer(l, -1);
    lua_pushvalue(l, -1);
    ctx->value_metatable_ref = luaL_ref(l, LUA_REGISTRYINDEX);
    luaL_register(l, NULL, value_methods);
    lua_newtable(l);
    luaL_register(l, NULL, value_methods + 1);
    lua_setfield(l, -2, "__index");
    lua_pushliteral(l, "typed value");
    lua_setfield(l, -2, "__metatable");

    /* Finalizer-free metatable for borrowed values and views. */
    lua_newtable(l);
    lua_getfield(l, -2, "__index");
    lua_setfield(l, -2, "__index");
    lua_pushliteral(l, "typed value");
    lua_setfield(l, -2, "__metatable");
    ctx->empty_metatable = lua_topointer(l, -1);
    ctx->empty_metatable_ref = luaL_ref(l, LUA_REGISTRYINDEX);
    lua_pop(l, 1);

    /* package.loaded.fluentbit */
    lua_getglobal(l, "package");
    lua_getfield(l, -1, "loaded");
    lua_newtable(l);

    lua_pushboolean(l, 0);
    lua_pushcclosure(l, new_integer, 1);
    lua_setfield(l, -2, "int64");

    lua_pushboolean(l, 1);
    lua_pushcclosure(l, new_integer, 1);
    lua_setfield(l, -2, "uint64");

    lua_pushboolean(l, 1);
    lua_pushcclosure(l, new_container, 1);
    lua_setfield(l, -2, "map");

    lua_pushboolean(l, 0);
    lua_pushcclosure(l, new_container, 1);
    lua_setfield(l, -2, "array");

    lua_pushcfunction(l, equal_values);
    lua_setfield(l, -2, "_fts_equal");
    lua_pushcfunction(l, add_metric_values);
    lua_setfield(l, -2, "_fts_add");
    lua_pushcfunction(l, redact);
    lua_setfield(l, -2, "redact");
    lua_pushcfunction(l, parse_json);
    lua_setfield(l, -2, "parse_json");
    lua_pushcfunction(l, new_bytes);
    lua_setfield(l, -2, "bytes");

    null_owner = fts_push_owned(l, NULL, FLB_TRUE);
    fts_charge_value(l, null_owner, 256);
    null_owner->owned = cfl_variant_create_from_null();
    if (!null_owner->owned) {
        lua_pop(l, 3);
        return -1;
    }
    lua_setfield(l, -2, "null");

    lua_pushliteral(l, "keep");
    lua_setfield(l, -2, "KEEP");
    lua_pushliteral(l, "drop");
    lua_setfield(l, -2, "DROP");

    lua_setfield(l, -2, "fluentbit");
    lua_pop(l, 2);

    if (fts_load_helpers(l, fts_value_helpers, sizeof(fts_value_helpers) - 1,
                         "fluentbit.helpers") != 0) {
        return -1;
    }

    return 0;
}

int fts_valid_utf8(const char *text, size_t length)
{
    const unsigned char *bytes = (const unsigned char *) text;
    size_t i = 0;
    unsigned char first;
    unsigned char second;
    int count;
    int j;

    while (i < length) {
        first = bytes[i++];
        if (first < 0x80) {
            continue;
        }

        if (first >= 0xc2 && first <= 0xdf) {
            count = 1;
        }
        else if (first >= 0xe0 && first <= 0xef) {
            count = 2;
        }
        else if (first >= 0xf0 && first <= 0xf4) {
            count = 3;
        }
        else {
            count = 0;
        }

        if (!count || length - i < (size_t) count) {
            return FLB_FALSE;
        }

        second = bytes[i];
        if ((first == 0xe0 && second < 0xa0) || (first == 0xed && second > 0x9f) ||
            (first == 0xf0 && second < 0x90) || (first == 0xf4 && second > 0x8f)) {
            return FLB_FALSE;
        }

        for (j = 0; j < count; j++) {
            if (bytes[i] < 0x80 || bytes[i++] > 0xbf) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}
