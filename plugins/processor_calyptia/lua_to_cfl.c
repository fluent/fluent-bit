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

#include "lua_to_cfl.h"

#include <fluent-bit/flb_lua.h>


cfl_sds_t lua_to_sds(lua_State *L)
{
    size_t len;
    const char *str;

    if (lua_type(L, -1) != LUA_TSTRING) {
        return NULL;
    }

    str = lua_tolstring(L, -1, &len);
    return cfl_sds_create_len(str, len);
}

double lua_to_double(lua_State *L, int index)
{
    int type = lua_type(L, index);
    if (type == LUA_TNUMBER) {
        return lua_tonumber(L, index);
    }
    else if (type == LUA_TSTRING) {
        return atof(lua_tostring(L, index));
    }
    else {
        return 0.0;
    }
}

uint64_t lua_to_uint(lua_State *L)
{
    int type = lua_type(L, -1);
    if (type == LUA_TNUMBER) {
        return lua_tointeger(L, -1);
    }
    else if (type == LUA_TSTRING) {
        return strtoull(lua_tostring(L, -1), NULL, 10);
    }
    else {
        return 0;
    }
}

long lua_to_int(lua_State *L)
{
    int type = lua_type(L, -1);
    if (type == LUA_TNUMBER) {
        return lua_tointeger(L, -1);
    }
    else if (type == LUA_TSTRING) {
        return strtol(lua_tostring(L, -1), NULL, 10);
    }
    else {
        return 0;
    }
}

struct cfl_variant *lua_string_to_variant(lua_State *L, int index)
{
    size_t len;
    const char *str = lua_tolstring(L, index, &len);
    return cfl_variant_create_from_string_s((char *) str, len, 0);
}

bool lua_isinteger(lua_State *L, int index)
{
    if (lua_isnumber(L, index)) {
        double val = lua_tonumber(L, index);
        return val == (int64_t) val;
    }
    return false;
}

struct cfl_array *lua_array_to_variant(lua_State *L, int array_len)
{
    int i;
    struct cfl_array *array = cfl_array_create(array_len);

    for (i = 1; i <= array_len; i++) {
        lua_rawgeti(L, -1, i);
        struct cfl_variant *variant = lua_to_variant(L, -1);
        cfl_array_append(array, variant);
        lua_pop(L, 1);
    }

    return array;
}

struct cfl_kvlist *lua_map_to_variant(lua_State *L)
{
    struct cfl_kvlist *kvlist = cfl_kvlist_create();

    lua_pushnil(L); // first key
    while (lua_next(L, -2) != 0) {
        const char *key = lua_tostring(L, -2);
        struct cfl_variant *value = lua_to_variant(L, -1);
        cfl_kvlist_insert(kvlist, (char *) key, value);

        // removes 'value'; keeps 'key' for next iteration
        lua_pop(L, 1);
    }

    return kvlist;
}

struct cfl_variant *lua_to_variant(lua_State *L, int index)
{
    int array_len;
    int type = lua_type(L, index);

    switch (type) {
    case LUA_TNUMBER:
        if (lua_isinteger(L, index)) {
            return cfl_variant_create_from_int64(lua_tointeger(L, index));
        }
        else {
            return cfl_variant_create_from_double(lua_tonumber(L, index));
        }
    case LUA_TBOOLEAN:
        return cfl_variant_create_from_bool(lua_toboolean(L, index));
    case LUA_TSTRING:
        return lua_string_to_variant(L, index);
    case LUA_TTABLE:
        array_len = flb_lua_arraylength(L, index);
        if (array_len > 0) {
            return cfl_variant_create_from_array(lua_array_to_variant(L, array_len));
        }
        else {
            return cfl_variant_create_from_kvlist(lua_map_to_variant(L));
        }
    default:
        // nil or Unsupported types
        return cfl_variant_create_from_null();
    }
}
