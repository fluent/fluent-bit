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

#ifndef FLB_CALYPTIA_PROCESSOR_LUA_TO_CFL_H
#define FLB_CALYPTIA_PROCESSOR_LUA_TO_CFL_H

#include <stdbool.h>
#include <lua.h>
#include <cfl/cfl.h>

cfl_sds_t lua_to_sds(lua_State *L);
double lua_to_double(lua_State *L, int index);
uint64_t lua_to_uint(lua_State *L);
long lua_to_int(lua_State *L);
struct cfl_variant *lua_string_to_variant(lua_State *L, int index);
bool lua_isinteger(lua_State *L, int index);
struct cfl_array *lua_array_to_variant(lua_State *L, int array_len);
struct cfl_kvlist *lua_map_to_variant(lua_State *L);
struct cfl_variant *lua_to_variant(lua_State *L, int index);

#endif
