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

#ifndef FLB_LUA_H
#define FLB_LUA_H

#include "lua.h"
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>

#include <monkey/mk_core/mk_list.h>
#include <msgpack/pack.h>

/* global variables in Lua */
#define FLB_LUA_VAR_FLB_NULL "flb_null"

#define FLB_LUA_L2C_TYPES_NUM_MAX   16

enum flb_lua_l2c_type_enum {
    FLB_LUA_L2C_TYPE_INT,
    FLB_LUA_L2C_TYPE_ARRAY,
    FLB_LUA_L2C_TYPE_MAP
};

struct flb_lua_l2c_type {
    flb_sds_t key;
    int type;
    struct mk_list _head;
};

struct flb_lua_l2c_config {
    int    l2c_types_num;      /* number of l2c_types */
    struct mk_list l2c_types;  /* data types (lua -> C) */
};


/*
 * Metatable for Lua table.
 * https://www.lua.org/manual/5.1/manual.html#2.8
 */
struct flb_lua_metadata {
    int initialized;
    int data_type; /* Map or Array */
};

static inline int flb_lua_metadata_init(struct flb_lua_metadata *meta)
{
    if (meta == NULL) {
        return -1;
    }
    meta->initialized = FLB_TRUE;
    meta->data_type = -1;

    return 0;
}

/* convert from negative index to positive index */
static inline int flb_lua_absindex(lua_State *l , int index)
{
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM < 520
    if (index < 0) {
        index = lua_gettop(l) + index + 1;
    }
#else
    index = lua_absindex(l, index);
#endif
    return index;
}

int flb_lua_arraylength(lua_State *l, int index);
void flb_lua_pushtimetable(lua_State *l, struct flb_time *tm);
int flb_lua_is_valid_func(lua_State *l, flb_sds_t func);
int flb_lua_pushmpack(lua_State *l, mpack_reader_t *reader);
void flb_lua_pushmsgpack(lua_State *l, msgpack_object *o);
void flb_lua_tomsgpack(lua_State *l,
                       msgpack_packer *pck,
                       int index,
                       struct flb_lua_l2c_config *l2cc);
void flb_lua_tompack(lua_State *l,
                     mpack_writer_t *writer,
                     int index,
                     struct flb_lua_l2c_config *l2cc);
void flb_lua_dump_stack(FILE *out, lua_State *l);
int flb_lua_enable_flb_null(lua_State *l);

#endif
