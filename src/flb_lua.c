/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include "lua.h"
#include "mpack/mpack.h"
#include "msgpack/unpack.h"
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_lua.h>
#include <stdint.h>

void flb_lua_pushtimetable(lua_State *l, struct flb_time *tm)
{
    lua_createtable(l, 0, 2);

    /* seconds */
    lua_pushlstring(l, "sec", 3);
    lua_pushinteger(l, tm->tm.tv_sec);
    lua_settable(l, -3);

    /* nanoseconds */
    lua_pushlstring(l, "nsec", 4);
    lua_pushinteger(l, tm->tm.tv_nsec);
    lua_settable(l, -3);
}

int flb_lua_is_valid_func(lua_State *lua, flb_sds_t func)
{
    int ret = FLB_FALSE;

    lua_getglobal(lua, func);
    if (lua_isfunction(lua, -1)) {
        ret = FLB_TRUE;
    }
    lua_pop(lua, -1); /* discard return value of isfunction */

    return ret;
}

int flb_lua_pushmpack(lua_State *l, mpack_reader_t *reader)
{
    int ret = 0;
    mpack_tag_t tag;
    uint32_t length;
    uint32_t i;

    tag = mpack_read_tag(reader);
    switch (mpack_tag_type(&tag)) {
        case mpack_type_nil:
            lua_pushnil(l);
            break;
        case mpack_type_bool:
            lua_pushboolean(l, mpack_tag_bool_value(&tag));
            break;
        case mpack_type_int:
            lua_pushinteger(l, mpack_tag_int_value(&tag));
            break;
        case mpack_type_uint:
            lua_pushinteger(l, mpack_tag_uint_value(&tag));
            break;
        case mpack_type_float:
            lua_pushnumber(l, mpack_tag_float_value(&tag));
            break;
        case mpack_type_double:
            lua_pushnumber(l, mpack_tag_double_value(&tag));
            break;
        case mpack_type_str:
        case mpack_type_bin:
        case mpack_type_ext:
            length = mpack_tag_bytes(&tag);
            lua_pushlstring(l, reader->data, length);
            reader->data += length;
            break;
        case mpack_type_array:
            length = mpack_tag_array_count(&tag);
            lua_createtable(l, length, 0);
            for (i = 0; i < length; i++) {
                ret = flb_lua_pushmpack(l, reader);
                if (ret) {
                    return ret;
                }
                lua_rawseti(l, -2, i+1);
            }
            break;
        case mpack_type_map:
            length = mpack_tag_map_count(&tag);
            lua_createtable(l, length, 0);
            for (i = 0; i < length; i++) {
                ret = flb_lua_pushmpack(l, reader);
                if (ret) {
                    return ret;
                }
                ret = flb_lua_pushmpack(l, reader);
                if (ret) {
                    return ret;
                }
                lua_settable(l, -3);
            }
            break;
        default:
            return -1;
    }
    return 0;
}

void flb_lua_pushmsgpack(lua_State *l, msgpack_object *o)
{
    int i;
    int size;

    lua_checkstack(l, 3);

    switch(o->type) {
        case MSGPACK_OBJECT_NIL:
            lua_pushnil(l);
            break;

        case MSGPACK_OBJECT_BOOLEAN:
            lua_pushboolean(l, o->via.boolean);
            break;

        case MSGPACK_OBJECT_POSITIVE_INTEGER:
            lua_pushinteger(l, (double) o->via.u64);
            break;

        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            lua_pushinteger(l, (double) o->via.i64);
            break;

        case MSGPACK_OBJECT_FLOAT32:
        case MSGPACK_OBJECT_FLOAT64:
            lua_pushnumber(l, (double) o->via.f64);
            break;

        case MSGPACK_OBJECT_STR:
            lua_pushlstring(l, o->via.str.ptr, o->via.str.size);
            break;

        case MSGPACK_OBJECT_BIN:
            lua_pushlstring(l, o->via.bin.ptr, o->via.bin.size);
            break;

        case MSGPACK_OBJECT_EXT:
            lua_pushlstring(l, o->via.ext.ptr, o->via.ext.size);
            break;

        case MSGPACK_OBJECT_ARRAY:
            size = o->via.array.size;
            lua_createtable(l, size, 0);
            if (size != 0) {
                msgpack_object *p = o->via.array.ptr;
                for (i = 0; i < size; i++) {
                    flb_lua_pushmsgpack(l, p+i);
                    lua_rawseti (l, -2, i+1);
                }
            }
            break;

        case MSGPACK_OBJECT_MAP:
            size = o->via.map.size;
            lua_createtable(l, 0, size);
            if (size != 0) {
                msgpack_object_kv *p = o->via.map.ptr;
                for (i = 0; i < size; i++) {
                    flb_lua_pushmsgpack(l, &(p+i)->key);
                    flb_lua_pushmsgpack(l, &(p+i)->val);
                    lua_settable(l, -3);
                }
            }
            break;
    }
}

static int lua_isinteger(lua_State *L, int index)
{
    lua_Number n;
    lua_Integer i;

    if (lua_type(L, index) == LUA_TNUMBER) {
        n = lua_tonumber(L, index);
        i = lua_tointeger(L, index);

        if (i == n) {
            return 1;
        }
    }
    return 0;
}

/*
 * This function is to call lua function table.maxn.
 * CAUTION: table.maxn is removed from Lua 5.2.
 * If we update luajit which is based Lua 5.2+,
 * this function should be removed.
*/
static int lua_table_maxn(lua_State *l)
{
#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM < 520
    int ret = -1;
    if (lua_type(l, -1) != LUA_TTABLE) {
        return -1;
    }

    lua_getglobal(l, "table");
    lua_getfield(l, -1, "maxn");
    lua_remove(l, -2);    /* remove table (lua_getglobal(L, "table")) */
    lua_pushvalue(l, -2); /* copy record to top of stack */
    ret = lua_pcall(l, 1, 1, 0);
    if (ret < 0) {
        flb_error("[filter_lua] failed to exec table.maxn ret=%d", ret);
        return -1;
    }
    if (lua_type(l, -1) != LUA_TNUMBER) {
        flb_error("[filter_lua] not LUA_TNUMBER");
        lua_pop(l, 1);
        return -1;
    }

    if (lua_isinteger(l, -1)) {
        ret = lua_tointeger(l, -1);
    }
    lua_pop(l, 1);

    return ret;
#else
    return (int)lua_rawlen(l, 1);
#endif
}

int flb_lua_arraylength(lua_State *l)
{
    lua_Integer n;
    int count = 0;
    int max = 0;
    int ret = 0;

    ret = lua_table_maxn(l);
    if (ret > 0) {
        return ret;
    }

    lua_pushnil(l);
    while (lua_next(l, -2) != 0) {
        if (lua_type(l, -2) == LUA_TNUMBER) {
            n = lua_tonumber(l, -2);
            if (n > 0) {
                max = n > max ? n : max;
                count++;
                lua_pop(l, 1);
                continue;
            }
        }
        lua_pop(l, 2);
        return -1;
    }
    if (max != count)
        return -1;
    return max;
}

static void lua_toarray(lua_State *l,
                        msgpack_packer *pck,
                        int index,
                        struct flb_lua_l2c_config *l2cc)
{
    int len;
    int i;

    lua_pushnumber(l, (lua_Number)lua_objlen(l, -1)); // lua_len
    len = (int)lua_tointeger(l, -1);
    lua_pop(l, 1);

    msgpack_pack_array(pck, len);
    for (i = 1; i <= len; i++) {
        lua_rawgeti(l, -1, i);
        flb_lua_tomsgpack(l, pck, 0, l2cc);
        lua_pop(l, 1);
    }
}

static void lua_toarray_mpack(lua_State *l,
                              mpack_writer_t *writer,
                              int index,
                              struct flb_lua_l2c_config *l2cc)
{
    int len;
    int i;

    lua_pushnumber(l, (lua_Number)lua_objlen(l, -1)); // lua_len
    len = (int)lua_tointeger(l, -1);
    lua_pop(l, 1);

    mpack_write_tag(writer, mpack_tag_array(len));
    for (i = 1; i <= len; i++) {
        lua_rawgeti(l, -1, i);
        flb_lua_tompack(l, writer, 0, l2cc);
        lua_pop(l, 1);
    }
}

static void try_to_convert_data_type(lua_State *l,
                                     msgpack_packer *pck,
                                     int index,
                                     struct flb_lua_l2c_config *l2cc)
{
    size_t   len;
    const char *tmp = NULL;

    struct mk_list  *tmp_list = NULL;
    struct mk_list  *head     = NULL;
    struct flb_lua_l2c_type *l2c      = NULL;

    // convert to int
    if ((lua_type(l, -2) == LUA_TSTRING)
        && lua_type(l, -1) == LUA_TNUMBER){
        tmp = lua_tolstring(l, -2, &len);

        mk_list_foreach_safe(head, tmp_list, &l2cc->l2c_types) {
            l2c = mk_list_entry(head, struct flb_lua_l2c_type, _head);
            if (!strncmp(l2c->key, tmp, len) && l2c->type == FLB_LUA_L2C_TYPE_INT) {
                flb_lua_tomsgpack(l, pck, -1, l2cc);
                msgpack_pack_int64(pck, (int64_t)lua_tonumber(l, -1));
                return;
            }
        }
    }
    else if ((lua_type(l, -2) == LUA_TSTRING)
             && lua_type(l, -1) == LUA_TTABLE){
        tmp = lua_tolstring(l, -2, &len);

        mk_list_foreach_safe(head, tmp_list, &l2cc->l2c_types) {
            l2c = mk_list_entry(head, struct flb_lua_l2c_type, _head);
            if (!strncmp(l2c->key, tmp, len) && l2c->type == FLB_LUA_L2C_TYPE_ARRAY) {
                flb_lua_tomsgpack(l, pck, -1, l2cc);
                lua_toarray(l, pck, 0, l2cc);
                return;
            }
        }
    }

    /* not matched */
    flb_lua_tomsgpack(l, pck, -1, l2cc);
    flb_lua_tomsgpack(l, pck, 0, l2cc);
}

static void try_to_convert_data_type_mpack(lua_State *l,
                                           mpack_writer_t *writer,
                                           int index,
                                           struct flb_lua_l2c_config *l2cc)
{
    size_t   len;
    const char *tmp = NULL;

    struct mk_list  *tmp_list = NULL;
    struct mk_list  *head     = NULL;
    struct flb_lua_l2c_type *l2c      = NULL;

    // convert to int
    if ((lua_type(l, -2) == LUA_TSTRING)
        && lua_type(l, -1) == LUA_TNUMBER){
        tmp = lua_tolstring(l, -2, &len);

        mk_list_foreach_safe(head, tmp_list, &l2cc->l2c_types) {
            l2c = mk_list_entry(head, struct flb_lua_l2c_type, _head);
            if (!strncmp(l2c->key, tmp, len) && l2c->type == FLB_LUA_L2C_TYPE_INT) {
                flb_lua_tompack(l, writer, -1, l2cc);
                mpack_write_int(writer, (int64_t)lua_tonumber(l, -1));
                return;
            }
        }
    }
    else if ((lua_type(l, -2) == LUA_TSTRING)
             && lua_type(l, -1) == LUA_TTABLE){
        tmp = lua_tolstring(l, -2, &len);

        mk_list_foreach_safe(head, tmp_list, &l2cc->l2c_types) {
            l2c = mk_list_entry(head, struct flb_lua_l2c_type, _head);
            if (!strncmp(l2c->key, tmp, len) && l2c->type == FLB_LUA_L2C_TYPE_ARRAY) {
                flb_lua_tompack(l, writer, -1, l2cc);
                lua_toarray_mpack(l, writer, 0, l2cc);
                return;
            }
        }
    }

    /* not matched */
    flb_lua_tompack(l, writer, -1, l2cc);
    flb_lua_tompack(l, writer, 0, l2cc);
}

void flb_lua_tompack(lua_State *l,
                     mpack_writer_t *writer,
                     int index,
                     struct flb_lua_l2c_config *l2cc)
{
    int len;
    int i;

    switch (lua_type(l, -1 + index)) {
        case LUA_TSTRING:
            {
                const char *str;
                size_t len;

                str = lua_tolstring(l, -1 + index, &len);

                mpack_write_str(writer, str, len);
            }
            break;
        case LUA_TNUMBER:
            {
                if (lua_isinteger(l, -1 + index)) {
                    int64_t num = lua_tointeger(l, -1 + index);
                    mpack_write_int(writer, num);
                }
                else {
                    double num = lua_tonumber(l, -1 + index);
                    mpack_write_double(writer, num);
                }
            }
            break;
        case LUA_TBOOLEAN:
            if (lua_toboolean(l, -1 + index))
                mpack_write_true(writer);
            else
                mpack_write_false(writer);
            break;
        case LUA_TTABLE:
            len = flb_lua_arraylength(l);
            if (len > 0) {
                mpack_write_tag(writer, mpack_tag_array(len));
                for (i = 1; i <= len; i++) {
                    lua_rawgeti(l, -1, i);
                    flb_lua_tompack(l, writer, 0, l2cc);
                    lua_pop(l, 1);
                }
            } else
            {
                len = 0;
                lua_pushnil(l);
                while (lua_next(l, -2) != 0) {
                    lua_pop(l, 1);
                    len++;
                }
                mpack_write_tag(writer, mpack_tag_map(len));

                lua_pushnil(l);

                if (l2cc->l2c_types_num > 0) {
                    /* type conversion */
                    while (lua_next(l, -2) != 0) {
                        try_to_convert_data_type_mpack(l, writer, index, l2cc);
                        lua_pop(l, 1);
                    }
                } else {
                    while (lua_next(l, -2) != 0) {
                        flb_lua_tompack(l, writer, -1, l2cc);
                        flb_lua_tompack(l, writer, 0, l2cc);
                        lua_pop(l, 1);
                    }
                }
            }
            break;
        case LUA_TNIL:
            mpack_write_nil(writer);
            break;

         case LUA_TLIGHTUSERDATA:
            if (lua_touserdata(l, -1 + index) == NULL) {
                mpack_write_nil(writer);
                break;
            }
         case LUA_TFUNCTION:
         case LUA_TUSERDATA:
         case LUA_TTHREAD:
           /* cannot serialize */
           break;
    }
}

void flb_lua_tomsgpack(lua_State *l,
                       msgpack_packer *pck,
                       int index,
                       struct flb_lua_l2c_config *l2cc)
{
    int len;
    int i;

    switch (lua_type(l, -1 + index)) {
        case LUA_TSTRING:
            {
                const char *str;
                size_t len;

                str = lua_tolstring(l, -1 + index, &len);

                msgpack_pack_str(pck, len);
                msgpack_pack_str_body(pck, str, len);
            }
            break;
        case LUA_TNUMBER:
            {
                if (lua_isinteger(l, -1 + index)) {
                    int64_t num = lua_tointeger(l, -1 + index);
                    msgpack_pack_int64(pck, num);
                }
                else {
                    double num = lua_tonumber(l, -1 + index);
                    msgpack_pack_double(pck, num);
                }
            }
            break;
        case LUA_TBOOLEAN:
            if (lua_toboolean(l, -1 + index))
                msgpack_pack_true(pck);
            else
                msgpack_pack_false(pck);
            break;
        case LUA_TTABLE:
            len = flb_lua_arraylength(l);
            if (len > 0) {
                msgpack_pack_array(pck, len);
                for (i = 1; i <= len; i++) {
                    lua_rawgeti(l, -1, i);
                    flb_lua_tomsgpack(l, pck, 0, l2cc);
                    lua_pop(l, 1);
                }
            } else
            {
                len = 0;
                lua_pushnil(l);
                while (lua_next(l, -2) != 0) {
                    lua_pop(l, 1);
                    len++;
                }
                msgpack_pack_map(pck, len);

                lua_pushnil(l);

                if (l2cc->l2c_types_num > 0) {
                    /* type conversion */
                    while (lua_next(l, -2) != 0) {
                        try_to_convert_data_type(l, pck, index, l2cc);
                        lua_pop(l, 1);
                    }
                } else {
                    while (lua_next(l, -2) != 0) {
                        flb_lua_tomsgpack(l, pck, -1, l2cc);
                        flb_lua_tomsgpack(l, pck, 0, l2cc);
                        lua_pop(l, 1);
                    }
                }
            }
            break;
        case LUA_TNIL:
            msgpack_pack_nil(pck);
            break;

         case LUA_TLIGHTUSERDATA:
            if (lua_touserdata(l, -1 + index) == NULL) {
                msgpack_pack_nil(pck);
                break;
            }
         case LUA_TFUNCTION:
         case LUA_TUSERDATA:
         case LUA_TTHREAD:
           /* cannot serialize */
           break;
    }
}
