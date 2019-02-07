/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>

#include "lua_config.h"
#include <msgpack.h>

static void lua_pushmsgpack(lua_State *l, msgpack_object *o)
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
            lua_pushnumber(l, (double) o->via.u64);
            break;

        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            lua_pushnumber(l, (double) o->via.i64);
            break;

        case MSGPACK_OBJECT_FLOAT32:
        case MSGPACK_OBJECT_FLOAT64:
            lua_pushnumber(l, (double) o->via.f64);
            break;

        case MSGPACK_OBJECT_STR:
            lua_pushlstring(l, (char*)o->via.str.ptr, o->via.str.size);
            break;

        case MSGPACK_OBJECT_BIN:
            lua_pushlstring(l, (char*)o->via.bin.ptr, o->via.bin.size);
            break;

        case MSGPACK_OBJECT_EXT:
            lua_pushlstring(l, (char*)o->via.ext.ptr, o->via.ext.size);
            break;

        case MSGPACK_OBJECT_ARRAY:
            size = o->via.array.size;
            lua_createtable(l, size, 0);
            if (size != 0) {
                msgpack_object *p = o->via.array.ptr;
                for (i = 0; i < size; i++) {
                    lua_pushmsgpack(l, p+i);
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
                    lua_pushmsgpack(l, &(p+i)->key);
                    lua_pushmsgpack(l, &(p+i)->val);
                    lua_settable(l, -3);
                }
            }
            break;
    }

}

static int lua_arraylength(lua_State *l)
{
    lua_Integer n;
    int count = 0;
    int max = 0;

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

static void lua_tomsgpack(struct lua_filter *lf, msgpack_packer *pck, int index);
static void try_to_convert_data_type(struct lua_filter *lf,
                                     msgpack_packer *pck,
                                     int index)
{
    size_t   len;
    const char *tmp = NULL;
    lua_State *l = lf->lua->state;

    struct mk_list  *tmp_list = NULL;
    struct mk_list  *head     = NULL;
    struct l2c_type *l2c      = NULL;

    if ((lua_type(l, -2) == LUA_TSTRING) 
        && lua_type(l, -1) == LUA_TNUMBER){
        tmp = lua_tolstring(l, -2, &len);
        
        mk_list_foreach_safe(head, tmp_list, &lf->l2c_types) {
            l2c = mk_list_entry(head, struct l2c_type, _head);
            if (!strncmp(l2c->key, tmp, len)) {
                lua_tomsgpack(lf, pck, -1);
                msgpack_pack_int64(pck, (int)lua_tonumber(l, -1));
                return;
            }
        }
    }

    /* not matched */
    lua_tomsgpack(lf, pck, -1);
    lua_tomsgpack(lf, pck, 0);
}

static void lua_tomsgpack(struct lua_filter *lf, msgpack_packer *pck, int index)
{
    int len;
    int i;
    lua_State *l = lf->lua->state;

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
                double num = lua_tonumber(l, -1 + index);
                msgpack_pack_double(pck, num);
            }
            break;
        case LUA_TBOOLEAN:
            if (lua_toboolean(l, -1 + index))
                msgpack_pack_true(pck);
            else
                msgpack_pack_false(pck);
            break;
        case LUA_TTABLE:
            len = lua_arraylength(l);
            if (len > 0) {
                msgpack_pack_array(pck, len);
                for (i = 1; i <= len; i++) {
                    lua_rawgeti(l, -1, i);
                    lua_tomsgpack(lf, pck, 0);
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

                if (lf->l2c_types_num > 0) {
                    /* type conversion */
                    while (lua_next(l, -2) != 0) {
                        try_to_convert_data_type(lf, pck, index);
                        lua_pop(l, 1);
                    }
                } else {
                    while (lua_next(l, -2) != 0) {
                        lua_tomsgpack(lf, pck, -1);
                        lua_tomsgpack(lf, pck, 0);
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

static int is_valid_func(lua_State *lua, flb_sds_t func)
{
    int ret = FLB_FALSE;

    lua_getglobal(lua, func);
    if (lua_isfunction(lua, -1)) {
        ret = FLB_TRUE;
    }
    lua_pop(lua, -1); /* discard return value of isfunction */

    return ret;
}

static int cb_lua_init(struct flb_filter_instance *f_ins,
                       struct flb_config *config,
                       void *data)
{
    int ret;
    (void) data;
    struct lua_filter *ctx;
    struct flb_luajit *lj;

    /* Create context */
    ctx = lua_config_create(f_ins, config);
    if (!ctx) {
        flb_error("[filter_lua] filter cannot be loaded");
        return -1;
    }

    /* Create LuaJIT state/vm */
    lj = flb_luajit_create(config);
    if (!lj) {
        lua_config_destroy(ctx);
        return -1;
    }
    ctx->lua = lj;

    /* Load Script */
    ret = flb_luajit_load_script(ctx->lua, ctx->script);
    if (ret == -1) {
        lua_config_destroy(ctx);
        return -1;
    }
    lua_pcall(ctx->lua->state, 0, 0, 0);

    if (is_valid_func(ctx->lua->state, ctx->call) != FLB_TRUE) {
        flb_error("[filter_lua] function %s is not found", ctx->call);

        lua_config_destroy(ctx);
        return -1;
    }

    /* Set context */
    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static int pack_result (double ts, msgpack_packer *pck, msgpack_sbuffer *sbuf,
                        char *data, size_t bytes)
{
    int ret;
    int size;
    int i;
    size_t off = 0;
    msgpack_object root;
    msgpack_unpacked result;
    struct flb_time t;

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, data, bytes, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);
        return FLB_FALSE;
    }

    root = result.data;
    /* check for array */
    if (root.type == MSGPACK_OBJECT_ARRAY) {
        size = root.via.array.size;
        if (size > 0) {
            msgpack_object *map = root.via.array.ptr;
            for (i = 0; i < size; i++) {
                if ((map+i)->type != MSGPACK_OBJECT_MAP) {
                    msgpack_unpacked_destroy(&result);
                    return FLB_FALSE;
                }
                if ((map+i)->via.map.size <= 0) {
                    msgpack_unpacked_destroy(&result);
                    return FLB_FALSE;
                }
                /* main array */
                msgpack_pack_array(pck, 2);

                /* timestamp: convert from double to Fluent Bit format */
                flb_time_from_double(&t, ts);
                flb_time_append_to_msgpack(&t, pck, 0);

                /* Pack lua table */
                msgpack_pack_object(pck, *(map+i));
            }
            msgpack_unpacked_destroy(&result);
            return FLB_TRUE;
        }
        else {
            msgpack_unpacked_destroy(&result);
            return FLB_FALSE;
        }
    }

    /* check for map */
    if (root.type != MSGPACK_OBJECT_MAP) {
        msgpack_unpacked_destroy(&result);
        return FLB_FALSE;
    }

    if (root.via.map.size <= 0) {
        msgpack_unpacked_destroy(&result);
        return FLB_FALSE;
    }

    /* main array */
    msgpack_pack_array(pck, 2);

    /* timestamp: convert from double to Fluent Bit format */
    flb_time_from_double(&t, ts);
    flb_time_append_to_msgpack(&t, pck, 0);

    /* Pack lua table */
    msgpack_sbuffer_write(sbuf, data, bytes);

    msgpack_unpacked_destroy(&result);
    return FLB_TRUE;
}

static int cb_lua_filter(void *data, size_t bytes,
                         char *tag, int tag_len,
                         void **out_buf, size_t *out_bytes,
                         struct flb_filter_instance *f_ins,
                         void *filter_context,
                         struct flb_config *config)
{
    int ret;
    size_t off = 0;
    (void) f_ins;
    (void) config;
    double ts;
    msgpack_object *p;
    msgpack_object root;
    msgpack_unpacked result;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    struct flb_time t;
    struct lua_filter *ctx = filter_context;
    /* Lua return values */
    int l_code;
    double l_timestamp;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        msgpack_packer data_pck;
        msgpack_sbuffer data_sbuf;

        msgpack_sbuffer_init(&data_sbuf);
        msgpack_packer_init(&data_pck, &data_sbuf, msgpack_sbuffer_write);

        root = result.data;

        /* Get timestamp */
        flb_time_pop_from_msgpack(&t, &result, &p);
        ts = flb_time_to_double(&t);

        /* Prepare function call, pass 3 arguments, expect 3 return values */
        lua_getglobal(ctx->lua->state, ctx->call);
        lua_pushstring(ctx->lua->state, tag);
        lua_pushnumber(ctx->lua->state, ts);
        lua_pushmsgpack(ctx->lua->state, p);
        lua_call(ctx->lua->state, 3, 3);

        /* Initialize Return values */
        l_code = 0;
        l_timestamp = ts;

        lua_tomsgpack(ctx, &data_pck, 0);
        lua_pop(ctx->lua->state, 1);

        l_timestamp = (double) lua_tonumber(ctx->lua->state, -1);
        lua_pop(ctx->lua->state, 1);

        l_code = (int) lua_tointeger(ctx->lua->state, -1);
        lua_pop(ctx->lua->state, 1);

        if (l_code == -1) { /* Skip record */
            msgpack_sbuffer_destroy(&data_sbuf);
            continue;
        }
        else if (l_code == 0) { /* Keep record, repack */
            msgpack_pack_object(&tmp_pck, root);
        }
        else if (l_code == 1) { /* Modified, pack new data */
            ret = pack_result(l_timestamp, &tmp_pck, &tmp_sbuf,
                              data_sbuf.data, data_sbuf.size);
            if (ret == FLB_FALSE) {
                flb_error("[filter_lua] invalid table returned at %s(), %s",
                          ctx->call, ctx->script);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                msgpack_sbuffer_destroy(&data_sbuf);
                msgpack_unpacked_destroy(&result);
                return FLB_FILTER_NOTOUCH;
            }
        }
        else { /* Unexpected return code, keep original content */
            flb_error("[filter_lua] unexpected Lua script return code %i, "
                      "original record will be kept." , l_code);
            msgpack_pack_object(&tmp_pck, root);
        }
        msgpack_sbuffer_destroy(&data_sbuf);
    }
    msgpack_unpacked_destroy(&result);

    /* link new buffers */
    *out_buf   = tmp_sbuf.data;
    *out_bytes = tmp_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_lua_exit(void *data, struct flb_config *config)
{
    struct lua_filter *ctx;

    ctx = data;
    flb_luajit_destroy(ctx->lua);
    lua_config_destroy(ctx);

    return 0;
}

struct flb_filter_plugin filter_lua_plugin = {
    .name         = "lua",
    .description  = "Lua Scripting Filter",
    .cb_init      = cb_lua_init,
    .cb_filter    = cb_lua_filter,
    .cb_exit      = cb_lua_exit,
    .flags        = 0
};
