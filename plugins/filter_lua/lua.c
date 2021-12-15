/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_lua.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <msgpack.h>

#include "lua_config.h"

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

    if (flb_lua_is_valid_func(ctx->lua->state, ctx->call) != FLB_TRUE) {
        flb_plg_error(ctx->ins, "function %s is not found", ctx->call);
        lua_config_destroy(ctx);
        return -1;
    }

    /* Set context */
    flb_filter_set_context(f_ins, ctx);

    return 0;
}

static int pack_result (struct flb_time *ts, msgpack_packer *pck, msgpack_sbuffer *sbuf,
                        char *data, size_t bytes)
{
    int ret;
    int size;
    int i;
    size_t off = 0;
    msgpack_object root;
    msgpack_unpacked result;

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
                flb_time_append_to_msgpack(ts, pck, 0);

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

    flb_time_append_to_msgpack(ts, pck, 0);

    /* Pack lua table */
    msgpack_sbuffer_write(sbuf, data, bytes);

    msgpack_unpacked_destroy(&result);
    return FLB_TRUE;
}

static int cb_lua_filter(const void *data, size_t bytes,
                         const char *tag, int tag_len,
                         void **out_buf, size_t *out_bytes,
                         struct flb_filter_instance *f_ins,
                         void *filter_context,
                         struct flb_config *config)
{
    int ret;
    size_t off = 0;
    (void) f_ins;
    (void) config;
    double ts = 0;
    msgpack_object *p;
    msgpack_object root;
    msgpack_unpacked result;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    struct flb_time t_orig;
    struct flb_time t;
    struct lua_filter *ctx = filter_context;
    /* Lua return values */
    int l_code;
    double l_timestamp;

    /* Create temporary msgpack buffer */
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
        t_orig = t;

        /* Prepare function call, pass 3 arguments, expect 3 return values */
        lua_getglobal(ctx->lua->state, ctx->call);
        lua_pushstring(ctx->lua->state, tag);

        /* Timestamp */
        if (ctx->time_as_table == FLB_TRUE) {
            flb_lua_pushtimetable(ctx->lua->state, &t);
        }
        else {
            ts = flb_time_to_double(&t);
            lua_pushnumber(ctx->lua->state, ts);
        }

        flb_lua_pushmsgpack(ctx->lua->state, p);
        if (ctx->protected_mode) {
            ret = lua_pcall(ctx->lua->state, 3, 3, 0);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "error code %d: %s",
                              ret, lua_tostring(ctx->lua->state, -1));
                lua_pop(ctx->lua->state, 1);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                msgpack_sbuffer_destroy(&data_sbuf);
                msgpack_unpacked_destroy(&result);
                return FLB_FILTER_NOTOUCH;
            }
        }
        else {
            lua_call(ctx->lua->state, 3, 3);
        }

        /* Initialize Return values */
        l_code = 0;
        l_timestamp = ts;

        flb_lua_tomsgpack(ctx->lua->state, &data_pck, 0, &ctx->l2cc);
        lua_pop(ctx->lua->state, 1);

        /* Lua table */
        if (ctx->time_as_table == FLB_TRUE) {
            if (lua_type(ctx->lua->state, -1) == LUA_TTABLE) {
                /* Retrieve seconds */
                lua_getfield(ctx->lua->state, -1, "sec");
                t.tm.tv_sec = lua_tointeger(ctx->lua->state, -1);
                lua_pop(ctx->lua->state, 1);

                /* Retrieve nanoseconds */
                lua_getfield(ctx->lua->state, -1, "nsec");
                t.tm.tv_nsec = lua_tointeger(ctx->lua->state, -1);
                lua_pop(ctx->lua->state, 2);
            }
            else {
                flb_plg_error(ctx->ins, "invalid lua timestamp type returned");
                t = t_orig;
            }
        }
        else {
            l_timestamp = (double) lua_tonumber(ctx->lua->state, -1);
            lua_pop(ctx->lua->state, 1);
        }

        l_code = (int) lua_tointeger(ctx->lua->state, -1);
        lua_pop(ctx->lua->state, 1);

        if (l_code == -1) { /* Skip record */
            msgpack_sbuffer_destroy(&data_sbuf);
            continue;
        }
        else if (l_code == 0) { /* Keep record, repack */
            msgpack_pack_object(&tmp_pck, root);
        }
        else if (l_code == 1 || l_code == 2) { /* Modified, pack new data */
            if (l_code == 1) {
                if (ctx->time_as_table == FLB_FALSE) {
                    flb_time_from_double(&t, l_timestamp);
                }
            }
            else if (l_code == 2) {
                /* Keep the timestamp */
                t = t_orig;
            }
            ret = pack_result(&t, &tmp_pck, &tmp_sbuf,
                              data_sbuf.data, data_sbuf.size);
            if (ret == FLB_FALSE) {
                flb_plg_error(ctx->ins, "invalid table returned at %s(), %s",
                              ctx->call, ctx->script);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                msgpack_sbuffer_destroy(&data_sbuf);
                msgpack_unpacked_destroy(&result);
                return FLB_FILTER_NOTOUCH;
            }
        }
        else { /* Unexpected return code, keep original content */
            flb_plg_error(ctx->ins, "unexpected Lua script return code %i, "
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

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "script", NULL,
     0, FLB_FALSE, 0,
     "The path of lua script."
    },
    {
     FLB_CONFIG_MAP_STR, "call", NULL,
     0, FLB_TRUE, offsetof(struct lua_filter, call),
     "Lua function name that will be triggered to do filtering."
    },
    {
     FLB_CONFIG_MAP_STR, "type_int_key", NULL,
     0, FLB_FALSE, 0,
     "If these keys are matched, the fields are converted to integer. "
     "If more than one key, delimit by space."
    },
    {
     FLB_CONFIG_MAP_STR, "type_array_key", NULL,
     0, FLB_FALSE, 0,
     "If these keys are matched, the fields are converted to array. "
     "If more than one key, delimit by space."
    },
    {
     FLB_CONFIG_MAP_BOOL, "protected_mode", "true",
     0, FLB_TRUE, offsetof(struct lua_filter, protected_mode),
     "If enabled, Lua script will be executed in protected mode. "
     "It prevents to crash when invalid Lua script is executed."
    },
    {
     FLB_CONFIG_MAP_BOOL, "time_as_table", "false",
     0, FLB_TRUE, offsetof(struct lua_filter, time_as_table),
     "If enabled, Fluent-bit will pass the timestamp as a Lua table "
     "with keys \"sec\" for seconds since epoch and \"nsec\" for nanoseconds."
    },
    {0}
};

struct flb_filter_plugin filter_lua_plugin = {
    .name         = "lua",
    .description  = "Lua Scripting Filter",
    .cb_init      = cb_lua_init,
    .cb_filter    = cb_lua_filter,
    .cb_exit      = cb_lua_exit,
    .config_map   = config_map,
    .flags        = 0
};
