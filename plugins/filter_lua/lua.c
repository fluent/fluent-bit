/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>

#include "lua_config.h"
#include <msgpack.h>

/*
 * This function validate if a msgpack formed from a Lua script JSON
 * content is a valid Map
 */
int is_valid_map(char *data, size_t bytes)
{
    int ret;
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
    if (root.type != MSGPACK_OBJECT_MAP) {
        msgpack_unpacked_destroy(&result);
        return FLB_FALSE;
    }

    if (root.via.map.size <= 0) {
        msgpack_unpacked_destroy(&result);
        return FLB_FALSE;
    }

    msgpack_unpacked_destroy(&result);
    return FLB_TRUE;
}

/*
 * This function is similar to flb_msgpack_to_json_str() but it have
 * two main differences:
 *
 * - use a pre-allocated buffer to perform the decoding operation
 * - use flb_sds_t data type instead of normal char *
 */
int msgpack_map_to_json(struct lua_filter *lf, msgpack_object *obj)
{
    int ret;
    size_t size;
    flb_sds_t tmp;

    if (obj == NULL) {
        return -1;
    }

    /* Reset length */
    flb_sds_len_set(lf->buffer, 0);

    while (1) {
        /* Get buffer size */
        size = flb_sds_alloc(lf->buffer);

        /* Decode from msgpack to json */
        ret = flb_msgpack_to_json(lf->buffer, size, obj);
        if (ret <= 0) {
            /* buffer is too small */
            tmp = flb_sds_increase(lf->buffer, LUA_BUFFER_CHUNK);
            if (tmp) {
                lf->buffer = tmp;
            }
            else {
                flb_error("[filter_lua] cannot adjust decode buffer size");
                flb_errno();
                return -1;
            }
        }
        else {
            break;
        }
    }

    return 0;
}

static int is_valid_func(struct flb_luajit *lua, flb_sds_t func)
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

static int cb_lua_filter(void *data, size_t bytes,
                         char *tag, int tag_len,
                         void **out_buf, size_t *out_bytes,
                         struct flb_filter_instance *f_ins,
                         void *filter_context,
                         struct flb_config *config)
{
    int ret;
    size_t len;
    size_t off = 0;
    (void) f_ins;
    (void) config;
    double ts;
    msgpack_object *p;
    msgpack_object root;
    msgpack_unpacked result;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    char *pack_data;
    size_t pack_size;
    struct flb_time t;
    struct lua_filter *ctx = filter_context;
    /* Lua return values */
    int l_code;
    double l_timestamp;
    char *l_record;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        root = result.data;

        /* Get timestamp */
        flb_time_pop_from_msgpack(&t, &result, &p);
        ts = flb_time_to_double(&t);

        /* Decode from msgpack to JSON */
        ret = msgpack_map_to_json(ctx, p);
        if (ret == -1) {
            msgpack_sbuffer_destroy(&tmp_sbuf);
            msgpack_unpacked_destroy(&result);
            return FLB_FILTER_NOTOUCH;
        }

        /* Prepare function call, pass 3 arguments, expect 3 return values */
        lua_getglobal(ctx->lua->state, ctx->call);
        lua_pushstring(ctx->lua->state, tag);
        lua_pushnumber(ctx->lua->state, ts);
        lua_pushstring(ctx->lua->state, ctx->buffer);
        lua_call(ctx->lua->state, 3, 3);

        /* Initialize Return values */
        l_code = 0;
        l_timestamp = ts;
        l_record = ctx->buffer;
        len = flb_sds_len(ctx->buffer);

        /* Record: must be a JSON Map if it was modified */
        l_record = (char *) lua_tolstring(ctx->lua->state, -1, &len);
        lua_pop(ctx->lua->state, 1);

        l_timestamp = (double) lua_tonumber(ctx->lua->state, -1);
        lua_pop(ctx->lua->state, 1);

        l_code = (int) lua_tointeger(ctx->lua->state, -1);
        lua_pop(ctx->lua->state, 1);

        /* Validations */
        if (l_code == 1) {
            /* Must be a valid string */
            if (len == 0 || l_record == NULL) {
                flb_error("[filter_lua] invalid record value for "
                          "return code 1 at %s(), %s",
                          ctx->call, ctx->script);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                msgpack_unpacked_destroy(&result);
                return FLB_FILTER_NOTOUCH;
            }

            /* Convert JSON to msgpack */
            ret = flb_pack_json(l_record, len, &pack_data, &pack_size);
            if (ret == -1) {
                flb_error("[filter_lua] invalid JSON at %s(), %s",
                          ctx->call, ctx->script);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                msgpack_unpacked_destroy(&result);
                return FLB_FILTER_NOTOUCH;
            }

            ret = is_valid_map(pack_data, pack_size);
            if (ret == FLB_FALSE) {
                flb_error("[filter_lua] invalid JSON map returned at %s(), %s",
                          ctx->call, ctx->script);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                msgpack_unpacked_destroy(&result);
                flb_free(pack_data);
                return FLB_FILTER_NOTOUCH;
            }
        }

        if (l_code == -1) { /* Skip record */
            continue;
        }
        else if (l_code == 0) { /* Keep record, repack */
            msgpack_pack_object(&tmp_pck, root);
        }
        else if (l_code == 1) { /* Modified, pack new data */
            /* main array */
            msgpack_pack_array(&tmp_pck, 2);

            /* timestamp: convert from double to Fluent Bit format */
            flb_time_from_double(&t, l_timestamp);
            flb_time_append_to_msgpack(&t, &tmp_pck, 0);

            /* Pack json map as string */
            msgpack_sbuffer_write(&tmp_sbuf, pack_data, pack_size);
            flb_free(pack_data);
        }
        else { /* Unexpected return code, keep original content */
            flb_error("[filter_lua] unexpected Lua script return code %i, "
                      "original record will be kept." , l_code);
            msgpack_pack_object(&tmp_pck, root);
        }
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
