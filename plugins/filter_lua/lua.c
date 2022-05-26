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

#include "fluent-bit/flb_mem.h"
#include "lua.h"
#include "lua_config.h"
#include "mpack/mpack.h"

static int cb_lua_init(struct flb_filter_instance *f_ins,
                       struct flb_config *config,
                       void *data)
{
    int err;
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

    /* Lua script source code */
    if (ctx->code) {
        ret = flb_luajit_load_buffer(ctx->lua,
                                     ctx->code, flb_sds_len(ctx->code),
                                     "fluentbit.lua");
    }
    else {
        /* Load Script / file path*/
        ret = flb_luajit_load_script(ctx->lua, ctx->script);
    }

    if (ret == -1) {
        lua_config_destroy(ctx);
        return -1;
    }

    err = lua_pcall(ctx->lua->state, 0, 0, 0);
    if (err != 0) {
        flb_error("[luajit] invalid lua content, error=%d: %s",
                  err, lua_tostring(lj->state, -1));
        lua_pop(lj->state, 1);
        lua_config_destroy(ctx);
        return -1;
    }


    if (flb_lua_is_valid_func(ctx->lua->state, ctx->call) != FLB_TRUE) {
        flb_plg_error(ctx->ins, "function %s is not found", ctx->call);
        lua_config_destroy(ctx);
        return -1;
    }

    /* Initialize packing buffer */
    ctx->packbuf = flb_sds_create_size(1024);
    if (!ctx->packbuf) {
        flb_error("[filter_lua] failed to allocate packbuf");
        return -1;
    }

    /* Set context */
    flb_filter_set_context(f_ins, ctx);

    return 0;
}

#ifdef FLB_FILTER_LUA_USE_MPACK

static void mpack_buffer_flush(mpack_writer_t* writer, const char* buffer, size_t count)
{
    struct lua_filter *ctx = writer->context;
    flb_sds_cat_safe(&ctx->packbuf, buffer, count);
}

static void pack_result_mpack(lua_State *l,
                              mpack_writer_t *writer,
                              struct flb_lua_l2c_config *l2cc,
                              struct flb_time *t)
{
    int i;
    int len;

    if (lua_type(l, -1) != LUA_TTABLE) {
        return;
    }

    len = flb_lua_arraylength(l);
    if (len > 0) {
        /* record split */
        for (i = 1; i <= len; i++) {
            /* write array tag */
            mpack_write_tag(writer, mpack_tag_array(2));
            /* write timestamp */
            flb_time_append_to_mpack(writer, t, 0);
            /* get the subrecord */
            lua_rawgeti(l, -1, i);
            /* convert */
            flb_lua_tompack(l, writer, 0, l2cc);
            lua_pop(l, 1);
        }
    }
    else {
        /* write array tag */
        mpack_write_tag(writer, mpack_tag_array(2));
        /* write timestamp */
        flb_time_append_to_mpack(writer, t, 0);
        /* convert */
        flb_lua_tompack(l, writer, 0, l2cc);
    }
    /* pop */
    lua_pop(l, 1);
}

static int cb_lua_filter_mpack(const void *data, size_t bytes,
                               const char *tag, int tag_len,
                               void **out_buf, size_t *out_bytes,
                               struct flb_filter_instance *f_ins,
                               struct flb_input_instance *i_ins,
                               void *filter_context,
                               struct flb_config *config)
{
    (void) i_ins;
    int ret;
    struct flb_time t_orig;
    struct flb_time t;
    struct lua_filter *ctx = filter_context;
    double ts = 0;
    int l_code;
    double l_timestamp;
    char *outbuf;
    char writebuf[1024];
    mpack_writer_t writer;

    flb_sds_len_set(ctx->packbuf, 0);
    mpack_reader_t reader;
    mpack_reader_init_data(&reader, data, bytes);

    while (bytes > 0) {
        /* Save record start */
        const char *record_start = reader.data;
        size_t record_size = 0;
        /* Get timestamp */
        if (flb_time_pop_from_mpack(&t, &reader)) {
            /* failed to parse */
            return FLB_FILTER_NOTOUCH;
        }
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

        if (flb_lua_pushmpack(ctx->lua->state, &reader)) {
            return FLB_FILTER_NOTOUCH;
        }
        record_size = reader.data - record_start;
        bytes -= record_size;

        if (ctx->protected_mode) {
            ret = lua_pcall(ctx->lua->state, 3, 3, 0);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "error code %d: %s",
                              ret, lua_tostring(ctx->lua->state, -1));
                lua_pop(ctx->lua->state, 1);
                return FLB_FILTER_NOTOUCH;
            }
        }
        else {
            lua_call(ctx->lua->state, 3, 3);
        }

        /* Returned values are on the stack in the following order:
         *  -1: table/record
         *  -2: timestamp
         *  -3: code
         *  since we will process code first, then timestamp then record,
         *  we need to swap
         *
         * use lua_insert to put the table/record on the bottom */
        lua_insert(ctx->lua->state, -3);
         /* now swap timestamp with code */
        lua_insert(ctx->lua->state, -2);

        /* check code */
        l_code = (int) lua_tointeger(ctx->lua->state, -1);
        lua_pop(ctx->lua->state, 1);

        if (l_code == -1) { /* Skip record */
            lua_pop(ctx->lua->state, 2);
            continue;
        }
        else if (l_code == 0) { /* Keep record, copy original to packbuf */
            flb_sds_cat_safe(&ctx->packbuf, record_start, record_size);
            lua_pop(ctx->lua->state, 2);
            continue;
        }
        else if (l_code != 1 && l_code != 2) {/* Unexpected return code, keep original content */
            flb_sds_cat_safe(&ctx->packbuf, record_start, record_size);
            lua_pop(ctx->lua->state, 2);
            flb_plg_error(ctx->ins, "unexpected Lua script return code %i, "
                          "original record will be kept." , l_code);
            continue;
        }

        /* process record timestamp */
        l_timestamp = ts;
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

        if (l_code == 1) {
            if (ctx->time_as_table == FLB_FALSE) {
                flb_time_from_double(&t, l_timestamp);
            }
        }
        else if (l_code == 2) {
            /* Keep the timestamp */
            t = t_orig;
        }

        /* process the record table */
        /* initialize writer and set packbuf as context */
        mpack_writer_init(&writer, writebuf, sizeof(writebuf));
        mpack_writer_set_context(&writer, ctx);
        mpack_writer_set_flush(&writer, mpack_buffer_flush);
        /* write the result */
        pack_result_mpack(ctx->lua->state, &writer, &ctx->l2cc, &t);
        /* flush the writer */
        mpack_writer_flush_message(&writer);
        mpack_writer_destroy(&writer);
    }

    if (flb_sds_len(ctx->packbuf) == 0) {
        /* All records are removed */
        *out_buf = NULL;
        *out_bytes = 0;
        return FLB_FILTER_MODIFIED;
    }

    /* allocate outbuf that contains the modified chunks */
    outbuf = flb_malloc(flb_sds_len(ctx->packbuf));
    if (!outbuf) {
        flb_plg_error(ctx->ins, "failed to allocate outbuf");
        return FLB_FILTER_NOTOUCH;
    }
    memcpy(outbuf, ctx->packbuf, flb_sds_len(ctx->packbuf));
    /* link new buffer */
    *out_buf   = outbuf;
    *out_bytes = flb_sds_len(ctx->packbuf);

    return FLB_FILTER_MODIFIED;
}

#else

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
                         struct flb_input_instance *i_ins,
                         void *filter_context,
                         struct flb_config *config)
{
    int ret;
    size_t off = 0;
    (void) f_ins;
    (void) i_ins;
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


#endif

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
     FLB_CONFIG_MAP_STR, "code", NULL,
     0, FLB_FALSE, 0,
     "String that contains the Lua script source code"
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
#ifdef FLB_FILTER_LUA_USE_MPACK
    .cb_filter    = cb_lua_filter_mpack,
#else
    .cb_filter    = cb_lua_filter,
#endif
    .cb_exit      = cb_lua_exit,
    .config_map   = config_map,
    .flags        = 0
};
