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
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <msgpack.h>

#include "fluent-bit/flb_mem.h"
#include "lua.h"
#include "lua_config.h"
#include "mpack/mpack.h"

/* helper to rollback encoder buffer to previous offset */
static inline void encoder_rollback(struct flb_log_event_encoder *enc,
                                    size_t offset)
{
    enc->buffer.size = offset;
    enc->output_buffer = enc->buffer.data;
    enc->output_length = offset;
}

static int cb_lua_pre_run(struct flb_filter_instance *f_ins,
                          struct flb_config *config, void *data)
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

    flb_luajit_destroy(ctx->lua);
    lua_config_destroy(ctx);

    return ret;
}

static int env_variables(struct flb_config *config, struct flb_luajit *lj)
{
    struct mk_list *list;
    struct mk_list *head;
    struct flb_env *env;
    struct flb_hash_table_entry *entry;

    lua_newtable(lj->state);

    env = (struct flb_env *) config->env;
    list = (struct mk_list *) &env->ht->entries;
    mk_list_foreach(head, list) {
        entry = mk_list_entry(head, struct flb_hash_table_entry, _head_parent);
        if (entry->val_size <= 0) {
            continue;
        }
        lua_pushlstring(lj->state, entry->key, entry->key_len);
        lua_pushlstring(lj->state, entry->val, entry->val_size);
        lua_settable(lj->state, -3);
    }

    lua_setglobal(lj->state, "FLB_ENV");
    return 0;
}

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

    /* register environment variables */
    env_variables(config, lj);

    if (ctx->enable_flb_null) {
        flb_lua_enable_flb_null(lj->state);
    }

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
        flb_luajit_destroy(ctx->lua);
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

#pragma message "This code does not support the new log event encoding format"

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

    len = flb_lua_arraylength(l, -1);
    if (len > 0) {
        /* record split */
        for (i = 1; i <= len; i++) {
            /* write array tag */
            mpack_write_tag(writer, mpack_tag_array(2));
            /* write header tag */
            mpack_write_tag(writer, mpack_tag_array(2));
            /* write timestamp */
            flb_time_append_to_mpack(writer, t, 0);
            /* write metadata */
            mpack_write_tag(writer, mpack_tag_map(0));
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
        /* write header tag */
        mpack_write_tag(writer, mpack_tag_array(2));
        /* write timestamp */
        flb_time_append_to_mpack(writer, t, 0);
        /* write metadata */
        mpack_write_tag(writer, mpack_tag_map(0));
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

        /* This is a hack, in order to have this thing work
         * we rely on flb_time_pop_from_mpack skipping the
         * metadata map.
         */

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

static int pack_group_start(struct lua_filter *ctx,
                            struct flb_log_event_encoder *log_encoder,
                            struct flb_log_event *log_event)

{
    int ret;

    ret = flb_log_event_encoder_group_init(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event encoder error : %d", ret);
        return -1;
    }

    if (log_event->metadata != NULL) {
        ret = flb_log_event_encoder_set_metadata_from_msgpack_object(log_encoder,
                                                                     log_event->metadata);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins, "Log event encoder error : %d", ret);
            return -1;
        }
    }

    if (log_event->body != NULL) {
        ret = flb_log_event_encoder_set_body_from_msgpack_object(log_encoder,
                                                                 log_event->body);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins, "Log event encoder error : %d", ret);
            return -1;
        }
    }

    ret = flb_log_event_encoder_group_header_end(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event encoder error : %d", ret);
        return -1;
    }

    return 0;
}

static int pack_group_end(struct lua_filter *ctx,
                          struct flb_log_event_encoder *log_encoder)
{
    int ret;

    ret = flb_log_event_encoder_group_end(log_encoder);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event encoder error : %d", ret);
        return -1;
    }

    return 0;
}

static int pack_record(struct lua_filter *ctx,
                       struct flb_log_event_encoder *log_encoder,
                       struct flb_time *ts,
                       msgpack_object *metadata,
                       msgpack_object *body)
{
    int ret;

    ret = flb_log_event_encoder_begin_record(log_encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_timestamp(log_encoder, ts);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS && metadata != NULL) {
        ret = flb_log_event_encoder_set_metadata_from_msgpack_object(
                log_encoder, metadata);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_body_from_msgpack_object(
                log_encoder, body);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(log_encoder);
    }

    return ret;
}

static int pack_result(struct lua_filter *ctx, struct flb_time *ts,
                       msgpack_object *metadata,
                       struct flb_log_event_encoder *log_encoder,
                       char *data, size_t bytes)
{
    int ret;
    size_t index = 0;
    size_t off = 0;
    msgpack_object *entry;
    msgpack_unpacked result;

    msgpack_unpacked_init(&result);

    ret = msgpack_unpack_next(&result, data, bytes, &off);

    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&result);

        return FLB_FALSE;
    }

    if (result.data.type == MSGPACK_OBJECT_MAP) {
        ret = pack_record(ctx, log_encoder,
                          ts, metadata, &result.data);

        msgpack_unpacked_destroy(&result);

        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            return FLB_FALSE;
        }

        return FLB_TRUE;
    }
    else if (result.data.type == MSGPACK_OBJECT_ARRAY) {
        for (index = 0 ; index < result.data.via.array.size ; index++) {
            entry = &result.data.via.array.ptr[index];

            if (entry->type == MSGPACK_OBJECT_MAP) {
                ret = pack_record(ctx, log_encoder,
                                  ts, metadata, entry);

                if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                    msgpack_unpacked_destroy(&result);

                    return FLB_FALSE;
                }
            }
            else {
                msgpack_unpacked_destroy(&result);

                return FLB_FALSE;
            }
        }

        msgpack_unpacked_destroy(&result);

        return FLB_TRUE;
    }

    msgpack_unpacked_destroy(&result);

    return FLB_FALSE;
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
    int record_type;
    double ts = 0;
    struct flb_time t_orig;
    struct flb_time t;
    struct lua_filter *ctx = filter_context;
    /* Lua return values */
    int l_code;
    double l_timestamp;
    msgpack_packer data_pck;
    msgpack_sbuffer data_sbuf;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    size_t group_offset = 0;
    int group_active = FLB_FALSE;
    int group_has_records = FLB_FALSE;

    (void) f_ins;
    (void) i_ins;
    (void) config;

    /* initialize the decoder */
    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    /* enable group reads */
    flb_log_event_decoder_read_groups(&log_decoder, FLB_TRUE);

    /* initialize the encoder */
    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event encoder initialization error : %d", ret);
        flb_log_event_decoder_destroy(&log_decoder);
        return FLB_FILTER_NOTOUCH;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        /* Check if the record is special (group) or a normal one */
        ret = flb_log_event_decoder_get_record_type(&log_event, &record_type);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "record has invalid event type");
            continue;
        }

        /* Handle group definitions */
        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            group_offset = log_encoder.buffer.size;
            group_active = FLB_TRUE;
            group_has_records = FLB_FALSE;

            ret = pack_group_start(ctx, &log_encoder, &log_event);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_log_event_decoder_destroy(&log_decoder);
                flb_log_event_encoder_destroy(&log_encoder);
                return FLB_FILTER_NOTOUCH;
            }
            continue;
        }
        else if (record_type == FLB_LOG_EVENT_GROUP_END) {
            if (group_active && !group_has_records) {
                encoder_rollback(&log_encoder, group_offset);
                group_active = FLB_FALSE;
                continue;
            }

            ret = pack_group_end(ctx, &log_encoder);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_log_event_decoder_destroy(&log_decoder);
                flb_log_event_encoder_destroy(&log_encoder);
                return FLB_FILTER_NOTOUCH;
            }
            group_active = FLB_FALSE;
            continue;
        }

        msgpack_sbuffer_init(&data_sbuf);
        msgpack_packer_init(&data_pck, &data_sbuf, msgpack_sbuffer_write);

        /* Get timestamp */
        flb_time_copy(&t, &log_event.timestamp);
        flb_time_copy(&t_orig, &log_event.timestamp);

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

        flb_lua_pushmsgpack(ctx->lua->state, log_event.body);
        if (ctx->protected_mode) {
            ret = lua_pcall(ctx->lua->state, 3, 3, 0);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "error code %d: %s",
                              ret, lua_tostring(ctx->lua->state, -1));
                lua_pop(ctx->lua->state, 1);

                msgpack_sbuffer_destroy(&data_sbuf);
                flb_log_event_decoder_destroy(&log_decoder);
                flb_log_event_encoder_destroy(&log_encoder);

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

            ret = pack_result(ctx, &t, log_event.metadata, &log_encoder,
                              data_sbuf.data, data_sbuf.size);

            if (ret == FLB_FALSE) {
                flb_plg_error(ctx->ins, "invalid table returned at %s(), %s",
                              ctx->call, ctx->script);
                msgpack_sbuffer_destroy(&data_sbuf);

                flb_log_event_decoder_destroy(&log_decoder);
                flb_log_event_encoder_destroy(&log_encoder);

                return FLB_FILTER_NOTOUCH;
            }
            if (group_active) {
                group_has_records = FLB_TRUE;
            }
        }
        else { /* Unexpected return code, keep original content */
            /* Code 0 means Keep record, so we don't emit the warning */
            if (l_code != 0) {
                flb_plg_error(ctx->ins,
                              "unexpected Lua script return code %i, "
                              "original record will be kept." , l_code);
            }

            ret = flb_log_event_encoder_emit_raw_record(
                    &log_encoder,
                    log_decoder.record_base,
                    log_decoder.record_length);

            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_plg_error(ctx->ins,
                              "Log event encoder error : %d", ret);
            }
            else if (group_active) {
                group_has_records = FLB_TRUE;
            }
        }

        msgpack_sbuffer_destroy(&data_sbuf);
    }

    if (ret == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA) {
        ret = FLB_EVENT_ENCODER_SUCCESS;
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        if (log_encoder.output_length > 0) {
            *out_buf   = log_encoder.output_buffer;
            *out_bytes = log_encoder.output_length;

            ret = FLB_FILTER_MODIFIED;

            flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
        }
        else {
            *out_buf = NULL;
            *out_bytes = 0;

            ret = FLB_FILTER_MODIFIED;
        }
    }
    else {
        flb_plg_error(ctx->ins,
                      "Log event encoder error : %d", ret);

        ret = FLB_FILTER_NOTOUCH;
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return ret;
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
    {
     FLB_CONFIG_MAP_BOOL, "enable_flb_null", "false",
     0, FLB_TRUE, offsetof(struct lua_filter, enable_flb_null),
     "If enabled, null will be converted to flb_null in Lua. "
     "It is useful to prevent removing key/value "
     "since nil is a special value to remove key value from map in Lua."
    },

    {0}
};

struct flb_filter_plugin filter_lua_plugin = {
    .name         = "lua",
    .description  = "Lua Scripting Filter",
    .cb_pre_run   = cb_lua_pre_run,
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
