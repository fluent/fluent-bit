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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_kv.h>

#include "tail_config.h"
#include "tail_multiline.h"

static int tail_mult_append(struct flb_parser *parser,
                            struct flb_tail_config *ctx)
{
    struct flb_tail_mult *mp;

    mp = flb_malloc(sizeof(struct flb_tail_mult));
    if (!mp) {
        flb_errno();
        return -1;
    }

    mp->parser = parser;
    mk_list_add(&mp->_head, &ctx->mult_parsers);

    return 0;
}

int flb_tail_mult_create(struct flb_tail_config *ctx,
                         struct flb_input_instance *ins,
                         struct flb_config *config)
{
    int ret;
    const char *tmp;
    struct mk_list *head;
    struct flb_parser *parser;
    struct flb_kv *kv;

    if (ctx->multiline_flush <= 0) {
        ctx->multiline_flush = 1;
    }

    mk_list_init(&ctx->mult_parsers);

    /* Get firstline parser */
    tmp = flb_input_get_property("parser_firstline", ins);
    if (!tmp) {
        flb_plg_error(ctx->ins, "multiline: no parser defined for firstline");
        return -1;
    }
    parser = flb_parser_get(tmp, config);
    if (!parser) {
        flb_plg_error(ctx->ins, "multiline: invalid parser '%s'", tmp);
        return -1;
    }

    ctx->mult_parser_firstline = parser;

    /* Read all multiline rules */
    mk_list_foreach(head, &ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strcasecmp("parser_firstline", kv->key) == 0) {
            continue;
        }

        if (strncasecmp("parser_", kv->key, 7) == 0) {
            parser = flb_parser_get(kv->val, config);
            if (!parser) {
                flb_plg_error(ctx->ins, "multiline: invalid parser '%s'", kv->val);
                return -1;
            }

            ret = tail_mult_append(parser, ctx);
            if (ret == -1) {
                return -1;
            }
        }
    }

    return 0;
}

int flb_tail_mult_destroy(struct flb_tail_config *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_mult *mp;

    if (ctx->multiline == FLB_FALSE) {
        return 0;
    }

    mk_list_foreach_safe(head, tmp, &ctx->mult_parsers) {
        mp = mk_list_entry(head, struct flb_tail_mult, _head);
        mk_list_del(&mp->_head);
        flb_free(mp);
    }

    return 0;
}

/* Process the result of a firstline match */
int flb_tail_mult_process_first(time_t now,
                                char *buf, size_t size,
                                struct flb_time *out_time,
                                struct flb_tail_file *file,
                                struct flb_tail_config *ctx)
{
    int ret;
    size_t off;
    msgpack_object map;
    msgpack_unpacked result;

    /* If a previous multiline context already exists, flush first */
    if (file->mult_firstline && !file->mult_skipping) {
        flb_tail_mult_flush(file, ctx);
    }

    /* Remark as first multiline message */
    file->mult_firstline = FLB_TRUE;

    /* Validate obtained time, if not set, set the current time */
    if (flb_time_to_nanosec(out_time) == 0L) {
        flb_time_get(out_time);
    }

    /* Should we skip this multiline record ? */
    if (ctx->ignore_older > 0) {
        if ((now - ctx->ignore_older) > out_time->tm.tv_sec) {
            flb_free(buf);
            file->mult_skipping = FLB_TRUE;
            file->mult_firstline = FLB_TRUE;

            /* we expect more data to skip */
            return FLB_TAIL_MULT_MORE;
        }
    }

    /* Re-initiate buffers */
    msgpack_sbuffer_init(&file->mult_sbuf);
    msgpack_packer_init(&file->mult_pck, &file->mult_sbuf, msgpack_sbuffer_write);

    /*
     * flb_parser_do() always return a msgpack buffer, so we tweak our
     * local msgpack reference to avoid an extra allocation. The only
     * concern is that we don't know what's the real size of the memory
     * allocated, so we assume it's just 'out_size'.
     */
    file->mult_flush_timeout = now + (ctx->multiline_flush - 1);
    file->mult_sbuf.data = buf;
    file->mult_sbuf.size = size;
    file->mult_sbuf.alloc = size;

    /* Set multiline status */
    file->mult_firstline = FLB_TRUE;
    file->mult_skipping = FLB_FALSE;
    flb_time_copy(&file->mult_time, out_time);

    off = 0;
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        msgpack_sbuffer_destroy(&file->mult_sbuf);
        msgpack_unpacked_destroy(&result);
        return FLB_TAIL_MULT_NA;
    }

    map = result.data;
    file->mult_keys = map.via.map.size;
    msgpack_unpacked_destroy(&result);

    /* We expect more data */
    return FLB_TAIL_MULT_MORE;
}

/* Append a raw log entry to the last structured field in the mult buffer */
static inline void flb_tail_mult_append_raw(char *buf, int size,
                                            struct flb_tail_file *file,
                                            struct flb_tail_config *config)
{
    /* Append the raw string */
    msgpack_pack_str(&file->mult_pck, size);
    msgpack_pack_str_body(&file->mult_pck, buf, size);
}

/* Check if the last key value type of a map is string or not */
static inline int is_last_key_val_string(char *buf, size_t size)
{
    int ret = FLB_FALSE;
    size_t off;
    msgpack_unpacked result;
    msgpack_object v;
    msgpack_object root;

    off = 0;
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        return ret;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        ret = FLB_FALSE;
    }
    else {
        if (root.via.map.size == 0) {
            ret = FLB_FALSE;
        }
        else {
            v = root.via.map.ptr[root.via.map.size - 1].val;
            if (v.type == MSGPACK_OBJECT_STR) {
                ret = FLB_TRUE;
            }
        }
    }

    msgpack_unpacked_destroy(&result);
    return ret;
}

int flb_tail_mult_process_content(time_t now,
                                  char *buf, size_t len,
                                  struct flb_tail_file *file,
                                  struct flb_tail_config *ctx,
                                  size_t processed_bytes)
{
    int ret;
    size_t off;
    void *out_buf;
    size_t out_size = 0;
    struct mk_list *head;
    struct flb_tail_mult *mult_parser = NULL;
    struct flb_time out_time = {0};
    msgpack_object map;
    msgpack_unpacked result;

    /* Always check if this line is the beginning of a new multiline message */
    ret = flb_parser_do(ctx->mult_parser_firstline,
                        buf, len,
                        &out_buf, &out_size, &out_time);
    if (ret >= 0) {
        /*
         * The content is a candidate for a firstline, but we need to perform
         * the extra-mandatory check where the last key value type must be
         * a string, otherwise no string concatenation with continuation lines
         * will be possible.
         */
        ret = is_last_key_val_string(out_buf, out_size);
        if (ret == FLB_TRUE)
            file->mult_firstline_append = FLB_TRUE;
        else
            file->mult_firstline_append = FLB_FALSE;

        flb_tail_mult_process_first(now, out_buf, out_size, &out_time,
                                    file, ctx);
        return FLB_TAIL_MULT_MORE;
    }

    if (file->mult_skipping == FLB_TRUE) {
        return FLB_TAIL_MULT_MORE;
    }

    /*
     * Once here means we have some data that is a continuation, iterate
     * parsers trying to find a match
     */
    out_buf = NULL;
    mk_list_foreach(head, &ctx->mult_parsers) {
        mult_parser = mk_list_entry(head, struct flb_tail_mult, _head);

        /* Process line text with current parser */
        out_buf = NULL;
        out_size = 0;
        ret = flb_parser_do(mult_parser->parser,
                            buf, len,
                            &out_buf, &out_size, &out_time);
        if (ret < 0) {
            mult_parser = NULL;
            continue;
        }

        /* The line was processed, break the loop and buffer the data */
        break;
    }

    if (!mult_parser) {
        /*
         * If no parser was found means the string log must be appended
         * to the last structured field.
         */
        if (file->mult_firstline && file->mult_firstline_append) {
            flb_tail_mult_append_raw(buf, len, file, ctx);
        }
        else {
            flb_tail_file_pack_line(NULL, buf, len, file, processed_bytes);
        }

        return FLB_TAIL_MULT_MORE;
    }

    off = 0;
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, out_buf, out_size, &off);
    map = result.data;

    /* Append new map to our local msgpack buffer */
    file->mult_keys += map.via.map.size;
    msgpack_unpacked_destroy(&result);
    msgpack_sbuffer_write(&file->mult_sbuf, out_buf, out_size);
    flb_free(out_buf);

    return FLB_TAIL_MULT_MORE;
}

static int flb_tail_mult_pack_line_body(
    struct flb_log_event_encoder *context,
    struct flb_tail_file *file)
{
    size_t                  adjacent_object_offset;
    size_t                  continuation_length;
    msgpack_unpacked        adjacent_object;
    msgpack_unpacked        current_object;
    size_t                  entry_index;
    msgpack_object          entry_value;
    msgpack_object          entry_key;
    msgpack_object_map     *data_map;
    size_t                  offset;
    struct flb_tail_config *config;
    int                     result;

    result = FLB_EVENT_ENCODER_SUCCESS;
    config = (struct flb_tail_config *) file->config;

    if (file->config->path_key != NULL) {
        result = flb_log_event_encoder_append_body_values(
                    context,
                    FLB_LOG_EVENT_CSTRING_VALUE(config->path_key),
                    FLB_LOG_EVENT_CSTRING_VALUE(file->name));
    }


    msgpack_unpacked_init(&current_object);
    msgpack_unpacked_init(&adjacent_object);

    offset = 0;

    while (result == FLB_EVENT_ENCODER_SUCCESS &&
           msgpack_unpack_next(&current_object,
                               file->mult_sbuf.data,
                               file->mult_sbuf.size,
                               &offset) == MSGPACK_UNPACK_SUCCESS) {
        if (current_object.data.type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        data_map = &current_object.data.via.map;

        continuation_length = 0;

        for (entry_index = 0; entry_index < data_map->size; entry_index++) {
            entry_key   = data_map->ptr[entry_index].key;
            entry_value = data_map->ptr[entry_index].val;

            result = flb_log_event_encoder_append_body_msgpack_object(context,
                                                                      &entry_key);

            if (result != FLB_EVENT_ENCODER_SUCCESS) {
                break;
            }

            /* Check if this is the last entry in the map and if that is
             * the case then add the lengths of all the trailing string
             * objects after the map in order to append them to the value
             * but only if the value object is a string
             */
            if (entry_index + 1 == data_map->size &&
                entry_value.type == MSGPACK_OBJECT_STR) {
                adjacent_object_offset = offset;

                while (msgpack_unpack_next(
                        &adjacent_object,
                        file->mult_sbuf.data,
                        file->mult_sbuf.size,
                        &adjacent_object_offset) == MSGPACK_UNPACK_SUCCESS) {
                    if (adjacent_object.data.type != MSGPACK_OBJECT_STR) {
                        break;
                    }

                    /* Sum total bytes to append */
                    continuation_length += adjacent_object.data.via.str.size + 1;
                }

                result = flb_log_event_encoder_append_body_string_length(
                            context,
                            entry_value.via.str.size +
                            continuation_length);

                if (result != FLB_EVENT_ENCODER_SUCCESS) {
                    break;
                }

                result = flb_log_event_encoder_append_body_string_body(
                            context,
                            (char *) entry_value.via.str.ptr,
                            entry_value.via.str.size);

                if (result != FLB_EVENT_ENCODER_SUCCESS) {
                    break;
                }

                if (continuation_length > 0) {
                    adjacent_object_offset = offset;

                    while (msgpack_unpack_next(
                            &adjacent_object,
                            file->mult_sbuf.data,
                            file->mult_sbuf.size,
                            &adjacent_object_offset) == MSGPACK_UNPACK_SUCCESS) {
                        if (adjacent_object.data.type != MSGPACK_OBJECT_STR) {
                            break;
                        }

                        result = flb_log_event_encoder_append_body_string_body(
                                    context,
                                    "\n",
                                    1);

                        if (result != FLB_EVENT_ENCODER_SUCCESS) {
                            break;
                        }

                        result = flb_log_event_encoder_append_body_string_body(
                                    context,
                                    (char *) adjacent_object.data.via.str.ptr,
                                    adjacent_object.data.via.str.size);

                        if (result != FLB_EVENT_ENCODER_SUCCESS) {
                            break;
                        }
                    }
                }
            }
            else {
                result = flb_log_event_encoder_append_body_msgpack_object(context,
                                                                          &entry_value);
            }
        }
    }

    msgpack_unpacked_destroy(&current_object);
    msgpack_unpacked_destroy(&adjacent_object);

    /* Reset status */
    file->mult_firstline = FLB_FALSE;
    file->mult_skipping = FLB_FALSE;
    file->mult_keys = 0;
    file->mult_flush_timeout = 0;

    msgpack_sbuffer_destroy(&file->mult_sbuf);

    file->mult_sbuf.data = NULL;

    flb_time_zero(&file->mult_time);

    return result;
}

/* Flush any multiline context data into outgoing buffers */
int flb_tail_mult_flush(struct flb_tail_file *file, struct flb_tail_config *ctx)
{
    int result;

    /* nothing to flush */
    if (file->mult_firstline == FLB_FALSE) {
        return -1;
    }

    if (file->mult_keys == 0) {
        return -1;
    }

    result = flb_log_event_encoder_begin_record(file->ml_log_event_encoder);

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_set_timestamp(
                    file->ml_log_event_encoder, &file->mult_time);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_tail_mult_pack_line_body(
                    file->ml_log_event_encoder,
                    file);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        result = flb_log_event_encoder_commit_record(
                    file->ml_log_event_encoder);
    }

    if (result == FLB_EVENT_ENCODER_SUCCESS) {
        flb_input_log_append(ctx->ins,
                             file->tag_buf,
                             file->tag_len,
                             file->ml_log_event_encoder->output_buffer,
                             file->ml_log_event_encoder->output_length);
        result = 0;
    }
    else {
        flb_plg_error(file->config->ins, "error packing event : %d", result);

        result = -1;
    }

    flb_log_event_encoder_reset(file->ml_log_event_encoder);

    return result;
}

static void file_pending_flush(struct flb_tail_config *ctx,
                               struct flb_tail_file *file, time_t now)
{
    if (file->mult_flush_timeout > now) {
        return;
    }

    if (file->mult_firstline == FLB_FALSE) {
        if (file->mult_sbuf.data == NULL || file->mult_sbuf.size <= 0) {
            return;
        }
    }

    flb_tail_mult_flush(file, ctx);
}

int flb_tail_mult_pending_flush_all(struct flb_tail_config *ctx)
{
    time_t expired;
    struct mk_list *head;
    struct flb_tail_file *file;

    expired = time(NULL) + 3600;

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach(head, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        file_pending_flush(ctx, file, expired);
    }

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach(head, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        file_pending_flush(ctx, file, expired);
    }

    return 0;
}

int flb_tail_mult_pending_flush(struct flb_input_instance *ins,
                                struct flb_config *config, void *context)
{
    time_t now;
    struct mk_list *head;
    struct flb_tail_file *file;
    struct flb_tail_config *ctx = context;

    now = time(NULL);

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach(head, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);

        file_pending_flush(ctx, file, now);
    }

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach(head, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);

        file_pending_flush(ctx, file, now);
    }

    return 0;
}
