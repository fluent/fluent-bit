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
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

#include <string.h>
#include <fluent-bit.h>

#include "filter_parser.h"

static int msgpackobj2char(msgpack_object *obj,
                           const char **ret_char, int *ret_char_size)
{
    int ret = -1;

    if (obj->type == MSGPACK_OBJECT_STR) {
        *ret_char      = obj->via.str.ptr;
        *ret_char_size = obj->via.str.size;
        ret = 0;
    }
    else if (obj->type == MSGPACK_OBJECT_BIN) {
        *ret_char      = obj->via.bin.ptr;
        *ret_char_size = obj->via.bin.size;
        ret = 0;
    }

    return ret;
}

static int add_parser(const char *parser, struct filter_parser_ctx *ctx,
                       struct flb_config *config)
{
    struct flb_parser *p;
    struct filter_parser *fp;

    p = flb_parser_get(parser, config);
    if (!p) {
        return -1;
    }

    fp = flb_malloc(sizeof(struct filter_parser));
    if (!fp) {
        flb_errno();
        return -1;
    }

    fp->parser = p;
    mk_list_add(&fp->_head, &ctx->parsers);
    return 0;
}

static int delete_parsers(struct filter_parser_ctx *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct filter_parser *fp;

    mk_list_foreach_safe(head, tmp, &ctx->parsers) {
        fp = mk_list_entry(head, struct filter_parser, _head);
        mk_list_del(&fp->_head);
        flb_free(fp);
        c++;
    }

    return c;
}

static int nest_raw_map(struct filter_parser_ctx *ctx,
                        char **buf,
                        size_t *size,
                        const flb_sds_t key)
{
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    msgpack_unpacked outbuf_result;
    msgpack_object obj;
    msgpack_object_kv *kv;
    const size_t key_len = flb_sds_len(key);
    int ret = 0;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&outbuf_result);
    ret = msgpack_unpack_next(&outbuf_result, *buf, *size, NULL);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Nest: failed to unpack msgpack data with error code %d",
                      ret);
        msgpack_unpacked_destroy(&outbuf_result);
        return -1;
    }

    /* Create a new map, unpacking map `buf` under the new `key` root key */
    obj = outbuf_result.data;
    if (obj.type == MSGPACK_OBJECT_MAP) {
        msgpack_pack_map(&pk, 1);
        msgpack_pack_str(&pk, key_len);
        msgpack_pack_str_body(&pk, key, key_len);
        msgpack_pack_map(&pk, obj.via.map.size);
        for (unsigned x = 0; x < obj.via.map.size; ++x) {
            kv = &obj.via.map.ptr[x];
            msgpack_pack_object(&pk, kv->key);
            msgpack_pack_object(&pk, kv->val);
        }
        flb_free(*buf);
        *buf = sbuf.data;
        *size = sbuf.size;
    }

    msgpack_unpacked_destroy(&outbuf_result);
    return 0;
}

static int configure(struct filter_parser_ctx *ctx,
                     struct flb_filter_instance *f_ins,
                     struct flb_config *config)
{
    int ret;
    struct mk_list *head;
    struct flb_kv *kv;

    ctx->key_name = NULL;
    ctx->ra_key = NULL;
    ctx->reserve_data = FLB_FALSE;
    ctx->preserve_key = FLB_FALSE;
    mk_list_init(&ctx->parsers);

    if (flb_filter_config_map_set(f_ins, ctx) < 0) {
        flb_errno();
        flb_plg_error(f_ins, "configuration error");
        return -1;
    }

    if (ctx->key_name == NULL) {
        flb_plg_error(ctx->ins, "missing 'key_name'");
        return -1;
    }
    ctx->key_name_len = flb_sds_len(ctx->key_name);

    if (ctx->key_name && ctx->key_name[0] == '$') {
        ctx->ra_key = flb_ra_create(ctx->key_name, FLB_TRUE);
        if (!ctx->ra_key) {
            flb_plg_error(ctx->ins, "invalid record accessor pattern '%s'",
                          ctx->key_name);
            return -1;
        }
    }

    /* Read all Parsers */
    mk_list_foreach(head, &f_ins->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        if (strcasecmp("parser", kv->key) != 0) {
            continue;
        }
        ret = add_parser(kv->val, ctx, config);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "requested parser '%s' not found", kv->val);
        }
    }

    if (mk_list_size(&ctx->parsers) == 0) {
        flb_plg_error(ctx->ins, "Invalid 'parser'");
        return -1;
    }

    return 0;
}

static int cb_parser_init(struct flb_filter_instance *f_ins,
                          struct flb_config *config,
                          void *data)
{
    struct filter_parser_ctx *ctx = NULL;

    /* Create context */
    ctx = flb_malloc(sizeof(struct filter_parser_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = f_ins;

    if (configure(ctx, f_ins, config) < 0) {
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int cb_parser_filter(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            void **ret_buf, size_t *ret_bytes,
                            struct flb_filter_instance *f_ins,
                            struct flb_input_instance *i_ins,
                            void *context,
                            struct flb_config *config)
{
    struct filter_parser_ctx *ctx = context;
    struct flb_time tm;
    msgpack_object *obj;
    msgpack_object_kv *kv;
    int i;
    int ret = FLB_FILTER_NOTOUCH;
    int parse_ret = -1;
    int map_num;
    const char *key_str;
    int key_len;
    const char *val_str;
    int val_len;
    char *out_buf;
    size_t out_size;
    struct flb_time parsed_time;
    msgpack_object_kv **append_arr = NULL;
    size_t append_arr_len = 0;
    struct mk_list *head;
    struct filter_parser *fp;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int encoder_result;

    (void) f_ins;
    (void) i_ins;
    (void) config;

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event decoder initialization error : %d", ret);
        return FLB_FILTER_NOTOUCH;
    }

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
        out_buf = NULL;

        flb_time_copy(&tm, &log_event.timestamp);
        obj = log_event.body;

        if (obj->type == MSGPACK_OBJECT_MAP) {
            map_num = obj->via.map.size;
            /* Calculate initial array size based on configuration */
            append_arr_len = (ctx->reserve_data ? map_num : 0);
            if (ctx->preserve_key && !ctx->reserve_data) {
                append_arr_len = 1; /* Space for preserved key */
            }

            if (append_arr_len > 0) {
                append_arr = flb_calloc(append_arr_len, sizeof(msgpack_object_kv *));
                if (append_arr == NULL) {
                    flb_errno();
                    flb_log_event_decoder_destroy(&log_decoder);
                    flb_log_event_encoder_destroy(&log_encoder);
                    return FLB_FILTER_NOTOUCH;
                }

                /* Initialize array */
                if (ctx->reserve_data) {
                    for (i = 0; i < map_num; i++) {
                        append_arr[i] = &obj->via.map.ptr[i];
                    }
                }
            }

            if (ctx->ra_key) {
                struct flb_ra_value *rval;

                rval = flb_ra_get_value_object(ctx->ra_key, *obj);
                if (rval && msgpackobj2char(&rval->o, &val_str, &val_len) == 0) {
                    mk_list_foreach(head, &ctx->parsers) {
                        fp = mk_list_entry(head, struct filter_parser, _head);
                        flb_time_zero(&parsed_time);

                        parse_ret = flb_parser_do(fp->parser, val_str, val_len,
                                                  (void **) &out_buf, &out_size,
                                                  &parsed_time);
                        if (parse_ret >= 0) {
                            if (flb_time_to_nanosec(&parsed_time) != 0L) {
                                flb_time_copy(&tm, &parsed_time);
                            }
                            break;
                        }
                    }
                }

                if (rval) {
                    flb_ra_key_value_destroy(rval);
                }
            }
            else {
                /* Process the target key */
                for (i = 0; i < map_num; i++) {
                    kv = &obj->via.map.ptr[i];
                    if (msgpackobj2char(&kv->key, &key_str, &key_len) < 0) {
                        continue;
                    }

                    if (key_len == ctx->key_name_len &&
                        !strncmp(key_str, ctx->key_name, key_len)) {
                        if (msgpackobj2char(&kv->val, &val_str, &val_len) < 0) {
                            continue;
                        }

                        /* Lookup parser */
                        mk_list_foreach(head, &ctx->parsers) {
                            fp = mk_list_entry(head, struct filter_parser, _head);
                            flb_time_zero(&parsed_time);

                            parse_ret = flb_parser_do(fp->parser, val_str, val_len,
                                                      (void **) &out_buf, &out_size,
                                                      &parsed_time);
                            if (parse_ret >= 0) {
                                if (flb_time_to_nanosec(&parsed_time) != 0L) {
                                    flb_time_copy(&tm, &parsed_time);
                                }

                                if (append_arr != NULL) {
                                    if (!ctx->preserve_key) {
                                        append_arr[i] = NULL;
                                    }
                                    else if (!ctx->reserve_data) {
                                        /* Store only the key being preserved */
                                        append_arr[0] = kv;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }

            encoder_result = flb_log_event_encoder_begin_record(&log_encoder);

            if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
                encoder_result = flb_log_event_encoder_set_timestamp(
                                     &log_encoder, &tm);
            }

            if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
                encoder_result = \
                    flb_log_event_encoder_set_metadata_from_msgpack_object(
                        &log_encoder, log_event.metadata);
            }

            if (out_buf != NULL && parse_ret >= 0) {
                if (ctx->nest_under) {
                    nest_raw_map(ctx, &out_buf, &out_size, ctx->nest_under);
                }
                if (append_arr != NULL && append_arr_len > 0) {
                    char *new_buf = NULL;
                    int new_size;
                    size_t valid_kv_count = 0;
                    msgpack_object_kv **valid_kv = NULL;

                    /* Count valid entries */
                    for (i = 0; i < append_arr_len; i++) {
                        if (append_arr[i] != NULL) {
                            valid_kv_count++;
                        }
                    }

                    if (valid_kv_count > 0) {
                        valid_kv = flb_calloc(valid_kv_count, sizeof(msgpack_object_kv *));
                        if (!valid_kv) {
                            flb_errno();
                            flb_log_event_decoder_destroy(&log_decoder);
                            flb_log_event_encoder_destroy(&log_encoder);
                            flb_free(append_arr);
                            flb_free(out_buf);
                            return FLB_FILTER_NOTOUCH;
                        }

                        /* Fill valid entries */
                        valid_kv_count = 0;
                        for (i = 0; i < append_arr_len; i++) {
                            if (append_arr[i] != NULL) {
                                valid_kv[valid_kv_count++] = append_arr[i];
                            }
                        }

                        ret = flb_msgpack_expand_map(out_buf, out_size,
                                                   valid_kv, valid_kv_count,
                                                   &new_buf, &new_size);

                        flb_free(valid_kv);

                        if (ret == -1) {
                            flb_plg_error(ctx->ins, "cannot expand map");
                            flb_log_event_decoder_destroy(&log_decoder);
                            flb_log_event_encoder_destroy(&log_encoder);
                            flb_free(append_arr);
                            flb_free(out_buf);
                            return FLB_FILTER_NOTOUCH;
                        }

                        flb_free(out_buf);
                        out_buf = new_buf;
                        out_size = new_size;
                    }
                }

                if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
                    encoder_result = \
                        flb_log_event_encoder_set_body_from_raw_msgpack(
                            &log_encoder, out_buf, out_size);
                }

                flb_free(out_buf);
                ret = FLB_FILTER_MODIFIED;
            }
            else {
                if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
                    encoder_result = \
                        flb_log_event_encoder_set_body_from_msgpack_object(
                            &log_encoder, log_event.body);
                }
            }

            if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
                encoder_result = flb_log_event_encoder_commit_record(&log_encoder);
            }

            if (encoder_result != FLB_EVENT_ENCODER_SUCCESS) {
                flb_plg_error(ctx->ins, "log event encoder error : %d", encoder_result);
            }

            if (append_arr != NULL) {
                flb_free(append_arr);
                append_arr = NULL;
            }
        }
    }

    if (log_encoder.output_length > 0) {
        *ret_buf = log_encoder.output_buffer;
        *ret_bytes = log_encoder.output_length;

        ret = FLB_FILTER_MODIFIED;
        flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
    }
    else {
        flb_plg_error(ctx->ins, "Log event encoder error : %d", ret);
        ret = FLB_FILTER_NOTOUCH;
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return ret;
}

static int cb_parser_exit(void *data, struct flb_config *config)
{
    struct filter_parser_ctx *ctx = data;

    if (!ctx) {
        return 0;
    }

    delete_parsers(ctx);
    if (ctx->ra_key) {
        flb_ra_destroy(ctx->ra_key);
    }
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "Key_Name", NULL,
     0, FLB_TRUE, offsetof(struct filter_parser_ctx, key_name),
     "Specify field name in record to parse."
    },
    {
     FLB_CONFIG_MAP_STR, "Parser", NULL,
     FLB_CONFIG_MAP_MULT, FLB_FALSE, 0,
     "Specify the parser name to interpret the field. "
     "Multiple Parser entries are allowed (one per line)."
    },
    {
     FLB_CONFIG_MAP_BOOL, "Preserve_Key", "false",
     0, FLB_TRUE, offsetof(struct filter_parser_ctx, preserve_key),
     "Keep original Key_Name field in the parsed result. If false, the field will be removed."
    },
    {
     FLB_CONFIG_MAP_BOOL, "Reserve_Data", "false",
     0, FLB_TRUE, offsetof(struct filter_parser_ctx, reserve_data),
     "Keep all other original fields in the parsed result. "
     "If false, all other original fields will be removed."
    },
    {
     FLB_CONFIG_MAP_STR, "Nest_Under", NULL,
     0, FLB_TRUE, offsetof(struct filter_parser_ctx, nest_under),
     "Specify field name to nest parsed records under."
    },
    {
     FLB_CONFIG_MAP_DEPRECATED, "Unescape_key", NULL,
     0, FLB_FALSE, 0,
     "(deprecated)"
    },
    {0}
};

struct flb_filter_plugin filter_parser_plugin = {
    .name         = "parser",
    .description  = "Parse events",
    .cb_init      = cb_parser_init,
    .cb_filter    = cb_parser_filter,
    .cb_exit      = cb_parser_exit,
    .config_map   = config_map,
    .flags        = 0
};
