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

static int configure(struct filter_parser_ctx *ctx,
                     struct flb_filter_instance *f_ins,
                     struct flb_config *config)
{
    int ret;
    struct mk_list *head;
    struct flb_kv *kv;

    ctx->key_name = NULL;
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
    (void) f_ins;
    (void) config;
    (void) data;

    struct filter_parser_ctx *ctx = NULL;

    /* Create context */
    ctx = flb_malloc(sizeof(struct filter_parser_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = f_ins;

    if ( configure(ctx, f_ins, config) < 0 ){
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
    int continue_parsing;
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
    int append_arr_i;
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
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);

        return FLB_FILTER_NOTOUCH;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        out_buf = NULL;
        append_arr_i = 0;

        flb_time_copy(&tm, &log_event.timestamp);
        obj = log_event.body;

        if (obj->type == MSGPACK_OBJECT_MAP) {
            map_num = obj->via.map.size;
            if (ctx->reserve_data) {
                append_arr_len = obj->via.map.size;
                append_arr = flb_calloc(append_arr_len, sizeof(msgpack_object_kv *));

                if (append_arr == NULL) {
                    flb_errno();

                    flb_log_event_decoder_destroy(&log_decoder);
                    flb_log_event_encoder_destroy(&log_encoder);

                    return FLB_FILTER_NOTOUCH;
                }
            }

            continue_parsing = FLB_TRUE;
            for (i = 0; i < map_num && continue_parsing; i++) {
                kv = &obj->via.map.ptr[i];
                if (ctx->reserve_data) {
                    append_arr[append_arr_i] = kv;
                    append_arr_i++;
                }
                if ( msgpackobj2char(&kv->key, &key_str, &key_len) < 0 ) {
                    /* key is not string */
                    continue;
                }
                if (key_len == ctx->key_name_len &&
                    !strncmp(key_str, ctx->key_name, key_len)) {
                    if ( msgpackobj2char(&kv->val, &val_str, &val_len) < 0 ) {
                        /* val is not string */
                        continue;
                    }

                    /* Lookup parser */
                    mk_list_foreach(head, &ctx->parsers) {
                        fp = mk_list_entry(head, struct filter_parser, _head);

                        /* Reset time */
                        flb_time_zero(&parsed_time);

                        parse_ret = flb_parser_do(fp->parser, val_str, val_len,
                                                  (void **) &out_buf, &out_size,
                                                  &parsed_time);
                        if (parse_ret >= 0) {
                            /*
                             * If the parser succeeded we need to check the
                             * status of the parsed time. If the time was
                             * parsed successfully 'parsed_time' will be
                             * different than zero, if so, override the time
                             * holder with the new value, otherwise keep the
                             * original.
                             */
                            if (flb_time_to_nanosec(&parsed_time) != 0L) {
                                flb_time_copy(&tm, &parsed_time);
                            }

                            if (ctx->reserve_data) {
                                if (!ctx->preserve_key) {
                                    append_arr_i--;
                                    append_arr_len--;
                                    append_arr[append_arr_i] = NULL;
                                }
                            }
                            else {
                                continue_parsing = FLB_FALSE;
                            }
                            break;
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

            if (out_buf != NULL) {
                if (ctx->reserve_data) {
                    char *new_buf = NULL;
                    int  new_size;
                    int ret;
                    ret = flb_msgpack_expand_map(out_buf, out_size,
                                                 append_arr, append_arr_len,
                                                 &new_buf, &new_size);
                    if (ret == -1) {
                        flb_plg_error(ctx->ins, "cannot expand map");

                        flb_log_event_decoder_destroy(&log_decoder);
                        flb_log_event_encoder_destroy(&log_encoder);
                        flb_free(append_arr);

                        return FLB_FILTER_NOTOUCH;
                    }

                    flb_free(out_buf);
                    out_buf = new_buf;
                    out_size = new_size;
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
                /* re-use original data*/
                if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
                    encoder_result = \
                        flb_log_event_encoder_set_body_from_msgpack_object(
                            &log_encoder, log_event.body);
                }
            }

            if (encoder_result == FLB_EVENT_ENCODER_SUCCESS) {
                encoder_result = flb_log_event_encoder_commit_record(&log_encoder);
            }

            flb_free(append_arr);
            append_arr = NULL;
        }
        else {
            continue;
        }
    }

    if (log_encoder.output_length > 0) {
        *ret_buf   = log_encoder.output_buffer;
        *ret_bytes = log_encoder.output_length;

        ret = FLB_FILTER_MODIFIED;

        flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);
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


static int cb_parser_exit(void *data, struct flb_config *config)
{
    struct filter_parser_ctx *ctx = data;

    if (!ctx) {
        return 0;
    }

    delete_parsers(ctx);
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
