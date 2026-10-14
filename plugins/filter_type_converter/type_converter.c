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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <msgpack.h>

#include "type_converter.h"

static int delete_conv_entry(struct conv_entry *conv)
{
    if (conv == NULL) {
        return 0;
    }

    if (conv->from_key != NULL) {
        flb_sds_destroy(conv->from_key);
        conv->from_key = NULL;
    }
    if (conv->to_key != NULL) {
        flb_sds_destroy(conv->to_key);
        conv->to_key = NULL;
    }
    if (conv->rule != NULL) {
        flb_typecast_rule_destroy(conv->rule);
    }
    if (conv->from_ra != NULL) {
        flb_ra_destroy(conv->from_ra);
    }
    mk_list_del(&conv->_head);
    flb_free(conv);
    return 0;
}

static int config_rule(struct type_converter_ctx *ctx, char* type_name,
                       struct flb_config_map_val *mv)
{
    struct conv_entry      *entry = NULL;
    struct flb_slist_entry *sentry = NULL;

    if (ctx == NULL || mv == NULL) {
        return -1;
    }

    entry = flb_calloc(1, sizeof(struct conv_entry));
    if (entry == NULL) {
        flb_errno();
        return -1;
    }

    entry->rule = NULL;
    if (mk_list_size(mv->val.list) != 3) {
        flb_plg_error(ctx->ins, "invalid record parameters, "
                      "expects 'from_key to_key type' %d", mk_list_size(mv->val.list));
        flb_free(entry);
        return -1;
    }

    /* from_key name */
    sentry          = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
    entry->from_key = flb_sds_create_len(sentry->str, flb_sds_len(sentry->str));

    /* to_key name */
    sentry = mk_list_entry_next(&sentry->_head, struct flb_slist_entry,
                                _head, mv->val.list);
    entry->to_key   = flb_sds_create_len(sentry->str, flb_sds_len(sentry->str));

    sentry = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);
    entry->rule = flb_typecast_rule_create(type_name, strlen(type_name),
                                           sentry->str,
                                           flb_sds_len(sentry->str));
    entry->from_ra = flb_ra_create(entry->from_key, FLB_FALSE);
    if (entry->rule == NULL || entry->from_ra == NULL) {
        flb_plg_error(ctx->ins,
                      "configuration error. ignore the key=%s",
                      entry->from_key);
        delete_conv_entry(entry);
        return -1;
    }

    mk_list_add(&entry->_head, &ctx->conv_entries);

    return 0;
}

static int configure(struct type_converter_ctx *ctx,
                     struct flb_filter_instance *f_ins)
{
    struct mk_list         *head = NULL;
    struct flb_config_map_val *mv = NULL;

    if (flb_filter_config_map_set(f_ins, ctx) < 0) {
        flb_errno();
        flb_plg_error(f_ins, "configuration error");
        return -1;
    }

    /* Create rules for each type */
    flb_config_map_foreach(head, mv, ctx->str_keys) {
        config_rule(ctx, "string", mv);
    }
    flb_config_map_foreach(head, mv, ctx->int_keys) {
        config_rule(ctx, "int", mv);
    }
    flb_config_map_foreach(head, mv, ctx->uint_keys) {
        config_rule(ctx, "uint", mv);
    }
    flb_config_map_foreach(head, mv, ctx->float_keys) {
        config_rule(ctx, "float", mv);
    }

    if (mk_list_size(&ctx->conv_entries) == 0) {
        flb_plg_error(ctx->ins, "no rules");
        return -1;
    }

    return 0;
}

static int delete_list(struct type_converter_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct conv_entry *conv;

    mk_list_foreach_safe(head, tmp, &ctx->conv_entries) {
        conv = mk_list_entry(head, struct conv_entry,  _head);
        delete_conv_entry(conv);
    }
    return 0;
}

static int cb_type_converter_init(struct flb_filter_instance *ins,
                                  struct flb_config *config,
                                  void *data)
{
    struct type_converter_ctx *ctx = NULL;
    int ret = 0;

    ctx = flb_calloc(1, sizeof(struct type_converter_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->conv_entries);

    ret = configure(ctx, ins);
    if (ret < 0) {
        flb_plg_error(ins, "configuration error");
        flb_free(ctx);
        return -1;
    }
    /* set context */
    flb_filter_set_context(ins, ctx);

    return 0;
}

static int cb_type_converter_filter(const void *data, size_t bytes,
                                    const char *tag, int tag_len,
                                    void **out_buf, size_t *out_bytes,
                                    struct flb_filter_instance *f_ins,
                                    struct flb_input_instance *i_ins,
                                    void *filter_context,
                                    struct flb_config *config)
{
    struct type_converter_ctx *ctx = filter_context;
    struct flb_time tm;
    int i;
    int map_num;
    int is_record_modified = FLB_FALSE;
    int ret;
    int dec_ret;
    int enc_ret;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer  tmp_pck;
    msgpack_object  *obj;
    struct conv_entry *entry;
    struct mk_list *tmp;
    struct mk_list *head;

    msgpack_object *start_key;
    msgpack_object *out_key;
    msgpack_object *out_val;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    (void) f_ins;
    (void) i_ins;
    (void) config;

    dec_ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (dec_ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(f_ins,
                      "Log event decoder initialization error : %s",
                      flb_log_event_decoder_get_error_description(dec_ret));

        return FLB_FILTER_NOTOUCH;
    }

    enc_ret = flb_log_event_encoder_init(&log_encoder,
                                         FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(f_ins,
                      "Log event encoder initialization error : %s",
                      flb_log_event_encoder_get_error_description(enc_ret));

        flb_log_event_decoder_destroy(&log_decoder);

        return FLB_FILTER_NOTOUCH;
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    /* Iterate each item to know map number */
    while ((dec_ret = flb_log_event_decoder_next(
                      &log_decoder,
                      &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        flb_time_copy(&tm, &log_event.timestamp);
        obj = log_event.body;

        map_num = obj->via.map.size;

        enc_ret = flb_log_event_encoder_begin_record(&log_encoder);

        if (enc_ret == FLB_EVENT_ENCODER_SUCCESS) {
            enc_ret = flb_log_event_encoder_set_timestamp(&log_encoder, &tm);
        }

        enc_ret = flb_log_event_encoder_set_metadata_from_msgpack_object(
                  &log_encoder,
                  log_event.metadata);
        if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(f_ins,
                          "flb_log_event_encoder_set_metadata_from_msgpack_object error: %s",
                          flb_log_event_encoder_get_error_description(enc_ret));
        }

        /* write original k/v */
        for (i = 0;
             i < map_num &&
             enc_ret == FLB_EVENT_ENCODER_SUCCESS;
             i++) {
            enc_ret = flb_log_event_encoder_append_body_values(
                      &log_encoder,
                      FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&obj->via.map.ptr[i].key),
                      FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&obj->via.map.ptr[i].val));
            if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_plg_error(f_ins,
                             "flb_log_event_encoder_append_body_values error: %s",
                              flb_log_event_encoder_get_error_description(enc_ret));
                break;
            }
        }

        if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_rollback_record(&log_encoder);

            /* To decode next record */
            enc_ret = FLB_EVENT_ENCODER_SUCCESS;
            continue;
        }

        mk_list_foreach_safe(head, tmp, &ctx->conv_entries) {
            start_key = NULL;
            out_key   = NULL;
            out_val   = NULL;

            entry = mk_list_entry(head, struct conv_entry, _head);
            ret = flb_ra_get_kv_pair(entry->from_ra, *obj, &start_key, &out_key, &out_val);
            if (start_key == NULL || out_key == NULL || out_val == NULL) {
                continue;
            }

            /* key is found. try to convert. */
            enc_ret = flb_log_event_encoder_append_body_string(
                      &log_encoder,
                      entry->to_key,
                      flb_sds_len(entry->to_key));
            if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_plg_error(f_ins,
                             "flb_log_event_encoder_append_body_string error : %s",
                              flb_log_event_encoder_get_error_description(enc_ret));
                continue;
            }

            ret = flb_typecast_pack(*out_val, entry->rule, &tmp_pck);
            if (ret < 0) {
                /* failed. try to write original val... */
                flb_plg_error(ctx->ins, "failed to convert. key=%s", entry->from_key);

                enc_ret = flb_log_event_encoder_append_body_msgpack_object(
                          &log_encoder,
                          out_val);
                if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
                    flb_plg_error(f_ins,
                                 "flb_log_event_encoder_append_body_msgpack_object error : %s",
                                  flb_log_event_encoder_get_error_description(enc_ret));

                    /* Break to rollback */
                    break;
                }

                continue;
            }
            else {
                enc_ret = flb_log_event_encoder_append_body_raw_msgpack(
                          &log_encoder,
                          tmp_sbuf.data, tmp_sbuf.size);
                if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
                    flb_plg_error(f_ins,
                                 "flb_log_event_encoder_append_body_raw_msgpack error : %s",
                                  flb_log_event_encoder_get_error_description(enc_ret));
                    /* Break to rollback */
                    break;
                }

                msgpack_sbuffer_clear(&tmp_sbuf);
            }

            is_record_modified = FLB_TRUE;
        }

        if (enc_ret == FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_commit_record(&log_encoder);
        }
        else {
            flb_log_event_encoder_rollback_record(&log_encoder);
        }

    }
    msgpack_sbuffer_destroy(&tmp_sbuf);

    if (is_record_modified != FLB_TRUE) {
        /* Destroy the buffer to avoid more overhead */
        flb_plg_trace(ctx->ins, "no touch");

        ret = FLB_FILTER_NOTOUCH;
        goto cb_type_converter_filter_end;
    }

    dec_ret = flb_log_event_decoder_get_last_result(&log_decoder);
    if (dec_ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "flb_log_event_decoder_get_last_result error : %s",
                      flb_log_event_decoder_get_error_description(dec_ret));
        ret = FLB_FILTER_NOTOUCH;
        goto cb_type_converter_filter_end;
    }

    if (enc_ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder error : %s",
                      flb_log_event_encoder_get_error_description(enc_ret));

        ret = FLB_FILTER_NOTOUCH;
        goto cb_type_converter_filter_end;
    }

    *out_buf   = log_encoder.output_buffer;
    *out_bytes = log_encoder.output_length;

    ret = FLB_FILTER_MODIFIED;

    flb_log_event_encoder_claim_internal_buffer_ownership(&log_encoder);

 cb_type_converter_filter_end:
    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return ret;
}

static int cb_type_converter_exit(void *data, struct flb_config *config) {
    struct type_converter_ctx *ctx = data;

    if (ctx == NULL) {
        return 0;
    }
    delete_list(ctx);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_SLIST_3, "int_key", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct type_converter_ctx, int_keys),
     "Convert integer to other type. e.g. int_key id id_str string"
    },
    {
     FLB_CONFIG_MAP_SLIST_3, "uint_key", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct type_converter_ctx, uint_keys),
     "Convert unsinged integer to other type. e.g. uint_key id id_str string"
    },
    {
     FLB_CONFIG_MAP_SLIST_3, "float_key", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct type_converter_ctx, float_keys),
     "Convert float to other type. e.g. float_key ratio id_str string"
    },
    {
     FLB_CONFIG_MAP_SLIST_3, "str_key", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct type_converter_ctx, str_keys),
     "Convert string to other type. e.g. str_key id id_val integer"
    },
    {0}
};
  

struct flb_filter_plugin filter_type_converter_plugin = {
    .name        = "type_converter",
    .description = "Data type converter",
    .cb_init     = cb_type_converter_init,
    .cb_filter   = cb_type_converter_filter,
    .cb_exit     = cb_type_converter_exit,
    .config_map  = config_map,
    .flags       = 0,
};
