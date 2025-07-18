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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/tls/flb_tls.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include "nightfall.h"
#include "nightfall_api.h"

static int redact_array_fields(msgpack_packer *new_rec_pk, int *to_redact_index,
                               msgpack_object_array *to_redact, struct nested_obj *cur,
                               struct mk_list *stack, char *should_pop);
static int redact_map_fields(msgpack_packer *new_rec_pk, int *to_redact_index,
                             msgpack_object_array *to_redact, struct nested_obj *cur,
                             struct mk_list *stack, char *should_pop);
static void maybe_redact_field(msgpack_packer *new_rec_pk, msgpack_object *field, 
                               msgpack_object_array *to_redact, int *to_redact_i,
                               int byte_offset);

static int cb_nightfall_init(struct flb_filter_instance *f_ins,
                             struct flb_config *config,
                             void *data)
{
    struct flb_filter_nightfall *ctx = NULL;
    int ret;

    /* Create context */
    ctx = flb_calloc(1, sizeof(struct flb_filter_nightfall));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->ins = f_ins;

    /* Populate context with config map defaults and incoming properties */
    ret = flb_filter_config_map_set(f_ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(f_ins, "configuration error");
        flb_free(ctx);
        return -1;
    }

    if (ctx->sampling_rate <= 0 || ctx->sampling_rate > 1) {
        flb_plg_error(f_ins, "invalid sampling rate, must be (0,1]");
        flb_free(ctx);
        return -1;
    }

    if (ctx->nightfall_api_key == NULL) {
        flb_plg_error(f_ins, "invalid Nightfall API key");
        flb_free(ctx);
        return -1;
    }

    if (ctx->policy_id == NULL) {
        flb_plg_error(f_ins, "invalid Nightfall policy ID");
        flb_free(ctx);
        return -1;
    }

    ctx->auth_header = flb_sds_create_size(42);
    flb_sds_printf(&ctx->auth_header, 
                   "Bearer %s",
                   ctx->nightfall_api_key);

    ctx->tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                              ctx->tls_verify,
                              ctx->tls_debug,
                              ctx->tls_vhost,
                              ctx->tls_ca_path,
                              NULL,
                              NULL, NULL, NULL, NULL);
    if (!ctx->tls) {
        flb_plg_error(f_ins, "tls initialization error");
        flb_free(ctx);
        return -1;
    }

    ctx->upstream = flb_upstream_create_url(config,
                                            FLB_FILTER_NIGHTFALL_API_URL,
                                            FLB_IO_TLS,
                                            ctx->tls);
    if (!ctx->upstream) {
        flb_plg_error(ctx->ins, "connection initialization error");
        flb_free(ctx);
        return -1;
    }

    flb_stream_disable_async_mode(&ctx->upstream->base);

    flb_filter_set_context(f_ins, ctx);

    srand((unsigned int)time(NULL));
    return 0;
}

static int redact_record(msgpack_object *data, char **to_redact_data, size_t *to_redact_size, 
                         struct flb_time t, msgpack_sbuffer *new_rec) 
{
    int ret;
    struct mk_list stack;
    struct nested_obj *cur;
    struct nested_obj *new_obj;
    struct mk_list *head;
    struct mk_list *tmp;

    msgpack_sbuffer new_rec_sbuf;
    msgpack_packer new_rec_pk;

    char should_pop = FLB_TRUE;

    int to_redact_index = 0;
    msgpack_unpacked finding_list_unpacked;
    size_t finding_list_off = 0;
    msgpack_object_array to_redact;

    /* Convert to_redact_data to a msgpack_object_array */
    msgpack_unpacked_init(&finding_list_unpacked);
    ret = msgpack_unpack_next(&finding_list_unpacked, *to_redact_data, *to_redact_size, 
                              &finding_list_off);
    if (ret == MSGPACK_UNPACK_SUCCESS) {
        to_redact = finding_list_unpacked.data.via.array;
    }

    mk_list_init(&stack);

    msgpack_sbuffer_init(&new_rec_sbuf);
    msgpack_packer_init(&new_rec_pk, &new_rec_sbuf, msgpack_sbuffer_write);

    new_obj = flb_calloc(1, sizeof(struct nested_obj));
    new_obj->obj = data;
    new_obj->cur_index = 0;
    new_obj->start_at_val = FLB_FALSE;
    mk_list_add(&new_obj->_head, &stack);
    
    if (data->type == MSGPACK_OBJECT_ARRAY) {
        msgpack_pack_array(&new_rec_pk, data->via.array.size);
    }
    else if (data->type == MSGPACK_OBJECT_MAP) {
        msgpack_pack_map(&new_rec_pk, data->via.map.size);
    }

    /* 
     * Since logs can contain many levels of nested objects, use stack-based DFS here
     * to build back and redact log.
     */
    while (mk_list_is_empty(&stack) == -1) {
        cur = mk_list_entry_last(&stack, struct nested_obj, _head);
        should_pop = FLB_TRUE;

        switch(cur->obj->type) {
            case MSGPACK_OBJECT_ARRAY:
                ret = redact_array_fields(&new_rec_pk, &to_redact_index, &to_redact, cur,
                                          &stack, &should_pop);
                if (ret != 0) {
                    msgpack_unpacked_destroy(&finding_list_unpacked);
                    mk_list_foreach_safe(head, tmp, &stack) {
                        cur = mk_list_entry(head, struct nested_obj, _head);
                        mk_list_del(&cur->_head);
                        flb_free(cur);
                    }
                    return -1;
                }
                break;
            case MSGPACK_OBJECT_MAP:
                ret = redact_map_fields(&new_rec_pk, &to_redact_index, &to_redact, cur,
                                          &stack, &should_pop);
                if (ret != 0) {
                    msgpack_unpacked_destroy(&finding_list_unpacked);
                    mk_list_foreach_safe(head, tmp, &stack) {
                        cur = mk_list_entry(head, struct nested_obj, _head);
                        mk_list_del(&cur->_head);
                        flb_free(cur);
                    }
                    return -1;
                }
                break;
            case MSGPACK_OBJECT_STR:
                maybe_redact_field(&new_rec_pk, cur->obj, &to_redact, &to_redact_index, 0);
                break;
            case MSGPACK_OBJECT_POSITIVE_INTEGER:
                maybe_redact_field(&new_rec_pk, cur->obj, &to_redact, &to_redact_index, 0);
                break;
            case MSGPACK_OBJECT_NEGATIVE_INTEGER:
                maybe_redact_field(&new_rec_pk, cur->obj, &to_redact, &to_redact_index, 0);
                break;
            default:
                msgpack_pack_object(&new_rec_pk, *cur->obj);
        }

        if (should_pop) {
            mk_list_del(&cur->_head);
            flb_free(cur);
        }
    }
    msgpack_unpacked_destroy(&finding_list_unpacked);

    *new_rec = new_rec_sbuf;
    return 0;
}

static int redact_array_fields(msgpack_packer *new_rec_pk, int *to_redact_index,
                               msgpack_object_array *to_redact, struct nested_obj *cur,
                               struct mk_list *stack, char *should_pop)
{
    msgpack_object *item;
    struct nested_obj *new_obj;
    int i;

    for (i = cur->cur_index; i < cur->obj->via.array.size; i++) {
        item = &cur->obj->via.array.ptr[i];
        if (item->type == MSGPACK_OBJECT_MAP || item->type == MSGPACK_OBJECT_ARRAY) {
            /* A nested object, so add to stack and return to DFS to process immediately */
            new_obj = flb_malloc(sizeof(struct nested_obj));
            if (!new_obj) {
                flb_errno();
                return -1;
            }
            new_obj->obj = item;
            new_obj->cur_index = 0;
            new_obj->start_at_val = FLB_FALSE;
            mk_list_add(&new_obj->_head, stack);

            if (item->type == MSGPACK_OBJECT_ARRAY) {
                msgpack_pack_array(new_rec_pk, item->via.array.size);
            }
            else {
                msgpack_pack_map(new_rec_pk, item->via.map.size);
            }

            /* 
             * Since we are not done yet with the current array, increment the index that 
             * keeps track of progress and don't pop the current array so we can come
             * back later.
             */
            cur->cur_index = i + 1;
            *should_pop = FLB_FALSE;
            break;
        }
        else if (item->type == MSGPACK_OBJECT_STR || 
                 item->type == MSGPACK_OBJECT_POSITIVE_INTEGER || 
                 item->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            /* 
             * A field that could potentially contain sensitive content, so we check
             * if there were any findings associated with it
             */
            maybe_redact_field(new_rec_pk, item, to_redact, to_redact_index, 0);
        }
        else {
            /* Non scannable type, so just append as is. */
            msgpack_pack_object(new_rec_pk, *item);
        }
    }

    return 0;
}

static int redact_map_fields(msgpack_packer *new_rec_pk, int *to_redact_index,
                             msgpack_object_array *to_redact, struct nested_obj *cur,
                             struct mk_list *stack, char *should_pop)
{
    msgpack_object *k;
    msgpack_object *v;
    struct nested_obj *new_obj;
    int i;

    for (i = cur->cur_index; i < cur->obj->via.map.size; i++) {
        k = &cur->obj->via.map.ptr[i].key;
        if (!cur->start_at_val) {
            /* Handle the key of this kv pair */
            if (k->type == MSGPACK_OBJECT_MAP || k->type == MSGPACK_OBJECT_ARRAY) {
                /* A nested object, so add to stack and return to DFS to process immediately */
                new_obj = flb_malloc(sizeof(struct nested_obj));
                if (!new_obj) {
                    flb_errno();
                    return -1;
                }
                new_obj->obj = k;
                new_obj->cur_index = 0;
                new_obj->start_at_val = FLB_FALSE;
                mk_list_add(&new_obj->_head, stack);

                if (k->type == MSGPACK_OBJECT_ARRAY) {
                    msgpack_pack_array(new_rec_pk, k->via.array.size);
                }
                else {
                    msgpack_pack_map(new_rec_pk, k->via.map.size);
                }

                /* 
                 * Since we are not done yet with the current kv pair, don't increment 
                 * the progress index and set flag so we know to start at the value later
                 */
                cur->cur_index = i;
                cur->start_at_val = FLB_TRUE;
                /* Set should_pop to false because we are not done with the current map */
                *should_pop = FLB_FALSE;
                break;
            }
            else if (k->type == MSGPACK_OBJECT_STR || 
                     k->type == MSGPACK_OBJECT_POSITIVE_INTEGER || 
                     k->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                /* 
                 * A field that could potentially contain sensitive content, so we check
                 * if there were any findings associated with it
                 */
                maybe_redact_field(new_rec_pk, k, to_redact, to_redact_index, 0);
            }
            else {
                /* Non scannable type, so just append as is. */
                msgpack_pack_object(new_rec_pk, *k);
            }
        }
        
        /* Handle the value of this kv pair */
        v = &cur->obj->via.map.ptr[i].val;
        if (v->type == MSGPACK_OBJECT_MAP || v->type == MSGPACK_OBJECT_ARRAY) {
            /* A nested object, so add to stack and return to DFS to process immediately */
            new_obj = flb_malloc(sizeof(struct nested_obj));
            if (!new_obj) {
                flb_errno();
                return -1;
            }
            new_obj->obj = v;
            new_obj->cur_index = 0;
            new_obj->start_at_val = FLB_FALSE;
            mk_list_add(&new_obj->_head, stack);

            if (v->type == MSGPACK_OBJECT_ARRAY) {
                msgpack_pack_array(new_rec_pk, v->via.array.size);
            }
            else {
                msgpack_pack_map(new_rec_pk, v->via.map.size);
            }

            /* Increment here because we are done with this kv pair */
            cur->cur_index = i + 1;
            cur->start_at_val = FLB_FALSE;
            /* Set should_pop to false because we are not done with the current map */
            *should_pop = FLB_FALSE;
            break;
        }
        else if (v->type == MSGPACK_OBJECT_STR || 
                 v->type == MSGPACK_OBJECT_POSITIVE_INTEGER || 
                 v->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            if (k->type == MSGPACK_OBJECT_STR) {
                /* 
                 * When building the request to scan the log, keys that are strings are
                 * appended to the beginning of the value to provide more context when 
                 * scanning in the format of "<key> <val>", which is why we need to 
                 * offset the length of the key plus a space when we do redaction on the
                 * value on its own.
                 */
                maybe_redact_field(new_rec_pk, v, to_redact, to_redact_index, 
                                   k->via.str.size + 1);
            }
            else {
                maybe_redact_field(new_rec_pk, v, to_redact, to_redact_index, 0);
            }
        }
        else {
            msgpack_pack_object(new_rec_pk, *v);
        }
    }

    return 0;
}

static void maybe_redact_field(msgpack_packer *new_rec_pk, msgpack_object *field, 
                               msgpack_object_array *to_redact, int *to_redact_i,
                               int byte_offset)
{
    flb_sds_t cur_str;
    msgpack_object_array content_range;
    int64_t content_start;
    int64_t content_end;
    int i;
    int64_t replace_i;

    /* 
     * Should not happen under normal circumstances as len of to_redact should be the
     * same as the number of scannable fields (positive/negative ints, strings) in the
     * event, but if that is the case just append the rest of the fields.
     */
    if (*to_redact_i >= to_redact->size) {
        msgpack_pack_object(new_rec_pk, *field);
        return;
    }

    /* 
     * Check if there was anything sensitive found for this field, if there wasn't we 
     * can leave it as is
     */
    if (to_redact->ptr[*to_redact_i].via.array.size == 0) {
        msgpack_pack_object(new_rec_pk, *field);
        *to_redact_i = *to_redact_i + 1;
        return;
    }

    /* If field is an integer redact entire field */
    if (field->type == MSGPACK_OBJECT_POSITIVE_INTEGER || 
        field->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        msgpack_pack_str_with_body(new_rec_pk, "******", 7);
        *to_redact_i = *to_redact_i + 1;
        return;
    }

    /* If field is a string redact only the sensitive parts */
    cur_str = flb_sds_create_len(field->via.str.ptr, field->via.str.size);
    for (i = 0; i < to_redact->ptr[*to_redact_i].via.array.size; i++) {
        content_range = to_redact->ptr[*to_redact_i].via.array.ptr[i].via.array;
        content_start = content_range.ptr[0].via.i64 - byte_offset;
        if (content_start < 0) {
            content_start = 0;
        }
        content_end = content_range.ptr[1].via.i64 - byte_offset;
        for (replace_i = content_start; replace_i < content_end &&
             replace_i < flb_sds_len(cur_str); replace_i++) {
            cur_str[replace_i] = '*';
        }
    }
    msgpack_pack_str_with_body(new_rec_pk, cur_str, flb_sds_len(cur_str));
    *to_redact_i = *to_redact_i + 1;

    flb_sds_destroy(cur_str);
}

static int cb_nightfall_filter(const void *data, size_t bytes,
                               const char *tag, int tag_len,
                               void **out_buf, size_t *out_size,
                               struct flb_filter_instance *f_ins,
                               struct flb_input_instance *i_ins,
                               void *context,
                               struct flb_config *config)
{
    struct flb_filter_nightfall *ctx = context;
    int ret;
    char is_modified = FLB_FALSE;

    struct flb_time tmp = {0};

    char *to_redact;
    size_t to_redact_size;
    char is_sensitive = FLB_FALSE;

    msgpack_sbuffer new_rec_sbuf;
    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    (void) f_ins;
    (void) i_ins;
    (void) config;

    /* 
     * Generate a random double between 0 and 1, if it is over the sampling rate 
     * configured don't scan this log.
     */
    if ((double)rand()/(double)RAND_MAX > ctx->sampling_rate) {
        return FLB_FILTER_NOTOUCH;
    }

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
        ret = scan_log(ctx, log_event.body, &to_redact, &to_redact_size, &is_sensitive);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "scanning error");

            flb_log_event_decoder_destroy(&log_decoder);
            flb_log_event_encoder_destroy(&log_encoder);

            return FLB_FILTER_NOTOUCH;
        }

        if (is_sensitive == FLB_TRUE) {
            ret = redact_record(log_event.body, &to_redact, &to_redact_size, tmp, &new_rec_sbuf);
            if (ret != 0) {
                flb_plg_error(ctx->ins, "redaction error");
                flb_free(to_redact);
                msgpack_sbuffer_destroy(&new_rec_sbuf);
                flb_log_event_decoder_destroy(&log_decoder);
                flb_log_event_encoder_destroy(&log_encoder);
                return FLB_FILTER_NOTOUCH;
            }
            is_modified = FLB_TRUE;
        }

        if (is_modified) {
            ret = flb_log_event_encoder_begin_record(&log_encoder);

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_set_timestamp(
                        &log_encoder, &log_event.timestamp);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_set_metadata_from_msgpack_object(
                        &log_encoder, log_event.metadata);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                        &log_encoder, new_rec_sbuf.data, new_rec_sbuf.size);
            }

            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_commit_record(
                        &log_encoder);
            }
        }
    }
    flb_free(to_redact);

    if (log_encoder.output_length > 0) {
        *out_buf  = log_encoder.output_buffer;
        *out_size = log_encoder.output_length;

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

static int cb_nightfall_exit(void *data, struct flb_config *config)
{
    struct flb_filter_nightfall *ctx = data;

    if (ctx == NULL) {
        return 0;
    }
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }
    if (ctx->tls) {
        flb_tls_destroy(ctx->tls);
    }
    if (ctx->auth_header) {
        flb_sds_destroy(ctx->auth_header);
    }
    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "nightfall_api_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_filter_nightfall, nightfall_api_key),
     "The Nightfall API key to scan your logs with."
    },
    {
     FLB_CONFIG_MAP_STR, "policy_id", NULL,
     0, FLB_TRUE, offsetof(struct flb_filter_nightfall, policy_id),
     "The Nightfall policy ID to scan your logs with."
    },
    {
     FLB_CONFIG_MAP_DOUBLE, "sampling_rate", "1",
     0, FLB_TRUE, offsetof(struct flb_filter_nightfall, sampling_rate),
     "The sampling rate for scanning, must be (0,1]. 1 means all logs will be scanned."
    },
    {
     FLB_CONFIG_MAP_INT, "tls.debug", "0",
     0, FLB_TRUE, offsetof(struct flb_filter_nightfall, tls_debug),
     "Set TLS debug level: 0 (no debug), 1 (error), "
     "2 (state change), 3 (info) and 4 (verbose)"
    },
    {
     FLB_CONFIG_MAP_BOOL, "tls.verify", "true",
     0, FLB_TRUE, offsetof(struct flb_filter_nightfall, tls_verify),
     "Enable or disable verification of TLS peer certificate"
    },
    {
     FLB_CONFIG_MAP_STR, "tls.vhost", NULL,
     0, FLB_TRUE, offsetof(struct flb_filter_nightfall, tls_vhost),
     "Set optional TLS virtual host"
    },
    {
     FLB_CONFIG_MAP_STR, "tls.ca_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_filter_nightfall, tls_ca_path),
     "Path to root certificates on the system"
    },
    {0}
};

struct flb_filter_plugin filter_nightfall_plugin = {
    .name         = "nightfall",
    .description  = "scans records for sensitive content",
    .cb_init      = cb_nightfall_init,
    .cb_filter    = cb_nightfall_filter,
    .cb_exit      = cb_nightfall_exit,
    .config_map   = config_map,
    .flags        = 0
};
