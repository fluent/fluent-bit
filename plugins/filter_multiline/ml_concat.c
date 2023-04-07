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

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>
#include <fluent-bit/flb_compat.h>
#include <stdio.h>

#include "ml_concat.h"

msgpack_object_kv *ml_get_key(msgpack_object *map, char *check_for_key)
{
    int i;
    char *key_str = NULL;
    size_t key_str_size = 0;
    msgpack_object_kv *kv;
    msgpack_object  key;
    int check_key = FLB_FALSE;

    kv = map->via.map.ptr;

    for(i=0; i < map->via.map.size; i++) {
        check_key = FLB_FALSE;

        key = (kv+i)->key;
        if (key.type == MSGPACK_OBJECT_BIN) {
            key_str  = (char *) key.via.bin.ptr;
            key_str_size = key.via.bin.size;
            check_key = FLB_TRUE;
        }
        if (key.type == MSGPACK_OBJECT_STR) {
            key_str  = (char *) key.via.str.ptr;
            key_str_size = key.via.str.size;
            check_key = FLB_TRUE;
        }

        if (check_key == FLB_TRUE) {
            if (strncmp(check_for_key, key_str, key_str_size) == 0) {
                return (kv+i);
            }
        }
    }
    return NULL;
}

int ml_is_partial(msgpack_object *map)
{
    char *val_str = NULL;
    msgpack_object_kv *kv;
    msgpack_object  val;
    
    kv = ml_get_key(map, FLB_MULTILINE_PARTIAL_MESSAGE_KEY);

    if (kv == NULL) {
        return FLB_FALSE;
    }

    val = kv->val;
    if (val.type == MSGPACK_OBJECT_BIN) {
        val_str  = (char *) val.via.bin.ptr;
    }
    if (val.type == MSGPACK_OBJECT_STR) {
        val_str  = (char *) val.via.str.ptr;
    }

    if (strncasecmp("true", val_str, 4) == 0) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

int ml_is_partial_last(msgpack_object *map)
{
    char *val_str = NULL;
    msgpack_object_kv *kv;
    msgpack_object  val;
    
    kv = ml_get_key(map, FLB_MULTILINE_PARTIAL_LAST_KEY);

    if (kv == NULL) {
        return FLB_FALSE;
    }

    val = kv->val;
    if (val.type == MSGPACK_OBJECT_BIN) {
        val_str  = (char *) val.via.bin.ptr;
    }
    if (val.type == MSGPACK_OBJECT_STR) {
        val_str  = (char *) val.via.str.ptr;
    }

    if (strncasecmp("true", val_str, 4) == 0) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

int ml_get_partial_id(msgpack_object *map, 
                     char **partial_id_str,
                     size_t *partial_id_size)
{
    char *val_str = NULL;
    size_t val_str_size = 0;
    msgpack_object_kv *kv;
    msgpack_object  val;
    
    kv = ml_get_key(map, FLB_MULTILINE_PARTIAL_ID_KEY);

    if (kv == NULL) {
        return -1;
    }

    val = kv->val;
    if (val.type == MSGPACK_OBJECT_BIN) {
        val_str  = (char *) val.via.bin.ptr;
        val_str_size  = val.via.bin.size;
    }
    if (val.type == MSGPACK_OBJECT_STR) {
        val_str  = (char *) val.via.str.ptr;
        val_str_size  = val.via.str.size;
    }

    *partial_id_str = val_str;
    *partial_id_size = val_str_size;

    return 0;
}

struct split_message_packer *ml_get_packer(struct mk_list *packers, const char *tag, 
                                           char *input_name, 
                                           char *partial_id_str, size_t partial_id_size)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct split_message_packer *packer;
    int name_check;
    int tag_check;
    int id_check;


    mk_list_foreach_safe(head, tmp, packers) {
        packer = mk_list_entry(head, struct split_message_packer, _head);
        id_check = strncmp(packer->partial_id, partial_id_str, partial_id_size);
        if (id_check != 0) {
            continue;
        }
        name_check = strcmp(packer->input_name, input_name);
        if (name_check != 0) {
            continue;
        }
        tag_check = strcmp(packer->tag, tag);
        if (tag_check == 0) {
            return packer;
        }
    }

    return NULL;
}

struct split_message_packer *ml_create_packer(const char *tag, char *input_name, 
                                              char *partial_id_str, size_t partial_id_size,
                                              msgpack_object *map, char *multiline_key_content,
                                              struct flb_time *tm)
{
    struct split_message_packer *packer;
    msgpack_object_kv *kv;
    msgpack_object_kv *split_kv;
    flb_sds_t tmp;
    int i;
    char *key_str = NULL;
    size_t key_str_size = 0;
    msgpack_object key;
    int check_key = FLB_FALSE;
    size_t len;
    int ret;

    packer = flb_calloc(1, sizeof(struct split_message_packer));
    if (!packer) {
        flb_errno();
        return NULL;
    }

    tmp = flb_sds_create(input_name);
    if (!tmp) {
        flb_errno();
        flb_free(packer);
        return NULL;
    }
    packer->input_name = tmp;

    tmp = flb_sds_create(tag);
    if (!tmp) {
        flb_errno();
        ml_split_message_packer_destroy(packer);
        return NULL;
    }
    packer->tag = tmp;

    tmp = flb_sds_create_len(partial_id_str, partial_id_size);
    if (!tmp) {
        flb_errno();
        ml_split_message_packer_destroy(packer);
        return NULL;
    }
    packer->partial_id = tmp;

    packer->buf = flb_sds_create_size(FLB_MULTILINE_PARTIAL_BUF_SIZE);
    if (!packer->buf) {
        flb_errno();
        ml_split_message_packer_destroy(packer);
        return NULL;
    }

    ret = flb_log_event_encoder_init(&packer->log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[partial message concat] Log event encoder initialization error : %d", ret);

        ml_split_message_packer_destroy(packer);

        return NULL;
    }

    /* get the key that is split */
    split_kv = ml_get_key(map, multiline_key_content);
    if (split_kv == NULL) {
        flb_error("[partial message concat] Could not find key %s in record", multiline_key_content);
        ml_split_message_packer_destroy(packer);
        return NULL;
    }

    ret = flb_log_event_encoder_begin_record(&packer->log_encoder);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[partial message concat] Log event encoder error : %d", ret);

        ml_split_message_packer_destroy(packer);

        return NULL;
    }

    /* write all of the keys except the split one and the partial metadata */
    ret = flb_log_event_encoder_set_timestamp(
            &packer->log_encoder, tm);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[partial message concat] Log event encoder error : %d", ret);

        ml_split_message_packer_destroy(packer);

        return NULL;
    }

    kv = map->via.map.ptr;

    for(i=0;
        i < map->via.map.size &&
        ret == FLB_EVENT_ENCODER_SUCCESS;
        i++) {
        if ((kv+i) == split_kv) {
            continue;
        }

        key = (kv+i)->key;
        if (key.type == MSGPACK_OBJECT_BIN) {
            key_str  = (char *) key.via.bin.ptr;
            key_str_size = key.via.bin.size;
            check_key = FLB_TRUE;
        }
        if (key.type == MSGPACK_OBJECT_STR) {
            key_str  = (char *) key.via.str.ptr;
            key_str_size = key.via.str.size;
            check_key = FLB_TRUE;
        }

        len = FLB_MULTILINE_PARTIAL_PREFIX_LEN;
        if (key_str_size < len) {
            len = key_str_size;
        }

        if (check_key == FLB_TRUE) {
            if (strncmp(FLB_MULTILINE_PARTIAL_PREFIX, key_str, len) == 0) {
                /* don't pack the partial keys */
                continue;
            }
        }

        ret = flb_log_event_encoder_append_body_values(
                &packer->log_encoder,
                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv[i].key),
                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv[i].val));
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        /* write split kv last, so we can append to it later as needed */
        ret = flb_log_event_encoder_append_body_msgpack_object(
                &packer->log_encoder,
                &split_kv->key);
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[partial message concat] Log event encoder error : %d", ret);

        ml_split_message_packer_destroy(packer);

        return NULL;
    }

    return packer;
}

unsigned long long ml_current_timestamp() {
    struct flb_time te;
    flb_time_get(&te);
    return flb_time_to_nanosec(&te) / 1000000LL;
}

int ml_split_message_packer_write(struct split_message_packer *packer, 
                                  msgpack_object *map, char *multiline_key_content)
{   
    char *val_str = NULL;
    size_t val_str_size = 0;
    msgpack_object_kv *kv;
    msgpack_object  val;
    
    kv = ml_get_key(map, multiline_key_content);

    if (kv == NULL) {
        flb_error("[partial message concat] Could not find key %s in record", multiline_key_content);
        return -1;
    }

    val = kv->val;
    if (val.type == MSGPACK_OBJECT_BIN) {
        val_str  = (char *) val.via.bin.ptr;
        val_str_size = val.via.bin.size;
    } else if (val.type == MSGPACK_OBJECT_STR) {
        val_str  = (char *) val.via.str.ptr;
        val_str_size = val.via.str.size;
    } else {
        return -1;
    }

    flb_sds_cat_safe(&packer->buf, val_str, val_str_size);
    packer->last_write_time = ml_current_timestamp();

    return 0;
}

void ml_split_message_packer_complete(struct split_message_packer *packer)
{
    flb_log_event_encoder_append_body_string(&packer->log_encoder,
                                             packer->buf,
                                             flb_sds_len(packer->buf));

    flb_log_event_encoder_commit_record(&packer->log_encoder);
}

void ml_append_complete_record(struct split_message_packer *packer,
                               struct flb_log_event_encoder *log_encoder)
{
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    ret = flb_log_event_decoder_init(
            &log_decoder,
            packer->log_encoder.output_buffer,
            packer->log_encoder.output_length);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_error("[partial message concat] Log event decoder error : %d",
                  ret);

        return;
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = flb_log_event_encoder_begin_record(log_encoder);

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_timestamp(
                    log_encoder,
                    &log_event.timestamp);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_metadata_from_msgpack_object(
                    log_encoder,
                    log_event.metadata);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_body_from_msgpack_object(
                    log_encoder,
                    log_event.body);
        }

        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(log_encoder);
        }
        else {
            flb_log_event_encoder_rollback_record(log_encoder);

            break;
        }
    }

    if (ret == FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA &&
        log_decoder.offset == packer->log_encoder.output_length) {
        ret = FLB_EVENT_ENCODER_SUCCESS;
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_error("[partial message concat] Log event encoder error : %d",
                  ret);

        return;
    }

    flb_log_event_decoder_destroy(&log_decoder);
}

void ml_split_message_packer_destroy(struct split_message_packer *packer)
{
    if (!packer) {
        return;
    }

    if (packer->tag) {
        flb_sds_destroy(packer->tag);
    }
    if (packer->buf) {
        flb_sds_destroy(packer->buf);
    }
    if (packer->input_name) {
        flb_sds_destroy(packer->input_name);
    }
    if (packer->partial_id) {
        flb_sds_destroy(packer->partial_id);
    }

    flb_log_event_encoder_destroy(&packer->log_encoder);

    flb_free(packer);
}

