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

#ifndef FLB_FILTER_MULTILINE_CONCAT_H
#define FLB_FILTER_MULTILINE_CONCAT_H

#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#define FLB_MULTILINE_MEM_BUF_LIMIT_DEFAULT  "10M"
#define FLB_MULTILINE_METRIC_EMITTED         200
/* docker logs are split at 16KB */
#define FLB_MULTILINE_PARTIAL_BUF_SIZE       24000

/* 
 * Long term these keys could be made user configurable
 * But everyone who's asking for this right now wants it for split
 * Docker logs, which has a set series of keys
 */
#define FLB_MULTILINE_PARTIAL_PREFIX       "partial_"
#define FLB_MULTILINE_PARTIAL_PREFIX_LEN   8
#define FLB_MULTILINE_PARTIAL_MESSAGE_KEY  "partial_message"
#define FLB_MULTILINE_PARTIAL_ID_KEY       "partial_id"
#define FLB_MULTILINE_PARTIAL_LAST_KEY     "partial_last"

struct split_message_packer {
    flb_sds_t tag;
    flb_sds_t input_name;
    flb_sds_t partial_id;

    /* packaging buffers */
    // msgpack_sbuffer mp_sbuf;  /* temporary msgpack buffer              */
    // msgpack_packer mp_pck;    /* temporary msgpack packer              */
    struct flb_log_event_encoder log_encoder;

    flb_sds_t buf;

    /* used to flush buffers that have been pending for more than flush_ms */
    unsigned long long last_write_time;

    struct mk_list _head;
};

msgpack_object_kv *ml_get_key(msgpack_object *map, char *check_for_key);
int ml_is_partial(msgpack_object *map);
int ml_is_partial_last(msgpack_object *map);
int ml_get_partial_id(msgpack_object *map, 
                      char **partial_id_str,
                      size_t *partial_id_size);
struct split_message_packer *ml_get_packer(struct mk_list *packers, const char *tag, 
                                           char *input_name, 
                                           char *partial_id_str, size_t partial_id_size);
struct split_message_packer *ml_create_packer(const char *tag, char *input_name, 
                                              char *partial_id_str, size_t partial_id_size,
                                              msgpack_object *map, char *multiline_key_content,
                                              struct flb_time *tm);
int ml_split_message_packer_write(struct split_message_packer *packer, 
                                  msgpack_object *map, char *multiline_key_content);
void ml_split_message_packer_complete(struct split_message_packer *packer);
void ml_split_message_packer_destroy(struct split_message_packer *packer);
void ml_append_complete_record(struct split_message_packer *packer,
                               struct flb_log_event_encoder *log_encoder);
unsigned long long ml_current_timestamp();


#endif
