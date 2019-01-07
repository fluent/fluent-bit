/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_PACK_H
#define FLB_PACK_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <jsmn/jsmn.h>
#include <msgpack.h>

#define FLB_PACK_JSON_UNDEFINED    JSMN_UNDEFINED
#define FLB_PACK_JSON_OBJECT       JSMN_OBJECT
#define FLB_PACK_JSON_ARRAY        JSMN_ARRAY
#define FLB_PACK_JSON_STRING       JSMN_STRING
#define FLB_PACK_JSON_PRIMITIVE    JSMN_PRIMITIVE

struct flb_pack_state {
    int multiple;         /* support multiple jsons? */
    int tokens_count;     /* number of parsed tokens */
    int tokens_size;      /* array size of tokens    */
    int last_byte;        /* last byte of a full msg */
    jsmntok_t *tokens;    /* tokens array            */
    jsmn_parser parser;   /* parser state            */
};

int flb_json_tokenise(char *js, size_t len, struct flb_pack_state *state);
int flb_pack_json(char *js, size_t len, char **buffer, size_t *size,
                  int *root_type);
int flb_pack_state_init(struct flb_pack_state *s);
void flb_pack_state_reset(struct flb_pack_state *s);

int flb_pack_json_state(char *js, size_t len,
                        char **buffer, int *size,
                        struct flb_pack_state *state);
int flb_pack_json_valid(char *json, size_t len);

void flb_pack_print(char *data, size_t bytes);
int flb_msgpack_to_json(char *json_str, size_t str_len,
                        msgpack_object *obj);
char* flb_msgpack_to_json_str(size_t size, msgpack_object *obj);
int flb_msgpack_raw_to_json_str(char *buf, size_t buf_size,
                                char **out_buf, size_t *out_size);
flb_sds_t flb_msgpack_raw_to_json_sds(void *in_buf, size_t in_size);

int flb_pack_time_now(msgpack_packer *pck);
int flb_msgpack_expand_map(char *map_data, size_t map_size,
                           msgpack_object_kv **obj_arr, int obj_arr_len,
                           char** out_buf, int* out_size);

struct flb_gelf_fields {
    flb_sds_t timestamp_key;
    flb_sds_t host_key;
    flb_sds_t short_message_key;
    flb_sds_t full_message_key;
    flb_sds_t level_key;
};

flb_sds_t flb_msgpack_to_gelf(flb_sds_t *s, msgpack_object *o,
   struct flb_time *tm, struct flb_gelf_fields *fields);

flb_sds_t flb_msgpack_raw_to_gelf(char *buf, size_t buf_size,
   struct flb_time *tm, struct flb_gelf_fields *fields);

#endif
