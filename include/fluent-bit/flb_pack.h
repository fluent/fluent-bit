/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2025 The Fluent Bit Authors
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
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_config.h>

#include <msgpack.h>
#include <yyjson.h>

/* JSON types */
#define FLB_PACK_JSON_UNDEFINED     JSMN_UNDEFINED
#define FLB_PACK_JSON_OBJECT        JSMN_OBJECT
#define FLB_PACK_JSON_ARRAY         JSMN_ARRAY
#define FLB_PACK_JSON_STRING        JSMN_STRING
#define FLB_PACK_JSON_PRIMITIVE     JSMN_PRIMITIVE

/* Date formats */
#define FLB_PACK_JSON_DATE_DOUBLE                0
#define FLB_PACK_JSON_DATE_ISO8601               1
#define FLB_PACK_JSON_DATE_EPOCH                 2
#define FLB_PACK_JSON_DATE_JAVA_SQL_TIMESTAMP    3
#define FLB_PACK_JSON_DATE_EPOCH_MS              4

/* Specific ISO8601 format */
#define FLB_PACK_JSON_DATE_ISO8601_FMT "%Y-%m-%dT%H:%M:%S"

/* Specific Java SQL Timestamp format */
#define FLB_PACK_JSON_DATE_JAVA_SQL_TIMESTAMP_FMT "%Y-%m-%d %H:%M:%S"

#define FBL_PACK_JSON_DATE_FORMAT_DESCRIPTION   "Specify the format of the date, " \
    "supported formats: double, " \
     "iso8601 (e.g: 2018-05-30T09:39:52.000681Z), " \
     "java_sql_timestamp (e.g: 2018-05-30 09:39:52.000681, useful for AWS Athena), "\
     "and epoch."

/* JSON formats (modes) */
#define FLB_PACK_JSON_FORMAT_NONE        0
#define FLB_PACK_JSON_FORMAT_JSON        1
#define FLB_PACK_JSON_FORMAT_STREAM      2
#define FLB_PACK_JSON_FORMAT_LINES       3

struct flb_pack_state {
    int multiple;         /* support multiple jsons? */
    int tokens_count;     /* number of parsed tokens */
    int tokens_size;      /* total tokens in the array */
    int last_byte;        /* last byte of a full msg   */
    jsmntok_t *tokens;    /* tokens array              */
    jsmn_parser parser;   /* parser state              */
    char *buf_data;       /* temporary buffer           */
    size_t buf_size;      /* temporary buffer size      */
    size_t buf_len;       /* temporary buffer length    */
};

int flb_pack_init(struct flb_config *config);
int flb_json_tokenise(const char *js, size_t len, struct flb_pack_state *state);


int flb_pack_json(const char *js, size_t len, char **buffer, size_t *size,
                  int *root_type, size_t *consumed);
int flb_pack_json_recs(const char *js, size_t len, char **buffer, size_t *size,
                       int *root_type, int *out_records, size_t *consumed);
int flb_pack_json_yyjson(const char *js, size_t len, char **buffer, size_t *size,
                         int *root_type, size_t *consumed);
int flb_pack_json_recs_yyjson(const char *js, size_t len, char **buffer,
                              size_t *size, int *root_type, int *out_records,
                              size_t *consumed);

int flb_pack_state_init(struct flb_pack_state *s);
void flb_pack_state_reset(struct flb_pack_state *s);

int flb_pack_json_state(const char *js, size_t len,
                        char **buffer, int *size,
                        struct flb_pack_state *state);
int flb_pack_json_valid(const char *json, size_t len);

flb_sds_t flb_pack_msgpack_to_json_format(const char *data, uint64_t bytes,
                                          int json_format, int date_format,
                                          flb_sds_t date_key);
int flb_pack_to_json_format_type(const char *str);
int flb_pack_to_json_date_type(const char *str);

void flb_pack_print(const char *data, size_t bytes);
int flb_msgpack_to_json(char *json_str, size_t str_len,
                        const msgpack_object *obj);
char* flb_msgpack_to_json_str(size_t size, const msgpack_object *obj);
flb_sds_t flb_msgpack_raw_to_json_sds(const void *in_buf, size_t in_size);

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
                              struct flb_time *tm,
                              struct flb_gelf_fields *fields);

flb_sds_t flb_msgpack_raw_to_gelf(char *buf, size_t buf_size,
                                  struct flb_time *tm,
                                  struct flb_gelf_fields *fields);

#endif
